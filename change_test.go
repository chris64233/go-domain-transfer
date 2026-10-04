package domaintransfer

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// changeSpecs 构造一笔变更申请的联系人入参，email 用于区分不同资料内容。
func changeSpecs(email string) []ContactSpec {
	return []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin", Email: email, Credential: "admin-secret"},
		{ID: "c-tech", Role: RoleTech, Name: "Tech", Email: "tech@example.com", Credential: "tech-secret"},
	}
}

// setupChangeableDomain 登记域名并配置初始联系人，返回当前资料版本。
func setupChangeableDomain(t *testing.T, svc *Service, domain string) int64 {
	t.Helper()
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatalf("RegisterDomain: %v", err)
	}
	configureTwoContacts(t, svc, domain, false, 48*time.Hour)
	d, err := svc.GetDomain(domain)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	return d.Version
}

func submitChange(t *testing.T, svc *Service, ref, domain, email string) *ContactChangeRequest {
	t.Helper()
	req, err := svc.SubmitContactChange(ref, domain, "owner-1", changeSpecs(email),
		[]ContactRole{RoleAdmin, RoleTech}, true, 0)
	if err != nil {
		t.Fatalf("SubmitContactChange: %v", err)
	}
	return req
}

func TestSubmitContactChange_FreezesSnapshotAndBaseVersion(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	base := setupChangeableDomain(t, svc, "example.com")

	req := submitChange(t, svc, "req-1", "example.com", "new-admin@example.com")
	if req.Status != ChangePending || req.BaseVersion != base {
		t.Fatalf("unexpected request: %+v", req)
	}
	if len(req.Contacts) != 2 || req.Contacts[0].CredentialHash == "" {
		t.Fatalf("snapshot not frozen with digests: %+v", req.Contacts)
	}

	// 申请创建后修改原联系人资料：待审批内容不得改变，旧申请被明确取代。
	configureTwoContacts(t, svc, "example.com", false, 24*time.Hour)
	got, err := svc.GetContactChange(req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ChangeSuperseded {
		t.Fatalf("want superseded, got %s", got.Status)
	}
	for _, c := range got.Contacts {
		if c.ID == "c-admin" && c.Email != "new-admin@example.com" {
			t.Fatalf("pending snapshot mutated by later configure: %+v", c)
		}
	}
}

func TestSubmitContactChange_IdempotentAndConflict(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupChangeableDomain(t, svc, "example.com")
	setupChangeableDomain(t, svc, "other.com")

	req := submitChange(t, svc, "req-1", "example.com", "new-admin@example.com")

	// 同号同内容：返回原记录。
	again, err := svc.SubmitContactChange("req-1", "example.com", "owner-1", changeSpecs("new-admin@example.com"),
		[]ContactRole{RoleAdmin, RoleTech}, true, 0)
	if err != nil || again.ID != req.ID {
		t.Fatalf("idempotent replay failed: %+v, %v", again, err)
	}

	// 同号不同资料：冲突。
	if _, err := svc.SubmitContactChange("req-1", "example.com", "owner-1", changeSpecs("other@example.com"),
		[]ContactRole{RoleAdmin, RoleTech}, true, 0); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want ErrChangeRequestConflict for changed contacts, got %v", err)
	}
	// 同号不同域名：冲突。
	if _, err := svc.SubmitContactChange("req-1", "other.com", "owner-1", changeSpecs("new-admin@example.com"),
		[]ContactRole{RoleAdmin, RoleTech}, true, 0); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want ErrChangeRequestConflict for changed domain, got %v", err)
	}
	// 资料再次修改使版本推进后，同号同内容重放也冲突（审批版本已变化）。
	configureTwoContacts(t, svc, "example.com", false, 24*time.Hour)
	if _, err := svc.SubmitContactChange("req-1", "example.com", "owner-1", changeSpecs("new-admin@example.com"),
		[]ContactRole{RoleAdmin, RoleTech}, true, 0); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want ErrChangeRequestConflict for stale base version, got %v", err)
	}
}

func TestDecideContactChange_ApproveWritesContactsAtomically(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	base := setupChangeableDomain(t, svc, "example.com")
	req := submitChange(t, svc, "req-1", "example.com", "new-admin@example.com")
	other := submitChange(t, svc, "req-2", "example.com", "rival@example.com")

	// 非所有者不得审批。
	if _, err := svc.DecideContactChange(req.ID, "intruder", true, ""); !errors.Is(err, ErrNotDomainOwner) {
		t.Fatalf("want ErrNotDomainOwner, got %v", err)
	}

	got, err := svc.DecideContactChange(req.ID, "owner-1", true, "verified")
	if err != nil {
		t.Fatalf("DecideContactChange: %v", err)
	}
	if got.Status != ChangeApproved {
		t.Fatalf("want approved, got %s", got.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Version != base+1 {
		t.Fatalf("version not advanced: %d", d.Version)
	}
	if d.Contacts["c-admin"].Email != "new-admin@example.com" {
		t.Fatalf("change not written to domain: %+v", d.Contacts["c-admin"])
	}
	if d.Approval == nil || !d.Approval.RequireAll {
		t.Fatalf("approval policy not updated: %+v", d.Approval)
	}
	// 同域其他待审批申请随之失效：一个域名只留一个有效联系人版本。
	rival, _ := svc.GetContactChange(other.ID)
	if rival.Status != ChangeSuperseded {
		t.Fatalf("rival request want superseded, got %s", rival.Status)
	}
	// outbox 与审计留痕。
	found := false
	for _, m := range svc.ListOutbox() {
		if m.Type == "contact_change.approved" && m.Domain == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing contact_change.approved outbox message")
	}
}

func TestDecideContactChange_DuplicateDecisionRejected(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupChangeableDomain(t, svc, "example.com")
	approved := submitChange(t, svc, "req-1", "example.com", "a@example.com")
	rejected := submitChange(t, svc, "req-2", "example.com", "b@example.com")

	if _, err := svc.DecideContactChange(approved.ID, "owner-1", true, ""); err != nil {
		t.Fatal(err)
	}
	// 重复审批：不得覆盖终态。
	if _, err := svc.DecideContactChange(approved.ID, "owner-1", true, ""); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("want ErrChangeRequestNotPending on re-approve, got %v", err)
	}
	if _, err := svc.DecideContactChange(approved.ID, "owner-1", false, ""); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("want ErrChangeRequestNotPending on reject-after-approve, got %v", err)
	}

	// req-2 已随 req-1 批准被取代；另提一笔验证拒绝终态同样不可翻案。
	if _, err := svc.DecideContactChange(rejected.ID, "owner-1", false, ""); !errors.Is(err, ErrChangeRequestStale) {
		t.Fatalf("want ErrChangeRequestStale for superseded request, got %v", err)
	}
	fresh := submitChange(t, svc, "req-3", "example.com", "c@example.com")
	if _, err := svc.DecideContactChange(fresh.ID, "owner-1", false, "no"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideContactChange(fresh.ID, "owner-1", true, ""); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("want ErrChangeRequestNotPending on approve-after-reject, got %v", err)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Contacts["c-admin"].Email != "a@example.com" {
		t.Fatalf("duplicate decisions mutated contacts: %+v", d.Contacts["c-admin"])
	}
}

func TestDecideContactChange_StaleOnLockAndTransferComplete(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupChangeableDomain(t, svc, "example.com")

	// 域名锁定（转移发起）使旧申请失效。
	lockedReq := submitChange(t, svc, "req-1", "example.com", "a@example.com")
	code, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideContactChange(lockedReq.ID, "owner-1", true, ""); !errors.Is(err, ErrChangeRequestStale) {
		t.Fatalf("want ErrChangeRequestStale after lock, got %v", err)
	}

	// 锁定期间可提交新申请；转移完成（所有权切换）使其失效。
	inFlight := submitChange(t, svc, "req-2", "example.com", "b@example.com")
	tr, _ := svc.GetTransferByRef("ext-1")
	if _, err := svc.SubmitContactDecision(tr.ID, "evt-a", 1, "c-admin", "admin-secret", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "evt-t", 1, "c-tech", "tech-secret", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideContactChange(inFlight.ID, "owner-2", true, ""); !errors.Is(err, ErrChangeRequestStale) {
		t.Fatalf("want ErrChangeRequestStale after transfer complete, got %v", err)
	}
	// 迟到的旧审批不得回写：域名联系人仍是转移前资料。
	d, _ := svc.GetDomain("example.com")
	if d.Contacts["c-admin"].Email != "admin@example.com" {
		t.Fatalf("stale approval wrote contacts: %+v", d.Contacts["c-admin"])
	}
}

// flakyPersister 可切换 Save 是否失败，用于验证写入失败时的原子性。
type flakyPersister struct {
	mu   sync.Mutex
	fail bool
}

func (p *flakyPersister) setFail(fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = fail
}

func (p *flakyPersister) Save([]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("disk full")
	}
	return nil
}

func (p *flakyPersister) Load() ([]byte, error) { return nil, nil }

func TestDecideContactChange_WriteFailureRollsBackBothSides(t *testing.T) {
	clk := newTestClock()
	persister := &flakyPersister{}
	svc := newTestService(t, clk, WithPersister(persister))
	base := setupChangeableDomain(t, svc, "example.com")
	req := submitChange(t, svc, "req-1", "example.com", "new-admin@example.com")

	// 写入失败：审批结果与域名资料都不能只更新一边。
	persister.setFail(true)
	if _, err := svc.DecideContactChange(req.ID, "owner-1", true, ""); err == nil {
		t.Fatal("want persistence error")
	}
	got, err := svc.GetContactChange(req.ID)
	if err != nil || got.Status != ChangePending {
		t.Fatalf("request must stay pending after failed write: %+v, %v", got, err)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Version != base || d.Contacts["c-admin"].Email != "admin@example.com" {
		t.Fatalf("domain mutated by failed approval: %+v", d)
	}
	if n := len(svc.ListOutbox()); n != 0 {
		t.Fatalf("outbox leaked from failed approval: %d", n)
	}

	// 恢复后同一申请可正常审批（失败不消费申请）。
	persister.setFail(false)
	if _, err := svc.DecideContactChange(req.ID, "owner-1", true, ""); err != nil {
		t.Fatalf("approve after recovery: %v", err)
	}
	d, _ = svc.GetDomain("example.com")
	if d.Contacts["c-admin"].Email != "new-admin@example.com" {
		t.Fatalf("change not applied after recovery: %+v", d.Contacts["c-admin"])
	}
}

func TestContactChange_ConcurrentApprovalModificationAndTransfer(t *testing.T) {
	for i := 0; i < 20; i++ {
		clk := newTestClock()
		svc := newTestService(t, clk)
		setupChangeableDomain(t, svc, "example.com")
		req := submitChange(t, svc, "req-1", "example.com", "change@example.com")
		code, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}

		// 审批、资料修改、转移发起并发竞争：旧审批不得回写，最终只留一个有效版本。
		var wg sync.WaitGroup
		var approveErr error
		var approveMu sync.Mutex
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := svc.DecideContactChange(req.ID, "owner-1", true, "")
			approveMu.Lock()
			approveErr = err
			approveMu.Unlock()
		}()
		go func() {
			defer wg.Done()
			_ = svc.ConfigureContacts("example.com", "owner-1", changeSpecs("reconfig@example.com"),
				[]ContactRole{RoleAdmin, RoleTech}, true, time.Hour)
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
		}()
		wg.Wait()

		approveMu.Lock()
		if approveErr != nil && !errors.Is(approveErr, ErrChangeRequestStale) {
			t.Fatalf("iter %d: unexpected approve error: %v", i, approveErr)
		}
		approveMu.Unlock()

		got, _ := svc.GetContactChange(req.ID)
		if !got.Status.Terminal() {
			t.Fatalf("iter %d: request must be terminal after the race, got %s", i, got.Status)
		}
		d, _ := svc.GetDomain("example.com")
		email := d.Contacts["c-admin"].Email
		if approveErr == nil && email != "change@example.com" && email != "reconfig@example.com" {
			t.Fatalf("iter %d: contacts from unknown generation: %q", i, email)
		}
		if approveErr != nil && email == "change@example.com" {
			t.Fatalf("iter %d: stale approval wrote contacts back", i)
		}
	}
}
