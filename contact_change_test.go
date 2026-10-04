package domaintransfer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// changeSpecs 构造一组变更后的联系人入参，返回明文凭据（仅测试持有）。
func changeSpecs() []ContactSpec {
	return []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin New", Email: "admin-new@example.com", Credential: "admin-new-secret"},
		{ID: "c-tech", Role: RoleTech, Name: "Tech New", Email: "tech-new@example.com", Credential: "tech-new-secret"},
	}
}

// setupChangeDomain 登记域名并配置初始联系人，返回当前资料版本。
func setupChangeDomain(t *testing.T, svc *Service) (domain string, version int64) {
	t.Helper()
	domain = "example.com"
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatalf("RegisterDomain: %v", err)
	}
	configureTwoContacts(t, svc, domain, false, 48*time.Hour)
	d, err := svc.GetDomain(domain)
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	return domain, d.Version
}

func TestSubmitContactChange_FreezesSnapshotAndVersion(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	domain, version := setupChangeDomain(t, svc)

	r, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs())
	if err != nil {
		t.Fatalf("SubmitContactChange: %v", err)
	}
	if r.Status != ChangePending || r.BaseVersion != version || len(r.Snapshot) != 2 {
		t.Fatalf("unexpected request: %+v", r)
	}

	// 申请创建后修改域名当前联系人，待审批申请内容不得改变。
	configureTwoContacts(t, svc, domain, false, 24*time.Hour)
	got, err := svc.GetContactChange("req-1")
	if err != nil {
		t.Fatalf("GetContactChange: %v", err)
	}
	if got.BaseVersion != version || got.Snapshot[0].Name != "Admin New" {
		t.Fatalf("pending request mutated by later configure: %+v", got)
	}
	// 原联系人被修改后，旧申请应已明确作废。
	if got.Status != ChangeVoided {
		t.Fatalf("want voided after contacts reconfigured, got %s", got.Status)
	}

	// 持久化快照中不得出现明文凭据。
	snap, err := svc.store.snapshotJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"admin-new-secret", "tech-new-secret"} {
		if strings.Contains(string(snap), secret) {
			t.Fatalf("raw credential leaked into persisted state: %q", secret)
		}
	}
}

func TestSubmitContactChange_IdempotencyAndConflict(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	domain, version := setupChangeDomain(t, svc)

	r1, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	// 同号同内容：返回原记录。
	r2, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs())
	if err != nil {
		t.Fatalf("idempotent resubmit: %v", err)
	}
	if r2.ID != r1.ID || r2.Status != r1.Status || r2.BaseVersion != r1.BaseVersion {
		t.Fatalf("idempotent resubmit returned different record: %+v vs %+v", r2, r1)
	}

	// 同号不同资料：冲突。
	altered := changeSpecs()
	altered[0].Email = "other@example.com"
	if _, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, altered); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want conflict on different contacts, got %v", err)
	}
	// 同号不同域名：冲突。
	if _, err := svc.SubmitContactChange("req-1", "other.com", "agent-1", version, changeSpecs()); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want conflict on different domain, got %v", err)
	}
	// 同号不同审批版本：冲突。
	if _, err := svc.SubmitContactChange("req-1", domain, "agent-1", version+1, changeSpecs()); !errors.Is(err, ErrChangeRequestConflict) {
		t.Fatalf("want conflict on different base version, got %v", err)
	}
	// 基于过期版本的新申请：明确失效。
	configureTwoContacts(t, svc, domain, false, 0)
	if _, err := svc.SubmitContactChange("req-2", domain, "agent-1", version, changeSpecs()); !errors.Is(err, ErrChangeRequestStale) {
		t.Fatalf("want stale on outdated base version, got %v", err)
	}
}

func TestDecideContactChange_ApproveWritesContactsAtomically(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	domain, version := setupChangeDomain(t, svc)

	if _, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	r, err := svc.DecideContactChange("req-1", "owner-1", true, "ok")
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if r.Status != ChangeApproved || r.DecidedBy != "owner-1" {
		t.Fatalf("unexpected request: %+v", r)
	}
	d, _ := svc.GetDomain(domain)
	if d.Version != version+1 {
		t.Fatalf("domain version not bumped: %d", d.Version)
	}
	if d.Contacts["c-admin"].Email != "admin-new@example.com" {
		t.Fatalf("contacts not written: %+v", d.Contacts["c-admin"])
	}
	if d.Approval == nil || d.Approval.Contacts[0].Email != "admin-new@example.com" {
		t.Fatalf("approval policy snapshot not updated: %+v", d.Approval)
	}
	// 重复审批：终态不可逆。
	if _, err := svc.DecideContactChange("req-1", "owner-1", true, "again"); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("want not-pending on repeated decide, got %v", err)
	}
	// 非所有者不得审批。
	if _, err := svc.SubmitContactChange("req-2", domain, "agent-1", d.Version, changeSpecs()); err != nil {
		t.Fatalf("submit req-2: %v", err)
	}
	if _, err := svc.DecideContactChange("req-2", "intruder", true, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("want forbidden for non-owner, got %v", err)
	}
	// 拒绝不改动域名资料。
	if _, err := svc.DecideContactChange("req-2", "owner-1", false, "no"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	d2, _ := svc.GetDomain(domain)
	if d2.Version != d.Version || d2.Contacts["c-admin"].Email != "admin-new@example.com" {
		t.Fatalf("reject must not change domain contacts: %+v", d2.Contacts["c-admin"])
	}
}

func TestDecideContactChange_StaleOnLockAndReconfigure(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	domain, version := setupChangeDomain(t, svc)

	// 场景一：域名被转移锁定后，旧申请明确作废，迟到审批不得回写。
	if _, err := svc.SubmitContactChange("req-lock", domain, "agent-1", version, changeSpecs()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	code, _, err := svc.GenerateAuthCode(domain, "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	if _, err := svc.InitiateTransfer("ext-1", domain, code, "reg-b"); err != nil {
		t.Fatalf("InitiateTransfer: %v", err)
	}
	r, _ := svc.GetContactChange("req-lock")
	if r.Status != ChangeVoided {
		t.Fatalf("want voided after domain locked, got %s", r.Status)
	}
	if _, err := svc.DecideContactChange("req-lock", "owner-1", true, ""); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("late approval on voided request must fail, got %v", err)
	}
	d, _ := svc.GetDomain(domain)
	if d.Contacts["c-admin"].Email != "admin@example.com" {
		t.Fatalf("late approval wrote contacts back: %+v", d.Contacts["c-admin"])
	}

	// 场景二：转移完成、所有权切换后，基于旧资料的申请作废。
	tr, _ := svc.GetTransferByRef("ext-1")
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-1", 1, "c-admin", "admin-secret", true, ""); err != nil {
		t.Fatalf("contact decision: %v", err)
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-2", 1, "c-tech", "tech-secret", true, ""); err != nil {
		t.Fatalf("contact decision: %v", err)
	}
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	d, _ = svc.GetDomain(domain)
	if _, err := svc.SubmitContactChange("req-done", domain, "agent-1", d.Version, changeSpecs()); err != nil {
		t.Fatalf("submit req-done: %v", err)
	}
	// 新所有者再次修改联系人 → req-done 作废。
	if err := svc.ConfigureContacts(domain, "owner-2", []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "A2", Email: "a2@example.com", Credential: "a2-secret"},
		{ID: "c-tech", Role: RoleTech, Name: "T2", Email: "t2@example.com", Credential: "t2-secret"},
	}, []ContactRole{RoleAdmin, RoleTech}, false, 0); err != nil {
		t.Fatalf("ConfigureContacts: %v", err)
	}
	r, _ = svc.GetContactChange("req-done")
	if r.Status != ChangeVoided {
		t.Fatalf("want voided after reconfigure, got %s", r.Status)
	}
	if _, err := svc.DecideContactChange("req-done", "owner-2", true, ""); !errors.Is(err, ErrChangeRequestNotPending) {
		t.Fatalf("late approval on voided request must fail, got %v", err)
	}

	// 场景三：提交后版本被并发推进，审批路径自身的版本校验作废申请。
	d, _ = svc.GetDomain(domain)
	if _, err := svc.SubmitContactChange("req-race", domain, "agent-1", d.Version, changeSpecs()); err != nil {
		t.Fatalf("submit req-race: %v", err)
	}
	if err := svc.store.transact(func(st *state) error {
		st.Domains[domain].Version++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideContactChange("req-race", "owner-2", true, ""); !errors.Is(err, ErrChangeRequestStale) {
		t.Fatalf("want stale on version mismatch, got %v", err)
	}
	r, _ = svc.GetContactChange("req-race")
	if r.Status != ChangeVoided {
		t.Fatalf("stale request must be voided, got %s", r.Status)
	}
}

func TestDecideContactChange_WriteFailureRollsBackBothSides(t *testing.T) {
	clk := newTestClock()
	p := &switchablePersister{}
	svc := newTestService(t, clk, WithPersister(p))
	domain, version := setupChangeDomain(t, svc)

	if _, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// 持久化失败：审批结果与域名资料都不得更新。
	p.fail = true
	if _, err := svc.DecideContactChange("req-1", "owner-1", true, ""); err == nil {
		t.Fatal("want persistence error")
	}
	r, _ := svc.GetContactChange("req-1")
	if r.Status != ChangePending {
		t.Fatalf("approval must roll back on write failure, got %s", r.Status)
	}
	d, _ := svc.GetDomain(domain)
	if d.Version != version || d.Contacts["c-admin"].Email != "admin@example.com" {
		t.Fatalf("domain contacts must roll back on write failure: %+v", d.Contacts["c-admin"])
	}
}

// switchablePersister 可开关的持久化器：fail 置位后 Save 失败，用于验证原子性。
type switchablePersister struct {
	mu   sync.Mutex
	fail bool
	data []byte
}

func (p *switchablePersister) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errors.New("disk full")
	}
	p.data = append([]byte(nil), b...)
	return nil
}

func (p *switchablePersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.data, nil
}

func TestContactChange_ConcurrentApproveVsReconfigure(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	domain, version := setupChangeDomain(t, svc)

	if _, err := svc.SubmitContactChange("req-1", domain, "agent-1", version, changeSpecs()); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// 审批与资料修改并发竞争：最终只能留下一个有效联系人版本。
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = svc.DecideContactChange("req-1", "owner-1", true, "")
		}()
		go func(i int) {
			defer wg.Done()
			_ = svc.ConfigureContacts(domain, "owner-1", []ContactSpec{
				{ID: "c-admin", Role: RoleAdmin, Name: fmt.Sprintf("A%d", i), Email: "a@example.com", Credential: "x"},
				{ID: "c-tech", Role: RoleTech, Name: fmt.Sprintf("T%d", i), Email: "t@example.com", Credential: "y"},
			}, []ContactRole{RoleAdmin, RoleTech}, false, 0)
		}(i)
	}
	wg.Wait()

	r, _ := svc.GetContactChange("req-1")
	d, _ := svc.GetDomain(domain)
	if !r.Status.Terminal() {
		t.Fatalf("request must reach a terminal state, got %s", r.Status)
	}
	// 域名最终只能留下一个一致的有效联系人版本：
	// 要么是申请快照（审批生效），要么是某次 ConfigureContacts 的完整写入。
	admin := d.Contacts["c-admin"]
	tech := d.Contacts["c-tech"]
	if admin.Email == "admin-new@example.com" {
		if r.Status != ChangeApproved {
			t.Fatal("snapshot contacts written without approval")
		}
		if admin.Name != "Admin New" || tech.Email != "tech-new@example.com" {
			t.Fatalf("mixed contact versions: %+v / %+v", admin, tech)
		}
	} else {
		if admin.Email != "a@example.com" || tech.Email != "t@example.com" {
			t.Fatalf("mixed contact versions: %+v / %+v", admin, tech)
		}
		if r.Status == ChangeApproved && d.Version < version+1 {
			t.Fatalf("approved but version not advanced: %d", d.Version)
		}
	}
}
