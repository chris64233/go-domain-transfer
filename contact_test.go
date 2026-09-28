package domaintransfer

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// setupContactDomain 登记域名、两个联系人并配置 admin+tech 双角色审批。
func setupContactDomain(t *testing.T, svc *Service, domain string, window time.Duration) {
	t.Helper()
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatalf("RegisterDomain: %v", err)
	}
	if err := svc.RegisterContact("c-admin", "Alice Admin", "alice@example.com"); err != nil {
		t.Fatalf("RegisterContact admin: %v", err)
	}
	if err := svc.RegisterContact("c-tech", "Bob Tech", "bob@example.com"); err != nil {
		t.Fatalf("RegisterContact tech: %v", err)
	}
	err := svc.ConfigureDomainContacts(domain, "owner-1", ContactConfig{
		AdminContactID: "c-admin",
		TechContactID:  "c-tech",
		RequiredRoles:  []ContactRole{RoleAdmin, RoleTech},
		DecisionWindow: window,
	})
	if err != nil {
		t.Fatalf("ConfigureDomainContacts: %v", err)
	}
}

func initiateContactTransfer(t *testing.T, svc *Service, ref, domain string) (*Transfer, string) {
	t.Helper()
	code, err := svc.generateCodeFor(domain)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	tr, err := svc.InitiateTransfer(ref, domain, code, "reg-b")
	if err != nil {
		t.Fatalf("InitiateTransfer: %v", err)
	}
	return tr, code
}

func (s *Service) generateCodeFor(domain string) (string, error) {
	code, _, err := s.GenerateAuthCode(domain, "owner-1", "reg-b", "owner-2", 30*time.Minute)
	return code, err
}

func TestContactApproval_StartsInContactsPhase(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	if tr.Phase != PhaseContacts {
		t.Fatalf("want awaiting_contacts, got %s", tr.Phase)
	}
	if !tr.Deadline.IsZero() {
		t.Fatalf("registrar deadline must not start before contacts approve: %v", tr.Deadline)
	}
	if tr.Policy == nil || len(tr.Policy.RequiredRoles) != 2 {
		t.Fatalf("frozen policy missing: %+v", tr.Policy)
	}
	if len(tr.Rounds) != 1 || tr.Rounds[0].Number != 1 {
		t.Fatalf("want round 1, got %+v", tr.Rounds)
	}
	if !tr.Rounds[0].ExpiresAt.Equal(clk.Now().Add(48 * time.Hour)) {
		t.Fatalf("unexpected round expiry: %v", tr.Rounds[0].ExpiresAt)
	}

	// 联系人门槛未达成：注册商不能决定，注册商超时也不起算。
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); !errors.Is(err, ErrAwaitingContacts) {
		t.Fatalf("want ErrAwaitingContacts, got %v", err)
	}
	clk.Advance(6 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("registrar timeout must not fire during contact phase, got %d", n)
	}
}

func TestContactApproval_FullFlowStartsRegistrarClock(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	clk.Advance(2 * time.Hour)
	tr, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, "")
	if err != nil {
		t.Fatalf("admin decide: %v", err)
	}
	if tr.Phase != PhaseContacts {
		t.Fatalf("still awaiting tech vote, got phase %s", tr.Phase)
	}
	// 单票不足以开启注册商期限。
	if !tr.Deadline.IsZero() {
		t.Fatalf("deadline must stay zero until all required roles approve")
	}

	tr, err = svc.ContactDecide(tr.ID, "ev-tech", 1, "c-tech", RoleTech, true, "")
	if err != nil {
		t.Fatalf("tech decide: %v", err)
	}
	// 最后一票：门槛达成，注册商决定期限此刻起算。
	if tr.Phase != PhaseRegistrar {
		t.Fatalf("want awaiting_registrar, got %s", tr.Phase)
	}
	if !tr.Deadline.Equal(clk.Now().Add(5 * 24 * time.Hour)) {
		t.Fatalf("registrar deadline must start at last vote, got %v", tr.Deadline)
	}
	if tr.ContactsSatisfiedAt == nil || !tr.ContactsSatisfiedAt.Equal(clk.Now()) {
		t.Fatalf("unexpected satisfied-at: %v", tr.ContactsSatisfiedAt)
	}

	// 注册商现在可以批准并完成所有权切换。
	done, err := svc.Decide(tr.ID, "reg-a", true, "ok")
	if err != nil {
		t.Fatalf("registrar decide: %v", err)
	}
	if done.Status != StatusApproved {
		t.Fatalf("want approved, got %s", done.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-2" || d.Registrar != "reg-b" || d.Locked {
		t.Fatalf("ownership not switched: %+v", d)
	}
	if n := len(svc.ListOutbox()); n != 1 {
		t.Fatalf("want exactly 1 outbox, got %d", n)
	}
}

func TestContactApproval_PolicyFrozenAtCreation(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// 转移进行中：联系人资料变更 + 域名门槛改为只要 admin，均不得影响在途转移。
	if err := svc.UpdateContact("c-tech", "Bob Renamed", "newbob@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfigureDomainContacts("example.com", "owner-1", ContactConfig{
		AdminContactID: "c-admin",
		TechContactID:  "c-tech",
		RequiredRoles:  []ContactRole{RoleAdmin},
		DecisionWindow: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	pol, err := svc.GetFrozenPolicy(tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.RequiredRoles) != 2 || pol.ContactDecisionWindow != 48*time.Hour {
		t.Fatalf("frozen policy silently changed: %+v", pol)
	}
	var techSnap FrozenContact
	for _, c := range pol.Contacts {
		if c.Role == RoleTech {
			techSnap = c
		}
	}
	if techSnap.Name != "Bob Tech" || techSnap.Email != "bob@example.com" {
		t.Fatalf("frozen contact snapshot changed: %+v", techSnap)
	}
	// 旧门槛下仍需 tech 一票。
	if _, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Phase != PhaseContacts {
		t.Fatal("in-flight transfer must still require the tech role")
	}
}

func TestContactApproval_DecisionEventIdempotentAndConflict(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// 同事件相同内容：幂等。
	r1, err := svc.ContactDecide(tr.ID, "ev-1", 1, "c-admin", RoleAdmin, true, "first reason")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.ContactDecide(tr.ID, "ev-1", 1, "c-admin", RoleAdmin, true, "other reason")
	if err != nil {
		t.Fatalf("same event same content must be idempotent: %v", err)
	}
	if r1.Phase != r2.Phase {
		t.Fatal("idempotent replay changed state")
	}
	rounds, _ := svc.ListContactRounds(tr.ID)
	if len(rounds[0].Decisions) != 1 {
		t.Fatalf("idempotent replay duplicated decision: %+v", rounds[0].Decisions)
	}

	// 同号异内容：冲突（逐个字段变化都应识别）。
	cases := []struct {
		round     int
		contactID string
		role      ContactRole
		approve   bool
	}{
		{1, "c-admin", RoleAdmin, false},
		{2, "c-admin", RoleAdmin, true},
		{1, "c-tech", RoleAdmin, true},
		{1, "c-admin", RoleTech, true},
	}
	for i, c := range cases {
		if _, err := svc.ContactDecide(tr.ID, "ev-1", c.round, c.contactID, c.role, c.approve, ""); !errors.Is(err, ErrContactDecisionConflict) {
			t.Fatalf("case %d: want ErrContactDecisionConflict, got %v", i, err)
		}
	}

	// 同角色换事件号再投：每轮每角色只能决定一次。
	if _, err := svc.ContactDecide(tr.ID, "ev-2", 1, "c-admin", RoleAdmin, true, ""); !errors.Is(err, ErrContactAlreadyDecided) {
		t.Fatalf("want ErrContactAlreadyDecided, got %v", err)
	}
}

func TestContactApproval_MismatchAndUnknownRole(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// 联系人与冻结角色不匹配。
	if _, err := svc.ContactDecide(tr.ID, "ev-1", 1, "c-tech", RoleAdmin, true, ""); !errors.Is(err, ErrContactRoleMismatch) {
		t.Fatalf("want ErrContactRoleMismatch, got %v", err)
	}
	// 陌生人不是冻结联系人。
	if _, err := svc.ContactDecide(tr.ID, "ev-2", 1, "stranger", RoleAdmin, true, ""); !errors.Is(err, ErrContactRoleMismatch) {
		t.Fatalf("want ErrContactRoleMismatch, got %v", err)
	}
	// 非法角色。
	if _, err := svc.ContactDecide(tr.ID, "ev-3", 1, "c-admin", "billing", true, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}

func TestContactApproval_ExplicitRejectIsTerminal(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// admin 先同意，tech 明确拒绝 → 立即 rejected 终局。
	if _, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}
	done, err := svc.ContactDecide(tr.ID, "ev-tech", 1, "c-tech", RoleTech, false, "no")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusRejected || done.DecidedBy != "c-tech" {
		t.Fatalf("want rejected by c-tech, got %+v", done)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Locked || d.OwnerID != "owner-1" {
		t.Fatalf("domain must be unlocked unchanged after contact reject: %+v", d)
	}

	// 拒绝后：同意、重签、注册商超时均不得再批准。
	if _, err := svc.ContactDecide(tr.ID, "ev-tech-2", 1, "c-tech", RoleTech, true, ""); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("want ErrTransferNotPending, got %v", err)
	}
	if _, err := svc.ReissueApprovalRound(tr.ID, "owner-1"); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("want ErrTransferNotPending, got %v", err)
	}
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("want ErrTransferNotPending, got %v", err)
	}
	clk.Advance(30 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("timeout must not override explicit reject, processed %d", n)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusRejected {
		t.Fatalf("explicit reject overwritten: %s", got.Status)
	}
	if n := len(svc.ListOutbox()); n != 1 || svc.ListOutbox()[0].Type != "transfer.rejected" {
		t.Fatalf("want single rejected outbox, got %+v", svc.ListOutbox())
	}
}

func TestContactApproval_RoundExpiryReissueAndStaleVotes(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 24*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// 第 1 轮 admin 同意，tech 沉默。
	if _, err := svc.ContactDecide(tr.ID, "ev-a1", 1, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}
	// 未到期不能重签。
	if _, err := svc.ReissueApprovalRound(tr.ID, "owner-1"); !errors.Is(err, ErrRoundNotExpired) {
		t.Fatalf("want ErrRoundNotExpired, got %v", err)
	}
	// 非所有者不能重签。
	clk.Advance(25 * time.Hour)
	if _, err := svc.ReissueApprovalRound(tr.ID, "intruder"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	// 到期后迟到投票不计入。
	if _, err := svc.ContactDecide(tr.ID, "ev-t-late", 1, "c-tech", RoleTech, true, ""); !errors.Is(err, ErrApprovalRoundExpired) {
		t.Fatalf("want ErrApprovalRoundExpired, got %v", err)
	}

	tr2, err := svc.ReissueApprovalRound(tr.ID, "owner-1")
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if len(tr2.Rounds) != 2 || tr2.Rounds[1].Number != 2 {
		t.Fatalf("want round 2, got %+v", tr2.Rounds)
	}
	// 旧轮次迟到决定不得推进当前转移。
	if _, err := svc.ContactDecide(tr.ID, "ev-t-stale", 1, "c-tech", RoleTech, true, ""); !errors.Is(err, ErrStaleRound) {
		t.Fatalf("want ErrStaleRound, got %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Phase != PhaseContacts {
		t.Fatal("stale vote must not advance transfer")
	}

	// 新一轮不沿用旧决定：admin 必须重新同意。
	if _, err := svc.ContactDecide(tr.ID, "ev-t2", 2, "c-tech", RoleTech, true, ""); err != nil {
		t.Fatalf("tech vote round 2: %v", err)
	}
	got, _ = svc.GetTransfer(tr.ID)
	if got.Phase != PhaseContacts {
		t.Fatal("tech-only in round 2 must not satisfy without renewed admin vote")
	}
	if _, err := svc.ContactDecide(tr.ID, "ev-a2", 2, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatalf("admin vote round 2: %v", err)
	}
	got, _ = svc.GetTransfer(tr.ID)
	if got.Phase != PhaseRegistrar {
		t.Fatalf("round 2 approvals must satisfy threshold, got %s", got.Phase)
	}

	// 各轮决定完整保留以供审计。
	rounds, _ := svc.ListContactRounds(tr.ID)
	if len(rounds) != 2 || len(rounds[0].Decisions) != 1 || len(rounds[1].Decisions) != 2 {
		t.Fatalf("round history not retained: %+v", rounds)
	}
}

func TestContactApproval_AutoApproveAfterThreshold(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 24*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")

	// 联系人阶段即使超过注册商窗口也不自动批准。
	clk.Advance(7 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("contacts pending must not auto-approve, got %d", n)
	}
	// 第 1 轮已过期：先重签，再双票通过。
	if _, err := svc.ReissueApprovalRound(tr.ID, "owner-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContactDecide(tr.ID, "ev-a2", 2, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContactDecide(tr.ID, "ev-t2", 2, "c-tech", RoleTech, true, ""); err != nil {
		t.Fatal(err)
	}
	// 期限从门槛达成起算 5 天；4 天不处理，6 天自动批准。
	clk.Advance(4 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("want 0 before registrar deadline, got %d", n)
	}
	clk.Advance(2 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 1 {
		t.Fatalf("want 1 auto-approval, got %d", n)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusAutoApproved {
		t.Fatalf("want auto_approved, got %s", got.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-2" || d.Locked {
		t.Fatalf("ownership not switched: %+v", d)
	}
}

func TestContactApproval_ConcurrencyLastVoteVsCancelVsRegistrar(t *testing.T) {
	for i := 0; i < 30; i++ {
		clk := newTestClock()
		svc := newTestService(t, clk)
		setupContactDomain(t, svc, "example.com", 48*time.Hour)
		tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")
		// admin 预先同意，使 tech 一票即达成门槛。
		if _, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, ""); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(3)
		// 最后一票（满足门槛，随后无终态）；所有者取消；注册商批准（仅当赢得门槛竞争才可能成功）。
		go func() { defer wg.Done(); _, _ = svc.ContactDecide(tr.ID, "ev-tech", 1, "c-tech", RoleTech, true, "") }()
		go func() { defer wg.Done(); _, _ = svc.Cancel(tr.ID, "owner-1") }()
		go func() { defer wg.Done(); _, _ = svc.Decide(tr.ID, "reg-a", true, "") }()
		wg.Wait()

		got, _ := svc.GetTransfer(tr.ID)
		// 若已终态，outbox 恰好一条且类型与终态一致；若仍 pending（门槛达成但注册商未决定），outbox 为 0。
		n := len(svc.ListOutbox())
		if got.Status.Terminal() && n != 1 {
			t.Fatalf("iter %d: terminal transfer must have exactly 1 outbox, got %d", i, n)
		}
		if !got.Status.Terminal() && n != 0 {
			t.Fatalf("iter %d: pending transfer must have no outbox, got %d", i, n)
		}
		d, _ := svc.GetDomain("example.com")
		switch got.Status {
		case StatusApproved, StatusAutoApproved:
			if d.OwnerID != "owner-2" || d.Locked {
				t.Fatalf("iter %d: approved but domain inconsistent: %+v", i, d)
			}
			if svc.ListOutbox()[0].Type != "transfer.approved" {
				t.Fatalf("iter %d: wrong outbox for approval: %s", i, svc.ListOutbox()[0].Type)
			}
		case StatusCancelled, StatusRejected:
			// 已取消/拒绝的转移绝不能伴随所有权切换。
			if d.OwnerID != "owner-1" || d.Registrar != "reg-a" || d.Locked {
				t.Fatalf("iter %d: cancelled/rejected but domain switched: %+v", i, d)
			}
		case StatusPending:
			if !d.Locked || d.OwnerID != "owner-1" {
				t.Fatalf("iter %d: pending domain inconsistent: %+v", i, d)
			}
		}
	}
}

func TestContactApproval_ConfigureValidation(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	if err := svc.RegisterDomain("example.com", "owner-1", "reg-a"); err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterContact("c-admin", "Alice", "a@x.com"); err != nil {
		t.Fatal(err)
	}
	// 非所有者不能配置。
	err := svc.ConfigureDomainContacts("example.com", "intruder", ContactConfig{
		AdminContactID: "c-admin",
		RequiredRoles:  []ContactRole{RoleAdmin},
	})
	if !errors.Is(err, ErrNotDomainOwner) {
		t.Fatalf("want ErrNotDomainOwner, got %v", err)
	}
	// 需要 tech 角色但未绑定联系人。
	err = svc.ConfigureDomainContacts("example.com", "owner-1", ContactConfig{
		AdminContactID: "c-admin",
		RequiredRoles:  []ContactRole{RoleTech},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput for unbound role, got %v", err)
	}
	// 绑定不存在的联系人。
	err = svc.ConfigureDomainContacts("example.com", "owner-1", ContactConfig{
		TechContactID: "ghost",
		RequiredRoles: []ContactRole{RoleTech},
	})
	if !errors.Is(err, ErrContactNotFound) {
		t.Fatalf("want ErrContactNotFound, got %v", err)
	}
	// 非法角色与重复角色去重。
	err = svc.ConfigureDomainContacts("example.com", "owner-1", ContactConfig{
		AdminContactID: "c-admin",
		RequiredRoles:  []ContactRole{RoleAdmin, "admin"},
	})
	if err != nil {
		t.Fatalf("duplicate roles should dedupe, got %v", err)
	}
	d, _ := svc.GetDomain("example.com")
	if len(d.RequiredRoles) != 1 {
		t.Fatalf("roles not deduped: %v", d.RequiredRoles)
	}
}

func TestContactApproval_PersistenceRoundTrip(t *testing.T) {
	clk := newTestClock()
	path := t.TempDir() + "/state.json"
	persister := NewFilePersister(path)
	svc := newTestService(t, clk, WithPersister(persister))
	setupContactDomain(t, svc, "example.com", 24*time.Hour)
	tr, _ := initiateContactTransfer(t, svc, "ext-1", "example.com")
	if _, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}

	svc2 := newTestService(t, clk, WithPersister(NewFilePersister(path)))
	got, err := svc2.GetTransfer(tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != PhaseContacts || got.Policy == nil || len(got.Rounds) != 1 {
		t.Fatalf("approval state not restored: %+v", got)
	}
	rounds, _ := svc2.ListContactRounds(tr.ID)
	if len(rounds) != 1 || len(rounds[0].Decisions) != 1 || rounds[0].Decisions[0].ContactID != "c-admin" {
		t.Fatalf("decisions not restored: %+v", rounds)
	}
	// 恢复后流程可继续：tech 投票 → 注册商批准。
	if _, err := svc2.ContactDecide(tr.ID, "ev-tech", 1, "c-tech", RoleTech, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc2.Decide(tr.ID, "reg-a", true, ""); err != nil {
		t.Fatalf("decide after restore: %v", err)
	}
}

func TestContactApproval_AuditAndNoCredentialLeak(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	setupContactDomain(t, svc, "example.com", 48*time.Hour)
	tr, code := initiateContactTransfer(t, svc, "ext-1", "example.com")
	if _, err := svc.ContactDecide(tr.ID, "ev-admin", 1, "c-admin", RoleAdmin, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContactDecide(tr.ID, "ev-tech", 1, "c-tech", RoleTech, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(tr.ID, "reg-a", true, "verified"); err != nil {
		t.Fatal(err)
	}

	audit := svc.ListAudit("example.com")
	wantActions := []string{
		"domain_registered", "domain_contacts_configured", "auth_code_generated",
		"transfer_initiated", "contact_decided", "contact_decided",
		"contacts_approved", "transfer_approved",
	}
	var got []string
	for _, e := range audit {
		got = append(got, e.Action)
	}
	if strings.Join(got, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("audit = %v, want %v", got, wantActions)
	}

	// 持久化数据中不得出现原始授权码。
	snap, err := svc.store.snapshotJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snap), code) {
		t.Fatal("raw auth code leaked into persisted state")
	}
}
