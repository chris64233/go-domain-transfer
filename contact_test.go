package domaintransfer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// configureTwoContacts 配置 admin+tech 两个联系人，requireAny 决定门槛模式，
// 并返回两者的明文审批凭据（仅测试持有）。
func configureTwoContacts(t *testing.T, svc *Service, domain string, requireAny bool, roundLapse time.Duration) (adminCred, techCred string) {
	t.Helper()
	adminCred, techCred = "admin-secret", "tech-secret"
	specs := []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin", Email: "admin@example.com", Credential: adminCred},
		{ID: "c-tech", Role: RoleTech, Name: "Tech", Email: "tech@example.com", Credential: techCred},
	}
	err := svc.ConfigureContacts(domain, "owner-1", specs, []ContactRole{RoleAdmin, RoleTech}, !requireAny, roundLapse)
	if err != nil {
		t.Fatalf("ConfigureContacts: %v", err)
	}
	return adminCred, techCred
}

// initiateWithContacts 配置联系人、生成授权码并发起转移，返回转移单与凭据。
func initiateWithContacts(t *testing.T, svc *Service, requireAny bool) (*Transfer, string, string) {
	t.Helper()
	const domain = "example.com"
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatalf("RegisterDomain: %v", err)
	}
	adminCred, techCred := configureTwoContacts(t, svc, domain, requireAny, 48*time.Hour)
	code, _, err := svc.GenerateAuthCode(domain, "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	tr, err := svc.InitiateTransfer("ext-1", domain, code, "reg-b")
	if err != nil {
		t.Fatalf("InitiateTransfer: %v", err)
	}
	return tr, adminCred, techCred
}

func TestConfigureContacts_ValidationAndDigestOnly(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	if err := svc.RegisterDomain("example.com", "owner-1", "reg-a"); err != nil {
		t.Fatal(err)
	}

	specs := []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin", Email: "a@x.com", Credential: "topsecret"},
		{ID: "c-tech", Role: RoleTech, Name: "Tech", Email: "t@x.com", Credential: "techsecret"},
	}
	if err := svc.ConfigureContacts("example.com", "owner-1", specs, []ContactRole{RoleAdmin, RoleTech}, true, 0); err != nil {
		t.Fatalf("ConfigureContacts: %v", err)
	}

	// 持久化快照中不得出现明文凭据。
	snap, err := svc.store.snapshotJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"topsecret", "techsecret"} {
		if strings.Contains(string(snap), secret) {
			t.Fatalf("raw credential leaked into persisted state: %q", secret)
		}
	}

	d, _ := svc.GetDomain("example.com")
	if d.Approval == nil || !d.Approval.RequireAll || len(d.Approval.RequiredRoles) != 2 {
		t.Fatalf("policy not stored: %+v", d.Approval)
	}
	if d.Approval.RoundLapse != 7*24*time.Hour { // 未指定时使用服务默认
		t.Fatalf("want default round lapse, got %s", d.Approval.RoundLapse)
	}

	// 参数校验。
	cases := []struct {
		domain string
		owner  string
		specs  []ContactSpec
		roles  []ContactRole
	}{
		{"missing.com", "owner-1", specs, []ContactRole{RoleAdmin}},                                     // 域名不存在
		{"example.com", "intruder", specs, []ContactRole{RoleAdmin}},                                    // 非所有者
		{"example.com", "owner-1", []ContactSpec{{ID: "x", Role: RoleAdmin}}, []ContactRole{RoleAdmin}}, // 字段缺失
		{"example.com", "owner-1", specs, nil},                                                          // 无所需角色
		{"example.com", "owner-1", specs[:1], []ContactRole{RoleAdmin, RoleTech}},                       // tech 角色无联系人
	}
	for i, c := range cases {
		err := svc.ConfigureContacts(c.domain, c.owner, c.specs, c.roles, true, time.Hour)
		if !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrDomainNotFound) &&
			!errors.Is(err, ErrNotDomainOwner) {
			t.Fatalf("case %d: want validation error, got %v", i, err)
		}
	}
}

func TestInitiate_FreezesPolicyAndDoesNotStartRegistrarClock(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, _, _ := initiateWithContacts(t, svc, false)

	if tr.FrozenPolicy == nil || len(tr.FrozenPolicy.Contacts) != 2 {
		t.Fatalf("policy not frozen: %+v", tr.FrozenPolicy)
	}
	if len(tr.ContactRounds) != 1 || tr.ContactRounds[0].Number != 1 {
		t.Fatalf("want round 1, got %+v", tr.ContactRounds)
	}
	if !tr.Deadline.IsZero() {
		t.Fatalf("registrar deadline must be zero before contact gate, got %v", tr.Deadline)
	}
	if tr.GatePassedAt != nil {
		t.Fatal("gate must not be passed at creation")
	}
}

func TestFreeze_LaterContactChangesDoNotMoveGate(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, oldAdmin, _ := initiateWithContacts(t, svc, false)

	// 转移进行中修改联系人资料（更换凭据/人员）。在途转移门槛必须保持旧快照。
	newSpecs := []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin2", Email: "a2@x.com", Credential: "rotated-secret"},
		{ID: "c-tech", Role: RoleTech, Name: "Tech2", Email: "t2@x.com", Credential: "rotated-tech"},
	}
	if err := svc.ConfigureContacts("example.com", "owner-1", newSpecs, []ContactRole{RoleTech}, false, time.Hour); err != nil {
		t.Fatalf("reconfigure during transfer: %v", err)
	}

	// 新凭据在冻结快照中不存在 → 无权决定旧转移。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-new", 1, "c-admin", "rotated-secret", true, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("rotated credential must not authorize old transfer, got %v", err)
	}
	// 旧凭据仍然有效，且仍要求两个角色（而非新策略的仅 tech）。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin", 1, "c-admin", oldAdmin, true, ""); err != nil {
		t.Fatalf("frozen admin approval: %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.GatePassedAt != nil {
		t.Fatal("gate must remain closed: frozen policy requires admin AND tech, new single-role policy must not apply")
	}
}

func TestContactGate_BlocksRegistrarAndTimeout(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)

	// 门槛未达成：注册商不能决定。
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); !errors.Is(err, ErrContactGatePending) {
		t.Fatalf("want ErrContactGatePending, got %v", err)
	}
	// 即使超过注册商决定窗口，门槛未达成也不得自动批准。
	clk.Advance(30 * 24 * time.Hour)
	if n, err := svc.AdvanceTimeouts(); err != nil || n != 0 {
		t.Fatalf("timeout must not fire before gate: n=%d err=%v", n, err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusPending {
		t.Fatalf("transfer must remain pending, got %s", got.Status)
	}

	// 达成门槛。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin", 1, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	gateAt := clk.Now()
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-tech", 1, "c-tech", techCred, true, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = svc.GetTransfer(tr.ID)
	if got.GatePassedAt == nil || !got.GatePassedAt.Equal(gateAt) {
		t.Fatalf("gate pass time not recorded: %+v", got.GatePassedAt)
	}
	if !got.Deadline.Equal(gateAt.Add(5 * 24 * time.Hour)) {
		t.Fatalf("registrar deadline must start at gate pass: %v", got.Deadline)
	}

	// 门槛达成后注册商方可决定。
	if _, err := svc.Decide(tr.ID, "reg-a", true, "ok"); err != nil {
		t.Fatalf("registrar decide after gate: %v", err)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-2" || d.Registrar != "reg-b" || d.Locked {
		t.Fatalf("ownership not switched: %+v", d)
	}
}

func TestContactGate_AnyModeSingleApproval(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, _, techCred := initiateWithContacts(t, svc, true) // requireAny

	if _, err := svc.SubmitContactDecision(tr.ID, "ev-tech", 1, "c-tech", techCred, true, ""); err != nil {
		t.Fatalf("single role approval should satisfy ANY gate: %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.GatePassedAt == nil {
		t.Fatal("ANY gate should pass with one approval")
	}
}

func TestContactDecision_NonRequiredRoleHasNoVeto(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	const domain = "example.com"
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatal(err)
	}
	// 配置两个联系人，但门槛只要求 admin。
	specs := []ContactSpec{
		{ID: "c-admin", Role: RoleAdmin, Name: "Admin", Email: "a@x.com", Credential: "admin-secret"},
		{ID: "c-tech", Role: RoleTech, Name: "Tech", Email: "t@x.com", Credential: "tech-secret"},
	}
	if err := svc.ConfigureContacts(domain, "owner-1", specs, []ContactRole{RoleAdmin}, true, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	code, _, err := svc.GenerateAuthCode(domain, "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := svc.InitiateTransfer("ext-1", domain, code, "reg-b")
	if err != nil {
		t.Fatal(err)
	}

	// tech 非所需角色：其拒绝记录留痕但不否决，转移仍 pending。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-tech-no", 1, "c-tech", "tech-secret", false, "not my call"); err != nil {
		t.Fatalf("non-required rejection should be accepted as record: %v", err)
	}
	if got, _ := svc.GetTransfer(tr.ID); got.Status != StatusPending || got.GatePassedAt != nil {
		t.Fatalf("non-required rejection must not veto nor pass gate: %+v", got)
	}
	// admin（所需且唯一角色）同意 → 门槛通过。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin-yes", 1, "c-admin", "admin-secret", true, ""); err != nil {
		t.Fatalf("required approval: %v", err)
	}
	if got, _ := svc.GetTransfer(tr.ID); got.GatePassedAt == nil {
		t.Fatal("gate should pass on admin approval despite tech objection")
	}
}

func TestContactDecision_RejectIsTerminalAndCannotBeOverridden(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)

	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin", 1, "c-admin", adminCred, false, "objection"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusRejected {
		t.Fatalf("want rejected, got %s", got.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Locked || d.OwnerID != "owner-1" {
		t.Fatalf("domain must be unlocked with ownership unchanged: %+v", d)
	}

	// 另一联系人的同意不得翻案。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-tech", 1, "c-tech", techCred, true, ""); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("late approve after rejection: want ErrTransferNotPending, got %v", err)
	}
	// 注册商同意也无效。
	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("registrar approve after rejection: want ErrTransferNotPending, got %v", err)
	}
	// 超时同样不得批准。
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("timeout must not override rejection: %d", n)
	}
	if len(svc.ListOutbox()) != 1 || svc.ListOutbox()[0].Type != "transfer.rejected" {
		t.Fatalf("want single rejected outbox, got %+v", svc.ListOutbox())
	}
}

func TestContactDecision_IdempotencyConflictAndDuplicate(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, adminCred, _ := initiateWithContacts(t, svc, false)

	submit := func(event, reason string, approve bool) error {
		_, err := svc.SubmitContactDecision(tr.ID, event, 1, "c-admin", adminCred, approve, reason)
		return err
	}

	// 相同事件相同内容：幂等。
	if err := submit("ev-1", "", true); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if err := submit("ev-1", "", true); err != nil {
		t.Fatalf("idempotent replay must succeed, got %v", err)
	}
	// 同号异内容：冲突（无论改 approve 还是 reason）。
	if err := submit("ev-1", "changed", true); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("want ErrDecisionConflict on changed reason, got %v", err)
	}
	if err := submit("ev-1", "", false); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("want ErrDecisionConflict on changed verdict, got %v", err)
	}
	// 同号但凭据错误：同样判为冲突，而非泄露幂等成功。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-1", 1, "c-admin", "wrong-credential", true, ""); !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("replay with wrong credential: want ErrDecisionConflict, got %v", err)
	}
	// 同联系人换新事件号再次决定：拒绝（当前轮一票）。
	if err := submit("ev-2", "", true); !errors.Is(err, ErrContactAlreadyDecided) {
		t.Fatalf("want ErrContactAlreadyDecided, got %v", err)
	}
	// 错误凭据 / 未知联系人：无权。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-x", 1, "c-admin", "wrong", true, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bad credential: want ErrForbidden")
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-y", 1, "ghost", adminCred, true, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown contact: want ErrForbidden")
	}
}

func TestContactRounds_ReissueKeepsOldDecisionsButDoesNotReuse(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	// ANY 模式下两联系人在第 1 轮均沉默，超期后由 owner 重开一轮。
	tr, adminCred, _ := initiateWithContacts(t, svc, true)

	// 轮次未超期不允许重签。
	if _, err := svc.ReissueContactRound(tr.ID, "owner-1"); !errors.Is(err, ErrContactRoundActive) {
		t.Fatalf("want ErrContactRoundActive, got %v", err)
	}
	if _, err := svc.ReissueContactRound(tr.ID, "intruder"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reissue by non-owner: want ErrForbidden, got %v", err)
	}

	clk.Advance(49 * time.Hour) // 超过 48h 单轮期限
	r2, err := svc.ReissueContactRound(tr.ID, "owner-1")
	if err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if len(r2.ContactRounds) != 2 || r2.ContactRounds[1].Number != 2 {
		t.Fatalf("want round 2, got %+v", r2.ContactRounds)
	}
	if len(r2.ContactRounds[0].Decisions) != 0 {
		t.Fatal("round 1 should have no decisions in this branch")
	}

	// 指向旧轮的迟到决定被拒绝。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-old", 1, "c-admin", adminCred, true, ""); !errors.Is(err, ErrDecisionRoundStale) {
		t.Fatalf("stale round decision: want ErrDecisionRoundStale, got %v", err)
	}
	// 第 2 轮 admin 同意 → ANY 门槛通过。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-r2-admin", 2, "c-admin", adminCred, true, ""); err != nil {
		t.Fatalf("round 2 approval: %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.GatePassedAt == nil {
		t.Fatal("gate should pass in round 2")
	}
	if !got.ContactRounds[1].GatePassed {
		t.Fatal("round 2 should be marked gate passed")
	}

	// 门槛已达成后不能再重签。
	if _, err := svc.ReissueContactRound(tr.ID, "owner-1"); !errors.Is(err, ErrContactGateAlreadyPassed) {
		t.Fatalf("want ErrContactGateAlreadyPassed, got %v", err)
	}
}

func TestContactRounds_OldApprovalRetainedNotReused(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	// ALL 模式：第 1 轮仅 admin 同意，门槛未达成；超期后重开，旧同意保留但不沿用。
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)

	if _, err := svc.SubmitContactDecision(tr.ID, "ev-r1-admin", 1, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetTransfer(tr.ID); got.GatePassedAt != nil {
		t.Fatal("ALL gate must not pass with admin only")
	}

	clk.Advance(49 * time.Hour)
	if _, err := svc.ReissueContactRound(tr.ID, "owner-1"); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	// 旧轮的决定仍保留可审计。
	if len(got.ContactRounds[0].Decisions) != 1 {
		t.Fatalf("round 1 decision must be retained for audit, got %+v", got.ContactRounds[0])
	}
	// 但当前轮无决定，门槛仍未达成。
	if got.GatePassedAt != nil || len(got.ContactRounds[1].Decisions) != 0 {
		t.Fatalf("old approval must not be reused: %+v", got)
	}

	// 第 2 轮 admin 迟到地“继续同意”没有意义；必须在第 2 轮重新投票，且两角色都同意。
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-r2-admin", 2, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetTransfer(tr.ID); got.GatePassedAt != nil {
		t.Fatal("ALL gate still needs tech in round 2")
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-r2-tech", 2, "c-tech", techCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetTransfer(tr.ID); got.GatePassedAt == nil {
		t.Fatal("ALL gate must pass after both fresh round-2 approvals")
	}

	// 各轮决定可完整查询。
	rounds, err := svc.ListContactRounds(tr.ID)
	if err != nil || len(rounds) != 2 {
		t.Fatalf("ListContactRounds: %+v %v", rounds, err)
	}
	if len(rounds[0].Decisions) != 1 || rounds[0].Decisions[0].EventID != "ev-r1-admin" {
		t.Fatalf("round 1 history mismatch: %+v", rounds[0].Decisions)
	}
}

func TestContactGate_RegistrarTimeoutStartsOnlyAfterGate(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)

	// 转移创建很久后才完成联系人门槛；注册商期限应从此刻重新计算，而非从创建时。
	clk.Advance(10 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatal("no timeout before gate")
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-a", 1, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-t", 1, "c-tech", techCred, true, ""); err != nil {
		t.Fatal(err)
	}
	gateAt := clk.Now()

	// 门槛后 4 天（窗口 5 天内）不超时。
	clk.Advance(4 * 24 * time.Hour)
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatal("registrar timeout must not fire within window measured from gate")
	}
	// 再过 2 天 → 自动批准。
	clk.Advance(2 * 24 * time.Hour)
	n, err := svc.AdvanceTimeouts()
	if err != nil || n != 1 {
		t.Fatalf("want 1 auto-approval, got %d %v", n, err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusAutoApproved {
		t.Fatalf("want auto_approved, got %s", got.Status)
	}
	if !got.Deadline.Equal(gateAt.Add(5 * 24 * time.Hour)) {
		t.Fatalf("deadline anchored to gate: %v", got.Deadline)
	}
}

func TestContactConcurrency_LastVoteVsCancelVsRegistrar(t *testing.T) {
	for i := 0; i < 30; i++ {
		clk := newTestClock()
		svc := newTestService(t, clk)
		tr, adminCred, techCred := initiateWithContacts(t, svc, false)

		// admin 先投票（不达成门槛），最后一票 tech 与取消、注册商决定并发。
		if _, err := svc.SubmitContactDecision(tr.ID, fmt.Sprintf("ev-a-%d", i), 1, "c-admin", adminCred, true, ""); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		successes := make(chan struct{}, 3)
		try := func(f func() error) {
			defer wg.Done()
			if err := f(); err == nil {
				successes <- struct{}{}
			}
		}
		wg.Add(3)
		go try(func() error {
			_, err := svc.SubmitContactDecision(tr.ID, fmt.Sprintf("ev-t-%d", i), 1, "c-tech", techCred, true, "")
			return err
		})
		go try(func() error { _, err := svc.Cancel(tr.ID, "owner-1"); return err })
		go try(func() error {
			// 仅当门槛恰好已达成且在窗口内才可能成功。
			_, err := svc.Decide(tr.ID, "reg-a", true, "")
			return err
		})
		wg.Wait()
		close(successes)

		got, _ := svc.GetTransfer(tr.ID)
		d, _ := svc.GetDomain("example.com")

		switch got.Status {
		case StatusCancelled:
			// 取消领先：tech 最后一票与注册商决定都失败；所有权绝不能已切换。
			if d.OwnerID != "owner-1" || d.Registrar != "reg-a" {
				t.Fatalf("iter %d: cancelled but ownership switched: %+v", i, d)
			}
			if n := len(svc.ListOutbox()); n != 1 || svc.ListOutbox()[0].Type != "transfer.cancelled" {
				t.Fatalf("iter %d: cancelled wants single cancelled outbox, got %+v", i, svc.ListOutbox())
			}
		case StatusApproved:
			// 门槛通过且注册商抢先批准；取消必然失败。
			if d.OwnerID != "owner-2" || d.Locked {
				t.Fatalf("iter %d: approved but domain wrong: %+v", i, d)
			}
			if n := len(svc.ListOutbox()); n != 1 {
				t.Fatalf("iter %d: approved wants single outbox, got %d", i, n)
			}
		default:
			t.Fatalf("iter %d: unexpected status %s (gate=%v)", i, got.Status, got.GatePassedAt)
		}
		// 任何终态下 outbox 都恰好一条，杜绝重复 outbox / 已取消的所有权切换。
		if n := len(svc.ListOutbox()); n != 1 {
			t.Fatalf("iter %d: want exactly 1 outbox, got %d", i, n)
		}
	}
}

func TestContactPersistence_RoundTripAndNoSecretLeak(t *testing.T) {
	clk := newTestClock()
	path := t.TempDir() + "/state.json"
	persister := NewFilePersister(path)

	svc := newTestService(t, clk, WithPersister(persister))
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin", 1, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	clk.Advance(49 * time.Hour)
	if _, err := svc.ReissueContactRound(tr.ID, "owner-1"); err != nil {
		t.Fatal(err)
	}

	// 落盘内容不得包含明文授权码或审批凭据。
	raw, err := persister.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{adminCred, techCred} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("raw contact credential persisted: %q", secret)
		}
	}

	// 用同一持久化文件重建：冻结策略、各轮决定完整恢复。
	svc2 := newTestService(t, clk, WithPersister(persister))
	got, err := svc2.GetTransfer(tr.ID)
	if err != nil {
		t.Fatalf("transfer not restored: %v", err)
	}
	if got.FrozenPolicy == nil || len(got.ContactRounds) != 2 {
		t.Fatalf("frozen policy/rounds not restored: %+v", got)
	}
	if len(got.ContactRounds[0].Decisions) != 1 || got.ContactRounds[0].Decisions[0].EventID != "ev-admin" {
		t.Fatalf("round 1 decision not restored: %+v", got.ContactRounds[0].Decisions)
	}
	if got.GatePassedAt != nil {
		t.Fatal("gate should still be closed after restore")
	}

	// 恢复后可在当前轮继续完成门槛。
	if _, err := svc2.SubmitContactDecision(tr.ID, "ev-r2-a", 2, "c-admin", adminCred, true, ""); err != nil {
		t.Fatalf("round 2 admin after restore: %v", err)
	}
	if _, err := svc2.SubmitContactDecision(tr.ID, "ev-r2-t", 2, "c-tech", techCred, true, ""); err != nil {
		t.Fatalf("round 2 tech after restore: %v", err)
	}
	if got2, _ := svc2.GetTransfer(tr.ID); got2.GatePassedAt == nil {
		t.Fatal("gate not passable after restore")
	}
}

func TestContactAudit_FullTrail(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	tr, adminCred, techCred := initiateWithContacts(t, svc, false)

	if _, err := svc.SubmitContactDecision(tr.ID, "ev-admin", 1, "c-admin", adminCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev-tech", 1, "c-tech", techCred, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(tr.ID, "reg-a", true, "ok"); err != nil {
		t.Fatal(err)
	}

	var actions []string
	for _, e := range svc.ListAudit("example.com") {
		actions = append(actions, e.Action)
	}
	want := []string{
		"domain_registered",
		"contacts_configured",
		"auth_code_generated",
		"transfer_initiated",
		"contact_decision_submitted",
		"contact_decision_submitted",
		"contact_gate_passed",
		"transfer_approved",
	}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v\n want %v", actions, want)
	}

	// 审计与查询中不得出现明文凭据。
	for _, e := range svc.ListAudit("example.com") {
		if strings.Contains(e.Detail, adminCred) || strings.Contains(e.Detail, techCred) {
			t.Fatalf("credential leaked into audit: %+v", e)
		}
	}
	pol, err := svc.GetApprovalPolicy(tr.ID)
	if err != nil || len(pol.Contacts) != 2 {
		t.Fatalf("GetApprovalPolicy: %+v %v", pol, err)
	}
}

func TestNoPolicy_TransfersUnchanged(t *testing.T) {
	// 未配置联系人策略的域名：流程与第一轮实现一致（无门禁，注册商期限立即起算）。
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "plain.com")
	tr, err := svc.InitiateTransfer("ext-plain", "plain.com", code, "reg-b")
	if err != nil {
		t.Fatal(err)
	}
	if tr.FrozenPolicy != nil || tr.Deadline.IsZero() {
		t.Fatalf("legacy transfer must have no gate and immediate deadline: %+v", tr)
	}
	if _, err := svc.SubmitContactDecision(tr.ID, "ev", 1, "x", "y", true, ""); !errors.Is(err, ErrContactPolicyMissing) {
		t.Fatalf("want ErrContactPolicyMissing, got %v", err)
	}
	if _, err := svc.ReissueContactRound(tr.ID, "owner-1"); !errors.Is(err, ErrContactPolicyMissing) {
		t.Fatalf("want ErrContactPolicyMissing, got %v", err)
	}
}
