package domaintransfer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture 组装可控时钟的内存服务与基础数据：
//   - 注册商 r_old（原注册商）、r_new（目标注册商）
//   - 域名 example.com，所有者 owner-alice，注册商 r_old
type fixture struct {
	svc   *Service
	store *MemoryStore
	clock *fakeClock
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{t: start} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFixture(t *testing.T, policy ExpiryPolicy) *fixture {
	t.Helper()
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newFakeClock(base)
	store := NewMemoryStore(WithClock(clk.now))
	svc := NewService(store, policy)

	must(t, svc.RegisterRegistrar(Registrar{ID: "r_old", Name: "Old Registrar"}))
	must(t, svc.RegisterRegistrar(Registrar{ID: "r_new", Name: "New Registrar"}))
	must(t, svc.RegisterDomain(Domain{Name: "example.com", OwnerID: "owner-alice", RegistrarID: "r_old"}))
	must(t, svc.RegisterDomain(Domain{Name: "second.example", OwnerID: "owner-bob", RegistrarID: "r_old"}))
	return &fixture{svc: svc, store: store, clock: clk}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantErrIs(t *testing.T, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected error %v, got %v", target, err)
	}
}

// issueAndStart 签发授权码并发起转移，返回转移 ID 与明文授权码。
func (f *fixture) issueAndStart(t *testing.T, domain, owner, target, newOwner, externalID string) (transferID, code string) {
	t.Helper()
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName:      domain,
		OwnerID:         owner,
		TargetRegistrar: target,
		TTL:             24 * time.Hour,
	})
	must(t, err)

	res, err := f.svc.StartTransfer(StartTransferInput{
		ExternalID:  externalID,
		DomainName:  domain,
		AuthCode:    issued.Code,
		ToRegistrar: target,
		NewOwnerID:  newOwner,
		DecisionTTL: 48 * time.Hour,
	})
	must(t, err)
	if res.Replayed {
		t.Fatal("expected fresh start, got replay")
	}
	return res.TransferID, issued.Code
}

// ---- 授权码签发 ----

func TestIssueAuthCode_OnlyDigestPersisted(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName:      "example.com",
		OwnerID:         "owner-alice",
		TargetRegistrar: "r_new",
	})
	must(t, err)
	if issued.Code == "" {
		t.Fatal("empty code returned")
	}

	// 存储内部不得出现明文，且必须有摘要与盐。
	var rec *AuthCodeRecord
	must(t, f.store.ReadTx(func(tx ReadView) error {
		recs := tx.AuthCodesForBinding("example.com", "r_new")
		if len(recs) != 1 {
			return fmt.Errorf("want 1 record, got %d", len(recs))
		}
		rec = recs[0]
		return nil
	}))
	if rec.Digest == "" || rec.Salt == "" {
		t.Fatal("digest and salt must be persisted")
	}
	if strings.Contains(rec.Digest, strings.ReplaceAll(issued.Code, "-", "")) {
		t.Fatal("digest must not contain the plaintext")
	}
	if rec.ExpiresAt.Sub(rec.IssuedAt) != DefaultAuthCodeTTL {
		t.Fatalf("unexpected ttl window: %s", rec.ExpiresAt.Sub(rec.IssuedAt))
	}
}

func TestIssueAuthCode_RejectsNonOwnerAndUnknowns(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)

	_, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-mallory", TargetRegistrar: "r_new",
	})
	wantErrIs(t, err, ErrUnauthorized)

	_, err = f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_ghost",
	})
	wantErrIs(t, err, ErrRegistrarNotFound)

	_, err = f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "no-such.example", OwnerID: "owner-alice", TargetRegistrar: "r_new",
	})
	wantErrIs(t, err, ErrDomainNotFound)
}

// ---- 发起转移：原子消费 + 锁定 ----

func TestStartTransfer_ConsumesCodeAndLocksDomain(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	transferID, code := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-1")

	d, err := f.svc.GetDomain("example.com")
	must(t, err)
	if d.LockedByTransfer != transferID {
		t.Fatalf("domain should be locked by %s, got %q", transferID, d.LockedByTransfer)
	}
	if d.OwnerID != "owner-alice" || d.RegistrarID != "r_old" {
		t.Fatal("ownership must not change until approval")
	}

	// 同一域名不得有第二笔进行中的转移。
	issued2, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_new",
	})
	// 域名锁定期间连授权码都不应再签发。
	wantErrIs(t, err, ErrTransferInProgress)
	if issued2 != nil {
		t.Fatal("no auth code should be issued while locked")
	}

	// 直接尝试发起第二单同样被拒（域名锁先于授权码校验）。
	_, err = f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-2", DomainName: "example.com", AuthCode: code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	wantErrIs(t, err, ErrTransferInProgress)
}

func TestStartTransfer_AuthCodeBindingEnforced(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)

	// 为 second.example / r_new 签发的码不能用于 example.com。
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "second.example", OwnerID: "owner-bob", TargetRegistrar: "r_new",
	})
	must(t, err)
	_, err = f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-x", DomainName: "example.com", AuthCode: issued.Code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	wantErrIs(t, err, ErrAuthCodeInvalid)

	// 绑定的目标注册商不符也必须拒绝。
	issued2, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_new",
	})
	must(t, err)
	_, err = f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-y", DomainName: "example.com", AuthCode: issued2.Code,
		ToRegistrar: "r_old", NewOwnerID: "owner-carol", // r_old 是当前注册商
	})
	if !errors.Is(err, ErrAuthCodeInvalid) && !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected binding/argument error, got %v", err)
	}
}

func TestStartTransfer_ExpiredAuthCode(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_new",
		TTL: time.Hour,
	})
	must(t, err)
	f.clock.advance(2 * time.Hour)

	_, err = f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-exp", DomainName: "example.com", AuthCode: issued.Code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	wantErrIs(t, err, ErrAuthCodeExpired)

	// 失败不得留下锁定或转移单。
	d, err := f.svc.GetDomain("example.com")
	must(t, err)
	if d.LockedByTransfer != "" {
		t.Fatal("domain must not be locked after failed start")
	}
}

// ---- 幂等与冲突 ----

func TestStartTransfer_IdempotentReplay(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, code := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-dedup")

	res, err := f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-dedup", DomainName: "example.com", AuthCode: code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	must(t, err)
	if !res.Replayed || res.TransferID != id {
		t.Fatalf("expected replay of %s, got %+v", id, res)
	}
}

func TestStartTransfer_ExternalIDConflict(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	_, code := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-same")

	// 同号但目标新所有者不同 -> 冲突，且不能覆盖原单。
	_, err := f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-same", DomainName: "example.com", AuthCode: code,
		ToRegistrar: "r_new", NewOwnerID: "owner-dave",
	})
	wantErrIs(t, err, ErrExternalIDConflict)
}

// ---- 决定：批准的原子切换 + 唯一 outbox ----

func TestDecide_ApproveSwitchesOwnerRegistrarAndOutbox(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-app")

	tr, err := f.svc.DecideTransfer(id, "r_old", DecisionApprove, "docs verified")
	must(t, err)
	if tr.Status != StatusApproved {
		t.Fatalf("status=%s", tr.Status)
	}
	if tr.DecidedBy != "r_old" {
		t.Fatalf("decided by %q", tr.DecidedBy)
	}

	d, err := f.svc.GetDomain("example.com")
	must(t, err)
	if d.OwnerID != "owner-carol" || d.RegistrarID != "r_new" {
		t.Fatalf("domain not switched: %+v", d)
	}
	if d.LockedByTransfer != "" {
		t.Fatal("approved domain must be unlocked")
	}

	events, err := f.svc.PendingOutbox(10)
	must(t, err)
	if len(events) != 1 {
		t.Fatalf("want exactly 1 outbox event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != EventTransferApproved || ev.TransferID != id ||
		ev.FromRegistrar != "r_old" || ev.ToRegistrar != "r_new" || ev.NewOwnerID != "owner-carol" {
		t.Fatalf("bad event: %+v", ev)
	}

	view, err := f.svc.GetTransfer(id)
	must(t, err)
	if view.OutboxEventID != ev.EventID {
		t.Fatal("transfer view should reference its outbox event")
	}
}

func TestDecide_RejectUnlocksWithoutChanges(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-rej")

	tr, err := f.svc.DecideTransfer(id, "r_old", DecisionReject, "bad docs")
	must(t, err)
	if tr.Status != StatusRejected {
		t.Fatalf("status=%s", tr.Status)
	}
	d, err := f.svc.GetDomain("example.com")
	must(t, err)
	if d.OwnerID != "owner-alice" || d.RegistrarID != "r_old" || d.LockedByTransfer != "" {
		t.Fatalf("domain changed on rejection: %+v", d)
	}
	events, err := f.svc.PendingOutbox(10)
	must(t, err)
	if len(events) != 0 {
		t.Fatal("rejection must not produce an approval outbox event")
	}
}

func TestDecide_AuthorizationAndLateCallback(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-auth")

	// 只有原注册商可以决定。
	_, err := f.svc.DecideTransfer(id, "r_new", DecisionApprove, "")
	wantErrIs(t, err, ErrUnauthorized)

	// 不存在的转移单。
	_, err = f.svc.DecideTransfer("tr_missing", "r_old", DecisionApprove, "")
	wantErrIs(t, err, ErrTransferNotFound)

	// 非法决定值。
	_, err = f.svc.DecideTransfer(id, "r_old", Decision("maybe"), "")
	wantErrIs(t, err, ErrInvalidArgument)

	// 首次拒绝终态化后，迟到的批准回调不得覆盖。
	_, err = f.svc.DecideTransfer(id, "r_old", DecisionReject, "")
	must(t, err)
	_, err = f.svc.DecideTransfer(id, "r_old", DecisionApprove, "late callback")
	wantErrIs(t, err, ErrTransferNotPending)

	d, _ := f.svc.GetDomain("example.com")
	if d.RegistrarID != "r_old" || d.OwnerID != "owner-alice" {
		t.Fatal("late approval must not mutate domain")
	}
}

func TestDecide_AfterDeadlineRejected(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-late")

	f.clock.advance(49 * time.Hour) // 决定期限 48h
	_, err := f.svc.DecideTransfer(id, "r_old", DecisionApprove, "")
	wantErrIs(t, err, ErrDeadlinePassed)
}

// ---- 取消 ----

func TestCancel_OnlyOwnerAndOnce(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-can")

	_, err := f.svc.CancelTransfer(id, "owner-bob", "")
	wantErrIs(t, err, ErrUnauthorized)

	tr, err := f.svc.CancelTransfer(id, "owner-alice", "changed my mind")
	must(t, err)
	if tr.Status != StatusCancelled {
		t.Fatalf("status=%s", tr.Status)
	}
	d, _ := f.svc.GetDomain("example.com")
	if d.LockedByTransfer != "" {
		t.Fatal("cancelled transfer must unlock domain")
	}

	// 终态后取消 / 决定都必须失败。
	_, err = f.svc.CancelTransfer(id, "owner-alice", "")
	wantErrIs(t, err, ErrTransferNotPending)
	_, err = f.svc.DecideTransfer(id, "r_old", DecisionApprove, "")
	wantErrIs(t, err, ErrTransferNotPending)

	// 取消后可以为同一域名发起新转移（旧码已消费，需要新码）。
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_new",
	})
	must(t, err)
	res, err := f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-can-2", DomainName: "example.com", AuthCode: issued.Code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	must(t, err)
	if res.Status != StatusPending {
		t.Fatalf("new transfer status=%s", res.Status)
	}
}

// ---- 超时自动批准 ----

func TestAdvanceTimeout_AutoApprove(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-to")

	// 未到期：无副作用。
	tr, err := f.svc.AdvanceTimeout(id)
	must(t, err)
	if tr.Status != StatusPending {
		t.Fatalf("premature advance changed status to %s", tr.Status)
	}

	f.clock.advance(49 * time.Hour)
	tr, err = f.svc.AdvanceTimeout(id)
	must(t, err)
	if tr.Status != StatusApproved || tr.DecidedBy != "system" {
		t.Fatalf("auto approve failed: %+v", tr)
	}

	// 所有权 / 注册商同样必须在同一事务中切换，且 outbox 仅一条。
	d, _ := f.svc.GetDomain("example.com")
	if d.OwnerID != "owner-carol" || d.RegistrarID != "r_new" || d.LockedByTransfer != "" {
		t.Fatalf("auto approval did not switch domain atomically: %+v", d)
	}
	events, _ := f.svc.PendingOutbox(10)
	if len(events) != 1 {
		t.Fatalf("want 1 outbox event, got %d", len(events))
	}

	// 再次推进不得重复生成事件或覆盖终态。
	tr2, err := f.svc.AdvanceTimeout(id)
	must(t, err)
	if tr2.Status != StatusApproved {
		t.Fatal("terminal state changed")
	}
	events, _ = f.svc.PendingOutbox(10)
	if len(events) != 1 {
		t.Fatalf("outbox must stay at 1 event, got %d", len(events))
	}
}

func TestAdvanceTimeout_ExpirePolicy(t *testing.T) {
	f := newFixture(t, ExpiryExpire)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-exp2")
	f.clock.advance(49 * time.Hour)

	tr, err := f.svc.AdvanceTimeout(id)
	must(t, err)
	if tr.Status != StatusExpired {
		t.Fatalf("status=%s", tr.Status)
	}
	d, _ := f.svc.GetDomain("example.com")
	if d.OwnerID != "owner-alice" || d.RegistrarID != "r_old" || d.LockedByTransfer != "" {
		t.Fatalf("expire policy must not switch domain: %+v", d)
	}
	events, _ := f.svc.PendingOutbox(10)
	if len(events) != 0 {
		t.Fatal("expire policy must not emit approval event")
	}
}

func TestSweepExpired_OnlyDueTransitions(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id1, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-s1")
	// second.example 的期限设置得更长，扫描时不应被动到。
	issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
		DomainName: "second.example", OwnerID: "owner-bob", TargetRegistrar: "r_new",
	})
	must(t, err)
	res, err := f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-s2", DomainName: "second.example", AuthCode: issued.Code,
		ToRegistrar: "r_new", NewOwnerID: "owner-erin", DecisionTTL: 10 * 24 * time.Hour,
	})
	must(t, err)
	id2 := res.TransferID

	f.clock.advance(49 * time.Hour)
	advanced, err := f.svc.SweepExpired()
	must(t, err)
	if len(advanced) != 1 || advanced[0].ID != id1 {
		t.Fatalf("sweep advanced %+v", advanced)
	}
	v1, _ := f.svc.GetTransfer(id1)
	v2, _ := f.svc.GetTransfer(id2)
	if v1.Transfer.Status != StatusApproved || v2.Transfer.Status != StatusPending {
		t.Fatalf("unexpected statuses: %s %s", v1.Transfer.Status, v2.Transfer.Status)
	}

	// 再次扫描幂等。
	advanced2, err := f.svc.SweepExpired()
	must(t, err)
	if len(advanced2) != 0 {
		t.Fatalf("second sweep should be a no-op, got %+v", advanced2)
	}
}

// ---- 并发：终态只能落入一个 ----

func TestConcurrent_DecideCancelTimeout_OnlyOneTerminal(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-race")

	// 场景一：决定期限内，批准 / 拒绝 / 取消并发，超时推进为空操作。
	runTerminalRace(t, f, id, 30, false)

	// 终态不变量校验。
	assertTerminalInvariants(t, f, id)
}

func TestConcurrent_CancelVsTimeout_OnlyOneTerminal(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, _ := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-race2")
	// 推到决定期限之后：取消与超时自动批准直接竞争。
	f.clock.advance(49 * time.Hour)

	runTerminalRace(t, f, id, 30, true)
	assertTerminalInvariants(t, f, id)
}

// runTerminalRace 发起 n 个并发终态操作并校验：
//   - 除幂等超时重放外，失败者只能拿到“已非 pending / 已超期”错误；
//   - 审计中该转移单的终态动作恰好发生一次。
func runTerminalRace(t *testing.T, f *fixture, id string, n int, pastDeadline bool) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			var err error
			switch i % 4 {
			case 0:
				_, err = f.svc.DecideTransfer(id, "r_old", DecisionApprove, "")
			case 1:
				_, err = f.svc.DecideTransfer(id, "r_old", DecisionReject, "")
			case 2:
				_, err = f.svc.CancelTransfer(id, "owner-alice", "")
			case 3:
				_, err = f.svc.AdvanceTimeout(id) // 未到期空操作 / 终态后幂等，err==nil
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, ErrTransferNotPending) && !errors.Is(err, ErrDeadlinePassed) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}

	entries, err := f.svc.AuditHistory()
	must(t, err)
	terminalActions := 0
	for _, e := range entries {
		if e.TransferID != id {
			continue
		}
		switch e.Action {
		case "transfer.approved", "transfer.rejected", "transfer.cancelled", "transfer.timeout_advanced":
			terminalActions++
		}
	}
	if terminalActions != 1 {
		t.Fatalf("exactly one terminal transition allowed, got %d (pastDeadline=%v)", terminalActions, pastDeadline)
	}
}

// assertTerminalInvariants 校验任何终态后的共同不变量。
func assertTerminalInvariants(t *testing.T, f *fixture, id string) {
	t.Helper()
	view, err := f.svc.GetTransfer(id)
	must(t, err)
	if !view.Transfer.Status.IsTerminal() {
		t.Fatal("transfer must be terminal after race")
	}
	// outbox 数量必须与“是否批准”严格一致：批准恰好 1 条，否则 0 条。
	events, _ := f.svc.PendingOutbox(100)
	if len(events) > 1 {
		t.Fatalf("at most one outbox event allowed, got %d", len(events))
	}
	if view.Transfer.Status == StatusApproved {
		if len(events) != 1 {
			t.Fatal("approved terminal requires exactly one outbox event")
		}
		d, _ := f.svc.GetDomain("example.com")
		if d.OwnerID != "owner-carol" || d.RegistrarID != "r_new" {
			t.Fatalf("approval must switch owner/registrar: %+v", d)
		}
	}
	d, _ := f.svc.GetDomain("example.com")
	if d.LockedByTransfer != "" {
		t.Fatal("terminal state must release domain lock")
	}
}

// ---- 并发发起：一个域名至多一笔 ----

func TestConcurrent_StartTransfer_OnlyOneActive(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)

	// 每个 goroutine 各持一张独立授权码与独立 ExternalID 抢同一域名。
	const n = 16
	codes := make([]string, n)
	ext := make([]string, n)
	for i := 0; i < n; i++ {
		issued, err := f.svc.IssueAuthCode(IssueAuthCodeInput{
			DomainName: "example.com", OwnerID: "owner-alice", TargetRegistrar: "r_new",
		})
		must(t, err)
		codes[i] = issued.Code
		ext[i] = fmt.Sprintf("ext-race-%d", i)
	}

	var wg sync.WaitGroup
	started := make(chan string, n)
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			res, err := f.svc.StartTransfer(StartTransferInput{
				ExternalID: ext[i], DomainName: "example.com", AuthCode: codes[i],
				ToRegistrar: "r_new", NewOwnerID: "owner-carol",
			})
			if err == nil && !res.Replayed {
				started <- res.TransferID
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(started)
	close(errs)

	var winners []string
	for id := range started {
		winners = append(winners, id)
	}
	if len(winners) != 1 {
		t.Fatalf("want exactly 1 active transfer, got %d", len(winners))
	}
	for err := range errs {
		if err != nil && !errors.Is(err, ErrTransferInProgress) &&
			!errors.Is(err, ErrAuthCodeUsed) && !errors.Is(err, ErrAuthCodeInvalid) {
			t.Fatalf("unexpected start race error: %v", err)
		}
	}
}

// ---- 审计与敏感信息 ----

func TestAuditHistory_PresentAndSanitized(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	id, code := f.issueAndStart(t, "example.com", "owner-alice", "r_new", "owner-carol", "ext-aud")
	_, err := f.svc.DecideTransfer(id, "r_old", DecisionApprove, "")
	must(t, err)

	entries, err := f.svc.AuditHistory()
	must(t, err)
	if len(entries) < 3 {
		t.Fatalf("expected issue/start/approve audit entries, got %d", len(entries))
	}
	needle := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	for _, e := range entries {
		blob := strings.ToLower(e.Action + " " + e.Detail + " " + e.Actor)
		if strings.Contains(blob, needle) {
			t.Fatalf("audit entry leaks auth code: %+v", e)
		}
		if e.TransferID == "" && e.Action != "auth_code.issued" {
			t.Fatalf("transfer-scoped audit missing transfer id: %+v", e)
		}
	}

	// 所有对外错误信息也不得携带明文授权码。
	_, err = f.svc.StartTransfer(StartTransferInput{
		ExternalID: "ext-aud-2", DomainName: "example.com", AuthCode: code,
		ToRegistrar: "r_new", NewOwnerID: "owner-carol",
	})
	if err == nil {
		t.Fatal("reusing consumed code should fail")
	}
	if strings.Contains(strings.ToLower(err.Error()), needle) {
		t.Fatalf("error message leaks auth code: %v", err)
	}
}

// ---- 状态查询 ----

func TestGetTransfer_NotFound(t *testing.T) {
	f := newFixture(t, ExpiryAutoApprove)
	_, err := f.svc.GetTransfer("tr_nope")
	wantErrIs(t, err, ErrTransferNotFound)

	_, err = f.svc.GetDomain("nope.example")
	wantErrIs(t, err, ErrDomainNotFound)
}
