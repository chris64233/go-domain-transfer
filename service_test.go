package domaintransfer

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClock 是可手动推进的并发安全时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestService(t *testing.T, clk *testClock, opts ...Option) *Service {
	t.Helper()
	all := append([]Option{
		WithClock(clk.Now),
		WithDecisionWindow(5 * 24 * time.Hour),
		WithMaxCodeTTL(time.Hour),
	}, opts...)
	svc, err := NewService(all...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// setupDomainWithCode 登记域名并生成授权码。
func setupDomainWithCode(t *testing.T, svc *Service, domain string) string {
	t.Helper()
	if err := svc.RegisterDomain(domain, "owner-1", "reg-a"); err != nil {
		t.Fatalf("RegisterDomain: %v", err)
	}
	code, _, err := svc.GenerateAuthCode(domain, "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	return code
}

func TestGenerateAuthCode_StoresOnlyDigest(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	if err := svc.RegisterDomain("example.com", "owner-1", "reg-a"); err != nil {
		t.Fatal(err)
	}
	code, expiresAt, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	if code == "" {
		t.Fatal("empty code")
	}
	if !expiresAt.Equal(clk.Now().Add(30 * time.Minute)) {
		t.Fatalf("unexpected expiry: %v", expiresAt)
	}
	// 持久化快照中不得出现明文授权码。
	snap, err := svc.store.snapshotJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snap), code) {
		t.Fatal("raw auth code leaked into persisted state")
	}
}

func TestGenerateAuthCode_Errors(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	if err := svc.RegisterDomain("example.com", "owner-1", "reg-a"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.GenerateAuthCode("missing.com", "owner-1", "reg-b", "owner-2", time.Minute); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("want ErrDomainNotFound, got %v", err)
	}
	if _, _, err := svc.GenerateAuthCode("example.com", "intruder", "reg-b", "owner-2", time.Minute); !errors.Is(err, ErrNotDomainOwner) {
		t.Fatalf("want ErrNotDomainOwner, got %v", err)
	}
	if _, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-a", "owner-2", time.Minute); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput for same registrar, got %v", err)
	}
	if _, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", 2*time.Hour); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput for ttl over max, got %v", err)
	}
}

func TestInitiateTransfer_ConsumesCodeAndLocks(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")

	tr, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
	if err != nil {
		t.Fatalf("InitiateTransfer: %v", err)
	}
	if tr.Status != StatusPending {
		t.Fatalf("want pending, got %s", tr.Status)
	}
	if tr.FromRegistrar != "reg-a" || tr.ToRegistrar != "reg-b" {
		t.Fatalf("unexpected registrars: %+v", tr)
	}
	if !tr.Deadline.Equal(clk.Now().Add(5 * 24 * time.Hour)) {
		t.Fatalf("unexpected deadline: %v", tr.Deadline)
	}

	d, err := svc.GetDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Locked {
		t.Fatal("domain must be locked after initiation")
	}

	// 授权码一次性：重放失败。
	if _, err := svc.InitiateTransfer("ext-2", "example.com", code, "reg-b"); !errors.Is(err, ErrDomainLocked) {
		t.Fatalf("want ErrDomainLocked on replay, got %v", err)
	}
}

func TestInitiateTransfer_InvalidAndExpiredCode(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")

	_, err := svc.InitiateTransfer("ext-1", "example.com", "wrong-code", "reg-b")
	if !errors.Is(err, ErrAuthCodeInvalid) {
		t.Fatalf("want ErrAuthCodeInvalid, got %v", err)
	}
	// 错误信息不得泄漏授权码内容。
	if strings.Contains(err.Error(), code) {
		t.Fatal("error message leaks auth code")
	}

	clk.Advance(31 * time.Minute) // 超过 30 分钟有效期
	if _, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b"); !errors.Is(err, ErrAuthCodeExpired) {
		t.Fatalf("want ErrAuthCodeExpired, got %v", err)
	}
	// 过期失败后域名不得被锁定。
	d, _ := svc.GetDomain("example.com")
	if d.Locked {
		t.Fatal("domain must not be locked after failed initiation")
	}
}

func TestInitiateTransfer_Idempotency(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")

	tr1, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
	if err != nil {
		t.Fatal(err)
	}
	// 同号同内容：幂等返回既有转移单。
	tr2, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if tr1.ID != tr2.ID {
		t.Fatalf("idempotent replay returned different transfer: %s vs %s", tr1.ID, tr2.ID)
	}

	// 同号异内容：冲突。
	code2, _, err := svc.GenerateAuthCode("other.com", "owner-1", "reg-b", "owner-2", time.Minute)
	if err == nil {
		t.Fatalf("expected error for unregistered domain, got code %s", code2)
	}
	if _, err := svc.InitiateTransfer("ext-1", "example.com", "different-code", "reg-b"); !errors.Is(err, ErrTransferConflict) {
		t.Fatalf("want ErrTransferConflict, got %v", err)
	}
}

func TestInitiateTransfer_OneInFlightPerDomain(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	if _, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b"); err != nil {
		t.Fatal(err)
	}
	// 进行中的转移锁定域名，第二个发起被拒绝。
	if _, err := svc.InitiateTransfer("ext-2", "example.com", code, "reg-b"); !errors.Is(err, ErrDomainLocked) {
		t.Fatalf("want ErrDomainLocked, got %v", err)
	}
	// 锁定期间也不能再生成授权码。
	if _, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-c", "owner-3", time.Minute); !errors.Is(err, ErrDomainLocked) {
		t.Fatalf("want ErrDomainLocked, got %v", err)
	}
}

func TestDecide_ApproveSwitchesOwnershipAtomically(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
	if err != nil {
		t.Fatal(err)
	}

	clk.Advance(time.Hour)
	done, err := svc.Decide(tr.ID, "reg-a", true, "ok")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if done.Status != StatusApproved {
		t.Fatalf("want approved, got %s", done.Status)
	}

	d, err := svc.GetDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.OwnerID != "owner-2" || d.Registrar != "reg-b" {
		t.Fatalf("ownership not switched: %+v", d)
	}
	if d.Locked {
		t.Fatal("domain must be unlocked after approval")
	}

	// 批准必须生成唯一 outbox。
	outbox := svc.ListOutbox()
	if len(outbox) != 1 {
		t.Fatalf("want 1 outbox message, got %d", len(outbox))
	}
	if outbox[0].Type != "transfer.approved" || outbox[0].TransferID != tr.ID {
		t.Fatalf("unexpected outbox: %+v", outbox[0])
	}

	// 审计历史完整。
	audit := svc.ListAudit("example.com")
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action)
	}
	want := []string{"domain_registered", "auth_code_generated", "transfer_initiated", "transfer_approved"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit = %v, want %v", actions, want)
	}
}

func TestDecide_RejectKeepsOwnership(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	if _, err := svc.Decide(tr.ID, "reg-a", false, "denied"); err != nil {
		t.Fatal(err)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-1" || d.Registrar != "reg-a" || d.Locked {
		t.Fatalf("unexpected domain state after reject: %+v", d)
	}
}

func TestDecide_PermissionsAndLateCallbacks(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	// 非原注册商无权决定。
	if _, err := svc.Decide(tr.ID, "reg-b", true, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}

	if _, err := svc.Decide(tr.ID, "reg-a", true, ""); err != nil {
		t.Fatal(err)
	}
	// 迟到回调不得覆盖终态。
	if _, err := svc.Decide(tr.ID, "reg-a", false, "late"); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("want ErrTransferNotPending, got %v", err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusApproved {
		t.Fatalf("terminal state overwritten: %s", got.Status)
	}
	// 迟到的取消同样无效。
	if _, err := svc.Cancel(tr.ID, "owner-1"); !errors.Is(err, ErrTransferNotPending) {
		t.Fatalf("want ErrTransferNotPending, got %v", err)
	}
}

func TestDecide_AfterDeadlineRejected(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	clk.Advance(6 * 24 * time.Hour) // 超过 5 天决定期限
	if _, err := svc.Decide(tr.ID, "reg-a", false, "late"); !errors.Is(err, ErrDecisionWindowLapsed) {
		t.Fatalf("want ErrDecisionWindowLapsed, got %v", err)
	}
}

func TestCancel_ByOwner(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	if _, err := svc.Cancel(tr.ID, "intruder"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrForbidden, got %v", err)
	}
	done, err := svc.Cancel(tr.ID, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusCancelled {
		t.Fatalf("want cancelled, got %s", done.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.Locked || d.OwnerID != "owner-1" || d.Registrar != "reg-a" {
		t.Fatalf("unexpected domain state after cancel: %+v", d)
	}
	// 取消后域名可重新发起转移。
	code2, _, err := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", time.Minute)
	if err != nil {
		t.Fatalf("re-generate after cancel: %v", err)
	}
	if _, err := svc.InitiateTransfer("ext-2", "example.com", code2, "reg-b"); err != nil {
		t.Fatalf("re-initiate after cancel: %v", err)
	}
}

func TestAdvanceTimeouts_AutoApprove(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	// 未到期不处理。
	clk.Advance(4 * 24 * time.Hour)
	if n, err := svc.AdvanceTimeouts(); err != nil || n != 0 {
		t.Fatalf("want 0 processed, got %d, %v", n, err)
	}

	clk.Advance(2 * 24 * time.Hour) // 超过 5 天期限
	n, err := svc.AdvanceTimeouts()
	if err != nil || n != 1 {
		t.Fatalf("want 1 processed, got %d, %v", n, err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusAutoApproved {
		t.Fatalf("want auto_approved, got %s", got.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-2" || d.Registrar != "reg-b" || d.Locked {
		t.Fatalf("ownership not switched on auto-approve: %+v", d)
	}
	if len(svc.ListOutbox()) != 1 {
		t.Fatal("auto-approve must emit outbox")
	}
	// 幂等：再次推进不再处理。
	if n, _ := svc.AdvanceTimeouts(); n != 0 {
		t.Fatalf("want 0 on second advance, got %d", n)
	}
}

func TestAdvanceTimeouts_AutoRejectPolicy(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk, WithTimeoutPolicy(TimeoutAutoReject))
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	clk.Advance(6 * 24 * time.Hour)
	if n, err := svc.AdvanceTimeouts(); err != nil || n != 1 {
		t.Fatalf("want 1 processed, got %d, %v", n, err)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if got.Status != StatusRejected {
		t.Fatalf("want rejected, got %s", got.Status)
	}
	d, _ := svc.GetDomain("example.com")
	if d.OwnerID != "owner-1" || d.Registrar != "reg-a" || d.Locked {
		t.Fatalf("unexpected domain state: %+v", d)
	}
}

func TestConcurrency_SingleTerminalState(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	code := setupDomainWithCode(t, svc, "example.com")
	tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

	// 并发批准 / 拒绝 / 取消：只能有一个成功落入终态。
	var wg sync.WaitGroup
	successes := make(chan struct{}, 3)
	for _, fn := range []func() error{
		func() error { _, err := svc.Decide(tr.ID, "reg-a", true, ""); return err },
		func() error { _, err := svc.Decide(tr.ID, "reg-a", false, ""); return err },
		func() error { _, err := svc.Cancel(tr.ID, "owner-1"); return err },
	} {
		wg.Add(1)
		go func(f func() error) {
			defer wg.Done()
			if err := f(); err == nil {
				successes <- struct{}{}
			}
		}(fn)
	}
	wg.Wait()
	close(successes)
	if n := len(successes); n != 1 {
		t.Fatalf("want exactly 1 successful terminal transition, got %d", n)
	}
	got, _ := svc.GetTransfer(tr.ID)
	if !got.Status.Terminal() {
		t.Fatalf("transfer not terminal: %s", got.Status)
	}
	// outbox 恰好一条，与终态一致。
	if n := len(svc.ListOutbox()); n != 1 {
		t.Fatalf("want exactly 1 outbox message, got %d", n)
	}
}

func TestConcurrency_DecideVsTimeout(t *testing.T) {
	for i := 0; i < 20; i++ {
		clk := newTestClock()
		svc := newTestService(t, clk)
		code := setupDomainWithCode(t, svc, "example.com")
		tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
		clk.Advance(6 * 24 * time.Hour) // 已过期限

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = svc.Decide(tr.ID, "reg-a", false, "") }()
		go func() { defer wg.Done(); _, _ = svc.AdvanceTimeouts() }()
		wg.Wait()

		got, _ := svc.GetTransfer(tr.ID)
		if !got.Status.Terminal() {
			t.Fatalf("iter %d: transfer not terminal: %s", i, got.Status)
		}
		if n := len(svc.ListOutbox()); n != 1 {
			t.Fatalf("iter %d: want exactly 1 outbox, got %d", i, n)
		}
	}
}

func TestPersistence_RoundTrip(t *testing.T) {
	clk := newTestClock()
	path := t.TempDir() + "/state.json"
	persister := NewFilePersister(path)

	svc := newTestService(t, clk, WithPersister(persister))
	code := setupDomainWithCode(t, svc, "example.com")
	tr, err := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
	if err != nil {
		t.Fatal(err)
	}

	// 用同一持久化文件重建服务，状态应完整恢复。
	svc2 := newTestService(t, clk, WithPersister(persister))
	got, err := svc2.GetTransfer(tr.ID)
	if err != nil {
		t.Fatalf("transfer not restored: %v", err)
	}
	if got.Status != StatusPending || got.ExternalRef != "ext-1" {
		t.Fatalf("unexpected restored transfer: %+v", got)
	}
	d, err := svc2.GetDomain("example.com")
	if err != nil || !d.Locked {
		t.Fatalf("domain lock not restored: %+v, %v", d, err)
	}
	// 恢复后授权码仍处于已消费状态。
	if _, err := svc2.InitiateTransfer("ext-9", "example.com", code, "reg-b"); !errors.Is(err, ErrDomainLocked) {
		t.Fatalf("want ErrDomainLocked after restore, got %v", err)
	}
	// 恢复后可正常完成转移。
	if _, err := svc2.Decide(tr.ID, "reg-a", true, ""); err != nil {
		t.Fatalf("decide after restore: %v", err)
	}
	if n := len(svc2.ListAudit("example.com")); n != 4 {
		t.Fatalf("audit history not fully restored, got %d entries", n)
	}
}

// failingPersister 在 Save 时永远失败，用于验证原子性。
type failingPersister struct{}

func (failingPersister) Save([]byte) error     { return errors.New("disk full") }
func (failingPersister) Load() ([]byte, error) { return nil, nil }

func TestPersistence_FailureLeavesNoPartialState(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk, WithPersister(failingPersister{}))
	if err := svc.RegisterDomain("example.com", "owner-1", "reg-a"); err == nil {
		t.Fatal("want persistence error")
	}
	// 持久化失败 → 状态完全未提交。
	if _, err := svc.GetDomain("example.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("partial state committed: %v", err)
	}
}

func TestStatusQueries_NotFound(t *testing.T) {
	clk := newTestClock()
	svc := newTestService(t, clk)
	if _, err := svc.GetTransfer("tr_missing"); !errors.Is(err, ErrTransferNotFound) {
		t.Fatalf("want ErrTransferNotFound, got %v", err)
	}
	if _, err := svc.GetTransferByRef("missing"); !errors.Is(err, ErrTransferNotFound) {
		t.Fatalf("want ErrTransferNotFound, got %v", err)
	}
	if _, err := svc.GetDomain("missing.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("want ErrDomainNotFound, got %v", err)
	}
}
