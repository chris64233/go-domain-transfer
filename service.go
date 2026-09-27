package domaintransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// TimeoutPolicy 决定转移超期后的自动处理策略。
type TimeoutPolicy int

const (
	// TimeoutAutoApprove 超期自动批准（默认，符合 EPP 转移惯例）。
	TimeoutAutoApprove TimeoutPolicy = iota
	// TimeoutAutoReject 超期自动拒绝。
	TimeoutAutoReject
)

// Service 提供域名转移的全部业务操作。所有方法并发安全。
type Service struct {
	store          *Store
	now            func() time.Time
	decisionWindow time.Duration
	maxCodeTTL     time.Duration
	timeoutPolicy  TimeoutPolicy
	err            error // Option 构造期的延迟错误
}

// Option 自定义 Service。
type Option func(*Service)

// WithStore 使用指定 Store（默认新建纯内存 Store）。
func WithStore(st *Store) Option {
	return func(s *Service) {
		if st != nil {
			s.store = st
		}
	}
}

// WithPersister 以指定持久化器新建 Store。
func WithPersister(p Persister) Option {
	return func(s *Service) {
		st, err := NewStore(p)
		if err != nil {
			s.err = err
			return
		}
		s.store = st
	}
}

// WithClock 注入时钟（测试用）。
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// WithDecisionWindow 设置原注册商的决定期限。
func WithDecisionWindow(d time.Duration) Option {
	return func(s *Service) { s.decisionWindow = d }
}

// WithMaxCodeTTL 设置授权码有效期上限。
func WithMaxCodeTTL(d time.Duration) Option {
	return func(s *Service) { s.maxCodeTTL = d }
}

// WithTimeoutPolicy 设置超时策略。
func WithTimeoutPolicy(p TimeoutPolicy) Option {
	return func(s *Service) { s.timeoutPolicy = p }
}

// NewService 创建服务。
func NewService(opts ...Option) (*Service, error) {
	s := &Service{
		now:            time.Now,
		decisionWindow: 5 * 24 * time.Hour, // 惯例 5 天
		maxCodeTTL:     24 * time.Hour,
		timeoutPolicy:  TimeoutAutoApprove,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.store == nil {
		st, err := NewStore(nil)
		if err != nil {
			return nil, err
		}
		s.store = st
	}
	if s.decisionWindow <= 0 || s.maxCodeTTL <= 0 {
		return nil, fmt.Errorf("%w: decision window and max code TTL must be positive", ErrInvalidInput)
	}
	return s, nil
}

// RegisterDomain 登记域名（初始化/迁入数据用）。
func (s *Service) RegisterDomain(name, ownerID, registrar string) error {
	if name == "" || ownerID == "" || registrar == "" {
		return fmt.Errorf("%w: name, owner and registrar are required", ErrInvalidInput)
	}
	return s.store.transact(func(st *state) error {
		if _, ok := st.Domains[name]; ok {
			return ErrDomainExists
		}
		st.Domains[name] = &Domain{Name: name, OwnerID: ownerID, Registrar: registrar, Version: 1}
		appendAudit(st, s.now(), "domain_registered", name, "", ownerID, "registrar="+registrar)
		return nil
	})
}

// GenerateAuthCode 为域名所有者生成一次性短期授权码。
// 明文授权码仅通过返回值下发一次，持久化层只保存绑定域名/目标注册商/有效期的摘要。
func (s *Service) GenerateAuthCode(domain, ownerID, targetRegistrar, targetOwnerID string, ttl time.Duration) (code string, expiresAt time.Time, err error) {
	if domain == "" || ownerID == "" || targetRegistrar == "" || targetOwnerID == "" || ttl <= 0 {
		return "", time.Time{}, fmt.Errorf("%w: domain, owner, target registrar/owner and positive ttl are required", ErrInvalidInput)
	}
	if ttl > s.maxCodeTTL {
		return "", time.Time{}, fmt.Errorf("%w: auth code ttl exceeds maximum", ErrInvalidInput)
	}
	raw, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expiresAt = now.Add(ttl)
	err = s.store.transact(func(st *state) error {
		d, ok := st.Domains[domain]
		if !ok {
			return ErrDomainNotFound
		}
		if d.OwnerID != ownerID {
			return ErrNotDomainOwner
		}
		if d.Locked {
			return ErrDomainLocked
		}
		if d.Registrar == targetRegistrar {
			return fmt.Errorf("%w: target registrar must differ from current registrar", ErrInvalidInput)
		}
		digest := codeDigest(domain, raw)
		st.AuthCodes[digest] = &AuthCodeRecord{
			Digest:          digest,
			Domain:          domain,
			TargetRegistrar: targetRegistrar,
			TargetOwnerID:   targetOwnerID,
			ExpiresAt:       expiresAt,
		}
		appendAudit(st, now, "auth_code_generated", domain, "", ownerID, "target_registrar="+targetRegistrar)
		return nil
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, expiresAt, nil
}

// InitiateTransfer 由目标注册商凭授权码发起转移。
// 在同一原子边界内：校验并消费授权码、锁定域名、创建转移单。
// externalRef 为幂等键：同号同内容返回既有转移单，同号异内容返回 ErrTransferConflict。
func (s *Service) InitiateTransfer(externalRef, domain, code, actor string) (*Transfer, error) {
	if externalRef == "" || domain == "" || code == "" || actor == "" {
		return nil, fmt.Errorf("%w: external ref, domain, code and actor are required", ErrInvalidInput)
	}
	now := s.now()
	digest := codeDigest(domain, code)
	var result *Transfer
	err := s.store.transact(func(st *state) error {
		// 幂等：外部转移号已存在时按内容判重。
		if id, ok := st.TransferByRef[externalRef]; ok {
			t := st.Transfers[id]
			rec, rok := st.AuthCodes[digest]
			if t.Domain == domain && rok &&
				t.ToRegistrar == rec.TargetRegistrar && t.ToOwnerID == rec.TargetOwnerID {
				cp := *t
				result = &cp
				return nil
			}
			return ErrTransferConflict
		}

		d, ok := st.Domains[domain]
		if !ok {
			return ErrDomainNotFound
		}
		if d.Locked {
			return ErrDomainLocked
		}
		if _, ok := st.PendingByDomain[domain]; ok {
			return ErrTransferInFlight
		}
		rec, ok := st.AuthCodes[digest]
		if !ok {
			return ErrAuthCodeInvalid
		}
		if rec.ConsumedAt != nil {
			return ErrAuthCodeConsumed
		}
		if now.After(rec.ExpiresAt) {
			return ErrAuthCodeExpired
		}

		// 同一原子边界：消费授权码 + 锁定域名 + 创建转移单。
		consumed := now
		rec.ConsumedAt = &consumed
		d.Locked = true
		d.Version++

		t := &Transfer{
			ID:            newTransferID(st),
			ExternalRef:   externalRef,
			Domain:        domain,
			FromRegistrar: d.Registrar,
			ToRegistrar:   rec.TargetRegistrar,
			FromOwnerID:   d.OwnerID,
			ToOwnerID:     rec.TargetOwnerID,
			Status:        StatusPending,
			CreatedAt:     now,
			Deadline:      now.Add(s.decisionWindow),
		}
		st.Transfers[t.ID] = t
		st.TransferByRef[externalRef] = t.ID
		st.PendingByDomain[domain] = t.ID
		appendAudit(st, now, "transfer_initiated", domain, t.ID, actor, "to_registrar="+t.ToRegistrar)
		cp := *t
		result = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Decide 由原注册商在决定期限内批准或拒绝。
// 终态不可逆：已终态的转移返回 ErrTransferNotPending，迟到回调不得覆盖。
func (s *Service) Decide(transferID, registrar string, approve bool, reason string) (*Transfer, error) {
	if transferID == "" || registrar == "" {
		return nil, fmt.Errorf("%w: transfer id and registrar are required", ErrInvalidInput)
	}
	now := s.now()
	var result *Transfer
	err := s.store.transact(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}
		if t.Status.Terminal() {
			return ErrTransferNotPending
		}
		if registrar != t.FromRegistrar {
			return ErrForbidden
		}
		if now.After(t.Deadline) {
			return ErrDecisionWindowLapsed
		}
		if approve {
			approveLocked(st, t, now, StatusApproved, registrar, reason)
		} else {
			rejectLocked(st, t, now, StatusRejected, registrar, reason)
		}
		cp := *t
		result = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Cancel 由域名所有者取消进行中的转移并解锁域名。
func (s *Service) Cancel(transferID, actor string) (*Transfer, error) {
	if transferID == "" || actor == "" {
		return nil, fmt.Errorf("%w: transfer id and actor are required", ErrInvalidInput)
	}
	now := s.now()
	var result *Transfer
	err := s.store.transact(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}
		if t.Status.Terminal() {
			return ErrTransferNotPending
		}
		if actor != t.FromOwnerID {
			return ErrForbidden
		}
		unlockLocked(st, t)
		t.Status = StatusCancelled
		t.DecidedAt = &now
		t.DecidedBy = actor
		emitOutbox(st, t, now, "transfer.cancelled")
		appendAudit(st, now, "transfer_cancelled", t.Domain, t.ID, actor, "")
		cp := *t
		result = &cp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AdvanceTimeouts 推进超时：对所有已过决定期限的 pending 转移按策略落终态。
// 与人工决定、取消共享同一事务边界，并发竞争时只有一个能生效。返回处理笔数。
func (s *Service) AdvanceTimeouts() (int, error) {
	now := s.now()
	count := 0
	err := s.store.transact(func(st *state) error {
		ids := make([]string, 0, len(st.PendingByDomain))
		for _, id := range st.PendingByDomain {
			ids = append(ids, id)
		}
		for _, id := range ids {
			t := st.Transfers[id]
			if t == nil || t.Status != StatusPending || !now.After(t.Deadline) {
				continue
			}
			switch s.timeoutPolicy {
			case TimeoutAutoReject:
				rejectLocked(st, t, now, StatusRejected, "system", "decision window lapsed")
			default:
				approveLocked(st, t, now, StatusAutoApproved, "system", "decision window lapsed")
			}
			count++
		}
		return nil
	})
	return count, err
}

// GetTransfer 按内部 ID 查询转移单。
func (s *Service) GetTransfer(id string) (*Transfer, error) {
	var out *Transfer
	s.store.view(func(st *state) {
		if t, ok := st.Transfers[id]; ok {
			cp := *t
			out = &cp
		}
	})
	if out == nil {
		return nil, ErrTransferNotFound
	}
	return out, nil
}

// GetTransferByRef 按外部转移号查询转移单。
func (s *Service) GetTransferByRef(externalRef string) (*Transfer, error) {
	var out *Transfer
	s.store.view(func(st *state) {
		if id, ok := st.TransferByRef[externalRef]; ok {
			if t, ok := st.Transfers[id]; ok {
				cp := *t
				out = &cp
			}
		}
	})
	if out == nil {
		return nil, ErrTransferNotFound
	}
	return out, nil
}

// GetDomain 查询域名当前登记信息。
func (s *Service) GetDomain(name string) (*Domain, error) {
	var out *Domain
	s.store.view(func(st *state) {
		if d, ok := st.Domains[name]; ok {
			cp := *d
			out = &cp
		}
	})
	if out == nil {
		return nil, ErrDomainNotFound
	}
	return out, nil
}

// ListAudit 返回指定域名的审计历史（按时间顺序）。
func (s *Service) ListAudit(domain string) []AuditEntry {
	var out []AuditEntry
	s.store.view(func(st *state) {
		for _, e := range st.Audit {
			if e.Domain == domain {
				out = append(out, e)
			}
		}
	})
	return out
}

// ListOutbox 返回全部 outbox 消息（供外发轮询）。
func (s *Service) ListOutbox() []OutboxMessage {
	var out []OutboxMessage
	s.store.view(func(st *state) {
		for _, m := range st.Outbox {
			out = append(out, *m)
		}
	})
	return out
}

// approveLocked 在事务内批准转移：切换所有权与注册商、解锁、生成唯一 outbox。
// 调用方必须已确认 t 处于 pending。
func approveLocked(st *state, t *Transfer, now time.Time, status TransferStatus, actor, reason string) {
	d := st.Domains[t.Domain]
	d.OwnerID = t.ToOwnerID
	d.Registrar = t.ToRegistrar
	d.Locked = false
	d.Version++
	delete(st.PendingByDomain, t.Domain)

	t.Status = status
	t.DecidedAt = &now
	t.DecidedBy = actor
	t.Reason = reason

	emitOutbox(st, t, now, "transfer.approved")
	appendAudit(st, now, "transfer_approved", t.Domain, t.ID, actor, "to_registrar="+t.ToRegistrar)
}

// rejectLocked 在事务内拒绝转移：仅解锁，所有权不变。
func rejectLocked(st *state, t *Transfer, now time.Time, status TransferStatus, actor, reason string) {
	unlockLocked(st, t)
	t.Status = status
	t.DecidedAt = &now
	t.DecidedBy = actor
	t.Reason = reason
	emitOutbox(st, t, now, "transfer.rejected")
	appendAudit(st, now, "transfer_rejected", t.Domain, t.ID, actor, "")
}

// unlockLocked 解除域名锁定并清除 pending 索引。
func unlockLocked(st *state, t *Transfer) {
	d := st.Domains[t.Domain]
	d.Locked = false
	d.Version++
	delete(st.PendingByDomain, t.Domain)
}

// emitOutbox 在事务内生成唯一 ID 的 outbox 消息。
func emitOutbox(st *state, t *Transfer, now time.Time, typ string) {
	m := &OutboxMessage{
		ID:         newOutboxID(st),
		TransferID: t.ID,
		Domain:     t.Domain,
		Type:       typ,
		CreatedAt:  now,
	}
	st.Outbox[m.ID] = m
}

// appendAudit 在事务内追加审计记录。调用方不得传入敏感值。
func appendAudit(st *state, now time.Time, action, domain, transferID, actor, detail string) {
	st.Seq++
	st.Audit = append(st.Audit, AuditEntry{
		Seq:        st.Seq,
		Time:       now,
		Action:     action,
		Domain:     domain,
		TransferID: transferID,
		Actor:      actor,
		Detail:     detail,
	})
}

// codeDigest 计算授权码摘要，绑定域名以防跨域名重放。
func codeDigest(domain, code string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0x00})
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// randomToken 生成密码学安全的随机令牌。
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// newTransferID / newOutboxID 生成唯一 ID（在事务内查重）。
func newTransferID(st *state) string {
	for {
		id := "tr_" + mustToken(8)
		if _, ok := st.Transfers[id]; !ok {
			return id
		}
	}
}

func newOutboxID(st *state) string {
	for {
		id := "ob_" + mustToken(8)
		if _, ok := st.Outbox[id]; !ok {
			return id
		}
	}
}

func mustToken(n int) string {
	t, err := randomToken(n)
	if err != nil {
		panic(err) // crypto/rand 失败属于不可恢复错误
	}
	return t
}
