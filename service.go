package domaintransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
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
	store             *Store
	now               func() time.Time
	decisionWindow    time.Duration
	maxCodeTTL        time.Duration
	contactRoundLapse time.Duration // 联系人单轮审批无响应期限的默认值
	timeoutPolicy     TimeoutPolicy
	err               error // Option 构造期的延迟错误
}

// ContactSpec 是配置联系人时的入参。明文凭据仅在配置请求中出现一次，
// 服务立即转为摘要存储，绝不落盘。
type ContactSpec struct {
	ID         string
	Role       ContactRole
	Name       string
	Email      string
	Credential string // 明文审批凭据：仅用于即时摘要，不持久化
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

// WithContactRoundLapse 设置联系人单轮审批无响应期限的默认值；
// 可被单个域名策略（ConfigureContacts）覆盖。
func WithContactRoundLapse(d time.Duration) Option {
	return func(s *Service) { s.contactRoundLapse = d }
}

// NewService 创建服务。
func NewService(opts ...Option) (*Service, error) {
	s := &Service{
		now:               time.Now,
		decisionWindow:    5 * 24 * time.Hour, // 惯例 5 天
		maxCodeTTL:        24 * time.Hour,
		contactRoundLapse: 7 * 24 * time.Hour, // 联系人单轮默认 7 天无响应
		timeoutPolicy:     TimeoutAutoApprove,
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
	if s.decisionWindow <= 0 || s.maxCodeTTL <= 0 || s.contactRoundLapse <= 0 {
		return nil, fmt.Errorf("%w: decision window, max code TTL and contact round lapse must be positive", ErrInvalidInput)
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
		st.Domains[name] = &Domain{
			Name:      name,
			OwnerID:   ownerID,
			Registrar: registrar,
			Contacts:  map[string]*Contact{},
			Version:   1,
		}
		appendAudit(st, s.now(), "domain_registered", name, "", ownerID, "registrar="+registrar)
		return nil
	})
}

// ConfigureContacts 由域名所有者配置管理/技术联系人与发起转移所需的角色组合。
// 这只改变域名的“当前”资料；任何已创建的转移持有冻结快照，不受影响。
// roundLapse <= 0 时使用服务默认的单轮无响应期限。
// 明文凭据立即转为摘要（SHA-256(contactID || 0x00 || credential)），绝不持久化。
func (s *Service) ConfigureContacts(domain, ownerID string, contacts []ContactSpec, requiredRoles []ContactRole, requireAll bool, roundLapse time.Duration) error {
	if domain == "" || ownerID == "" {
		return fmt.Errorf("%w: domain and owner are required", ErrInvalidInput)
	}
	if len(contacts) == 0 {
		return fmt.Errorf("%w: at least one contact is required", ErrInvalidInput)
	}
	now := s.now()
	return s.store.transact(func(st *state) error {
		d, ok := st.Domains[domain]
		if !ok {
			return ErrDomainNotFound
		}
		if d.OwnerID != ownerID {
			return ErrNotDomainOwner
		}
		// 注意：转移进行中（域名锁定）仍允许修改“当前”联系人资料；
		// 已创建的转移持有冻结快照，门槛不受影响。

		// 规范化并校验联系人。
		newContacts := make(map[string]*Contact, len(contacts))
		for _, c := range contacts {
			if c.ID == "" || c.Name == "" || c.Email == "" || c.Credential == "" {
				return fmt.Errorf("%w: contact id, name, email and credential are required", ErrInvalidInput)
			}
			if !validRole(c.Role) {
				return fmt.Errorf("%w: unsupported contact role %q", ErrInvalidInput, c.Role)
			}
			if _, dup := newContacts[c.ID]; dup {
				return fmt.Errorf("%w: duplicate contact id %q", ErrInvalidInput, c.ID)
			}
			newContacts[c.ID] = &Contact{
				ID:              c.ID,
				Role:            c.Role,
				Name:            c.Name,
				Email:           c.Email,
				CredentialHash:  credentialDigest(c.ID, c.Credential),
				CredentialSetAt: now,
			}
		}

		// 规范化并校验所需角色组合。
		roles := normalizeRoles(requiredRoles)
		if len(roles) == 0 {
			return fmt.Errorf("%w: required roles must not be empty", ErrInvalidInput)
		}
		roleCovered := map[ContactRole]bool{}
		for _, c := range newContacts {
			roleCovered[c.Role] = true
		}
		for _, r := range roles {
			if !roleCovered[r] {
				return fmt.Errorf("%w: no contact configured for required role %q", ErrInvalidInput, r)
			}
		}

		lapse := roundLapse
		if lapse <= 0 {
			lapse = s.contactRoundLapse
		}
		if lapse <= 0 {
			return fmt.Errorf("%w: contact round lapse must be positive", ErrInvalidInput)
		}

		// 冻结联系人快照（值拷贝）写入实时策略；转移创建时再整体深拷贝。
		snapshot := make([]Contact, 0, len(newContacts))
		for _, c := range newContacts {
			snapshot = append(snapshot, *c)
		}
		d.Contacts = newContacts
		d.Approval = &ApprovalPolicy{
			RequiredRoles: roles,
			Contacts:      snapshot,
			RoundLapse:    lapse,
			RequireAll:    requireAll,
		}
		d.Version++
		appendAudit(st, now, "contacts_configured", domain, "", ownerID,
			fmt.Sprintf("roles=%s require_all=%t round_lapse=%s", joinRoles(roles), requireAll, lapse))
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
				result = cloneTransfer(t)
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
			// Deadline 保持零值：联系人门槛达成后才开始计算注册商决定期限。
		}
		// 冻结联系人与审批策略：之后域名资料变化不得改变进行中转移的门槛。
		if d.Approval != nil {
			t.FrozenPolicy = clonePolicy(d.Approval)
			t.ContactRounds = []ContactRound{newContactRound(1, now, t.FrozenPolicy.RoundLapse)}
		} else {
			// 无联系人门槛：注册商决定期限立即开始计算。
			t.Deadline = now.Add(s.decisionWindow)
		}
		st.Transfers[t.ID] = t
		st.TransferByRef[externalRef] = t.ID
		st.PendingByDomain[domain] = t.ID
		appendAudit(st, now, "transfer_initiated", domain, t.ID, actor,
			"to_registrar="+t.ToRegistrar+contactGateDetail(t.FrozenPolicy))
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Decide 由原注册商在决定期限内批准或拒绝。
// 只有联系人门槛达成后注册商决定期限才开始计算；门槛未达成返回 ErrContactGatePending。
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
		if t.FrozenPolicy != nil && t.GatePassedAt == nil {
			return ErrContactGatePending
		}
		if now.After(t.Deadline) {
			return ErrDecisionWindowLapsed
		}
		if approve {
			approveLocked(st, t, now, StatusApproved, registrar, reason)
		} else {
			rejectLocked(st, t, now, StatusRejected, registrar, reason)
		}
		result = cloneTransfer(t)
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
		result = cloneTransfer(t)
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
			if t == nil || t.Status != StatusPending {
				continue
			}
			// 联系人门槛未达成时注册商期限尚未开始计算（Deadline 为零值），不得超时落终态。
			if t.FrozenPolicy != nil && t.GatePassedAt == nil {
				continue
			}
			if !now.After(t.Deadline) {
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

// SubmitContactDecision 记录联系人在指定审批轮的唯一决定事件。
// 决定必须匹配转移、轮次、联系人及其冻结角色与凭据摘要；
// 相同事件相同内容幂等，同号异内容冲突；指向旧轮次的迟到决定返回 ErrDecisionRoundStale，
// 不得推进当前转移。任一所需角色明确拒绝，转移立即终态拒绝，
// 且不会再被其他同意或超时规则批准。所需角色门槛达成时，注册商决定期限从该刻开始计算。
func (s *Service) SubmitContactDecision(transferID, eventID string, round int, contactID, credential string, approve bool, reason string) (*Transfer, error) {
	if transferID == "" || eventID == "" || contactID == "" || credential == "" || round <= 0 {
		return nil, fmt.Errorf("%w: transfer id, event id, positive round, contact id and credential are required", ErrInvalidInput)
	}
	now := s.now()
	credHash := credentialDigest(contactID, credential)
	var result *Transfer
	err := s.store.transact(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}
		if t.FrozenPolicy == nil {
			return ErrContactPolicyMissing
		}

		// 事件幂等 / 冲突：同号同内容（含凭据摘要）返回既有转移，同号异内容拒绝。
		// 该检查优先，使已记录事件（即使来自旧轮）的重放保持幂等。
		if existingTransfer, seen := st.DecisionByEvent[eventID]; seen {
			if existingTransfer != transferID {
				return ErrDecisionConflict
			}
			if !decisionMatches(t, eventID, round, contactID, credHash, approve, reason) {
				return ErrDecisionConflict
			}
			result = cloneTransfer(t)
			return nil
		}

		if t.Status.Terminal() {
			return ErrTransferNotPending
		}
		if t.GatePassedAt != nil {
			return ErrContactGateAlreadyPassed
		}

		// 当前轮为最后一个元素；决定只能落在当前轮，旧轮迟到决定拒绝。
		roundIdx := len(t.ContactRounds) - 1
		current := &t.ContactRounds[roundIdx]
		if round != current.Number {
			return ErrDecisionRoundStale
		}

		// 联系人必须存在于冻结快照且角色匹配。
		frozen, ok := findFrozenContact(t.FrozenPolicy, contactID)
		if !ok {
			return ErrForbidden
		}
		// 凭据仅以摘要比对，绝不持久化明文。
		if frozen.CredentialHash != credHash {
			return ErrForbidden
		}
		// 同一联系人在当前轮只能决定一次。
		for i := range current.Decisions {
			if current.Decisions[i].ContactID == contactID {
				return ErrContactAlreadyDecided
			}
		}

		dec := ContactDecision{
			EventID:        eventID,
			ContactID:      contactID,
			Role:           frozen.Role,
			Round:          current.Number,
			Approve:        approve,
			CredentialHash: frozen.CredentialHash,
			Reason:         reason,
			DecidedAt:      now,
		}
		current.Decisions = append(current.Decisions, dec)
		st.DecisionByEvent[eventID] = transferID

		appendAudit(st, now, "contact_decision_submitted", t.Domain, t.ID, contactID,
			fmt.Sprintf("round=%d role=%s approve=%t", current.Number, frozen.Role, approve))

		// 仅“所需角色组合”内的联系人参与门槛：其同意计入，其明确拒绝立即终态拒绝。
		// 非所需角色联系人的决定仅记录留痕，既不通过也不否决。
		if !approve && roleRequired(t.FrozenPolicy, frozen.Role) {
			// 明确拒绝：立即终态拒绝，且此后不可能再被同意或超时批准。
			rejectLocked(st, t, now, StatusRejected, contactID, "contact rejected: "+reason)
			result = cloneTransfer(t)
			return nil
		}

		// 依据冻结策略判定门槛是否达成。
		if gateSatisfied(t.FrozenPolicy, current.Decisions) {
			s.passGateLocked(st, t, now, current)
		}
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReissueContactRound 在当前联系人轮超期后由所有者重新签发一轮审批。
// 新一轮保留旧轮决定用于审计，但不沿用；旧轮迟到决定由 SubmitContactDecision 拒绝
// （决定只能落在当前轮），因而不得推进当前转移。
func (s *Service) ReissueContactRound(transferID, actor string) (*Transfer, error) {
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
		if t.FrozenPolicy == nil {
			return ErrContactPolicyMissing
		}
		if t.Status.Terminal() {
			return ErrTransferNotPending
		}
		if actor != t.FromOwnerID {
			return ErrForbidden
		}
		if t.GatePassedAt != nil {
			return ErrContactGateAlreadyPassed
		}
		round := &t.ContactRounds[len(t.ContactRounds)-1]
		if !now.After(round.LapsesAt) {
			return ErrContactRoundActive
		}
		next := newContactRound(round.Number+1, now, t.FrozenPolicy.RoundLapse)
		t.ContactRounds = append(t.ContactRounds, next)
		appendAudit(st, now, "contact_round_reissued", t.Domain, t.ID, actor,
			fmt.Sprintf("round=%d lapse=%s", next.Number, next.LapsesAt))
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListContactRounds 返回该转移各轮联系人审批（含历史轮次的全部决定），按轮次排序。
func (s *Service) ListContactRounds(transferID string) ([]ContactRound, error) {
	var out []ContactRound
	err := s.store.viewErr(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}
		if len(t.ContactRounds) > 0 {
			out = cloneRounds(t.ContactRounds)
		}
		return nil
	})
	return out, err
}

// passGateLocked 在事务内将联系人门槛标记为达成，并从该刻开始计算注册商决定期限。
func (s *Service) passGateLocked(st *state, t *Transfer, now time.Time, round *ContactRound) {
	round.GatePassed = true
	t.GatePassedAt = &now
	t.Deadline = now.Add(s.decisionWindow)
	appendAudit(st, now, "contact_gate_passed", t.Domain, t.ID, "contacts",
		fmt.Sprintf("round=%d registrar_deadline=%s", round.Number, t.Deadline))
}

// GetApprovalPolicy 返回冻结进转移单的联系人审批策略（快照）。
func (s *Service) GetApprovalPolicy(transferID string) (*ApprovalPolicy, error) {
	var out *ApprovalPolicy
	err := s.store.viewErr(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}
		if t.FrozenPolicy != nil {
			out = clonePolicy(t.FrozenPolicy)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetTransfer 按内部 ID 查询转移单。
func (s *Service) GetTransfer(id string) (*Transfer, error) {
	var out *Transfer
	s.store.view(func(st *state) {
		if t, ok := st.Transfers[id]; ok {
			out = cloneTransfer(t)
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
				out = cloneTransfer(t)
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
			out = cloneDomain(d)
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

// credentialDigest 计算联系人审批凭据摘要，绑定联系人 ID 防跨账号重放。
// 仅保存摘要，明文凭据绝不持久化。
func credentialDigest(contactID, credential string) string {
	h := sha256.New()
	h.Write([]byte(contactID))
	h.Write([]byte{0x00})
	h.Write([]byte(credential))
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeRoles 去重并校验角色，返回稳定顺序的所需角色组合。
func normalizeRoles(roles []ContactRole) []ContactRole {
	seen := map[ContactRole]bool{}
	out := make([]ContactRole, 0, len(roles))
	for _, r := range roles {
		if !validRole(r) || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// joinRoles 以稳定顺序拼接角色，用于审计明细。
func joinRoles(roles []ContactRole) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, "+")
}

// contactGateDetail 生成转移发起时的联系人门禁审计明细（不含敏感值）。
func contactGateDetail(p *ApprovalPolicy) string {
	if p == nil {
		return " contact_gate=none"
	}
	mode := "all"
	if !p.RequireAll {
		mode = "any"
	}
	return " contact_gate=" + joinRoles(p.RequiredRoles) + "(" + mode + ")"
}

// newContactRound 构造一轮联系人审批。
func newContactRound(number int, start time.Time, lapse time.Duration) ContactRound {
	return ContactRound{
		Number:    number,
		StartedAt: start,
		LapsesAt:  start.Add(lapse),
		Decisions: []ContactDecision{},
	}
}

// findFrozenContact 在冻结策略快照中按 ID 查找联系人。
func findFrozenContact(p *ApprovalPolicy, contactID string) (Contact, bool) {
	for _, c := range p.Contacts {
		if c.ID == contactID {
			return c, true
		}
	}
	return Contact{}, false
}

// roleRequired 报告角色是否在所需角色组合内。
func roleRequired(p *ApprovalPolicy, role ContactRole) bool {
	for _, r := range p.RequiredRoles {
		if r == role {
			return true
		}
	}
	return false
}

// gateSatisfied 依据冻结策略判定当前轮的同意决定是否已满足门槛。
// RequireAll：所需的每个角色都至少有一名联系人同意；否则任一所需角色联系人同意即可。
func gateSatisfied(p *ApprovalPolicy, decisions []ContactDecision) bool {
	approvedRoles := map[ContactRole]bool{}
	for _, d := range decisions {
		if d.Approve && roleRequired(p, d.Role) {
			approvedRoles[d.Role] = true
		}
	}
	if p.RequireAll {
		for _, r := range p.RequiredRoles {
			if !approvedRoles[r] {
				return false
			}
		}
		return true
	}
	return len(approvedRoles) > 0
}

// decisionMatches 报告某事件 ID 的既有决定是否与本次提交内容一致（幂等判重，含凭据摘要）。
func decisionMatches(t *Transfer, eventID string, round int, contactID, credHash string, approve bool, reason string) bool {
	for ri := range t.ContactRounds {
		for _, d := range t.ContactRounds[ri].Decisions {
			if d.EventID == eventID {
				return d.Round == round && d.ContactID == contactID &&
					d.CredentialHash == credHash && d.Approve == approve && d.Reason == reason
			}
		}
	}
	return false
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
