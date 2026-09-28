package domaintransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
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

// ContactConfig 是域名的联系人审批配置。空 RequiredRoles 表示不设联系人门槛。
// 联系人资料本身（Contact）可随时更新；进行中的转移使用创建时冻结的快照。
type ContactConfig struct {
	AdminContactID string
	TechContactID  string
	// RequiredRoles 为发起转移所需的角色组合；角色去重后按固定顺序冻结。
	RequiredRoles []ContactRole
	// DecisionWindow 为每轮联系人审批有效期；0 表示使用服务默认值。
	DecisionWindow time.Duration
}

// Service 提供域名转移的全部业务操作。所有方法并发安全。
type Service struct {
	store          *Store
	now            func() time.Time
	decisionWindow time.Duration
	maxCodeTTL     time.Duration
	contactWindow  time.Duration
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

// WithContactDecisionWindow 设置每轮联系人审批的默认有效期。
func WithContactDecisionWindow(d time.Duration) Option {
	return func(s *Service) { s.contactWindow = d }
}

// NewService 创建服务。
func NewService(opts ...Option) (*Service, error) {
	s := &Service{
		now:            time.Now,
		decisionWindow: 5 * 24 * time.Hour, // 惯例 5 天
		maxCodeTTL:     24 * time.Hour,
		contactWindow:  7 * 24 * time.Hour, // 联系人每轮审批默认 7 天
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
	if s.decisionWindow <= 0 || s.maxCodeTTL <= 0 || s.contactWindow <= 0 {
		return nil, fmt.Errorf("%w: decision windows and max code TTL must be positive", ErrInvalidInput)
	}
	return s, nil
}

// RegisterContact 登记联系人资料。不含任何凭据字段。
func (s *Service) RegisterContact(id, name, email string) error {
	if id == "" || name == "" || email == "" {
		return fmt.Errorf("%w: contact id, name and email are required", ErrInvalidInput)
	}
	return s.store.transact(func(st *state) error {
		if _, ok := st.Contacts[id]; ok {
			return ErrContactExists
		}
		st.Contacts[id] = &Contact{ID: id, Name: name, Email: email}
		return nil
	})
}

// GetContact 查询联系人资料。
func (s *Service) GetContact(id string) (*Contact, error) {
	var out *Contact
	s.store.view(func(st *state) {
		if c, ok := st.Contacts[id]; ok {
			cp := *c
			out = &cp
		}
	})
	if out == nil {
		return nil, ErrContactNotFound
	}
	return out, nil
}

// UpdateContact 更新联系人资料。只影响之后冻结的策略；
// 进行中转移持有的冻结快照不变（门槛不会被悄悄改变）。
func (s *Service) UpdateContact(id, name, email string) error {
	if id == "" || name == "" || email == "" {
		return fmt.Errorf("%w: contact id, name and email are required", ErrInvalidInput)
	}
	return s.store.transact(func(st *state) error {
		c, ok := st.Contacts[id]
		if !ok {
			return ErrContactNotFound
		}
		c.Name = name
		c.Email = email
		return nil
	})
}

// ConfigureDomainContacts 设置域名的管理/技术联系人与转移所需角色组合。
// 仅域名所有者可改；仅影响之后创建的转移，进行中的转移使用冻结快照，不受影响。
// cfg.RequiredRoles 为空时清除联系人门槛。
func (s *Service) ConfigureDomainContacts(domain, ownerID string, cfg ContactConfig) error {
	if domain == "" || ownerID == "" {
		return fmt.Errorf("%w: domain and owner are required", ErrInvalidInput)
	}
	roles, err := normalizeRoles(cfg.RequiredRoles)
	if err != nil {
		return err
	}
	if cfg.DecisionWindow < 0 {
		return fmt.Errorf("%w: contact decision window must not be negative", ErrInvalidInput)
	}
	return s.store.transact(func(st *state) error {
		d, ok := st.Domains[domain]
		if !ok {
			return ErrDomainNotFound
		}
		if d.OwnerID != ownerID {
			return ErrNotDomainOwner
		}
		// 所需角色必须绑定已登记的联系人。
		for _, role := range roles {
			contactID := cfg.AdminContactID
			if role == RoleTech {
				contactID = cfg.TechContactID
			}
			if contactID == "" {
				return fmt.Errorf("%w: role %s requires a contact", ErrInvalidInput, role)
			}
			if _, ok := st.Contacts[contactID]; !ok {
				return ErrContactNotFound
			}
		}
		d.AdminContactID = cfg.AdminContactID
		d.TechContactID = cfg.TechContactID
		d.RequiredRoles = roles
		d.ContactDecisionWindow = cfg.DecisionWindow
		d.Version++
		appendAudit(st, s.now(), "domain_contacts_configured", domain, "", d.OwnerID,
			"required_roles="+rolesString(roles))
		return nil
	})
}

// normalizeRoles 校验、去重并固定角色顺序（admin 在 tech 之前），
// 使冻结策略的角色组合具有确定表示。
func normalizeRoles(roles []ContactRole) ([]ContactRole, error) {
	seen := map[ContactRole]bool{}
	for _, r := range roles {
		if !r.Valid() {
			return nil, fmt.Errorf("%w: unsupported contact role %q", ErrInvalidInput, r)
		}
		seen[r] = true
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]ContactRole, 0, len(seen))
	if seen[RoleAdmin] {
		out = append(out, RoleAdmin)
	}
	if seen[RoleTech] {
		out = append(out, RoleTech)
	}
	return out, nil
}

func rolesString(roles []ContactRole) string {
	if len(roles) == 0 {
		return "none"
	}
	out := ""
	for i, r := range roles {
		if i > 0 {
			out += ","
		}
		out += string(r)
	}
	return out
}

// freezePolicy 在转移创建时冻结联系人与审批策略快照。
// 调用方须持有事务并已完成角色归一化。
func (s *Service) freezePolicy(st *state, d *Domain, now time.Time) (*FrozenApprovalPolicy, error) {
	roles, err := normalizeRoles(d.RequiredRoles)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, nil
	}
	window := d.ContactDecisionWindow
	if window <= 0 {
		window = s.contactWindow
	}
	p := &FrozenApprovalPolicy{
		RequiredRoles:         roles,
		ContactDecisionWindow: window,
	}
	for _, role := range roles {
		contactID := d.AdminContactID
		if role == RoleTech {
			contactID = d.TechContactID
		}
		c, ok := st.Contacts[contactID]
		if !ok {
			return nil, ErrContactNotFound
		}
		p.Contacts = append(p.Contacts, FrozenContact{
			ContactID: c.ID,
			Role:      role,
			Name:      c.Name,
			Email:     c.Email,
		})
	}
	return p, nil
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

		// 同一原子边界：消费授权码 + 锁定域名 + 创建转移单（含冻结策略）。
		consumed := now
		rec.ConsumedAt = &consumed
		d.Locked = true
		d.Version++

		policy, err := s.freezePolicy(st, d, now)
		if err != nil {
			return err
		}
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
			Policy:        policy,
		}
		if policy != nil {
			// 联系人门槛阶段：注册商决定期限此时尚未起算。
			t.Phase = PhaseContacts
			t.Rounds = []*ContactRound{newContactRound(1, now, policy.ContactDecisionWindow)}
		} else {
			// 无联系人门槛：直接进入注册商阶段，保持历史语义。
			t.Phase = PhaseRegistrar
			t.Deadline = now.Add(s.decisionWindow)
		}
		st.Transfers[t.ID] = t
		st.TransferByRef[externalRef] = t.ID
		st.PendingByDomain[domain] = t.ID
		appendAudit(st, now, "transfer_initiated", domain, t.ID, actor, "to_registrar="+t.ToRegistrar)
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Decide 由原注册商在决定期限内批准或拒绝。
// 联系人门槛达成前注册商决定期限不起算，此时返回 ErrAwaitingContacts。
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
		if t.Phase != PhaseRegistrar {
			return ErrAwaitingContacts
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
			if t == nil || t.Status != StatusPending || t.Phase != PhaseRegistrar || !now.After(t.Deadline) {
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

// ContactDecide 记录联系人的唯一决定事件。
// eventID 是幂等键：同一事件相同内容（轮次/联系人/角色/同意与否）幂等返回，
// 同号异内容返回 ErrContactDecisionConflict。
// 决定必须匹配转移、联系人及其冻结角色；旧轮次的迟到决定返回 ErrStaleRound，
// 不得推进当前转移。任一所需联系人明确拒绝，转移立即以 rejected 终局，
// 此后其他同意或超时规则都不能再批准该转移。
func (s *Service) ContactDecide(transferID, eventID string, round int, contactID string, role ContactRole, approve bool, reason string) (*Transfer, error) {
	if transferID == "" || eventID == "" || contactID == "" || !role.Valid() {
		return nil, fmt.Errorf("%w: transfer id, event id, contact id and valid role are required", ErrInvalidInput)
	}
	now := s.now()
	var result *Transfer
	err := s.store.transact(func(st *state) error {
		t, ok := st.Transfers[transferID]
		if !ok {
			return ErrTransferNotFound
		}

		// 幂等优先：事件号已在任意轮次出现时，按内容判重（reason 不参与）。
		if d, ok := findDecision(t, eventID); ok {
			if d.Round == round && d.ContactID == contactID && d.Role == role && d.Approve == approve {
				result = cloneTransfer(t)
				return nil
			}
			return ErrContactDecisionConflict
		}

		if t.Status.Terminal() {
			return ErrTransferNotPending
		}
		if t.Phase != PhaseContacts || t.Policy == nil {
			return ErrContactApprovalClosed
		}
		cur := t.CurrentRound()
		if round < cur.Number {
			// 旧轮次迟到决定：记录但绝不推进——这里直接拒绝，不写入当前轮。
			return ErrStaleRound
		}
		if round > cur.Number {
			return fmt.Errorf("%w: unknown approval round %d", ErrInvalidInput, round)
		}
		if now.After(cur.ExpiresAt) {
			// 本轮已到期：迟到决定不计入，需由所有者重签新一轮后再投。
			return ErrApprovalRoundExpired
		}

		// 决定必须匹配冻结策略中的角色与该角色绑定的联系人。
		var frozen *FrozenContact
		for i := range t.Policy.Contacts {
			if t.Policy.Contacts[i].Role == role {
				frozen = &t.Policy.Contacts[i]
				break
			}
		}
		if frozen == nil {
			return ErrContactNotRequired
		}
		if frozen.ContactID != contactID {
			return ErrContactRoleMismatch
		}
		for _, d := range cur.Decisions {
			if d.Role == role {
				// 每轮每角色只能有一个决定事件（事件号不同即为重复决定）。
				return ErrContactAlreadyDecided
			}
		}

		cur.Decisions = append(cur.Decisions, ContactDecision{
			EventID:   eventID,
			Round:     round,
			ContactID: contactID,
			Role:      role,
			Approve:   approve,
			Reason:    reason,
			At:        now,
		})
		verdict := "approved"
		if !approve {
			verdict = "rejected"
		}
		appendAudit(st, now, "contact_decided", t.Domain, t.ID, contactID,
			fmt.Sprintf("round=%d role=%s decision=%s", round, role, verdict))

		if !approve {
			// 明确拒绝立即终局：后续同意、重签或超时均无法再批准。
			rejectLocked(st, t, now, StatusRejected, contactID, "contact rejected: "+string(role))
			result = cloneTransfer(t)
			return nil
		}

		if contactsSatisfied(t, cur) {
			// 最后一票：联系人门槛达成，注册商决定期限此刻起算。
			t.Phase = PhaseRegistrar
			satisfiedAt := now
			t.ContactsSatisfiedAt = &satisfiedAt
			t.Deadline = now.Add(s.decisionWindow)
			appendAudit(st, now, "contacts_approved", t.Domain, t.ID, "system",
				"round="+strconv.Itoa(round))
		}
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ReissueApprovalRound 在当前联系人审批轮次到期后由所有者重新签发一轮。
// 旧轮次及其决定完整保留以供审计，但新一轮不沿用任何旧决定，
// 旧轮次的迟到决定一律按 ErrStaleRound 拒绝。
func (s *Service) ReissueApprovalRound(transferID, actor string) (*Transfer, error) {
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
		if t.Phase != PhaseContacts || t.Policy == nil {
			return ErrContactApprovalClosed
		}
		cur := t.CurrentRound()
		if !now.After(cur.ExpiresAt) {
			return ErrRoundNotExpired
		}
		next := newContactRound(cur.Number+1, now, t.Policy.ContactDecisionWindow)
		t.Rounds = append(t.Rounds, next)
		appendAudit(st, now, "contact_round_reissued", t.Domain, t.ID, actor,
			"round="+strconv.Itoa(next.Number))
		result = cloneTransfer(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetFrozenPolicy 返回转移创建时冻结的联系人审批策略副本；无联系人策略时返回 nil。
func (s *Service) GetFrozenPolicy(transferID string) (*FrozenApprovalPolicy, error) {
	var out *FrozenApprovalPolicy
	found := false
	s.store.view(func(st *state) {
		t, ok := st.Transfers[transferID]
		if !ok {
			return
		}
		found = true
		if t.Policy != nil {
			p := *t.Policy
			p.RequiredRoles = append([]ContactRole(nil), t.Policy.RequiredRoles...)
			p.Contacts = append([]FrozenContact(nil), t.Policy.Contacts...)
			out = &p
		}
	})
	if !found {
		return nil, ErrTransferNotFound
	}
	return out, nil
}

// ListContactRounds 返回各轮联系人审批及其决定的完整副本（按轮次顺序）。
func (s *Service) ListContactRounds(transferID string) ([]ContactRound, error) {
	var out []ContactRound
	found := false
	s.store.view(func(st *state) {
		t, ok := st.Transfers[transferID]
		if !ok {
			return
		}
		found = true
		for _, r := range t.Rounds {
			rc := *r
			rc.Decisions = append([]ContactDecision(nil), r.Decisions...)
			out = append(out, rc)
		}
	})
	if !found {
		return nil, ErrTransferNotFound
	}
	return out, nil
}

// contactsSatisfied 报告当前轮次是否已收齐所有所需角色的同意。
func contactsSatisfied(t *Transfer, r *ContactRound) bool {
	approved := map[ContactRole]bool{}
	for _, d := range r.Decisions {
		if d.Approve {
			approved[d.Role] = true
		}
	}
	for _, role := range t.Policy.RequiredRoles {
		if !approved[role] {
			return false
		}
	}
	return true
}

// findDecision 在全部轮次中按事件号查找决定。
func findDecision(t *Transfer, eventID string) (ContactDecision, bool) {
	for _, r := range t.Rounds {
		for _, d := range r.Decisions {
			if d.EventID == eventID {
				return d, true
			}
		}
	}
	return ContactDecision{}, false
}

// newContactRound 创建一轮审批。
func newContactRound(number int, now time.Time, window time.Duration) *ContactRound {
	return &ContactRound{
		Number:    number,
		StartedAt: now,
		ExpiresAt: now.Add(window),
	}
}

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
			cp := *d
			if len(d.RequiredRoles) > 0 {
				cp.RequiredRoles = append([]ContactRole(nil), d.RequiredRoles...)
			}
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
