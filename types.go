package domaintransfer

import "time"

// TransferStatus 是转移单的状态机取值。
type TransferStatus string

const (
	StatusPending      TransferStatus = "pending"       // 等待原注册商决定
	StatusApproved     TransferStatus = "approved"      // 人工批准（终态）
	StatusAutoApproved TransferStatus = "auto_approved" // 超时按策略自动批准（终态）
	StatusRejected     TransferStatus = "rejected"      // 人工/策略拒绝（终态）
	StatusCancelled    TransferStatus = "cancelled"     // 所有者取消（终态）
)

// Terminal 报告状态是否为终态。终态不可逆，迟到回调不得覆盖。
func (s TransferStatus) Terminal() bool { return s != StatusPending }

// ContactRole 是联系人在转移审批中承担的角色。
type ContactRole string

const (
	RoleAdmin ContactRole = "admin" // 管理联系人
	RoleTech  ContactRole = "tech"  // 技术联系人
)

// Valid 报告角色是否受支持。
func (r ContactRole) Valid() bool { return r == RoleAdmin || r == RoleTech }

// TransferPhase 是 pending 状态内部的两个阶段：先过联系人门槛，再到注册商决定。
type TransferPhase string

const (
	// PhaseContacts 等待联系人审批，注册商决定期限尚未起算。
	PhaseContacts TransferPhase = "awaiting_contacts"
	// PhaseRegistrar 联系人门槛已达成，等待原注册商决定（期限起算中）。
	PhaseRegistrar TransferPhase = "awaiting_registrar"
)

// Contact 是联系人资料。不含任何凭据字段。
type Contact struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// FrozenContact 是转移创建时冻结的联系人快照。
// 转移进行中联系人资料变更不得影响该快照。
type FrozenContact struct {
	ContactID string      `json:"contact_id"`
	Role      ContactRole `json:"role"`
	Name      string      `json:"name"`
	Email     string      `json:"email"`
}

// FrozenApprovalPolicy 是转移创建时冻结的联系人审批策略。
type FrozenApprovalPolicy struct {
	// RequiredRoles 是必须在当前轮次中同意的角色集合（已去重排序）。
	RequiredRoles []ContactRole `json:"required_roles"`
	// Contacts 按 RequiredRoles 逐一冻结的联系人快照。
	Contacts []FrozenContact `json:"contacts"`
	// ContactDecisionWindow 是每一轮联系人审批的有效期，过期后所有者可重签一轮。
	ContactDecisionWindow time.Duration `json:"contact_decision_window"`
}

// ContactDecision 是联系人的唯一决定事件。
// 同一 EventID 同内容幂等、异内容冲突；决定必须匹配转移、联系人及其冻结角色。
type ContactDecision struct {
	EventID   string      `json:"event_id"`
	Round     int         `json:"round"`
	ContactID string      `json:"contact_id"`
	Role      ContactRole `json:"role"`
	Approve   bool        `json:"approve"`
	Reason    string      `json:"reason,omitempty"`
	At        time.Time   `json:"at"`
}

// ContactRound 是一轮联系人审批。旧轮次及其决定永久保留，但不参与当前门槛计算。
type ContactRound struct {
	Number    int               `json:"number"`
	StartedAt time.Time         `json:"started_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Decisions []ContactDecision `json:"decisions,omitempty"`
}

// Domain 是域名的当前登记信息。
type Domain struct {
	Name      string `json:"name"`
	OwnerID   string `json:"owner_id"`
	Registrar string `json:"registrar"`
	Locked    bool   `json:"locked"`
	Version   int64  `json:"version"`

	// 联系人审批配置（可随时变更；进行中的转移使用冻结快照，不受影响）。
	AdminContactID        string        `json:"admin_contact_id,omitempty"`
	TechContactID         string        `json:"tech_contact_id,omitempty"`
	RequiredRoles         []ContactRole `json:"required_roles,omitempty"`
	ContactDecisionWindow time.Duration `json:"contact_decision_window,omitempty"` // 0 表示用服务默认值
}

// AuthCodeRecord 是授权码的持久化记录。只保存摘要，绝不保存明文。
type AuthCodeRecord struct {
	Digest          string     `json:"digest"` // SHA-256(domain || 0x00 || code)
	Domain          string     `json:"domain"`
	TargetRegistrar string     `json:"target_registrar"`
	TargetOwnerID   string     `json:"target_owner_id"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ConsumedAt      *time.Time `json:"consumed_at,omitempty"` // 一次性：消费后不可再用
}

// Transfer 是一笔域名转移单。
type Transfer struct {
	ID            string         `json:"id"`
	ExternalRef   string         `json:"external_ref"` // 外部转移号，幂等键
	Domain        string         `json:"domain"`
	FromRegistrar string         `json:"from_registrar"`
	ToRegistrar   string         `json:"to_registrar"`
	FromOwnerID   string         `json:"from_owner_id"`
	ToOwnerID     string         `json:"to_owner_id"`
	Status        TransferStatus `json:"status"`
	// Phase 是 pending 内部阶段：联系人审批未通过前为 awaiting_contacts，
	// 通过后为 awaiting_registrar；终态时保持通过时的取值。
	Phase     TransferPhase `json:"phase"`
	Reason    string        `json:"reason,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	Deadline  time.Time     `json:"deadline"` // 原注册商决定期限；联系人门槛达成时才设置
	DecidedAt *time.Time    `json:"decided_at,omitempty"`
	DecidedBy string        `json:"decided_by,omitempty"`

	// 联系人审批：创建时冻结，之后不再受域名配置变更影响。
	Policy *FrozenApprovalPolicy `json:"policy,omitempty"`
	Rounds []*ContactRound       `json:"rounds,omitempty"`
	// ContactsSatisfiedAt 记录联系人门槛达成时刻（即注册商期限起算时刻）。
	ContactsSatisfiedAt *time.Time `json:"contacts_satisfied_at,omitempty"`
}

// CurrentRound 返回当前联系人审批轮次；无联系人策略时返回 nil。
func (t *Transfer) CurrentRound() *ContactRound {
	if len(t.Rounds) == 0 {
		return nil
	}
	return t.Rounds[len(t.Rounds)-1]
}

// OutboxMessage 是状态终局时生成的唯一外发消息（outbox 模式），
// 与状态变更处于同一原子边界内。
type OutboxMessage struct {
	ID         string    `json:"id"`
	TransferID string    `json:"transfer_id"`
	Domain     string    `json:"domain"`
	Type       string    `json:"type"` // transfer.approved / transfer.rejected / ...
	CreatedAt  time.Time `json:"created_at"`
}

// AuditEntry 是一条审计记录。不得包含授权码明文或摘要以外的敏感值。
type AuditEntry struct {
	Seq        int64     `json:"seq"`
	Time       time.Time `json:"time"`
	Action     string    `json:"action"`
	Domain     string    `json:"domain"`
	TransferID string    `json:"transfer_id,omitempty"`
	Actor      string    `json:"actor"`
	Detail     string    `json:"detail,omitempty"`
}
