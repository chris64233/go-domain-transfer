package domaintransfer

import "time"

// TransferStatus 是转移单的状态机取值。
type TransferStatus string

const (
	StatusPending      TransferStatus = "pending"       // 等待（先经联系人门槛，后等原注册商决定）
	StatusApproved     TransferStatus = "approved"      // 人工批准（终态）
	StatusAutoApproved TransferStatus = "auto_approved" // 超时按策略自动批准（终态）
	StatusRejected     TransferStatus = "rejected"      // 人工/策略拒绝（终态）
	StatusCancelled    TransferStatus = "cancelled"     // 所有者取消（终态）
)

// Terminal 报告状态是否为终态。终态不可逆，迟到回调不得覆盖。
func (s TransferStatus) Terminal() bool { return s != StatusPending }

// ContactRole 是联系人在转移审批中承担的冻结角色。
type ContactRole string

const (
	// RoleAdmin 管理联系人。
	RoleAdmin ContactRole = "admin"
	// RoleTech 技术联系人。
	RoleTech ContactRole = "tech"
)

// validRole 报告角色是否受支持。
func validRole(r ContactRole) bool { return r == RoleAdmin || r == RoleTech }

// Contact 是域名的当前联系人资料。凭据只保存摘要，绝不保存明文。
type Contact struct {
	ID              string      `json:"id"`
	Role            ContactRole `json:"role"`
	Name            string      `json:"name"`
	Email           string      `json:"email"`
	CredentialHash  string      `json:"credential_hash"` // SHA-256(contactID || 0x00 || credential)
	CredentialSetAt time.Time   `json:"credential_set_at"`
}

// ApprovalPolicy 是发起转移时冻结进转移单的联系人审批策略（值类型快照）。
// 之后域名联系人资料如何变化，都不得改变进行中转移的门槛。
type ApprovalPolicy struct {
	RequiredRoles []ContactRole `json:"required_roles"` // 发起转移所需的角色组合（去重）
	Contacts      []Contact     `json:"contacts"`       // 创建时冻结的联系人快照（含凭据摘要）
	RoundLapse    time.Duration `json:"round_lapse"`    // 单轮联系人审批无响应期限
	RequireAll    bool          `json:"require_all"`    // true=所需角色全部同意；false=任一同意
}

// ContactDecision 是某个联系人在某一轮中的唯一决定事件。
type ContactDecision struct {
	EventID        string      `json:"event_id"` // 幂等键
	ContactID      string      `json:"contact_id"`
	Role           ContactRole `json:"role"` // 冻结角色，必须与策略匹配
	Round          int         `json:"round"`
	Approve        bool        `json:"approve"`
	CredentialHash string      `json:"credential_hash"` // 与冻结快照比对，绝不保存明文
	Reason         string      `json:"reason,omitempty"`
	DecidedAt      time.Time   `json:"decided_at"`
}

// ContactRound 是一轮联系人审批。旧轮次的决定保留用于审计，但不再推进当前转移。
type ContactRound struct {
	Number     int               `json:"number"` // 从 1 起
	StartedAt  time.Time         `json:"started_at"`
	LapsesAt   time.Time         `json:"lapses_at"`
	GatePassed bool              `json:"gate_passed"` // 门槛是否在本轮达成
	Decisions  []ContactDecision `json:"decisions"`
}

// ChangeRequestStatus 是联系人变更申请的状态机取值。
type ChangeRequestStatus string

const (
	ChangePending  ChangeRequestStatus = "pending"  // 待审批
	ChangeApproved ChangeRequestStatus = "approved" // 审批通过并已写入域名当前资料（终态）
	ChangeRejected ChangeRequestStatus = "rejected" // 审批拒绝（终态）
	ChangeVoided   ChangeRequestStatus = "voided"   // 失效：版本不一致/域名锁定/转移完成，不可继续处理（终态）
)

// Terminal 报告申请状态是否为终态。终态不可逆，迟到的审批不得覆盖。
func (s ChangeRequestStatus) Terminal() bool { return s != ChangePending }

// ContactChangeRequest 是一笔联系人变更申请。
// 申请创建时深拷贝冻结当时的联系人资料快照与域名资料版本；
// 此后域名当前联系人如何修改，都不会改变待审批的内容。
type ContactChangeRequest struct {
	ID          string              `json:"id"`           // 申请号，幂等键
	Domain      string              `json:"domain"`       // 目标域名
	RequesterID string              `json:"requester_id"` // 申请人
	BaseVersion int64               `json:"base_version"` // 提交时看到的域名资料版本
	Snapshot    []Contact           `json:"snapshot"`     // 冻结的联系人资料快照（凭据仅存摘要）
	Status      ChangeRequestStatus `json:"status"`
	Reason      string              `json:"reason,omitempty"` // 审批意见或作废原因
	CreatedAt   time.Time           `json:"created_at"`
	DecidedAt   *time.Time          `json:"decided_at,omitempty"`
	DecidedBy   string              `json:"decided_by,omitempty"`
}

// Domain 是域名的当前登记信息。
type Domain struct {
	Name      string              `json:"name"`
	OwnerID   string              `json:"owner_id"`
	Registrar string              `json:"registrar"`
	Locked    bool                `json:"locked"`
	Version   int64               `json:"version"`
	Contacts  map[string]*Contact `json:"contacts"`           // 实时联系人资料（按 ID）
	Approval  *ApprovalPolicy     `json:"approval,omitempty"` // 实时审批策略（转移时冻结拷贝）
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
	Reason        string         `json:"reason,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	// FrozenPolicy 是创建时冻结的联系人审批策略；nil 表示该转移无联系人门槛（向后兼容）。
	FrozenPolicy *ApprovalPolicy `json:"frozen_policy,omitempty"`
	// ContactRounds 是各轮联系人审批（含历史轮次），当前轮为最后一个元素。
	ContactRounds []ContactRound `json:"contact_rounds,omitempty"`
	// GatePassedAt 记录联系人门槛达成时刻；为零表示门槛尚未达成。
	GatePassedAt *time.Time `json:"gate_passed_at,omitempty"`
	// Deadline 是原注册商决定期限；门槛达成前为零值，达成时才开始计算。
	Deadline  time.Time  `json:"deadline"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	DecidedBy string     `json:"decided_by,omitempty"`
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
