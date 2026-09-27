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

// Domain 是域名的当前登记信息。
type Domain struct {
	Name      string `json:"name"`
	OwnerID   string `json:"owner_id"`
	Registrar string `json:"registrar"`
	Locked    bool   `json:"locked"`
	Version   int64  `json:"version"`
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
	Deadline      time.Time      `json:"deadline"` // 原注册商决定期限
	DecidedAt     *time.Time     `json:"decided_at,omitempty"`
	DecidedBy     string         `json:"decided_by,omitempty"`
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
