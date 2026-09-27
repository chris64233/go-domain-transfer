package domaintransfer

import "time"

// TransferStatus 转移单状态。
type TransferStatus string

const (
	// StatusPending 等待原注册商决定（域名已锁定，授权码已消费）。
	StatusPending TransferStatus = "pending"
	// StatusApproved 已批准：所有权与注册商已切换，终态。
	StatusApproved TransferStatus = "approved"
	// StatusRejected 已被原注册商拒绝，终态。
	StatusRejected TransferStatus = "rejected"
	// StatusCancelled 被域名所有者取消，终态。
	StatusCancelled TransferStatus = "cancelled"
	// StatusExpired 超过决定期限后按策略处理（自动批准或标记过期），终态。
	StatusExpired TransferStatus = "expired"
)

// IsTerminal 判断状态是否为终态。
func (s TransferStatus) IsTerminal() bool {
	switch s {
	case StatusApproved, StatusRejected, StatusCancelled, StatusExpired:
		return true
	}
	return false
}

// Decision 原注册商的人工决定。
type Decision string

const (
	// DecisionApprove 批准转移。
	DecisionApprove Decision = "approve"
	// DecisionReject 拒绝转移。
	DecisionReject Decision = "reject"
)

// ExpiryPolicy 超时策略。
type ExpiryPolicy string

const (
	// ExpiryAutoApprove 超期自动批准（本包默认且题目要求的策略）。
	ExpiryAutoApprove ExpiryPolicy = "auto_approve"
	// ExpiryExpire 超期后转移单进入 expired 终态而不转移所有权。
	ExpiryExpire ExpiryPolicy = "expire"
)

// Registrar 注册商信息。
type Registrar struct {
	ID   string
	Name string
}

// Domain 域名聚合：记录当前所有者与注册商，以及转移锁。
type Domain struct {
	Name             string
	OwnerID          string
	RegistrarID      string
	LockedByTransfer string // 非空表示被某笔进行中的转移锁定
}

// AuthCodeRecord 授权码持久化记录。明文 code 与 Digest 均不落库，
// 这里只保存摘要与绑定信息。
type AuthCodeRecord struct {
	ID              string
	Digest          string // 明文授权码的高熵随机盐 + SHA-256 摘要
	Salt            string
	DomainName      string
	TargetRegistrar string
	OwnerID         string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	ConsumedBy      string // 消费该授权码的转移单号；空表示未消费
	ConsumedAt      time.Time
	Revoked         bool
}

// Available 判断授权码在时刻 now 是否仍可用于发起转移。
func (c *AuthCodeRecord) Available(now time.Time) bool {
	return !c.Revoked && c.ConsumedBy == "" && now.Before(c.ExpiresAt)
}

// Transfer 转移单聚合。
type Transfer struct {
	ID             string
	ExternalID     string // 调用方提供的幂等键
	DomainName     string
	FromRegistrar  string
	ToRegistrar    string
	RequesterOwner string // 发起时的域名所有者
	NewOwnerID     string // 批准后域名的新所有者
	AuthCodeID     string
	Status         TransferStatus
	RequestedAt    time.Time
	DecideDeadline time.Time
	DecidedAt      time.Time
	DecidedBy      string // registrar / owner / system
	DecisionReason string
}

// AuditEntry 审计历史条目。敏感值（授权码）从不写入 Detail。
type AuditEntry struct {
	At         time.Time
	TransferID string // 对授权码签发等无转移单的操作可为空
	Actor      string
	Action     string
	Detail     string
}

// OutboxEvent 事务性发件箱事件。每笔被批准（含超时自动批准）的转移
// 在其批准事务中生成且仅生成一条，由外部投递器读取发布。
type OutboxEvent struct {
	EventID       string
	OccurredAt    time.Time
	Type          string // 始终为 "domain.transfer.approved"
	TransferID    string
	ExternalID    string
	DomainName    string
	FromRegistrar string
	ToRegistrar   string
	NewOwnerID    string
	Published     bool
}
