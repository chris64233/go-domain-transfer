package domaintransfer

import (
	"errors"
	"fmt"
	"time"
)

// 默认参数。
const (
	// DefaultAuthCodeTTL 授权码默认有效期。
	DefaultAuthCodeTTL = 72 * time.Hour
	// DefaultDecisionTTL 转移单默认人工决定期限。
	DefaultDecisionTTL = 5 * 24 * time.Hour
	// MaxDecisionTTL 决定期限上限，避免调用方传入荒谬的值。
	MaxDecisionTTL = 30 * 24 * time.Hour
)

// Service 是域名转移应用服务，编排授权码签发、转移发起、
// 决定、取消与超时推进。所有复合写操作都在 Store 的单个事务内完成。
type Service struct {
	store  Store
	policy ExpiryPolicy
}

// NewService 创建服务。policy 为空时使用超期自动批准策略。
func NewService(store Store, policy ExpiryPolicy) *Service {
	if policy == "" {
		policy = ExpiryAutoApprove
	}
	return &Service{store: store, policy: policy}
}

// ---- 基础数据维护（测试 / 初始化用） ----

// RegisterRegistrar 登记注册商。
func (s *Service) RegisterRegistrar(r Registrar) error {
	if r.ID == "" {
		return fmt.Errorf("%w: registrar id is empty", ErrInvalidArgument)
	}
	return s.store.WriteTx(func(tx Tx) error {
		tx.AddRegistrar(r)
		return nil
	})
}

// RegisterDomain 登记域名及其当前所有者与注册商。
func (s *Service) RegisterDomain(d Domain) error {
	if d.Name == "" || d.OwnerID == "" || d.RegistrarID == "" {
		return fmt.Errorf("%w: domain name, owner and registrar are required", ErrInvalidArgument)
	}
	d.LockedByTransfer = ""
	return s.store.WriteTx(func(tx Tx) error {
		if _, ok := tx.Registrar(d.RegistrarID); !ok {
			return fmt.Errorf("%w: %s", ErrRegistrarNotFound, d.RegistrarID)
		}
		tx.AddDomain(d)
		return nil
	})
}

// ---- 授权码 ----

// IssueAuthCodeInput 签发授权码入参。
type IssueAuthCodeInput struct {
	DomainName      string
	OwnerID         string // 请求签发的所有者，必须是域名当前所有者
	TargetRegistrar string // 授权码绑定的唯一目标注册商
	TTL             time.Duration
}

// IssuedAuthCode 是签发结果。明文 Code 只在本次返回，服务端不留存。
type IssuedAuthCode struct {
	AuthCodeID string
	Code       string
	ExpiresAt  time.Time
}

// IssueAuthCode 生成一次性短期授权码。持久化的只有随机盐与摘要，
// 以及绑定的域名、目标注册商、所有者与有效期。
func (s *Service) IssueAuthCode(in IssueAuthCodeInput) (*IssuedAuthCode, error) {
	if in.DomainName == "" || in.OwnerID == "" || in.TargetRegistrar == "" {
		return nil, fmt.Errorf("%w: domain, owner and target registrar are required", ErrInvalidArgument)
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultAuthCodeTTL
	}
	if ttl < 0 {
		return nil, fmt.Errorf("%w: auth code ttl must be positive", ErrInvalidArgument)
	}

	code, err := generateAuthCode(20)
	if err != nil {
		return nil, fmt.Errorf("generate auth code: %w", err)
	}
	salt, err := generateSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	var out *IssuedAuthCode
	err = s.store.WriteTx(func(tx Tx) error {
		domain, ok := tx.Domain(in.DomainName)
		if !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotFound, in.DomainName)
		}
		if domain.OwnerID != in.OwnerID {
			// 错误中只出现域名与操作者标识，不出现任何授权码材料。
			return fmt.Errorf("%w: caller is not owner of %s", ErrUnauthorized, in.DomainName)
		}
		if _, ok := tx.Registrar(in.TargetRegistrar); !ok {
			return fmt.Errorf("%w: %s", ErrRegistrarNotFound, in.TargetRegistrar)
		}
		if domain.LockedByTransfer != "" {
			return fmt.Errorf("%w: %s", ErrTransferInProgress, in.DomainName)
		}

		now := tx.Now()
		rec := &AuthCodeRecord{
			ID:              newAuthCodeID(),
			Salt:            salt,
			Digest:          digestCode(salt, code),
			DomainName:      in.DomainName,
			TargetRegistrar: in.TargetRegistrar,
			OwnerID:         in.OwnerID,
			IssuedAt:        now,
			ExpiresAt:       now.Add(ttl),
		}
		// 直接落库（记录中只有盐与摘要，没有明文）。
		tx.PutAuthCode(rec)
		tx.AppendAudit(AuditEntry{
			At:         now,
			Actor:      in.OwnerID,
			Action:     "auth_code.issued",
			Detail:     fmt.Sprintf("domain=%s target_registrar=%s ttl=%s", in.DomainName, in.TargetRegistrar, ttl),
			TransferID: "",
		})
		out = &IssuedAuthCode{AuthCodeID: rec.ID, Code: code, ExpiresAt: rec.ExpiresAt}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---- 发起转移 ----

// StartTransferInput 发起转移入参。
type StartTransferInput struct {
	ExternalID  string // 调用方幂等键，必填
	DomainName  string
	AuthCode    string // 授权码明文，仅用于事务内比对摘要，不入库、不进日志
	ToRegistrar string
	NewOwnerID  string // 批准后域名的新所有者
	DecisionTTL time.Duration
}

// StartTransferResult 发起结果。
type StartTransferResult struct {
	TransferID     string
	Status         TransferStatus
	DecideDeadline time.Time
	// Replayed 为 true 表示这是同一 ExternalID 的幂等重放，未创建新单。
	Replayed bool
}

// StartTransfer 在单个原子事务内：校验授权码（摘要比对 + 绑定关系 +
// 有效期）、消费一次性授权码、锁定域名、创建 pending 转移单。
// ExternalID 相同时按幂等处理；同号但业务内容不同返回冲突错误。
func (s *Service) StartTransfer(in StartTransferInput) (*StartTransferResult, error) {
	if in.ExternalID == "" || in.DomainName == "" || in.AuthCode == "" ||
		in.ToRegistrar == "" || in.NewOwnerID == "" {
		return nil, fmt.Errorf("%w: external id, domain, auth code, target registrar and new owner are required", ErrInvalidArgument)
	}
	ttl := in.DecisionTTL
	if ttl == 0 {
		ttl = DefaultDecisionTTL
	}
	if ttl <= 0 || ttl > MaxDecisionTTL {
		return nil, fmt.Errorf("%w: decision ttl must be within (0, %s]", ErrInvalidArgument, MaxDecisionTTL)
	}

	var result *StartTransferResult
	err := s.store.WriteTx(func(tx Tx) error {
		now := tx.Now()

		// 幂等：ExternalID 已存在时，只允许完全相同的请求重放。
		if existing, ok := tx.TransferByExternal(in.ExternalID); ok {
			if existing.DomainName != in.DomainName ||
				existing.ToRegistrar != in.ToRegistrar ||
				existing.NewOwnerID != in.NewOwnerID {
				return fmt.Errorf("%w: external_id=%s", ErrExternalIDConflict, in.ExternalID)
			}
			result = &StartTransferResult{
				TransferID:     existing.ID,
				Status:         existing.Status,
				DecideDeadline: existing.DecideDeadline,
				Replayed:       true,
			}
			tx.AppendAudit(AuditEntry{
				At:         now,
				Actor:      existing.RequesterOwner,
				Action:     "transfer.start.replayed",
				Detail:     fmt.Sprintf("external_id=%s domain=%s", in.ExternalID, in.DomainName),
				TransferID: existing.ID,
			})
			return nil
		}

		domain, ok := tx.Domain(in.DomainName)
		if !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotFound, in.DomainName)
		}
		toReg, ok := tx.Registrar(in.ToRegistrar)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRegistrarNotFound, in.ToRegistrar)
		}
		if domain.RegistrarID == in.ToRegistrar {
			return fmt.Errorf("%w: domain %s is already at registrar %s", ErrInvalidArgument, in.DomainName, in.ToRegistrar)
		}
		if domain.LockedByTransfer != "" {
			return fmt.Errorf("%w: %s", ErrTransferInProgress, in.DomainName)
		}
		if _, active := tx.ActiveTransferForDomain(in.DomainName); active {
			// 与域名锁互为双保险。
			return fmt.Errorf("%w: %s", ErrTransferInProgress, in.DomainName)
		}
		_ = toReg

		// 在绑定到 (域名, 目标注册商) 的授权码中逐条做盐化摘要比对，
		// 匹配不到时不透露“码是否存在”的额外信息，仅区分已消费 / 过期。
		matched := s.findAuthCode(tx, in.DomainName, in.ToRegistrar, in.AuthCode)
		if matched == nil {
			return fmt.Errorf("%w: domain=%s", ErrAuthCodeInvalid, in.DomainName)
		}
		switch {
		case matched.Revoked || matched.ConsumedBy != "":
			return fmt.Errorf("%w: domain=%s", ErrAuthCodeUsed, in.DomainName)
		case !now.Before(matched.ExpiresAt):
			return fmt.Errorf("%w: domain=%s", ErrAuthCodeExpired, in.DomainName)
		}

		t := &Transfer{
			ID:             newTransferID(),
			ExternalID:     in.ExternalID,
			DomainName:     in.DomainName,
			FromRegistrar:  domain.RegistrarID,
			ToRegistrar:    in.ToRegistrar,
			RequesterOwner: domain.OwnerID,
			NewOwnerID:     in.NewOwnerID,
			AuthCodeID:     matched.ID,
			Status:         StatusPending,
			RequestedAt:    now,
			DecideDeadline: now.Add(ttl),
		}

		// 核心原子边界：消费授权码、锁域名、写转移单必须一起生效。
		tx.ConsumeAuthCode(matched.ID, t.ID, now)
		tx.LockDomain(in.DomainName, t.ID)
		tx.InsertPendingTransfer(t)
		tx.AppendAudit(AuditEntry{
			At:         now,
			Actor:      domain.OwnerID,
			Action:     "transfer.started",
			Detail:     fmt.Sprintf("external_id=%s domain=%s from=%s to=%s deadline=%s", in.ExternalID, in.DomainName, t.FromRegistrar, t.ToRegistrar, t.DecideDeadline.Format(time.RFC3339)),
			TransferID: t.ID,
		})

		result = &StartTransferResult{
			TransferID:     t.ID,
			Status:         StatusPending,
			DecideDeadline: t.DecideDeadline,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// findAuthCode 返回绑定关系与盐化摘要均匹配的授权码记录
// （不校验是否已消费 / 过期，由调用方分类）。
func (s *Service) findAuthCode(tx ReadView, domain, target, code string) *AuthCodeRecord {
	for _, c := range tx.AuthCodesForBinding(domain, target) {
		if codeMatches(c.Digest, c.Salt, code) {
			return c
		}
	}
	return nil
}

// ---- 决定 / 取消 / 超时 ----

// DecideTransfer 由原注册商对 pending 转移单作出人工决定。
// 超过决定期限后人工决定被拒绝，必须调用 AdvanceTimeout 走策略推进。
func (s *Service) DecideTransfer(transferID, registrarID string, decision Decision, reason string) (*Transfer, error) {
	if transferID == "" || registrarID == "" {
		return nil, fmt.Errorf("%w: transfer id and registrar id are required", ErrInvalidArgument)
	}
	if decision != DecisionApprove && decision != DecisionReject {
		return nil, fmt.Errorf("%w: decision must be approve or reject", ErrInvalidArgument)
	}

	var out *Transfer
	err := s.store.WriteTx(func(tx Tx) error {
		now := tx.Now()
		t, ok := tx.Transfer(transferID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrTransferNotFound, transferID)
		}
		if t.FromRegistrar != registrarID {
			return fmt.Errorf("%w: registrar %s does not own transfer %s", ErrUnauthorized, registrarID, transferID)
		}
		if t.Status != StatusPending {
			// 迟到回调不能覆盖终态。
			return fmt.Errorf("%w: transfer=%s status=%s", ErrTransferNotPending, transferID, t.Status)
		}
		if !now.Before(t.DecideDeadline) {
			return fmt.Errorf("%w: transfer=%s", ErrDeadlinePassed, transferID)
		}

		switch decision {
		case DecisionApprove:
			if err := tx.ApplyApproval(t, now, registrarID, t.NewOwnerID, false); err != nil {
				return err
			}
		case DecisionReject:
			if !tx.SetTransferTerminal(t.ID, StatusRejected, now, registrarID, reason) {
				return fmt.Errorf("%w: transfer=%s", ErrTransferNotPending, transferID)
			}
		}
		action := "transfer.approved"
		if decision == DecisionReject {
			action = "transfer.rejected"
		}
		tx.AppendAudit(AuditEntry{
			At:         now,
			Actor:      registrarID,
			Action:     action,
			Detail:     fmt.Sprintf("domain=%s reason=%q", t.DomainName, reason),
			TransferID: t.ID,
		})

		var ok2 bool
		out, ok2 = tx.Transfer(t.ID)
		if !ok2 {
			return ErrInvalidState
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CancelTransfer 由域名所有者取消 pending 转移单，并释放域名锁。
func (s *Service) CancelTransfer(transferID, ownerID, reason string) (*Transfer, error) {
	if transferID == "" || ownerID == "" {
		return nil, fmt.Errorf("%w: transfer id and owner id are required", ErrInvalidArgument)
	}
	var out *Transfer
	err := s.store.WriteTx(func(tx Tx) error {
		now := tx.Now()
		t, ok := tx.Transfer(transferID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrTransferNotFound, transferID)
		}
		if t.RequesterOwner != ownerID {
			return fmt.Errorf("%w: caller is not requester of transfer %s", ErrUnauthorized, transferID)
		}
		if t.Status != StatusPending {
			return fmt.Errorf("%w: transfer=%s status=%s", ErrTransferNotPending, transferID, t.Status)
		}
		if !tx.SetTransferTerminal(t.ID, StatusCancelled, now, ownerID, reason) {
			return fmt.Errorf("%w: transfer=%s", ErrTransferNotPending, transferID)
		}
		tx.AppendAudit(AuditEntry{
			At:         now,
			Actor:      ownerID,
			Action:     "transfer.cancelled",
			Detail:     fmt.Sprintf("domain=%s reason=%q", t.DomainName, reason),
			TransferID: t.ID,
		})
		var ok2 bool
		out, ok2 = tx.Transfer(t.ID)
		if !ok2 {
			return ErrInvalidState
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AdvanceTimeout 推进单笔已过决定期限的转移单：
//   - 未到期：直接返回当前状态，无副作用；
//   - 已终态：返回终态（迟到推进不覆盖）；
//   - 已到期且 pending：按超时策略自动批准（默认）或标记 expired。
//
// 并发调用时由事务的终态守卫保证只有一个调用方完成推进。
func (s *Service) AdvanceTimeout(transferID string) (*Transfer, error) {
	if transferID == "" {
		return nil, fmt.Errorf("%w: transfer id is required", ErrInvalidArgument)
	}
	var out *Transfer
	err := s.store.WriteTx(func(tx Tx) error {
		now := tx.Now()
		t, ok := tx.Transfer(transferID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrTransferNotFound, transferID)
		}
		if t.Status != StatusPending {
			out = t
			return nil
		}
		if now.Before(t.DecideDeadline) {
			out = t
			return nil
		}

		switch s.policy {
		case ExpiryAutoApprove, "":
			if err := tx.ApplyApproval(t, now, "system", t.NewOwnerID, true); err != nil {
				return err
			}
		case ExpiryExpire:
			if !tx.SetTransferTerminal(t.ID, StatusExpired, now, "system", "decision deadline expired") {
				return fmt.Errorf("%w: transfer=%s", ErrTransferNotPending, transferID)
			}
		default:
			return fmt.Errorf("%w: unknown expiry policy %s", ErrInvalidState, s.policy)
		}
		tx.AppendAudit(AuditEntry{
			At:         now,
			Actor:      "system",
			Action:     "transfer.timeout_advanced",
			Detail:     fmt.Sprintf("domain=%s policy=%s", t.DomainName, s.policy),
			TransferID: t.ID,
		})
		var ok2 bool
		out, ok2 = tx.Transfer(t.ID)
		if !ok2 {
			return ErrInvalidState
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SweepExpired 扫描全部 pending 转移单并推进已到期者，
// 返回被本次推进到终态的转移单。供定时任务调用。
func (s *Service) SweepExpired() ([]*Transfer, error) {
	var advanced []*Transfer
	err := s.store.WriteTx(func(tx Tx) error {
		now := tx.Now()
		for _, t := range tx.PendingTransfers() {
			if now.Before(t.DecideDeadline) {
				continue
			}
			switch s.policy {
			case ExpiryAutoApprove, "":
				if err := tx.ApplyApproval(t, now, "system", t.NewOwnerID, true); err != nil {
					if errors.Is(err, ErrTransferNotPending) {
						continue
					}
					return err
				}
			case ExpiryExpire:
				if !tx.SetTransferTerminal(t.ID, StatusExpired, now, "system", "decision deadline expired") {
					continue
				}
			}
			tx.AppendAudit(AuditEntry{
				At:         now,
				Actor:      "system",
				Action:     "transfer.timeout_advanced",
				Detail:     fmt.Sprintf("domain=%s policy=%s", t.DomainName, s.policy),
				TransferID: t.ID,
			})
			got, ok := tx.Transfer(t.ID)
			if !ok {
				return ErrInvalidState
			}
			advanced = append(advanced, got)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return advanced, nil
}

// ---- 查询 ----

// TransferView 是状态查询结果。
type TransferView struct {
	Transfer      Transfer
	OutboxEventID string // 已批准时对应的唯一 outbox 事件 ID
}

// GetTransfer 查询转移单状态。
func (s *Service) GetTransfer(transferID string) (*TransferView, error) {
	if transferID == "" {
		return nil, fmt.Errorf("%w: transfer id is required", ErrInvalidArgument)
	}
	var out *TransferView
	err := s.store.ReadTx(func(tx ReadView) error {
		t, ok := tx.Transfer(transferID)
		if !ok {
			return fmt.Errorf("%w: %s", ErrTransferNotFound, transferID)
		}
		v := &TransferView{Transfer: *t}
		if e, ok := tx.OutboxByTransfer(transferID); ok {
			v.OutboxEventID = e.EventID
		}
		out = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetDomain 返回域名当前状态（含锁标记）。
func (s *Service) GetDomain(name string) (*Domain, error) {
	var out *Domain
	err := s.store.ReadTx(func(tx ReadView) error {
		d, ok := tx.Domain(name)
		if !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotFound, name)
		}
		out = d
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuditHistory 返回审计历史（不含任何授权码明文或摘要）。
func (s *Service) AuditHistory() ([]AuditEntry, error) {
	var entries []AuditEntry
	err := s.store.ReadTx(func(tx ReadView) error {
		entries = tx.AuditEntries()
		return nil
	})
	return entries, err
}

// PendingOutbox 返回未发布的 outbox 事件，供外部投递器拉取。
func (s *Service) PendingOutbox(limit int) ([]OutboxEvent, error) {
	var events []OutboxEvent
	err := s.store.ReadTx(func(tx ReadView) error {
		events = tx.OutboxUnpublished(limit)
		return nil
	})
	return events, err
}

// MarkOutboxPublished 由外部投递器在事件成功发布到消息系统后调用。
func (s *Service) MarkOutboxPublished(eventID string) (bool, error) {
	if eventID == "" {
		return false, fmt.Errorf("%w: event id is required", ErrInvalidArgument)
	}
	var marked bool
	err := s.store.WriteTx(func(tx Tx) error {
		marked = tx.MarkOutboxPublished(eventID, tx.Now())
		return nil
	})
	return marked, err
}
