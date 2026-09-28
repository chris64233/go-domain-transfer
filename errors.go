package domaintransfer

import "errors"

// 服务返回的全部哨兵错误。错误信息中绝不包含授权码明文、摘要等敏感值。
var (
	// ErrInvalidInput 表示请求参数缺失或不合法。
	ErrInvalidInput = errors.New("domaintransfer: invalid input")
	// ErrDomainNotFound 表示域名不存在。
	ErrDomainNotFound = errors.New("domaintransfer: domain not found")
	// ErrDomainExists 表示域名已注册。
	ErrDomainExists = errors.New("domaintransfer: domain already exists")
	// ErrDomainLocked 表示域名被进行中的转移锁定。
	ErrDomainLocked = errors.New("domaintransfer: domain is locked by an in-flight transfer")
	// ErrNotDomainOwner 表示调用者不是域名所有者。
	ErrNotDomainOwner = errors.New("domaintransfer: caller is not the domain owner")
	// ErrAuthCodeInvalid 表示授权码不存在或与域名不匹配。
	ErrAuthCodeInvalid = errors.New("domaintransfer: authorization code is invalid")
	// ErrAuthCodeExpired 表示授权码已过有效期。
	ErrAuthCodeExpired = errors.New("domaintransfer: authorization code has expired")
	// ErrAuthCodeConsumed 表示授权码已被消费（一次性）。
	ErrAuthCodeConsumed = errors.New("domaintransfer: authorization code has already been used")
	// ErrTransferNotFound 表示转移单不存在。
	ErrTransferNotFound = errors.New("domaintransfer: transfer not found")
	// ErrTransferConflict 表示外部转移号已被不同内容的请求占用（幂等冲突）。
	ErrTransferConflict = errors.New("domaintransfer: external reference already used with different content")
	// ErrTransferInFlight 表示该域名已有一笔进行中的转移。
	ErrTransferInFlight = errors.New("domaintransfer: domain already has an in-flight transfer")
	// ErrTransferNotPending 表示转移已进入终态，迟到回调不得覆盖。
	ErrTransferNotPending = errors.New("domaintransfer: transfer is already in a terminal state")
	// ErrDecisionWindowLapsed 表示人工决定期限已过，需由超时推进按策略处理。
	ErrDecisionWindowLapsed = errors.New("domaintransfer: decision window has lapsed; awaiting timeout processing")
	// ErrForbidden 表示调用者无权执行该操作。
	ErrForbidden = errors.New("domaintransfer: caller is not allowed to perform this action")
	// ErrContactNotFound 表示联系人不存在。
	ErrContactNotFound = errors.New("domaintransfer: contact not found")
	// ErrContactExists 表示联系人 ID 已存在。
	ErrContactExists = errors.New("domaintransfer: contact already exists")
	// ErrContactRoleMismatch 表示决定中的联系人/角色与冻结策略不匹配。
	ErrContactRoleMismatch = errors.New("domaintransfer: contact or role does not match the frozen policy")
	// ErrContactNotRequired 表示该角色不在转移所需角色组合内。
	ErrContactNotRequired = errors.New("domaintransfer: contact role is not required by this transfer")
	// ErrContactDecisionConflict 表示同一事件号携带了不同内容。
	ErrContactDecisionConflict = errors.New("domaintransfer: decision event id reused with different content")
	// ErrStaleRound 表示决定属于旧轮次，旧轮次迟到决定不得推进当前转移。
	ErrStaleRound = errors.New("domaintransfer: decision belongs to a superseded approval round")
	// ErrRoundNotExpired 表示联系人审批轮次尚未到期，不能重签。
	ErrRoundNotExpired = errors.New("domaintransfer: current contact approval round has not expired yet")
	// ErrAwaitingContacts 表示联系人门槛尚未达成，注册商决定期限尚未起算。
	ErrAwaitingContacts = errors.New("domaintransfer: contact approval threshold not yet satisfied")
	// ErrContactApprovalClosed 表示联系人审批阶段已关闭（门槛已达成或转移已终态），不再接受决定。
	ErrContactApprovalClosed = errors.New("domaintransfer: contact approval phase is closed")
	// ErrContactAlreadyDecided 表示该角色在本轮已经作出过决定。
	ErrContactAlreadyDecided = errors.New("domaintransfer: contact has already decided in this round")
	// ErrApprovalRoundExpired 表示当前联系人审批轮次已到期，迟到决定不计入，需所有者重签一轮。
	ErrApprovalRoundExpired = errors.New("domaintransfer: contact approval round has expired; await a new round")
)
