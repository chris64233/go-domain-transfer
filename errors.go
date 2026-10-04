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
	// ErrContactGatePending 表示联系人审批门槛尚未达成，注册商决定期限尚未开始。
	ErrContactGatePending = errors.New("domaintransfer: contact approval gate has not been satisfied")
	// ErrContactGateAlreadyPassed 表示联系人门槛已达成，无需（也不允许）再重开轮次。
	ErrContactGateAlreadyPassed = errors.New("domaintransfer: contact approval gate has already been satisfied")
	// ErrContactPolicyMissing 表示该转移未冻结任何联系人审批策略。
	ErrContactPolicyMissing = errors.New("domaintransfer: transfer has no contact approval policy")
	// ErrContactRoundActive 表示当前联系人轮次尚未超期，所有者还不能重新签发。
	ErrContactRoundActive = errors.New("domaintransfer: current contact approval round has not lapsed yet")
	// ErrContactAlreadyDecided 表示该联系人在当前轮次已提交过决定。
	ErrContactAlreadyDecided = errors.New("domaintransfer: contact has already decided in the current approval round")
	// ErrDecisionConflict 表示同一决定事件号已被不同内容占用（幂等冲突）。
	ErrDecisionConflict = errors.New("domaintransfer: decision event id already used with different content")
	// ErrDecisionRoundStale 表示决定指向已被取代的旧轮次，不得推进当前转移。
	ErrDecisionRoundStale = errors.New("domaintransfer: decision belongs to a superseded approval round")
	// ErrChangeRequestNotFound 表示联系人变更申请不存在。
	ErrChangeRequestNotFound = errors.New("domaintransfer: contact change request not found")
	// ErrChangeRequestConflict 表示同一申请号已被不同资料、域名或审批版本占用（幂等冲突）。
	ErrChangeRequestConflict = errors.New("domaintransfer: contact change request id already used with different content")
	// ErrChangeRequestNotPending 表示申请已进入终态，迟到的审批不得覆盖。
	ErrChangeRequestNotPending = errors.New("domaintransfer: contact change request is already in a terminal state")
	// ErrChangeRequestStale 表示申请基于的资料版本已失效（联系人被再次修改、域名锁定或转移完成），
	// 申请被明确作废，不可继续处理。
	ErrChangeRequestStale = errors.New("domaintransfer: contact change request is stale and has been voided")
)
