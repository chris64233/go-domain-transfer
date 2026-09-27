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
)
