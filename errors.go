package domaintransfer

import "errors"

// 领域错误。所有错误信息都只包含非敏感标识（域名、转移号等），
// 绝不包含授权码明文或摘要。
var (
	// ErrInvalidArgument 入参非法。
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrUnauthorized 操作者无权执行该操作。
	ErrUnauthorized = errors.New("not authorized")
	// ErrRegistrarNotFound 注册商不存在。
	ErrRegistrarNotFound = errors.New("registrar not found")
	// ErrDomainNotFound 域名不存在。
	ErrDomainNotFound = errors.New("domain not found")
	// ErrAuthCodeInvalid 授权码无效（含不匹配、绑定对象不符）。
	ErrAuthCodeInvalid = errors.New("authorization code is invalid")
	// ErrAuthCodeExpired 授权码已过期。
	ErrAuthCodeExpired = errors.New("authorization code expired")
	// ErrAuthCodeUsed 授权码已被消费（一次性）。
	ErrAuthCodeUsed = errors.New("authorization code already used")
	// ErrTransferNotFound 转移单不存在。
	ErrTransferNotFound = errors.New("transfer not found")
	// ErrTransferInProgress 该域名已存在一笔进行中的转移。
	ErrTransferInProgress = errors.New("a transfer is already in progress for domain")
	// ErrTransferNotPending 转移单已离开 pending 状态，迟到操作不得覆盖终态。
	ErrTransferNotPending = errors.New("transfer is not pending")
	// ErrDeadlinePassed 已超过人工决定期限，应走超时推进。
	ErrDeadlinePassed = errors.New("decision deadline has passed")
	// ErrExternalIDConflict 同一外部转移号对应了不同的请求内容。
	ErrExternalIDConflict = errors.New("idempotency key conflicts with an existing transfer")
	// ErrInvalidState 内部不变量被破坏（理论上不应发生）。
	ErrInvalidState = errors.New("inconsistent transfer state")
)
