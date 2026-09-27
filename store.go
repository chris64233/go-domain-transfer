package domaintransfer

import (
	"sync"
	"time"
)

// Store 是领域状态的持久化抽象。生产环境可以由数据库实现，
// 所有多实体写操作必须在单个数据库事务内完成。
type Store interface {
	// ReadTx 在一致性读视图上执行只读操作。
	ReadTx(func(tx ReadView) error) error
	// WriteTx 在单个原子事务内执行读改写。fn 返回错误时事务整体回滚，
	// 不得留下任何部分写入。
	WriteTx(fn func(tx Tx) error) error
}

// ReadView 暴露事务内的只读查询。
type ReadView interface {
	Registrar(id string) (Registrar, bool)
	Domain(name string) (*Domain, bool)
	AuthCodeByDigest(digest string) (*AuthCodeRecord, bool)
	AuthCode(id string) (*AuthCodeRecord, bool)
	// AuthCodesForBinding 返回绑定到指定域名与目标注册商的全部授权码记录，
	// 用于在只持有明文时逐条加盐验证摘要。
	AuthCodesForBinding(domainName, targetRegistrar string) []*AuthCodeRecord
	Transfer(id string) (*Transfer, bool)
	TransferByExternal(externalID string) (*Transfer, bool)
	ActiveTransferForDomain(domain string) (*Transfer, bool)
	OutboxByTransfer(transferID string) (*OutboxEvent, bool)
	AuditEntries() []AuditEntry
	OutboxUnpublished(limit int) []OutboxEvent
}

// Tx 在 ReadView 之上提供事务内变更与时间访问。
type Tx interface {
	ReadView

	// Now 返回事务使用的逻辑时钟。
	Now() time.Time

	AddRegistrar(r Registrar)
	AddDomain(d Domain)

	// PutAuthCode 持久化授权码记录（仅含盐与摘要，不含明文）。
	PutAuthCode(c *AuthCodeRecord)

	// PendingTransfers 返回全部进行中的转移单。
	PendingTransfers() []*Transfer

	ConsumeAuthCode(id, transferID string, at time.Time)
	RevokeAuthCode(id string)

	// InsertPendingTransfer 创建转移单。要求调用方已验证：
	// 域名无进行中转移、externalID 未占用。
	InsertPendingTransfer(t *Transfer)
	// LockDomain 将域名锁定到指定转移单。
	LockDomain(name, transferID string)
	// UnlockDomain 解除域名锁定。
	UnlockDomain(name string)

	// SetTransferTerminal 仅当转移单当前为 pending 时，将其原子地
	// 切换到终态；返回 false 表示它已被并发操作推进，调用方必须放弃。
	SetTransferTerminal(id string, status TransferStatus, at time.Time, actor, reason string) bool

	// ApplyApproval 与 SetTransferTerminal(approved) 在同一事务内
	// 一起完成：转移单终态化、域名解锁并切换所有者与注册商、写入唯一
	// outbox。任何一步失败整体回滚。
	ApplyApproval(t *Transfer, at time.Time, actor string, newOwnerID string, auto bool) error

	AppendAudit(e AuditEntry)

	// MarkOutboxPublished 将指定 outbox 事件标记为已发布。
	MarkOutboxPublished(eventID string, at time.Time) bool
}

// MemoryStore 是 Store 的内存实现，主要用于测试与示例。
// 一把全局锁将所有 WriteTx 串行化，等价于可序列化隔离级别：
// 这保证了“消费授权码 + 锁定域名 + 写入转移单”等复合操作的原子性，
// 以及并发决定 / 取消 / 超时推进时只有一个能落入终态。
type MemoryStore struct {
	mu sync.Mutex

	now        func() time.Time
	registrars map[string]Registrar
	domains    map[string]*Domain
	authCodes  map[string]*AuthCodeRecord // key: id
	byDigest   map[string]string          // digest -> id
	transfers  map[string]*Transfer
	byExternal map[string]string       // externalID -> transferID
	outbox     map[string]*OutboxEvent // key: transferID
	outboxIDs  []string
	audit      []AuditEntry
}

// MemoryStoreOption 配置 MemoryStore。
type MemoryStoreOption func(*MemoryStore)

// WithClock 注入逻辑时钟（测试用）。
func WithClock(clock func() time.Time) MemoryStoreOption {
	return func(s *MemoryStore) { s.now = clock }
}

// NewMemoryStore 创建内存存储。
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{
		now:        time.Now,
		registrars: make(map[string]Registrar),
		domains:    make(map[string]*Domain),
		authCodes:  make(map[string]*AuthCodeRecord),
		byDigest:   make(map[string]string),
		transfers:  make(map[string]*Transfer),
		byExternal: make(map[string]string),
		outbox:     make(map[string]*OutboxEvent),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// clone 必须在持锁状态下调用，生成深拷贝快照供事务外读取，
// 避免调用方拿到可变内部指针。
func (s *MemoryStore) snapshot() *memView {
	v := &memView{
		registrars: make(map[string]Registrar, len(s.registrars)),
		domains:    make(map[string]*Domain, len(s.domains)),
		authCodes:  make(map[string]*AuthCodeRecord, len(s.authCodes)),
		byDigest:   make(map[string]string, len(s.byDigest)),
		transfers:  make(map[string]*Transfer, len(s.transfers)),
		byExternal: make(map[string]string, len(s.byExternal)),
		outbox:     make(map[string]*OutboxEvent, len(s.outbox)),
		audit:      make([]AuditEntry, len(s.audit)),
		outboxIDs:  append([]string(nil), s.outboxIDs...),
	}
	for k, val := range s.registrars {
		v.registrars[k] = val
	}
	for k, val := range s.domains {
		cp := *val
		v.domains[k] = &cp
	}
	for k, val := range s.authCodes {
		cp := *val
		v.authCodes[k] = &cp
	}
	for k, val := range s.byDigest {
		v.byDigest[k] = val
	}
	for k, val := range s.transfers {
		cp := *val
		v.transfers[k] = &cp
	}
	for k, val := range s.byExternal {
		v.byExternal[k] = val
	}
	for k, val := range s.outbox {
		cp := *val
		v.outbox[k] = &cp
	}
	copy(v.audit, s.audit)
	return v
}

// memView 是 MemoryStore 在单个事务期间的可写深拷贝。
// 事务正常结束时整体提交回主存储；出错则丢弃，实现回滚。
type memView struct {
	registrars map[string]Registrar
	domains    map[string]*Domain
	authCodes  map[string]*AuthCodeRecord
	byDigest   map[string]string
	transfers  map[string]*Transfer
	byExternal map[string]string
	outbox     map[string]*OutboxEvent
	outboxIDs  []string
	audit      []AuditEntry
}

type readTxImpl struct{ v *memView }
type writeTxImpl struct {
	readTxImpl
	now func() time.Time
}

// ReadTx 执行只读事务。
func (s *MemoryStore) ReadTx(fn func(tx ReadView) error) error {
	s.mu.Lock()
	view := s.snapshot()
	s.mu.Unlock()
	return fn(readTxImpl{v: view})
}

// WriteTx 在全局锁内对深拷贝执行变更；fn 成功才提交。
func (s *MemoryStore) WriteTx(fn func(tx Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	view := s.snapshot()
	tx := writeTxImpl{readTxImpl: readTxImpl{v: view}, now: s.now}
	if err := fn(tx); err != nil {
		return err // 丢弃 view，等价于回滚
	}
	s.commit(view)
	return nil
}

// commit 将事务视图合并回主存储，必须在持锁状态下调用。
func (s *MemoryStore) commit(v *memView) {
	s.registrars = v.registrars
	s.domains = v.domains
	s.authCodes = v.authCodes
	s.byDigest = v.byDigest
	s.transfers = v.transfers
	s.byExternal = v.byExternal
	s.outbox = v.outbox
	s.outboxIDs = v.outboxIDs
	s.audit = v.audit
}

// ---- ReadView ----

func (r readTxImpl) Registrar(id string) (Registrar, bool) {
	reg, ok := r.v.registrars[id]
	return reg, ok
}

func (r readTxImpl) Domain(name string) (*Domain, bool) {
	d, ok := r.v.domains[name]
	if !ok {
		return nil, false
	}
	cp := *d
	return &cp, true
}

func (r readTxImpl) AuthCodeByDigest(digest string) (*AuthCodeRecord, bool) {
	id, ok := r.v.byDigest[digest]
	if !ok {
		return nil, false
	}
	return r.AuthCode(id)
}

func (r readTxImpl) AuthCode(id string) (*AuthCodeRecord, bool) {
	c, ok := r.v.authCodes[id]
	if !ok {
		return nil, false
	}
	cp := *c
	return &cp, true
}

func (r readTxImpl) AuthCodesForBinding(domainName, targetRegistrar string) []*AuthCodeRecord {
	var out []*AuthCodeRecord
	for _, c := range r.v.authCodes {
		if c.DomainName == domainName && c.TargetRegistrar == targetRegistrar {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out
}

func (r readTxImpl) Transfer(id string) (*Transfer, bool) {
	t, ok := r.v.transfers[id]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

func (r readTxImpl) TransferByExternal(externalID string) (*Transfer, bool) {
	id, ok := r.v.byExternal[externalID]
	if !ok {
		return nil, false
	}
	return r.Transfer(id)
}

func (r readTxImpl) ActiveTransferForDomain(domain string) (*Transfer, bool) {
	// 内存实现数据量小，直接扫描；数据库实现可用唯一部分索引
	// (domain) WHERE status = 'pending' 保证“一域名至多一笔进行中转移”。
	for _, t := range r.v.transfers {
		if t.DomainName == domain && t.Status == StatusPending {
			cp := *t
			return &cp, true
		}
	}
	return nil, false
}

func (r readTxImpl) OutboxByTransfer(transferID string) (*OutboxEvent, bool) {
	e, ok := r.v.outbox[transferID]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

func (r readTxImpl) AuditEntries() []AuditEntry {
	return append([]AuditEntry(nil), r.v.audit...)
}

func (r readTxImpl) OutboxUnpublished(limit int) []OutboxEvent {
	var out []OutboxEvent
	for _, id := range r.v.outboxIDs {
		e := r.v.outbox[id]
		if e.Published {
			continue
		}
		cp := *e
		out = append(out, cp)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// ---- Tx mutations ----

func (w writeTxImpl) Now() time.Time { return w.now() }

func (w writeTxImpl) AddRegistrar(reg Registrar) { w.v.registrars[reg.ID] = reg }

func (w writeTxImpl) AddDomain(d Domain) {
	cp := d
	w.v.domains[d.Name] = &cp
}

func (w writeTxImpl) PutAuthCode(c *AuthCodeRecord) {
	cp := *c
	w.v.authCodes[c.ID] = &cp
	w.v.byDigest[c.Digest] = c.ID
}

func (w writeTxImpl) PendingTransfers() []*Transfer {
	var out []*Transfer
	for _, t := range w.v.transfers {
		if t.Status == StatusPending {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out
}

func (w writeTxImpl) ConsumeAuthCode(id, transferID string, at time.Time) {
	c, ok := w.v.authCodes[id]
	if !ok {
		return
	}
	c.ConsumedBy = transferID
	c.ConsumedAt = at
}

func (w writeTxImpl) RevokeAuthCode(id string) {
	if c, ok := w.v.authCodes[id]; ok {
		c.Revoked = true
	}
}

func (w writeTxImpl) InsertPendingTransfer(t *Transfer) {
	cp := *t
	w.v.transfers[t.ID] = &cp
	if t.ExternalID != "" {
		w.v.byExternal[t.ExternalID] = t.ID
	}
}

func (w writeTxImpl) LockDomain(name, transferID string) {
	if d, ok := w.v.domains[name]; ok {
		d.LockedByTransfer = transferID
	}
}

func (w writeTxImpl) UnlockDomain(name string) {
	if d, ok := w.v.domains[name]; ok {
		d.LockedByTransfer = ""
	}
}

func (w writeTxImpl) SetTransferTerminal(id string, status TransferStatus, at time.Time, actor, reason string) bool {
	t, ok := w.v.transfers[id]
	if !ok || t.Status != StatusPending {
		return false
	}
	t.Status = status
	t.DecidedAt = at
	t.DecidedBy = actor
	t.DecisionReason = reason
	if d, ok := w.v.domains[t.DomainName]; ok && d.LockedByTransfer == id {
		d.LockedByTransfer = ""
	}
	return true
}

func (w writeTxImpl) AppendAudit(e AuditEntry) {
	w.v.audit = append(w.v.audit, e)
}

func (w writeTxImpl) MarkOutboxPublished(eventID string, at time.Time) bool {
	for _, e := range w.v.outbox {
		if e.EventID == eventID && !e.Published {
			e.Published = true
			return true
		}
	}
	return false
}

func (w writeTxImpl) ApplyApproval(t *Transfer, at time.Time, actor string, newOwnerID string, auto bool) error {
	cur, ok := w.v.transfers[t.ID]
	if !ok {
		return ErrTransferNotFound
	}
	if cur.Status != StatusPending {
		// 迟到的批准不得覆盖终态。
		return ErrTransferNotPending
	}
	// 唯一 outbox：批准事件必须只生成一次。
	if _, exists := w.v.outbox[t.ID]; exists {
		return ErrInvalidState
	}

	// 1) 转移单终态化。
	cur.Status = StatusApproved
	cur.DecidedAt = at
	cur.DecidedBy = actor
	cur.DecisionReason = map[bool]string{true: "auto-approved after deadline", false: "approved by registrar"}[auto]
	cur.NewOwnerID = newOwnerID

	// 2) 同一事务内切换域名所有权与注册商并解锁。
	d, ok := w.v.domains[t.DomainName]
	if !ok {
		return ErrDomainNotFound
	}
	if d.LockedByTransfer != "" && d.LockedByTransfer != t.ID {
		return ErrInvalidState
	}
	d.OwnerID = newOwnerID
	d.RegistrarID = t.ToRegistrar
	d.LockedByTransfer = ""

	// 3) 写入唯一 outbox 事件。
	w.v.outbox[t.ID] = &OutboxEvent{
		EventID:       newEventID(),
		OccurredAt:    at,
		Type:          EventTransferApproved,
		TransferID:    t.ID,
		ExternalID:    t.ExternalID,
		DomainName:    t.DomainName,
		FromRegistrar: t.FromRegistrar,
		ToRegistrar:   t.ToRegistrar,
		NewOwnerID:    newOwnerID,
	}
	w.v.outboxIDs = append(w.v.outboxIDs, t.ID)
	return nil
}
