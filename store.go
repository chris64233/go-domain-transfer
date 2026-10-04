package domaintransfer

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
)

// Persister 抽象持久化介质。Save 必须原子生效（全部写入或完全不写）。
type Persister interface {
	Save(snapshot []byte) error
	Load() ([]byte, error)
}

// FilePersister 以 JSON 快照持久化到本地文件，通过临时文件 + rename 保证原子写。
type FilePersister struct{ path string }

// NewFilePersister 创建文件持久化器。
func NewFilePersister(path string) *FilePersister { return &FilePersister{path: path} }

// Save 原子写入快照。
func (p *FilePersister) Save(data []byte) error {
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

// Load 读取快照；文件不存在时返回 nil, nil。
func (p *FilePersister) Load() ([]byte, error) {
	b, err := os.ReadFile(p.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// state 是全部可持久化状态。AuthCodes 以摘要为键。
type state struct {
	Domains         map[string]*Domain               `json:"domains"`
	AuthCodes       map[string]*AuthCodeRecord       `json:"auth_codes"`
	Transfers       map[string]*Transfer             `json:"transfers"`
	TransferByRef   map[string]string                `json:"transfer_by_ref"`   // externalRef -> transferID
	DecisionByEvent map[string]string                `json:"decision_by_event"` // contact decision eventID -> transferID（幂等/冲突）
	PendingByDomain map[string]string                `json:"pending_by_domain"`
	ChangeRequests  map[string]*ContactChangeRequest `json:"change_requests"` // 变更申请（按 ID）
	ChangeByRef     map[string]string                `json:"change_by_ref"`   // requestRef -> changeRequestID（幂等/冲突）
	Outbox          map[string]*OutboxMessage        `json:"outbox"`
	Audit           []AuditEntry                     `json:"audit"`
	Seq             int64                            `json:"seq"`
}

func newState() *state {
	return &state{
		Domains:         map[string]*Domain{},
		AuthCodes:       map[string]*AuthCodeRecord{},
		Transfers:       map[string]*Transfer{},
		TransferByRef:   map[string]string{},
		DecisionByEvent: map[string]string{},
		PendingByDomain: map[string]string{},
		ChangeRequests:  map[string]*ContactChangeRequest{},
		ChangeByRef:     map[string]string{},
		Outbox:          map[string]*OutboxMessage{},
	}
}

// clone 深拷贝整个状态，用于 clone-and-swap 事务。
func (s *state) clone() *state {
	c := &state{
		Domains:         make(map[string]*Domain, len(s.Domains)),
		AuthCodes:       make(map[string]*AuthCodeRecord, len(s.AuthCodes)),
		Transfers:       make(map[string]*Transfer, len(s.Transfers)),
		TransferByRef:   make(map[string]string, len(s.TransferByRef)),
		DecisionByEvent: make(map[string]string, len(s.DecisionByEvent)),
		PendingByDomain: make(map[string]string, len(s.PendingByDomain)),
		ChangeRequests:  make(map[string]*ContactChangeRequest, len(s.ChangeRequests)),
		ChangeByRef:     make(map[string]string, len(s.ChangeByRef)),
		Outbox:          make(map[string]*OutboxMessage, len(s.Outbox)),
		Audit:           make([]AuditEntry, len(s.Audit)),
		Seq:             s.Seq,
	}
	for k, v := range s.Domains {
		d := *v
		if v.Contacts != nil {
			d.Contacts = make(map[string]*Contact, len(v.Contacts))
			for cid, c := range v.Contacts {
				cc := *c
				d.Contacts[cid] = &cc
			}
		}
		if v.Approval != nil {
			d.Approval = clonePolicy(v.Approval)
		}
		c.Domains[k] = &d
	}
	for k, v := range s.AuthCodes {
		r := *v
		if v.ConsumedAt != nil {
			t := *v.ConsumedAt
			r.ConsumedAt = &t
		}
		c.AuthCodes[k] = &r
	}
	for k, v := range s.Transfers {
		t := *v
		if v.DecidedAt != nil {
			d := *v.DecidedAt
			t.DecidedAt = &d
		}
		if v.GatePassedAt != nil {
			g := *v.GatePassedAt
			t.GatePassedAt = &g
		}
		if v.FrozenPolicy != nil {
			t.FrozenPolicy = clonePolicy(v.FrozenPolicy)
		}
		if len(v.ContactRounds) > 0 {
			t.ContactRounds = cloneRounds(v.ContactRounds)
		}
		c.Transfers[k] = &t
	}
	for k, v := range s.TransferByRef {
		c.TransferByRef[k] = v
	}
	for k, v := range s.DecisionByEvent {
		c.DecisionByEvent[k] = v
	}
	for k, v := range s.PendingByDomain {
		c.PendingByDomain[k] = v
	}
	for k, v := range s.ChangeRequests {
		c.ChangeRequests[k] = cloneChangeRequest(v)
	}
	for k, v := range s.ChangeByRef {
		c.ChangeByRef[k] = v
	}
	for k, v := range s.Outbox {
		m := *v
		c.Outbox[k] = &m
	}
	copy(c.Audit, s.Audit)
	return c
}

// Store 持有全部状态，以单互斥锁 + clone-and-swap 提供原子事务边界：
// 事务函数在副本上修改，持久化成功后才整体换入；任何失败都不会留下中间状态。
type Store struct {
	mu        sync.Mutex
	st        *state
	persister Persister // 可为 nil（纯内存）
}

// NewStore 创建 Store；若 persister 非 nil 且已有快照则加载恢复。
func NewStore(persister Persister) (*Store, error) {
	st := newState()
	if persister != nil {
		data, err := persister.Load()
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, st); err != nil {
				return nil, err
			}
		}
	}
	return &Store{st: st, persister: persister}, nil
}

// transact 在原子边界内执行 fn：先在状态副本上应用变更，再持久化，
// 全部成功才提交换入；任一步失败，已提交状态不受影响。
func (s *Store) transact(fn func(st *state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.st.clone()
	if err := fn(next); err != nil {
		return err
	}
	if s.persister != nil {
		data, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if err := s.persister.Save(data); err != nil {
			return err
		}
	}
	s.st = next
	return nil
}

// view 在锁内执行只读函数。实现方必须返回拷贝，不得泄露内部指针。
func (s *Store) view(fn func(st *state)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.st)
}

// viewErr 在锁内执行可返回错误的只读函数。实现方必须返回拷贝，不得泄露内部指针。
func (s *Store) viewErr(fn func(st *state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.st)
}

// snapshotJSON 导出当前状态快照（测试与调试用途）。
func (s *Store) snapshotJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.st)
}

// clonePolicy 深拷贝审批策略及其冻结的联系人快照。
func clonePolicy(p *ApprovalPolicy) *ApprovalPolicy {
	if p == nil {
		return nil
	}
	c := &ApprovalPolicy{
		RoundLapse: p.RoundLapse,
		RequireAll: p.RequireAll,
	}
	if len(p.RequiredRoles) > 0 {
		c.RequiredRoles = append([]ContactRole(nil), p.RequiredRoles...)
	}
	if len(p.Contacts) > 0 {
		c.Contacts = make([]Contact, len(p.Contacts))
		copy(c.Contacts, p.Contacts)
	}
	return c
}

// cloneRounds 深拷贝各轮审批及其决定。
func cloneRounds(rounds []ContactRound) []ContactRound {
	out := make([]ContactRound, len(rounds))
	for i := range rounds {
		out[i].Number = rounds[i].Number
		out[i].StartedAt = rounds[i].StartedAt
		out[i].LapsesAt = rounds[i].LapsesAt
		out[i].GatePassed = rounds[i].GatePassed
		if len(rounds[i].Decisions) > 0 {
			out[i].Decisions = make([]ContactDecision, len(rounds[i].Decisions))
			copy(out[i].Decisions, rounds[i].Decisions)
		}
	}
	return out
}

// cloneTransfer 深拷贝转移单（含冻结策略与各轮决定），避免泄露内部指针。
func cloneTransfer(t *Transfer) *Transfer {
	cp := *t
	if t.DecidedAt != nil {
		d := *t.DecidedAt
		cp.DecidedAt = &d
	}
	if t.GatePassedAt != nil {
		g := *t.GatePassedAt
		cp.GatePassedAt = &g
	}
	if t.FrozenPolicy != nil {
		cp.FrozenPolicy = clonePolicy(t.FrozenPolicy)
	}
	if len(t.ContactRounds) > 0 {
		cp.ContactRounds = cloneRounds(t.ContactRounds)
	}
	return &cp
}

// cloneDomain 深拷贝域名当前资料（含联系人和实时策略）。
func cloneDomain(d *Domain) *Domain {
	cp := *d
	if d.Contacts != nil {
		cp.Contacts = make(map[string]*Contact, len(d.Contacts))
		for k, c := range d.Contacts {
			cc := *c
			cp.Contacts[k] = &cc
		}
	}
	if d.Approval != nil {
		cp.Approval = clonePolicy(d.Approval)
	}
	return &cp
}

// cloneChangeRequest 深拷贝联系人变更申请（含冻结的联系人快照），避免泄露内部指针。
func cloneChangeRequest(r *ContactChangeRequest) *ContactChangeRequest {
	cp := *r
	if r.DecidedAt != nil {
		d := *r.DecidedAt
		cp.DecidedAt = &d
	}
	if len(r.Contacts) > 0 {
		cp.Contacts = make([]Contact, len(r.Contacts))
		copy(cp.Contacts, r.Contacts)
	}
	if len(r.RequiredRoles) > 0 {
		cp.RequiredRoles = append([]ContactRole(nil), r.RequiredRoles...)
	}
	return &cp
}
