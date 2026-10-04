package domaintransfer

import (
	"fmt"
	"sort"
	"time"
)

// SubmitContactChange 提交一笔联系人变更申请。
// baseVersion 是申请人提交时看到的域名资料版本（乐观并发控制）；
// 与域名当前版本不一致时返回 ErrChangeRequestStale，申请不会创建。
// 申请在同一原子边界内冻结：目标域名、申请人、资料版本以及联系人资料快照
// （凭据仅存摘要）。申请创建后，域名当前联系人如何修改，都不会改变这笔
// 待审批申请的内容。
// 申请号（requestID）为幂等键：同号同内容返回既有申请，同号异内容
// （资料、域名或审批版本不同）返回 ErrChangeRequestConflict。
func (s *Service) SubmitContactChange(requestID, domain, requesterID string, baseVersion int64, contacts []ContactSpec) (*ContactChangeRequest, error) {
	if requestID == "" || domain == "" || requesterID == "" || baseVersion <= 0 {
		return nil, fmt.Errorf("%w: request id, domain, requester and positive base version are required", ErrInvalidInput)
	}
	if len(contacts) == 0 {
		return nil, fmt.Errorf("%w: at least one contact is required", ErrInvalidInput)
	}
	now := s.now()
	newContacts, err := normalizeContactSpecs(contacts, now)
	if err != nil {
		return nil, err
	}
	var result *ContactChangeRequest
	err = s.store.transact(func(st *state) error {
		// 幂等：申请号已存在时按内容判重（含资料版本），优先于域名状态校验。
		if existing, ok := st.ChangeRequests[requestID]; ok {
			if existing.Domain == domain && existing.RequesterID == requesterID &&
				existing.BaseVersion == baseVersion && snapshotEqual(existing.Snapshot, snapshotOf(newContacts)) {
				result = cloneChangeRequest(existing)
				return nil
			}
			return ErrChangeRequestConflict
		}
		d, ok := st.Domains[domain]
		if !ok {
			return ErrDomainNotFound
		}
		if d.Locked {
			// 域名锁定期间创建的申请不可能被批准，直接拒绝。
			return ErrDomainLocked
		}
		// 版本一致性：申请人必须基于域名当前资料版本提交。
		if d.Version != baseVersion {
			return ErrChangeRequestStale
		}
		// 新资料必须覆盖现有审批策略所需的角色，否则批准后策略将不可满足。
		if d.Approval != nil {
			roleCovered := map[ContactRole]bool{}
			for _, c := range newContacts {
				roleCovered[c.Role] = true
			}
			for _, r := range d.Approval.RequiredRoles {
				if !roleCovered[r] {
					return fmt.Errorf("%w: no contact configured for required role %q", ErrInvalidInput, r)
				}
			}
		}
		snapshot := snapshotOf(newContacts)

		r := &ContactChangeRequest{
			ID:          requestID,
			Domain:      domain,
			RequesterID: requesterID,
			BaseVersion: baseVersion,
			Snapshot:    snapshot,
			Status:      ChangePending,
			CreatedAt:   now,
		}
		st.ChangeRequests[r.ID] = r
		appendAudit(st, now, "contact_change_submitted", domain, "", requesterID,
			fmt.Sprintf("request=%s base_version=%d contacts=%d", r.ID, r.BaseVersion, len(snapshot)))
		result = cloneChangeRequest(r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DecideContactChange 由域名所有者审批一笔联系人变更申请。
// 审批只能作用于当前未完成且版本一致的申请：转移完成、域名锁定或联系人
// 再次修改都会使申请明确作废（ChangeVoided），此时返回 ErrChangeRequestStale，
// 迟到的旧审批不得回写。审批通过与联系人写入处于同一原子边界：
// 任何一步失败（含持久化失败），审批结果与域名资料都不会只更新一边。
func (s *Service) DecideContactChange(requestID, approver string, approve bool, reason string) (*ContactChangeRequest, error) {
	if requestID == "" || approver == "" {
		return nil, fmt.Errorf("%w: request id and approver are required", ErrInvalidInput)
	}
	now := s.now()
	var result *ContactChangeRequest
	var stale bool
	err := s.store.transact(func(st *state) error {
		r, ok := st.ChangeRequests[requestID]
		if !ok {
			return ErrChangeRequestNotFound
		}
		d, ok := st.Domains[r.Domain]
		if !ok {
			return ErrDomainNotFound
		}
		if approver != d.OwnerID {
			return ErrForbidden
		}
		if r.Status.Terminal() {
			return ErrChangeRequestNotPending
		}
		// 版本一致性：域名锁定（转移在途）或资料版本已前进时，
		// 旧申请明确作废（作废标记随事务提交），不得继续处理。
		if d.Locked || d.Version != r.BaseVersion {
			voidChangeLocked(st, r, now, "base version stale or domain locked")
			stale = true
			return nil
		}

		r.DecidedAt = &now
		r.DecidedBy = approver
		r.Reason = reason
		if !approve {
			r.Status = ChangeRejected
			appendAudit(st, now, "contact_change_rejected", r.Domain, "", approver, "request="+r.ID)
			result = cloneChangeRequest(r)
			return nil
		}

		// 审批通过与写入域名当前资料在同一事务边界内：任一失败整体回滚。
		contacts := make(map[string]*Contact, len(r.Snapshot))
		for i := range r.Snapshot {
			c := r.Snapshot[i]
			contacts[c.ID] = &c
		}
		d.Contacts = contacts
		if d.Approval != nil {
			d.Approval.Contacts = append([]Contact(nil), r.Snapshot...)
		}
		d.Version++
		r.Status = ChangeApproved
		appendAudit(st, now, "contact_change_approved", r.Domain, "", approver,
			fmt.Sprintf("request=%s new_version=%d", r.ID, d.Version))
		result = cloneChangeRequest(r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if stale {
		return nil, ErrChangeRequestStale
	}
	return result, nil
}

// GetContactChange 按申请号查询联系人变更申请。
func (s *Service) GetContactChange(requestID string) (*ContactChangeRequest, error) {
	var out *ContactChangeRequest
	s.store.view(func(st *state) {
		if r, ok := st.ChangeRequests[requestID]; ok {
			out = cloneChangeRequest(r)
		}
	})
	if out == nil {
		return nil, ErrChangeRequestNotFound
	}
	return out, nil
}

// ListContactChanges 返回指定域名的全部变更申请（按创建时间排序）。
func (s *Service) ListContactChanges(domain string) []ContactChangeRequest {
	var out []ContactChangeRequest
	s.store.view(func(st *state) {
		for _, r := range st.ChangeRequests {
			if r.Domain == domain {
				out = append(out, *cloneChangeRequest(r))
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// voidPendingChangesLocked 在事务内将指定域名的全部待审批变更申请明确作废。
// 触发点：域名被转移锁定、转移完成、联系人资料被再次修改。
func voidPendingChangesLocked(st *state, domain string, now time.Time, reason string) {
	for _, r := range st.ChangeRequests {
		if r.Domain == domain && r.Status == ChangePending {
			voidChangeLocked(st, r, now, reason)
		}
	}
}

// voidChangeLocked 在事务内作废单笔申请。调用方必须确认申请处于 pending。
func voidChangeLocked(st *state, r *ContactChangeRequest, now time.Time, reason string) {
	r.Status = ChangeVoided
	r.Reason = reason
	r.DecidedAt = &now
	appendAudit(st, now, "contact_change_voided", r.Domain, "", "system",
		fmt.Sprintf("request=%s reason=%s", r.ID, reason))
}

// snapshotEqual 报告两份联系人快照内容是否一致（按 ID 排序后逐字段比较，含凭据摘要）。
func snapshotEqual(a, b []Contact) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]Contact(nil), a...)
	bs := append([]Contact(nil), b...)
	sort.Slice(as, func(i, j int) bool { return as[i].ID < as[j].ID })
	sort.Slice(bs, func(i, j int) bool { return bs[i].ID < bs[j].ID })
	for i := range as {
		if as[i].ID != bs[i].ID || as[i].Role != bs[i].Role ||
			as[i].Name != bs[i].Name || as[i].Email != bs[i].Email ||
			as[i].CredentialHash != bs[i].CredentialHash {
			return false
		}
	}
	return true
}

// snapshotOf 将规范化联系人表转为稳定排序的快照（值拷贝）。
func snapshotOf(contacts map[string]*Contact) []Contact {
	snapshot := make([]Contact, 0, len(contacts))
	for _, c := range contacts {
		snapshot = append(snapshot, *c)
	}
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].ID < snapshot[j].ID })
	return snapshot
}
