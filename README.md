# go-domain-transfer

域名所有权转移与注册商协作状态管理服务。实现带一次性授权码、**联系人审批门禁**、决定期限和完整状态控制的域名转移流程。

开发环境：Go 1.23.0。

## 功能概览

- **一次性授权码**：域名所有者生成短期授权码（默认上限 24h）。持久化层只保存 `SHA-256(domain || 0x00 || code)` 摘要，授权码绑定域名、目标注册商、目标所有者和有效期；明文仅通过返回值下发一次。
- **联系人与审批策略**：域名可配置管理联系人（admin）和技术联系人（tech），各自持有独立审批凭据（仅存 `SHA-256(contactID || 0x00 || credential)` 摘要）；可指定发起转移所需的角色组合（全部同意 `require_all` 或任一同意 `require_any`）以及单轮联系人无响应期限。
- **转移发起即冻结**：目标注册商凭授权码发起时，在**同一原子边界内**校验消费授权码 → 锁定域名 → 创建转移单，并**深拷贝冻结**当时的联系人与审批策略。此后域名联系人资料如何变化（含转移进行中轮换凭据），都不会改变在途转移的门槛。一个域名同时至多一笔进行中的转移。
- **联系人审批门禁**：只有所需角色的联系人门槛达成后，原注册商的批准期限或自动批准期限**才开始计算**（`Transfer.Deadline` 在门槛达成前为零值）。任一所需角色联系人明确拒绝，转移立即终态拒绝，且不会再被其他同意或超时规则批准。
- **联系人决定事件**：每票是唯一事件（`eventID`），必须匹配转移、轮次、联系人及其冻结角色与凭据摘要。相同事件相同内容幂等，同号异内容返回 `ErrDecisionConflict`；同一联系人在同一轮只能投一票。
- **多轮审批**：联系人长期无响应时，所有者可在单轮期限超期后重新签发一轮。新一轮保留旧轮决定用于审计但**不沿用**；指向旧轮的迟到决定返回 `ErrDecisionRoundStale`，不得推进当前转移。
- **幂等发起**：外部转移号（`externalRef`）为幂等键——同号同内容返回既有转移单，同号异内容返回 `ErrTransferConflict`。
- **注册商决定与超时**：门禁通过后，原注册商可在决定期限内（默认 5 天，自门禁通过时起算）批准或拒绝；超期由 `AdvanceTimeouts` 按策略落终态（默认自动批准，可配置自动拒绝）。门禁未通过时超时绝不触发。
- **终态唯一**：联系人最后一票、所有者取消、注册商决定、超时推进共享同一事务边界，并发竞争时只有一个生效；终态不可逆，迟到回调返回 `ErrTransferNotPending`，不得覆盖。
- **批准原子性**：批准在同一事务内切换域名所有权与注册商、解锁域名并生成唯一 outbox 消息；任何失败（含持久化失败）都不会留下"域名已锁定但转移没记录"或"已取消却已切换所有权"的中间状态。
- **安全**：授权码与联系人凭据的明文绝不出现在持久化数据、错误信息、日志和审计记录中（只保存绑定主体的 SHA-256 摘要）；所有错误为可判定的哨兵错误（`errors.Is`）。

## 状态机

```
                                  initiate
                                     │
                                     ▼
                         pending（联系人门禁中）
              ContactDecision(所需角色满足) │ ContactDecision(reject)
                                     ▼       └──────────────▶ rejected (终态)
                         pending（注册商决定中, 期限自门禁通过起算）
              ┌──────────────┬──────────────┬──────────────────────┐
       Decide(approve)  Decide(reject)    Cancel                timeout
              ▼               ▼                ▼                    ▼
         approved        rejected        cancelled        auto_approved / rejected
         (终态)           (终态)           (终态)           (终态, 按策略)

   门禁中超期 → 所有者 ReissueContactRound 重开一轮（旧轮保留可审计，不沿用）
```

## API

| 方法 | 说明 |
|---|---|
| `RegisterDomain(name, owner, registrar)` | 登记域名 |
| `ConfigureContacts(domain, owner, contacts, requiredRoles, requireAll, roundLapse)` | 所有者配置管理/技术联系人、所需角色组合与单轮期限（转移进行中也可改当前资料，不影响已冻结转移） |
| `GenerateAuthCode(domain, owner, targetRegistrar, targetOwner, ttl)` | 生成一次性授权码，返回明文（仅此一次）与过期时间 |
| `InitiateTransfer(externalRef, domain, code, actor)` | 消费授权码、锁定域名、冻结联系人策略、创建转移单（幂等） |
| `SubmitContactDecision(transferID, eventID, round, contactID, credential, approve, reason)` | 联系人提交某一轮的唯一决定事件（幂等/冲突/旧轮拒绝） |
| `ReissueContactRound(transferID, owner)` | 单轮超期后所有者重新签发一轮审批 |
| `Decide(transferID, registrar, approve, reason)` | 门禁通过后原注册商在期限内批准/拒绝 |
| `Cancel(transferID, actor)` | 域名所有者取消 |
| `AdvanceTimeouts()` | 门禁通过且超期后按策略落终态，返回处理笔数 |
| `GetTransfer(id)` / `GetTransferByRef(ref)` / `GetDomain(name)` | 状态查询（含冻结策略、各轮、门禁时间与注册商期限） |
| `GetApprovalPolicy(transferID)` / `ListContactRounds(transferID)` | 冻结策略 / 各轮联系人决定查询 |
| `ListAudit(domain)` / `ListOutbox()` | 完整审计历史 / outbox 消息 |

## 架构

```
service.go    业务操作与状态机（全部并发安全）
store.go      Store：单互斥锁 + clone-and-swap 事务；Persister 抽象与文件实现
types.go      Domain / Contact / ApprovalPolicy / ContactRound / ContactDecision / Transfer / ...
errors.go     哨兵错误（不含敏感值）
contact_test.go 联系人门禁相关自动化测试
```

**冻结设计**：`ApprovalPolicy` 在 `InitiateTransfer` 时经 `clonePolicy` 深拷贝进 `Transfer.FrozenPolicy`，联系人凭据以摘要形式冻结；`ContactRounds` 逐轮追加，历史轮决定保留可审计。所有深拷贝在 `store.go` 的 `clone*` 辅助函数中维护。

**原子性设计**：`Store.transact` 在状态副本上应用变更，先持久化（`FilePersister` 用临时文件 + rename 原子写），全部成功才整体换入。联系人最后一票与门禁通过、注册商决定、取消、超时因此天然串行化，保证状态单调、终态唯一且 outbox 不重复。任一步失败，已提交状态不受影响。

**时钟注入**：`WithClock` 可替换时钟，测试可手动推进时间验证轮次超期与门禁后超时行为；`WithContactRoundLapse` 配置默认单轮期限（可被单域名策略覆盖）。

## 使用示例

```go
svc, _ := domaintransfer.NewService(
    domaintransfer.WithPersister(domaintransfer.NewFilePersister("state.json")),
    domaintransfer.WithDecisionWindow(5*24*time.Hour),
)

svc.RegisterDomain("example.com", "owner-1", "reg-a")

// 配置管理 + 技术联系人，要求两者都同意，单轮 48 小时无响应
svc.ConfigureContacts("example.com", "owner-1",
    []domaintransfer.ContactSpec{
        {ID: "c-admin", Role: domaintransfer.RoleAdmin, Name: "Admin",
            Email: "admin@x.com", Credential: "admin-credential"},
        {ID: "c-tech", Role: domaintransfer.RoleTech, Name: "Tech",
            Email: "tech@x.com", Credential: "tech-credential"},
    },
    []domaintransfer.ContactRole{domaintransfer.RoleAdmin, domaintransfer.RoleTech},
    true, 48*time.Hour)

// 所有者生成授权码（明文仅返回一次），目标注册商发起
code, _, _ := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", time.Hour)
tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

// 联系人分别投票（明文凭据即时转摘要，不落盘）；门槛达成时刻起注册商期限才开始
svc.SubmitContactDecision(tr.ID, "evt-admin", 1, "c-admin", "admin-credential", true, "")
svc.SubmitContactDecision(tr.ID, "evt-tech", 1, "c-tech", "tech-credential", true, "")

// 原注册商批准；或门禁通过后超期由 svc.AdvanceTimeouts() 自动批准
svc.Decide(tr.ID, "reg-a", true, "verified")
```

## 运行测试

    go test ./... -race

测试覆盖：

- 既有全部能力（授权码摘要与一次性消费、幂等/冲突、单在途、批准/拒绝/取消/超时终态、并发唯一终态、持久化往返与失败原子性）；
- 联系人策略校验与凭据仅摘要存储；
- 发起时冻结策略、门槛前注册商期限为零、注册商决定与超时被门禁阻断；
- 转移进行中轮换联系人资料不改变在途门槛；
- 联系人同意达成门槛（ALL/ANY）、明确拒绝终态且不被同意/超时翻案；
- 决定事件幂等、同号异内容冲突、同人单轮一票、旧轮迟到决定被拒；
- 超期重开一轮：旧决定保留不沿用、当前轮重新投票、门禁后不可再重签；
- 注册商期限自门禁通过时起算（而非创建时）；
- 联系人最后一票 / 所有者取消 / 注册商决定并发下状态单调、唯一终态、无重复 outbox、无"已取消却切换所有权"；
- 持久化往返后冻结策略与各轮决定完整恢复，落盘不含明文授权码或凭据；
- 完整审计轨迹与冻结策略/各轮决定查询；未配置策略的域名保持原有行为。
