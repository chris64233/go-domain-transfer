# go-domain-transfer

域名所有权转移与注册商协作状态管理服务。实现带一次性授权码、**联系人按角色审批**、决定期限和完整状态控制的域名转移流程。

开发环境：Go 1.23.0。

## 功能概览

- **一次性授权码**：域名所有者生成短期授权码（默认上限 24h）。持久化层只保存 `SHA-256(domain || 0x00 || code)` 摘要，授权码绑定域名、目标注册商、目标所有者和有效期；明文仅通过返回值下发一次。
- **联系人与角色策略**：可为域名配置管理联系人（admin）与技术联系人（tech），以及发起转移所需的角色组合（仅 admin、仅 tech 或两者皆需），并可单独设置每轮联系人审批有效期。
- **策略冻结**：转移创建时在同一原子边界内冻结联系人快照与审批策略。之后联系人资料或域名策略发生变化，**不影响进行中的转移门槛**。
- **两阶段 pending**：
  1. `awaiting_contacts`：等待所需角色在当前轮次内全部同意。此阶段原注册商的决定期限**不起算**，注册商批准与超时自动批准都不可用。
  2. `awaiting_registrar`：联系人门槛于"最后一票"达成，原注册商决定期限（默认 5 天）自此刻起算。
  - 域名未配置联系人门槛时，发起后直接进入第二阶段，行为与无审批流程一致。
- **唯一决定事件**：联系人通过事件号（`eventID`）作出唯一决定。同事件相同内容（轮次/联系人/角色/同意与否）幂等；**同号异内容返回 `ErrContactDecisionConflict`**；决定必须匹配转移、联系人及其冻结角色。
- **拒绝即终局**：任一所需联系人明确拒绝，转移立即 `rejected`；此后其他同意、轮次重签或注册商超时规则都**不能再批准**该转移。
- **轮次重签**：当前联系人审批轮次到期（且只有所有者、只有到期后）可由所有者重新签发一轮。旧轮次及各轮决定**完整保留但不沿用**；旧轮次的迟到决定返回 `ErrStaleRound`，绝不推进当前转移；到期轮次的迟到投票返回 `ErrApprovalRoundExpired`。
- **并发单调**：联系人最后一票、所有者取消、注册商决定共享同一事务边界，并发竞争时只有一个生效；不会产生"已取消却切换所有权"或重复 outbox。
- **幂等发起**：外部转移号（`externalRef`）为幂等键——同号同内容返回既有转移单，同号异内容返回 `ErrTransferConflict`。
- **安全**：授权码明文、摘要不出现在错误信息、日志和审计记录中；持久化数据中不含任何审批凭据字段（联系人与决定只保存标识、角色与意见）；所有错误为可判定的哨兵错误（`errors.Is`）。

## 状态机

```
                initiate
                   │
        ┌──────────┴───────────┐
   无联系人门槛            有联系人门槛
        │                      │
        ▼                      ▼
 awaiting_registrar    awaiting_contacts ──任一所需联系人拒绝──▶ rejected (终态)
        ▲                      │
        │  所需角色在本轮全部同意（最后一票）
        └──────────────────────┘
        │
 awaiting_registrar ──Decide(approve)──▶ approved        (终态)
        │             ──Decide(reject)───▶ rejected        (终态)
        │             ──Cancel───────────▶ cancelled       (终态, 两阶段均可)
        │             ──timeout──────────▶ auto_approved / rejected (终态, 按策略)

 awaiting_contacts ──本轮到期──▶ 所有者 ReissueApprovalRound ──▶ 新一轮 awaiting_contacts
                              （旧轮决定保留但不沿用）
```

## API

| 方法 | 说明 |
|---|---|
| `RegisterContact(id, name, email)` | 登记联系人（不含任何凭据字段） |
| `UpdateContact(id, name, email)` | 更新联系人资料（仅影响之后冻结的策略） |
| `GetContact(id)` | 查询联系人 |
| `ConfigureDomainContacts(domain, owner, ContactConfig)` | 所有者配置管理/技术联系人、所需角色组合与每轮审批有效期 |
| `RegisterDomain(name, owner, registrar)` | 登记域名 |
| `GenerateAuthCode(domain, owner, targetRegistrar, targetOwner, ttl)` | 生成一次性授权码，返回明文（仅此一次）与过期时间 |
| `InitiateTransfer(externalRef, domain, code, actor)` | 消费授权码、锁定域名、创建转移单并**冻结联系人策略**（幂等） |
| `ContactDecide(transferID, eventID, round, contactID, role, approve, reason)` | 联系人唯一决定事件（幂等/冲突/角色匹配/轮次校验） |
| `ReissueApprovalRound(transferID, owner)` | 轮次到期后所有者重签新一轮 |
| `Decide(transferID, registrar, approve, reason)` | 原注册商在期限内批准/拒绝（门槛未达成返回 `ErrAwaitingContacts`） |
| `Cancel(transferID, actor)` | 域名所有者取消（联系人阶段亦可） |
| `AdvanceTimeouts()` | 推进**注册商阶段**超时，按策略落终态，返回处理笔数 |
| `GetTransfer(id)` / `GetTransferByRef(ref)` / `GetDomain(name)` | 状态查询（返回深拷贝） |
| `GetFrozenPolicy(transferID)` | 查询冻结的联系人审批策略快照 |
| `ListContactRounds(transferID)` | 查询各轮审批及每轮全部决定 |
| `ListAudit(domain)` / `ListOutbox()` | 完整审计历史 / outbox 消息 |

配置项：`WithContactDecisionWindow(d)` 设置每轮联系人审批默认有效期（默认 7 天）；
`ContactConfig.DecisionWindow` 可按域名覆盖。

## 架构

```
service.go   业务操作与状态机（联系人注册/配置/冻结、决定事件、轮次重签；全部并发安全）
store.go     Store：单互斥锁 + clone-and-swap 事务（含策略/轮次深拷贝）；Persister 抽象与文件实现
types.go     Contact / FrozenApprovalPolicy / ContactRound / ContactDecision / Transfer(两阶段) 等
errors.go    哨兵错误（不含敏感值）
```

**原子性设计**：`Store.transact` 在状态副本上应用变更，先持久化（`FilePersister` 用临时文件 + rename 原子写），全部成功才整体换入。任一步失败，已提交状态不受影响。

**时钟注入**：`WithClock` 可替换时钟，测试可手动推进时间验证轮次到期与注册商超时行为。

## 使用示例

```go
svc, _ := domaintransfer.NewService(
    domaintransfer.WithPersister(domaintransfer.NewFilePersister("state.json")),
    domaintransfer.WithDecisionWindow(5*24*time.Hour),
    domaintransfer.WithContactDecisionWindow(7*24*time.Hour),
)

svc.RegisterDomain("example.com", "owner-1", "reg-a")
svc.RegisterContact("c-admin", "Alice", "alice@example.com")
svc.RegisterContact("c-tech", "Bob", "bob@example.com")

// 所有者配置：本域名转移需 admin 与 tech 都同意，每轮 48 小时
svc.ConfigureDomainContacts("example.com", "owner-1", domaintransfer.ContactConfig{
    AdminContactID: "c-admin",
    TechContactID:  "c-tech",
    RequiredRoles:  []domaintransfer.ContactRole{domaintransfer.RoleAdmin, domaintransfer.RoleTech},
    DecisionWindow: 48 * time.Hour,
})

code, _, _ := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", time.Hour)
tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")
// tr.Phase == awaiting_contacts，注册商期限尚未起算

// 两位联系人凭各自唯一事件号同意；最后一票后进入 awaiting_registrar，5 天期限起算
svc.ContactDecide(tr.ID, "evt-admin-1", 1, "c-admin", domaintransfer.RoleAdmin, true, "")
svc.ContactDecide(tr.ID, "evt-tech-1", 1, "c-tech", domaintransfer.RoleTech, true, "")

svc.Decide(tr.ID, "reg-a", true, "verified")

// 若联系人长期无响应：本轮到期后所有者重签一轮（旧决定保留但不沿用）
// svc.ReissueApprovalRound(tr.ID, "owner-1")
```

## 运行测试

    go test ./... -race

测试覆盖：授权码摘要存储与一次性消费、有效期、幂等/冲突、单域名单在途；联系人策略冻结（资料/门槛变更不影响在途转移）、两阶段流转与注册商期限起算、决定事件幂等与同号异内容冲突、角色与联系人匹配校验、明确拒绝终局、轮次到期/重签/旧轮迟到决定失效、注册商超时仅在门槛达成后计算、最后一票与取消/注册商决定并发的单调终态（30 轮）、持久化往返、完整审计与敏感值不泄漏。
