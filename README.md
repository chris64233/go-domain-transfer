# go-domain-transfer

域名所有权转移与注册商协作状态管理服务。实现带一次性授权码、决定期限和完整状态控制的域名转移流程。

开发环境：Go 1.23.0。

## 功能概览

- **一次性授权码**：域名所有者生成短期授权码（默认上限 24h）。持久化层只保存 `SHA-256(domain || 0x00 || code)` 摘要，授权码绑定域名、目标注册商、目标所有者和有效期；明文仅通过返回值下发一次。
- **转移发起**：目标注册商凭授权码发起。在**同一原子边界内**完成：校验并消费授权码 → 锁定域名 → 创建转移单。一个域名同时至多一笔进行中的转移。
- **幂等发起**：外部转移号（`externalRef`）为幂等键——同号同内容返回既有转移单，同号异内容返回 `ErrTransferConflict`。
- **决定与超时**：原注册商可在决定期限内（默认 5 天）批准或拒绝；超期由 `AdvanceTimeouts` 按策略落终态（默认自动批准，可配置自动拒绝）。
- **终态唯一**：人工决定、取消、超时推进共享同一事务边界，并发竞争时只有一个生效；终态不可逆，迟到回调返回 `ErrTransferNotPending`，不得覆盖。
- **批准原子性**：批准在同一事务内切换域名所有权与注册商、解锁域名并生成唯一 outbox 消息；任何失败（含持久化失败）都不会留下"域名已锁定但转移没记录"的中间状态。
- **安全**：授权码明文、摘要不出现在错误信息、日志和审计记录中；所有错误为可判定的哨兵错误（`errors.Is`）。

## 状态机

```
                initiate
                   │
                   ▼
               pending ──Decide(approve)──▶ approved      (终态)
                   │────Decide(reject)───▶ rejected      (终态)
                   │────Cancel───────────▶ cancelled     (终态)
                   │────timeout──────────▶ auto_approved / rejected (终态, 按策略)
```

## API

| 方法 | 说明 |
|---|---|
| `RegisterDomain(name, owner, registrar)` | 登记域名 |
| `GenerateAuthCode(domain, owner, targetRegistrar, targetOwner, ttl)` | 生成一次性授权码，返回明文（仅此一次）与过期时间 |
| `InitiateTransfer(externalRef, domain, code, actor)` | 消费授权码、锁定域名、创建转移单（幂等） |
| `Decide(transferID, registrar, approve, reason)` | 原注册商在期限内批准/拒绝 |
| `Cancel(transferID, actor)` | 域名所有者取消 |
| `AdvanceTimeouts()` | 推进超时，按策略落终态，返回处理笔数 |
| `GetTransfer(id)` / `GetTransferByRef(ref)` / `GetDomain(name)` | 状态查询 |
| `ListAudit(domain)` / `ListOutbox()` | 审计历史 / outbox 消息 |

## 架构

```
service.go   业务操作与状态机（全部并发安全）
store.go     Store：单互斥锁 + clone-and-swap 事务；Persister 抽象与文件实现
types.go     Domain / AuthCodeRecord / Transfer / OutboxMessage / AuditEntry
errors.go    哨兵错误（不含敏感值）
```

**原子性设计**：`Store.transact` 在状态副本上应用变更，先持久化（`FilePersister` 用临时文件 + rename 原子写），全部成功才整体换入。任一步失败，已提交状态不受影响。

**时钟注入**：`WithClock` 可替换时钟，测试可手动推进时间验证超时行为。

## 使用示例

```go
svc, _ := domaintransfer.NewService(
    domaintransfer.WithPersister(domaintransfer.NewFilePersister("state.json")),
    domaintransfer.WithDecisionWindow(5*24*time.Hour),
)

svc.RegisterDomain("example.com", "owner-1", "reg-a")

// 所有者生成授权码（明文仅返回一次）
code, expiresAt, _ := svc.GenerateAuthCode("example.com", "owner-1", "reg-b", "owner-2", time.Hour)

// 目标注册商发起转移（幂等键 ext-1）
tr, _ := svc.InitiateTransfer("ext-1", "example.com", code, "reg-b")

// 原注册商批准；或超期后 svc.AdvanceTimeouts() 自动批准
svc.Decide(tr.ID, "reg-a", true, "verified")
```

## 运行测试

    go test ./... -race

测试覆盖：授权码摘要存储与一次性消费、有效期、幂等/冲突、单域名单在途、批准/拒绝/取消/超时全部终态路径、并发竞争唯一终态、持久化往返与失败原子性、敏感值不泄漏。
