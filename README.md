# go-domain-transfer

域名所有权 / 注册商转移的领域服务（Go 1.23，无第三方依赖）。实现了带一次性
授权码、人工决定期限与完整状态控制的域名转移流程：

- 域名所有者签发**短期、一次性授权码**，授权码只持久化**随机盐 + SHA-256 摘要**，
  并与域名、唯一目标注册商、所有者、有效期绑定；
- 发起转移在**同一个原子事务**内消费授权码、锁定域名、写入转移单；
  一个域名同时至多一笔进行中的转移；
- 调用方的外部转移号（`ExternalID`）保证**幂等**，同号异内容返回冲突；
- 原注册商在决定期限内可批准 / 拒绝，超期由策略自动处理（默认自动批准）；
- 人工决定、所有者取消、超时推进并发执行时，**只有一个操作能落入终态**，
  迟到回调不能覆盖终态；
- 批准操作在同一事务内切换所有权与注册商信息，并生成**唯一一条**
  transactional outbox 事件，不存在“域名锁定但无转移记录”的中间状态；
- 持久化内容、日志、审计与错误信息中**绝不出现授权码明文**。

## 状态机

```
                 IssueAuthCode (只存摘要)
                        │
                        ▼
  StartTransfer ──► pending ──原注册商 approve──► approved   (终态, outbox)
   (消费码+锁域名)     │
                       ├────原注册商 reject──────► rejected   (终态, 解锁)
                       ├────所有者 cancel────────► cancelled  (终态, 解锁)
                       └────超过决定期限─────────► approved（默认自动批准）
                                                 或 expired（ExpiryExpire 策略）
```

- pending 之外的所有状态均为终态；终态上的任何决定 / 取消 / 超时回调都被拒绝
  （超时推进对终态返回幂等结果，便于定时器重复调用）。
- 终态后域名锁必定释放；批准时所有者与注册商必定已切换。

## 包结构

| 文件 | 内容 |
| --- | --- |
| `model.go` | 领域模型：域名、授权码记录、转移单、审计条目、outbox 事件、状态枚举 |
| `errors.go` | 哨兵错误（`errors.Is` 判定），错误文本只含非敏感标识 |
| `authcode.go` | 高熵授权码生成（CSPRNG）、加盐 SHA-256 摘要、恒定时间比对 |
| `store.go` | `Store` / `Tx` 事务接口与内存实现（一把锁模拟可序列化事务） |
| `service.go` | 应用服务：签发、发起、决定、取消、超时推进 / 扫描、查询、outbox |
| `events.go` | outbox 事件类型常量 |
| `ids.go` | 加密随机 ID 生成 |

`Store` 是接口：内存实现可直接用于测试与单机部署；接入数据库时，只需用
**单个数据库事务**实现 `WriteTx`，并为
`(domain) WHERE status = 'pending'` 增加唯一部分索引，即可在数据库层兜底
“一域名至多一笔进行中转移”的不变量。

## 使用示例

```go
store := domaintransfer.NewMemoryStore()
svc := domaintransfer.NewService(store, domaintransfer.ExpiryAutoApprove)

_ = svc.RegisterRegistrar(domaintransfer.Registrar{ID: "r_old", Name: "Old"})
_ = svc.RegisterRegistrar(domaintransfer.Registrar{ID: "r_new", Name: "New"})
_ = svc.RegisterDomain(domaintransfer.Domain{
    Name: "example.com", OwnerID: "owner-alice", RegistrarID: "r_old",
})

// 1) 所有者签发一次性授权码（明文只返回这一次）
issued, _ := svc.IssueAuthCode(domaintransfer.IssueAuthCodeInput{
    DomainName:      "example.com",
    OwnerID:         "owner-alice",
    TargetRegistrar: "r_new",
})

// 2) 原子发起：消费授权码 + 锁定域名 + 建转移单
res, _ := svc.StartTransfer(domaintransfer.StartTransferInput{
    ExternalID:  "req-0001", // 调用方幂等键
    DomainName:  "example.com",
    AuthCode:    issued.Code,
    ToRegistrar: "r_new",
    NewOwnerID:  "owner-carol",
})

// 3a) 人工决定（期限内）
tr, _ := svc.DecideTransfer(res.TransferID, "r_old", domaintransfer.DecisionApprove, "docs ok")

// 3b) 或由定时任务推进超期转移（默认自动批准）
// tr, _ := svc.AdvanceTimeout(res.TransferID)
// _, _  = svc.SweepExpired() // 批量扫描

// 4) 投递事务性 outbox（at-least-once，发布成功后回标记）
events, _ := svc.PendingOutbox(100)
for _, ev := range events {
    // publish(ev) ...
    _, _ = svc.MarkOutboxPublished(ev.EventID)
}
```

完整可运行示例见 `example_test.go`（`go test` 会实际执行并校验输出）。

## API 概览

| 方法 | 说明 |
| --- | --- |
| `IssueAuthCode` | 所有者签发一次性授权码；仅盐与摘要落库 |
| `StartTransfer` | 原子消费码 + 锁域名 + 建单；`ExternalID` 幂等 |
| `DecideTransfer` | 原注册商批准 / 拒绝；超期返回 `ErrDeadlinePassed` |
| `CancelTransfer` | 所有者取消 pending 转移并解锁 |
| `AdvanceTimeout` | 推进单笔超期转移（自动批准 / 过期） |
| `SweepExpired` | 批量扫描并推进全部到期转移 |
| `GetTransfer` / `GetDomain` | 状态查询（含锁标记与 outbox 事件 ID） |
| `PendingOutbox` / `MarkOutboxPublished` | outbox 拉取与发布确认 |
| `AuditHistory` | 审计历史（签发、发起、重放、各终态动作） |

### 关键错误

`ErrInvalidArgument`、`ErrUnauthorized`、`ErrDomainNotFound`、
`ErrRegistrarNotFound`、`ErrAuthCodeInvalid`、`ErrAuthCodeExpired`、
`ErrAuthCodeUsed`、`ErrTransferNotFound`、`ErrTransferInProgress`、
`ErrTransferNotPending`、`ErrDeadlinePassed`、`ErrExternalIDConflict`。

## 一致性与安全设计

- **原子边界**：`StartTransfer` 的“校验授权码 → 消费授权码 → 锁域名 → 写转移单”
  以及批准的“终态化 → 解锁 → 切换所有者 / 注册商 → 写 outbox”均在单个 `WriteTx`
  内完成；事务中途失败整体回滚，不产生部分写入。
- **终态守卫**：`SetTransferTerminal` / `ApplyApproval` 仅在当前状态为 pending 时
  生效（CAS 语义），并发终态操作必有且仅有一个成功。
- **一次性授权码**：消费记录（`ConsumedBy`）与转移单同事务写入；重复使用返回
  `ErrAuthCodeUsed`。
- **授权码保护**：每码独立 128-bit 随机盐 + SHA-256；比对使用恒定时间比较；
  明文仅在签发响应中出现一次，不持久化、不写审计、不进错误信息。
- **幂等**：相同 `ExternalID` 且内容相同的重复发起返回原单（`Replayed=true`）；
  内容不同返回 `ErrExternalIDConflict`，原单不受影响。
- **Outbox**：批准（人工或超时自动批准）在批准事务内插入恰好一条
  `domain.transfer.approved` 事件，由外部投递器拉取发布并回标记，
  避免双写不一致。

## 测试

```
go test ./...            # 全部单元测试 + Example 文档测试
go test -race ./...      # 含并发竞态检测
```

测试覆盖：授权码格式 / 摘要归一化与恒定时间比对、仅摘要落库、绑定关系校验、
过期与一次性消费、原子锁定与失败回滚、幂等重放与同号冲突、批准的所有权 /
注册商原子切换与唯一 outbox、拒绝 / 取消解锁、超期自动批准与 `ExpiryExpire`
策略、批量扫描幂等、多 goroutine 终态竞态与并发发起竞态（`-race`）、
审计 / 错误中的敏感信息泄漏检查。
