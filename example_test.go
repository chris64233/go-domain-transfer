package domaintransfer_test

import (
	"fmt"
	"time"

	domaintransfer "github.com/chris64233/go-domain-transfer"
)

// 完整流程：签发授权码 -> 发起转移 -> 超期自动批准 -> 读取 outbox。
func ExampleService_endToEnd() {
	// 示例使用固定的可控时钟；生产环境用 NewMemoryStore() 或自定义 Store。
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	now := base
	store := domaintransfer.NewMemoryStore(domaintransfer.WithClock(func() time.Time { return now }))
	svc := domaintransfer.NewService(store, domaintransfer.ExpiryAutoApprove)

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	must(svc.RegisterRegistrar(domaintransfer.Registrar{ID: "r_old", Name: "Old"}))
	must(svc.RegisterRegistrar(domaintransfer.Registrar{ID: "r_new", Name: "New"}))
	must(svc.RegisterDomain(domaintransfer.Domain{
		Name: "example.com", OwnerID: "owner-alice", RegistrarID: "r_old",
	}))

	// 1) 所有者签发一次性授权码：明文只返回这一次。
	issued, err := svc.IssueAuthCode(domaintransfer.IssueAuthCodeInput{
		DomainName:      "example.com",
		OwnerID:         "owner-alice",
		TargetRegistrar: "r_new",
		TTL:             24 * time.Hour,
	})
	must(err)
	fmt.Println("issued code length:", len(issued.Code) > 0)

	// 2) 在单个事务内消费授权码、锁定域名并创建转移单。
	res, err := svc.StartTransfer(domaintransfer.StartTransferInput{
		ExternalID:  "req-2026-0001",
		DomainName:  "example.com",
		AuthCode:    issued.Code,
		ToRegistrar: "r_new",
		NewOwnerID:  "owner-carol",
		DecisionTTL: 48 * time.Hour,
	})
	must(err)
	fmt.Println("transfer status:", res.Status)

	// 重复发起（同号同内容）是幂等重放，不会重复消费授权码。
	replay, err := svc.StartTransfer(domaintransfer.StartTransferInput{
		ExternalID:  "req-2026-0001",
		DomainName:  "example.com",
		AuthCode:    issued.Code,
		ToRegistrar: "r_new",
		NewOwnerID:  "owner-carol",
	})
	must(err)
	fmt.Println("replayed:", replay.Replayed)

	// 3) 期限内原注册商可人工决定；这里模拟超时自动批准。
	now = now.Add(49 * time.Hour)
	tr, err := svc.AdvanceTimeout(res.TransferID)
	must(err)
	fmt.Println("final status:", tr.Status, "by:", tr.DecidedBy)

	// 所有权与注册商在同一事务内完成切换。
	d, err := svc.GetDomain("example.com")
	must(err)
	fmt.Printf("domain owner=%s registrar=%s locked=%t\n", d.OwnerID, d.RegistrarID, d.LockedByTransfer != "")

	// 批准事务中生成了恰好一条 outbox 事件。
	events, err := svc.PendingOutbox(10)
	must(err)
	fmt.Println("outbox events:", len(events), events[0].Type)

	// Output:
	// issued code length: true
	// transfer status: pending
	// replayed: true
	// final status: approved by: system
	// domain owner=owner-carol registrar=r_new locked=false
	// outbox events: 1 domain.transfer.approved
}
