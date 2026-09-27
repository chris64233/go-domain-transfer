package domaintransfer

import (
	"crypto/rand"
	"encoding/hex"
)

func randomHex(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败意味着运行环境已不可用，直接崩溃比静默降级安全。
		panic("domaintransfer: cannot read crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func newTransferID() string { return "tr_" + randomHex(12) }

func newAuthCodeID() string { return "ac_" + randomHex(12) }

func newEventID() string { return "ev_" + randomHex(16) }
