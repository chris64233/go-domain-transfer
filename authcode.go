package domaintransfer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

// codeAlphabet 去掉易混淆字符（0/O、1/I/L）的 Crockford 风格字母表，
// 方便域名所有者手工抄送给注册商。
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var b32 = base32.NewEncoding(codeAlphabet).WithPadding(base32.NoPadding)

// generateAuthCode 生成 nBytes 字节随机熵的一次性授权码明文。
// 20 字节 => 100 bit 熵，32 字符分组展示。明文只在签发时返回一次。
func generateAuthCode(nBytes int) (string, error) {
	if nBytes <= 0 {
		nBytes = 20
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	raw := b32.EncodeToString(buf)
	// 每 4 个字符插入连字符，形如 XXXX-XXXX-...，便于人工传递。
	var b strings.Builder
	for i, r := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

// generateSalt 生成每码独立的随机盐。
func generateSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// normalizeCode 去除授权码中的分隔符并统一大写，
// 使 "abcd-efgh" 与 "ABCDEFGH" 等价。
func normalizeCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '-', ' ', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// digestCode 计算 salt + 明文的 SHA-256 摘要。数据库被拖库后，
// 没有盐与明文也无法直接还原 / 碰撞出授权码。
func digestCode(salt, code string) string {
	sum := sha256.Sum256([]byte(salt + ":" + normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// codeMatches 以恒定时间比较摘要，避免计时侧信道。
func codeMatches(digest, salt, code string) bool {
	got := digestCode(salt, code)
	return subtle.ConstantTimeCompare([]byte(got), []byte(digest)) == 1
}
