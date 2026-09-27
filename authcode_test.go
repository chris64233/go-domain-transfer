package domaintransfer

import (
	"strings"
	"testing"
)

// ---- 授权码工具 ----

func TestGenerateAuthCode_FormatAndEntropy(t *testing.T) {
	a, err := generateAuthCode(20)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := generateAuthCode(20)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if a == b {
		t.Fatal("two auth codes must differ")
	}
	// 20 字节 base32 => 32 个字符，分成 8 组。
	groups := strings.Split(a, "-")
	if len(groups) != 8 {
		t.Fatalf("expected 8 groups, got %d (%q)", len(groups), a)
	}
}

func TestDigestAndNormalize(t *testing.T) {
	salt, err := generateSalt()
	if err != nil {
		t.Fatal(err)
	}
	const code = "ABCD-EFGH-KMNP"
	d := digestCode(salt, code)

	if !codeMatches(d, salt, code) {
		t.Fatal("same code should match")
	}
	// 忽略大小写、分隔符与空格。
	if !codeMatches(d, salt, "  abcdefghkmnp ") {
		t.Fatal("normalized code should match")
	}
	if codeMatches(d, salt, "ABCD-EFGH-KMNQ") {
		t.Fatal("different code must not match")
	}
	if codeMatches(d, salt+"x", code) {
		t.Fatal("code must not match under different salt")
	}
}
