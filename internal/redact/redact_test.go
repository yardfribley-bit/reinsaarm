package redact

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := []string{
		"export OPENAI_API_KEY=sk-live-0123456789abcdefghij",
		"token ghp_0123456789abcdefghijABCDEFGHIJ",
		"github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
		"aws AKIAIOSFODNN7EXAMPLE",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz.123",
		"git clone https://user:hunter2pass@github.com/x/y",
		"https://api.example.com/v1?access_token=abcdef123456&x=1",
		`{"password": "s3cret-value", "user": "a"}`,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"slack xoxb-1234567890-abcdefghij",
	}
	secrets := []string{"sk-live-0123", "ghp_0123", "github_pat_11", "AKIAIOSFODNN7EXAMPLE", "abcdefghijklmnopqrstuvwxyz.123", "hunter2pass", "abcdef123456", "s3cret-value", "b3BlbnNzaC1rZXktdjEAAAA", "xoxb-1234567890"}
	for i, c := range cases {
		got := Mask(c)
		if strings.Contains(got, secrets[i]) || !strings.Contains(got, "[REDACTED]") {
			t.Errorf("case %d: %q -> %q", i, c, got)
		}
	}
	if Mask("go test ./... && git status") != "go test ./... && git status" {
		t.Fatal("plain text changed")
	}
}

func TestTruncateRunes(t *testing.T) {
	s, cut := Truncate("会话时间线", 3)
	if s != "会话时…" || !cut {
		t.Fatalf("%q %v", s, cut)
	}
	if s, cut := Truncate("abc", 3); s != "abc" || cut {
		t.Fatalf("%q", s)
	}
	if s, _ := Text("a\n\n  b\tc", 10); s != "a b c" {
		t.Fatalf("%q", s)
	}
}
