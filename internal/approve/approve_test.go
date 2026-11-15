package approve

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
)

func TestOneTimeBoundApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	h := ArgsHash("Bash", "git push origin main", nil, nil)
	g := Grant{ID: "abc", ArgsHash: h, Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Tool: "Bash"}
	if err := Put(path, g); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Consume(path, h, time.Now()); err != nil || ok {
		t.Fatalf("unapproved consume ok=%v err=%v", ok, err)
	}
	if _, err := Approve(path, "abc"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := Consume(path, h, time.Now())
	if err != nil || !ok || got.ID != "abc" {
		t.Fatalf("consume %+v ok=%v err=%v", got, ok, err)
	}
	if _, ok, err := Consume(path, h, time.Now()); err != nil || ok {
		t.Fatalf("second consume ok=%v err=%v", ok, err)
	}
	other := ArgsHash("Bash", "git push origin main --force", nil, nil)
	if other == h {
		t.Fatal("hash should change")
	}
}

func TestApprovalReceiptFillsTheChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	led, err := ledger.Open(path, "local", pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Append(ledger.Receipt{
		EventID: "e", AgentID: "a", Client: "codex", Tool: "Bash",
		Decision: "STEP_UP", EnforcedDecision: "DENY", Tier: "T0",
		RuleIDs: []string{"R-GIT-PUSH-PROTECTED"}, Reason: "held", TS: "2026-11-15T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := AppendReceipt(led, "a", Grant{ID: "abc", Tool: "Bash", ArgsHash: "ff"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 2 || got.EventType != "approval.granted" || got.Decision != "ALLOW" {
		t.Fatalf("%+v", got)
	}
	n, problem, err := ledger.Verify(path, pub)
	if err != nil || problem != nil || n != 2 {
		t.Fatalf("n=%d problem=%v err=%v", n, problem, err)
	}
}
