package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAndTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	led, err := Open(path, "local", pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := led.Append(Receipt{
			EventID: "e", AgentID: "a", Client: "test", Tool: "Bash",
			Decision: "ALLOW", EnforcedDecision: "ALLOW", Tier: "T0",
			RuleIDs: []string{"R-DEFAULT-ALLOW"}, Reason: "ok", TS: "2026-11-15T00:00:00Z",
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, problem, err := Verify(path, pub)
	if err != nil || problem != nil || n != 3 {
		t.Fatalf("verify n=%d problem=%v err=%v", n, problem, err)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(original)), "\n")

	// Modify one byte of the reason inside the second receipt.
	mut := strings.Replace(string(original), `"reason":"ok"`, `"reason":"no"`, 1)
	if err := os.WriteFile(path, []byte(mut), 0o600); err != nil {
		t.Fatal(err)
	}
	_, problem, err = Verify(path, pub)
	if err != nil || problem == nil {
		t.Fatalf("modify should fail, problem=%v err=%v", problem, err)
	}

	// Delete the middle receipt.
	deleted := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(deleted), 0o600); err != nil {
		t.Fatal(err)
	}
	_, problem, err = Verify(path, pub)
	if err != nil || problem == nil {
		t.Fatalf("delete should fail, problem=%v err=%v", problem, err)
	}

	// Swap the first two receipts.
	swapped := lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(swapped), 0o600); err != nil {
		t.Fatal(err)
	}
	_, problem, err = Verify(path, pub)
	if err != nil || problem == nil {
		t.Fatalf("reorder should fail, problem=%v err=%v", problem, err)
	}
}
