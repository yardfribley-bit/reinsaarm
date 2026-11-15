package ledger

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func fixtureKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// testdata/pre-activity.jsonl was written by the main-branch ledger before
// cwd, turn_id, tool_use_id, ref_seq, and activity existed. It must still
// verify, and new activity receipts must chain onto it.
func TestPreActivityReceiptsStillVerify(t *testing.T) {
	pub, priv := fixtureKey()
	src, err := os.ReadFile(filepath.Join("testdata", "pre-activity.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, p, err := Verify(path, pub); err != nil || p != nil || n != 2 {
		t.Fatalf("old chain: n=%d problem=%+v err=%v", n, p, err)
	}
	l, err := Open(path, "local", pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	ok, code, ms := true, 0, int64(42)
	rec, err := l.Append(Receipt{
		EventID: "e3", AgentID: "dev", Client: "codex", SessionID: "s1", CWD: "/Users/dev/proj",
		ToolUseID: "call_1", TurnID: "1", RefSeq: 1, Tool: "Bash", Kind: "shell",
		Decision: "OBSERVE", EnforcedDecision: "OBSERVE", Tier: "T0", EventType: "tool.result",
		Activity: &Activity{Hook: "PostToolUse", Success: &ok, ExitCode: &code, DurationMS: &ms, DurationFrom: "hooks", Output: "会话 ok"},
		TS:       "2026-11-15T09:00:02Z",
	})
	if err != nil || rec.Seq != 3 {
		t.Fatalf("append %+v %v", rec, err)
	}
	if n, p, err := Verify(path, pub); err != nil || p != nil || n != 3 {
		t.Fatalf("mixed chain: n=%d problem=%+v err=%v", n, p, err)
	}
	recs, _ := Tail(path, 1)
	a := recs[0].Activity
	if a == nil || a.ExitCode == nil || *a.ExitCode != 0 || a.Success == nil || !*a.Success || recs[0].RefSeq != 1 {
		t.Fatalf("round trip %+v", recs[0])
	}
}
