package daemon

import (
	"os"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

// A console save replaces profile.yaml by rename. The running sidecar must
// pick the new rule up on the next call, even if the mtime did not move.
func TestReloadAfterAtomicReplace(t *testing.T) {
	srv := startServer(t, nil)
	tool := "mcp__selftest__ping"
	if r := callAs(t, srv.cfg.Socket, "demo", tool, "", "r1"); r.Decision != string(decision.Allow) {
		t.Fatalf("before %+v", r)
	}
	raw, err := os.ReadFile(srv.cfg.ProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(srv.cfg.ProfilePath)
	next, _, err := policy.AddMCPRule(raw, policy.MCPRule{ID: policy.ConsoleRulePrefix + "t1", Server: "selftest", Tool: "ping", Decision: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	tmp := srv.cfg.ProfilePath + ".tmp"
	if err := os.WriteFile(tmp, next, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, srv.cfg.ProfilePath); err != nil {
		t.Fatal(err)
	}
	r := callAs(t, srv.cfg.Socket, "demo", tool, "", "r1")
	if r.Decision != string(decision.Deny) {
		t.Fatalf("after replace %+v", r)
	}
}
