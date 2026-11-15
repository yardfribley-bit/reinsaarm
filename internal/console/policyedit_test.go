package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

func TestMCPRuleSaveAndRemove(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	orig := policy.DefaultYAML()
	if err := os.WriteFile(profile, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "identity.key")
	pub, priv, err := identity.LoadOrCreate(key)
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	led, err := ledger.Open(audit, "local", pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := led.Append(ledger.Receipt{EventID: "e1", Tool: "Bash", Decision: "ALLOW", EnforcedDecision: "ALLOW", TS: "2026-11-15T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Addr: "127.0.0.1:0", AuditPath: audit, ApprovalPath: filepath.Join(dir, "approvals.json"), ProfilePath: profile,
		IdentityKey: key, Project: "/home/dev/project", Home: "/home/dev", CodexHome: filepath.Join(dir, "nocodex"), Token: "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	call := func(path string, body any, hdr map[string]string) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path+"?token=tok", strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	simDecision := func() string {
		code, out := call("/api/policy/test", map[string]any{"kind": "mcp", "server": "selftest", "tool": "ping"}, nil)
		if code != 200 {
			t.Fatalf("sim %d %v", code, out)
		}
		return out["decision"].(string)
	}
	if d := simDecision(); d != "ALLOW" {
		t.Fatalf("before: %s", d)
	}
	add := map[string]any{"op": "add", "dry_run": true, "server": "selftest", "tool": "ping", "decision": "STEP_UP", "reason": "测试"}

	// Cross-site and plain-form posts are refused.
	if code, _ := call("/api/policy/mcp-rules", add, map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("cross-origin %d", code)
	}
	if code, _ := call("/api/policy/mcp-rules", add, map[string]string{"Content-Type": "text/plain"}); code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain %d", code)
	}
	if code, _ := call("/api/policy/mcp-rules", map[string]any{"op": "add", "server": "*", "tool": "*", "decision": "DENY"}, nil); code != 400 {
		t.Fatalf("match-all %d", code)
	}

	code, prev := call("/api/policy/mcp-rules", add, nil)
	if code != 200 || !strings.Contains(prev["diff"].(string), "server: \"selftest\"") {
		t.Fatalf("preview %d %v", code, prev)
	}
	if now, _ := os.ReadFile(profile); string(now) != string(orig) {
		t.Fatal("dry run wrote the file")
	}
	id := prev["rule"].(map[string]any)["id"].(string)
	save := map[string]any{"op": "add", "id": id, "server": "selftest", "tool": "ping", "decision": "STEP_UP", "reason": "测试"}
	save["base_version"] = "stale"
	if code, _ := call("/api/policy/mcp-rules", save, nil); code != http.StatusConflict {
		t.Fatalf("stale %d", code)
	}
	save["base_version"] = prev["base_version"]
	code, done := call("/api/policy/mcp-rules", save, nil)
	if code != 200 {
		t.Fatalf("save %d %v", code, done)
	}
	if d := simDecision(); d != "STEP_UP" {
		t.Fatalf("after save: %s", d)
	}
	st, _ := os.Stat(profile)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("perm %v", st.Mode().Perm())
	}
	if b, err := os.ReadFile(done["backup"].(string)); err != nil || string(b) != string(orig) {
		t.Fatalf("backup %v", err)
	}
	if code, _ := call("/api/policy/mcp-rules", map[string]any{"op": "add", "dry_run": true, "server": "SELFTEST", "tool": "ping", "decision": "DENY"}, nil); code != 400 {
		t.Fatalf("duplicate %d", code)
	}

	// The policy view lists the rule as removable.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/policy?token=tok", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Rules []struct {
			ID        string `json:"id"`
			Removable bool   `json:"removable"`
		} `json:"mcp_rules"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&view)
	resp.Body.Close()
	if len(view.Rules) != 1 || view.Rules[0].ID != id || !view.Rules[0].Removable {
		t.Fatalf("view %+v", view)
	}

	code, rprev := call("/api/policy/mcp-rules", map[string]any{"op": "remove", "dry_run": true, "id": id}, nil)
	if code != 200 {
		t.Fatalf("remove preview %d %v", code, rprev)
	}
	code, rdone := call("/api/policy/mcp-rules", map[string]any{"op": "remove", "id": id, "base_version": rprev["base_version"]}, nil)
	if code != 200 {
		t.Fatalf("remove %d %v", code, rdone)
	}
	if now, _ := os.ReadFile(profile); string(now) != string(orig) {
		t.Fatalf("remove did not restore the file:\n%s", now)
	}
	if d := simDecision(); d != "ALLOW" {
		t.Fatalf("after remove: %s", d)
	}

	n, problem, err := ledger.Verify(audit, pub)
	if err != nil || problem != nil || n != 3 {
		t.Fatalf("verify n=%d %v %v", n, problem, err)
	}
	recs, _ := ledger.Tail(audit, 10)
	if recs[1].EventType != "policy.changed" || recs[1].RuleIDs[0] != id || recs[2].EventType != "policy.changed" {
		t.Fatalf("receipts %+v", recs)
	}
}

func TestLineDiff(t *testing.T) {
	d := lineDiff("a\nb\nc\n", "a\nb\nx\nc\n")
	if !strings.Contains(d, "+ x\n") || strings.Contains(d, "- ") {
		t.Fatalf("%q", d)
	}
}
