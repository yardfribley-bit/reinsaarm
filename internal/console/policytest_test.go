package console

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/approve"
	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

func TestPolicyTestEndpointWritesNothing(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profile, policy.DefaultYAML(), 0o644); err != nil {
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
	if _, err := led.Append(ledger.Receipt{EventID: "e1", Tool: "Bash", Decision: "ALLOW", EnforcedDecision: "ALLOW", EventType: "action.decision", TS: "2026-11-15T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	approvals := filepath.Join(dir, "approvals.json")
	// An approved, unused grant for exactly the command we will test. A real
	// call would consume it; the simulation must not.
	if err := approve.Put(approvals, approve.Grant{ID: "g1", ArgsHash: approve.ArgsHash("Bash", "git push origin main", nil, nil), Tool: "Bash", Command: "git push origin main", Approved: true}); err != nil {
		t.Fatal(err)
	}
	beforeAudit, _ := os.ReadFile(audit)
	beforeApprovals, _ := os.ReadFile(approvals)

	srv, err := New(Config{
		Addr: "127.0.0.1:0", AuditPath: audit, ApprovalPath: approvals, ProfilePath: profile,
		IdentityKey: key, Project: "/home/dev/project", Home: "/home/dev", CodexHome: filepath.Join(dir, "nocodex"), Token: "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	post := func(token, ctype, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/policy/test"+token, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return res.StatusCode, m
	}

	if code, _ := post("", "application/json", `{"command":"ls"}`); code != http.StatusOK {
		t.Fatalf("loopback without token: %d", code)
	}
	if code, _ := post("?token=tok", "text/plain", `{"command":"ls"}`); code != http.StatusUnsupportedMediaType {
		t.Fatalf("form-style post must be refused: %d", code)
	}
	res, err := http.Get(ts.URL + "/api/policy/test?token=tok")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", res.StatusCode)
	}

	code, m := post("?token=tok", "application/json", `{"payload":{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}},"agent":"claude-code"}`)
	if code != 200 || m["decision"] != "DENY" || !strings.Contains(strings.Join(toStrings(m["rule_ids"]), ","), "R-CRED-PATH") {
		t.Fatalf("read: %d %v", code, m)
	}
	code, m = post("?token=tok", "application/json", `{"command":"git push origin main","agent":"codex"}`)
	if code != 200 || m["decision"] != "STEP_UP" || m["agent_enforced"] != "DENY" {
		t.Fatalf("push: %d %v", code, m)
	}
	code, m = post("?token=tok", "application/json", `{"kind":"mcp","server":"x"}`)
	if code != 400 || m["error"] == nil {
		t.Fatalf("bad input: %d %v", code, m)
	}

	afterAudit, _ := os.ReadFile(audit)
	afterApprovals, _ := os.ReadFile(approvals)
	if string(beforeAudit) != string(afterAudit) {
		t.Fatal("policy test wrote to the audit log")
	}
	if string(beforeApprovals) != string(afterApprovals) {
		t.Fatal("policy test changed approvals")
	}
	page, _ := http.Get(ts.URL + "/?token=tok")
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(body), "模拟执行") || !strings.Contains(string(body), "/api/policy/test") {
		t.Fatal("policy page has no test box")
	}
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
