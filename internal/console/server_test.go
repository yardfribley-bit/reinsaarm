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

func TestPagesAndApprove(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profile.yaml"), policy.DefaultYAML(), 0o644); err != nil {
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
	if _, err := led.Append(ledger.Receipt{
		EventID: "e1", AgentID: "dev", Client: "codex", Tool: "Bash",
		CommandPreview: "git push origin main", Decision: "STEP_UP", EnforcedDecision: "DENY",
		Tier: "T0", RuleIDs: []string{"R-GIT-PUSH-PROTECTED"}, Reason: "push to a protected branch needs approval",
		EventType: "action.decision", TS: "2026-11-15T00:00:00Z", LatencyUS: 400,
	}); err != nil {
		t.Fatal(err)
	}
	approvals := filepath.Join(dir, "approvals.json")
	if err := approve.Put(approvals, approve.Grant{
		ID: "abc", ArgsHash: "ff", Tool: "Bash", Command: "git push origin main",
		Client: "codex", Reason: "push to a protected branch needs approval",
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		Addr: "127.0.0.1:0", AuditPath: audit, ApprovalPath: approvals,
		ProfilePath: filepath.Join(dir, "profile.yaml"), IdentityKey: key,
		Project: dir, CodexHome: filepath.Join(dir, "nocodex"), Token: "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("loopback without token: %d", res.StatusCode)
	}
	res, err = http.Get(ts.URL + "/?token=tok")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	html := string(body)
	for _, label := range []string{"实时流", "审批", "审计链", "策略", "健康检查", "钩子未被信任，拦截未生效"} {
		if !strings.Contains(html, label) {
			t.Fatalf("page missing %s", label)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/approvals/abc/approve?token=tok", nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("approve %d %s", res.StatusCode, raw)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	rec := payload["receipt"].(map[string]any)
	if rec["event_type"] != "approval.granted" {
		t.Fatalf("%v", rec)
	}
	n, problem, err := ledger.Verify(audit, pub)
	if err != nil || problem != nil || n != 2 {
		t.Fatalf("n=%d problem=%v err=%v", n, problem, err)
	}
	res, err = http.Get(ts.URL + "/api/health?token=tok")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(raw), "Codex 项目信任") || !strings.Contains(string(raw), `"ok":false`) {
		t.Fatalf("health %s", raw)
	}
	if _, err := New(Config{Addr: "0.0.0.0:8787", Token: "t"}); err == nil {
		t.Fatal("non-loopback bind should fail")
	}
}
