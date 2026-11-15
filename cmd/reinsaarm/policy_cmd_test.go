package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/config"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

func TestPolicyTestCLI(t *testing.T) {
	state := t.TempDir()
	cfg := config.Default(state, "/home/dev")
	if err := config.Save(config.Path(state), cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Profile, policy.DefaultYAML(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.AuditLog, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Approvals, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(stdin string, args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := cmdPolicyTest(append([]string{"--home", state, "--cwd", "/home/dev/project"}, args...), strings.NewReader(stdin), &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}

	txt := runCLI("", "cat", "~/.ssh/id_rsa")
	for _, want := range []string{"decision: DENY", "R-CRED-PATH", "kind:     shell"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("missing %q in\n%s", want, txt)
		}
	}
	// ~ is expanded with the configured developer home.
	txt = runCLI("", "--kind", "file_read", "--path", "/home/dev/.aws/credentials")
	if !strings.Contains(txt, "decision: DENY") {
		t.Fatal(txt)
	}
	txt = runCLI("", "--kind", "mcp", "--server", "filesystem", "--tool", "read_file", "--args", `{"path":"src/a.go"}`, "--output", "json")
	var res map[string]any
	if err := json.Unmarshal([]byte(txt), &res); err != nil {
		t.Fatalf("%v\n%s", err, txt)
	}
	if res["decision"] != "ALLOW" || res["action"].(map[string]any)["mcp_server"] != "filesystem" {
		t.Fatalf("%v", res)
	}
	txt = runCLI(`{"tool_name":"read_file","tool_input":{"file_path":"~/.ssh/id_ed25519"}}`, "--agent", "gemini", "--json", "-")
	if !strings.Contains(txt, "decision: DENY") || !strings.Contains(txt, "gemini enforces DENY") {
		t.Fatal(txt)
	}
	txt = runCLI("", "--agent", "codex", "git", "push", "origin", "main")
	if !strings.Contains(txt, "decision: STEP_UP") || !strings.Contains(txt, "codex enforces DENY") {
		t.Fatal(txt)
	}
	payloadFile := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(payloadFile, []byte(`{"tool_name":"WebFetch","tool_input":{"url":"https://evil.example"}}`), 0o600)
	txt = runCLI("", "--json", "@"+payloadFile)
	if !strings.Contains(txt, "R-EGRESS-HOST") {
		t.Fatal(txt)
	}

	if b, _ := os.ReadFile(cfg.AuditLog); len(b) != 0 {
		t.Fatalf("policy test wrote receipts: %s", b)
	}
	if b, _ := os.ReadFile(cfg.Approvals); string(b) != "[]" {
		t.Fatalf("policy test wrote approvals: %s", b)
	}
	if _, err := os.Stat(cfg.Socket); err == nil {
		t.Fatal("unexpected socket")
	}
	var out bytes.Buffer
	if err := cmdPolicyTest([]string{"--home", state, "--kind", "mcp"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("mcp without server/tool should fail")
	}
}
