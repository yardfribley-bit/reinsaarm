package hooks

import (
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
)

func input() Input {
	return Input{
		SessionID: "s", CWD: "/work", HookEvent: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]any{"command": "git push --force origin feature", "description": "push"},
	}
}

func TestRenderClients(t *testing.T) {
	in := input()
	deny := Response{Decision: "DENY", Enforced: "DENY", Reason: "blocked", RuleIDs: []string{"R-CRED-PATH"}}
	for _, client := range []string{ClientClaude, ClientCodex, ClientGemini, ClientCodeBuddy} {
		out, err := Render(client, in, deny)
		if err != nil {
			t.Fatal(err)
		}
		if out.ExitCode != 0 {
			t.Fatalf("%s exit %d", client, out.ExitCode)
		}
		body := string(out.Stdout)
		if !strings.Contains(body, "deny") && !strings.Contains(body, "block") {
			t.Fatalf("%s body %s", client, body)
		}
	}

	step := Response{Decision: "STEP_UP", Enforced: "STEP_UP", Reason: "needs approval", ApprovalID: "abc"}
	claude, err := Render(ClientClaude, in, step)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(claude.Stdout), `"permissionDecision":"ask"`) && !strings.Contains(string(claude.Stdout), `"permissionDecision": "ask"`) {
		t.Fatalf("claude ask: %s", claude.Stdout)
	}
	codex, err := Render(ClientCodex, in, step)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(codex.Stdout), `"ask"`) {
		t.Fatalf("codex must not emit ask: %s", codex.Stdout)
	}
	if !strings.Contains(string(codex.Stdout), `"deny"`) {
		t.Fatalf("codex step-up: %s", codex.Stdout)
	}
	gem, err := Render(ClientGemini, in, step)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gem.Stdout), `"decision":"deny"`) && !strings.Contains(string(gem.Stdout), `"decision": "deny"`) {
		t.Fatalf("gemini: %s", gem.Stdout)
	}
	cb, err := Render(ClientCodeBuddy, in, step)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cb.Stdout), `"ask"`) {
		t.Fatalf("codebuddy ask: %s", cb.Stdout)
	}

	mod := Response{Decision: "MODIFY", Enforced: "MODIFY", Reason: "stripped", Rewrite: "git push origin feature"}
	codexMod, err := Render(ClientCodex, in, mod)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(codexMod.Stdout), "updatedInput") || !strings.Contains(string(codexMod.Stdout), "git push origin feature") {
		t.Fatalf("codex modify: %s", codexMod.Stdout)
	}
	cbMod, err := Render(ClientCodeBuddy, in, mod)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cbMod.Stdout), "modifiedInput") {
		t.Fatalf("codebuddy modify: %s", cbMod.Stdout)
	}
	gemMod, err := Render(ClientGemini, in, mod)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gemMod.Stdout), "tool_input") || !strings.Contains(string(gemMod.Stdout), "git push origin feature") {
		t.Fatalf("gemini modify: %s", gemMod.Stdout)
	}
	allow := Response{Decision: "ALLOW", Enforced: "ALLOW", Reason: "no blocking rule matched"}
	codexAllow, err := Render(ClientCodex, in, allow)
	if err != nil {
		t.Fatal(err)
	}
	if codexAllow.ExitCode != 0 || len(codexAllow.Stdout) != 0 || strings.Contains(string(codexAllow.Stdout), "allow") {
		t.Fatalf("codex allow must be silent stdout, got %q exit %d", codexAllow.Stdout, codexAllow.ExitCode)
	}
	if ProjectEnforced(ClientCodex, decision.StepUp) != decision.Deny {
		t.Fatal("codex step-up must be recorded as deny")
	}
	if ProjectEnforced(ClientClaude, decision.StepUp) != decision.StepUp {
		t.Fatal("claude step-up stays step-up")
	}
}

func TestFailClosedExit2(t *testing.T) {
	for _, client := range []string{ClientClaude, ClientCodex, ClientGemini, ClientCodeBuddy} {
		out := FailClosed(client, "connection refused")
		if out.ExitCode != 2 {
			t.Fatalf("%s exit %d", client, out.ExitCode)
		}
		if !strings.Contains(string(out.Stdout), "deny") {
			t.Fatalf("%s stdout %s", client, out.Stdout)
		}
		if out.ExitCode != 2 || strings.TrimSpace(out.Stderr) == "" || !strings.Contains(out.Stderr, "connection refused") {
			t.Fatalf("%s stderr %q", client, out.Stderr)
		}
	}
	empty := FailClosed(ClientCodex, "   ")
	if empty.ExitCode != 2 || strings.TrimSpace(empty.Stderr) == "" {
		t.Fatalf("empty reason still needs stderr: %q", empty.Stderr)
	}
}

func TestParse(t *testing.T) {
	raw := `{"session_id":"abc","cwd":"/work","hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"go test"}}`
	in, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if in.ToolName != "run_shell_command" || in.ToolInput["command"] != "go test" {
		t.Fatalf("%+v", in)
	}
}
