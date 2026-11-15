package policy

import (
	"strings"
	"testing"
)

func TestAddRemoveMCPRuleRoundTrip(t *testing.T) {
	raw := DefaultYAML()
	next, r, err := AddMCPRule(raw, MCPRule{ID: ConsoleRulePrefix + "a1", Server: "Codex_Apps", Tool: "search_*", Decision: "STEP_UP", Reason: "需要确认 #1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Server != "codex_apps" || r.Decision != "STEP_UP" {
		t.Fatalf("not normalized: %+v", r)
	}
	p, err := Load(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.MCP.Rules) != 1 || p.Spec.MCP.Rules[0].Reason != "需要确认 #1" {
		t.Fatalf("rules %+v", p.Spec.MCP.Rules)
	}
	// Only lines were added or the rules line changed.
	if !strings.Contains(string(next), "    rules:\n      - id: R-MCP-CONSOLE-a1\n") {
		t.Fatalf("layout:\n%s", next)
	}
	next2, _, err := AddMCPRule(next, MCPRule{ID: ConsoleRulePrefix + "b2", Server: "fs", Tool: "write_*", Decision: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddMCPRule(next2, MCPRule{ID: ConsoleRulePrefix + "c3", Server: "FS", Tool: "write_*", Decision: "allow"}); err == nil {
		t.Fatal("duplicate server/tool accepted")
	}
	if _, _, err := AddMCPRule(next2, MCPRule{ID: ConsoleRulePrefix + "b2", Server: "x", Decision: "allow"}); err == nil {
		t.Fatal("duplicate id accepted")
	}
	back, gone, err := RemoveMCPRule(next2, ConsoleRulePrefix+"b2")
	if err != nil || gone.Server != "fs" {
		t.Fatal(err, gone)
	}
	if string(back) != string(next) {
		t.Fatalf("remove b2 not inverse:\n%s", back)
	}
	orig, _, err := RemoveMCPRule(back, ConsoleRulePrefix+"a1")
	if err != nil {
		t.Fatal(err)
	}
	if string(orig) != string(raw) {
		t.Fatalf("remove a1 not inverse:\n%s", orig)
	}
}

func TestAddMCPRuleLayouts(t *testing.T) {
	base := "kind: AgentProfile\nspec:\n  remit: x\n"
	cases := map[string]string{
		"missing":   base,
		"mcp-empty": base + "  mcp: {}\n",
		"mcp-null":  base + "  mcp:\n",
		"no-rules":  base + "  mcp:\n    other: 1\n",
		"null":      base + "  mcp:\n    rules:   # keep\n",
		"block":     base + "  mcp:\n    rules:\n      # existing\n      - id: R-OLD\n        server: a\n        decision: allow\n  network:\n    mode: off\n",
	}
	for name, raw := range cases {
		next, _, err := AddMCPRule([]byte(raw), MCPRule{ID: ConsoleRulePrefix + "x", Server: "srv", Tool: "t?", Decision: "ask"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p, err := Load(next)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, next)
		}
		found := false
		for _, r := range p.Spec.MCP.Rules {
			if r.ID == ConsoleRulePrefix+"x" && r.Decision == "STEP_UP" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: rule missing\n%s", name, next)
		}
		if name == "block" || name == "null" {
			back, _, err := RemoveMCPRule(next, ConsoleRulePrefix+"x")
			if err != nil {
				t.Fatalf("%s remove: %v", name, err)
			}
			if name == "block" && string(back) != raw {
				t.Fatalf("block remove not inverse:\n%s", back)
			}
		}
	}
}

func TestAddMCPRuleRejects(t *testing.T) {
	raw := DefaultYAML()
	bad := []MCPRule{
		{ID: ConsoleRulePrefix + "1", Decision: "allow"},
		{ID: ConsoleRulePrefix + "2", Server: "a[", Decision: "allow"},
		{ID: ConsoleRulePrefix + "3", Server: "a", Decision: "maybe"},
	}
	for _, r := range bad {
		if _, _, err := AddMCPRule(raw, r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	flow := []byte("spec:\n  remit: x\n  mcp:\n    rules: [{id: A, server: a, decision: allow}]\n")
	if _, _, err := AddMCPRule(flow, MCPRule{ID: ConsoleRulePrefix + "f", Server: "b", Decision: "deny"}); err == nil {
		t.Fatal("flow list accepted")
	}
	if _, _, err := RemoveMCPRule(raw, "R-MCP-FS-WRITE"); err == nil {
		t.Fatal("removed a non-console rule")
	}
}
