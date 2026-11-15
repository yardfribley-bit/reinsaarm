package activity

import (
	"encoding/json"
	"strings"
	"testing"
)

func payload(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Codex 0.151 PostToolUse for Bash: tool_response is the output string,
// shape from codex-rs/hooks/schema/generated/post-tool-use.command.input.schema.json
// and ExecCommandToolOutput::post_tool_use_response.
func TestCodexBashResult(t *testing.T) {
	p := payload(t, `{"session_id":"019a3c2e-7f1b-7c40-9a55-3f1f0c2d8e11","turn_id":"1","transcript_path":null,
	"cwd":"/Users/dev/proj","hook_event_name":"PostToolUse","model":"gpt-5.1-codex","permission_mode":"default",
	"tool_name":"Bash","tool_input":{"command":"go test ./..."},"tool_use_id":"call_7Yk2",
	"tool_response":"ok  \tgithub.com/x/proj\t0.012s\nexport GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`)
	a := Build("codex", "PostToolUse", p, nil, Options{})
	if a.Success != nil {
		t.Fatalf("codex gives no exit code; success must stay unknown, got %v", *a.Success)
	}
	if !strings.Contains(a.Output, "github.com/x/proj") || strings.Contains(a.Output, "ghp_") {
		t.Fatalf("output %q", a.Output)
	}
	if a.Model != "gpt-5.1-codex" || a.Hook != "PostToolUse" {
		t.Fatalf("%+v", a)
	}
}

// WorkBuddy Bash rawResponse (WorkBuddy AI 5.9.4 bundled CLI): exitCode,
// interrupted, is_error, error (stderr slice), no stdout.
func TestWorkBuddyBashFailure(t *testing.T) {
	p := payload(t, `{"session_id":"wb-sess-1","transcript_path":"/Users/dev/.workbuddy-ai/projects/x.jsonl","cwd":"/Users/dev/proj",
	"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"npm test"},"call_id":"tc_91","tool_use_id":"tc_91",
	"tool_response":{"exitCode":1,"signal":null,"interrupted":false,"sandboxDenied":false,"stderrBytesTruncated":0,"stdoutBytesTruncated":0,
	"tool_error_code":"90021","is_error":true,"error":"Error: Cannot find module 'express'"}}`)
	a := Build("workbuddy", "PostToolUse", p, nil, Options{})
	if a.Success == nil || *a.Success || a.ExitCode == nil || *a.ExitCode != 1 {
		t.Fatalf("%+v", a)
	}
	if !strings.Contains(a.Error, "Cannot find module") {
		t.Fatalf("error %q", a.Error)
	}
}

func TestWorkBuddyWriteSuccess(t *testing.T) {
	p := payload(t, `{"session_id":"wb-sess-1","cwd":"/Users/dev/proj","hook_event_name":"PostToolUse","tool_name":"Write",
	"tool_input":{"file_path":"/Users/dev/proj/src/app.ts","content":"export {}"},"tool_use_id":"tc_92",
	"tool_response":{"filePath":"/Users/dev/proj/src/app.ts","success":true}}`)
	a := Build("workbuddy", "PostToolUse", p, []string{"/Users/dev/proj/src/app.ts"}, Options{})
	if a.Success == nil || !*a.Success {
		t.Fatalf("%+v", a)
	}
	if len(a.Files) != 1 || a.Files[0] != "/Users/dev/proj/src/app.ts" {
		t.Fatalf("files %v", a.Files)
	}
}

// Claude Code PostToolUseFailure (code.claude.com/docs/en/hooks).
func TestClaudeFailure(t *testing.T) {
	p := payload(t, `{"session_id":"abc123","cwd":"/Users/dev/proj","permission_mode":"default","hook_event_name":"PostToolUseFailure",
	"tool_name":"Bash","tool_input":{"command":"npm test","description":"Run test suite"},"tool_use_id":"toolu_01ABC123",
	"error":"Exit code 1\nError: Cannot find module 'express'","is_interrupt":false,"duration_ms":4187}`)
	a := Build("claude-code", "PostToolUseFailure", p, nil, Options{})
	if a.Success == nil || *a.Success || a.ExitCode == nil || *a.ExitCode != 1 {
		t.Fatalf("%+v", a)
	}
	if a.DurationMS == nil || *a.DurationMS != 4187 || a.DurationFrom != "agent" {
		t.Fatalf("duration %+v", a)
	}
}

func TestClaudeBashSuccess(t *testing.T) {
	p := payload(t, `{"session_id":"abc123","cwd":"/p","hook_event_name":"PostToolUse","tool_name":"Bash",
	"tool_input":{"command":"ls"},"tool_response":{"stdout":"README.md\nmain.go","stderr":"","interrupted":false,"isImage":false},
	"tool_use_id":"toolu_02","duration_ms":12}`)
	a := Build("claude-code", "PostToolUse", p, nil, Options{})
	if a.Success == nil || !*a.Success || !strings.Contains(a.Output, "README.md\nmain.go") {
		t.Fatalf("%+v", a)
	}
}

// Gemini CLI AfterTool: tool_response {llmContent, returnDisplay, error}.
func TestGeminiAfterToolError(t *testing.T) {
	p := payload(t, `{"session_id":"g1","cwd":"/p","hook_event_name":"AfterTool","timestamp":"2026-11-15T12:00:00Z",
	"tool_name":"read_file","tool_input":{"file_path":"/p/missing.txt"},
	"tool_response":{"llmContent":"File not found","returnDisplay":"File not found","error":{"message":"ENOENT: no such file","type":"FILE_NOT_FOUND"}}}`)
	a := Build("gemini", "AfterTool", p, []string{"/p/missing.txt"}, Options{})
	if a.Success == nil || *a.Success || !strings.Contains(a.Error, "ENOENT") {
		t.Fatalf("%+v", a)
	}
}

func TestPromptSummaryAndFull(t *testing.T) {
	long := strings.Repeat("修复登录页面的样式问题，", 40) + " 用这个 key: sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456"
	p := map[string]any{"session_id": "s", "hook_event_name": "UserPromptSubmit", "prompt": long, "turn_id": "3"}
	a := Build("codex", "UserPromptSubmit", p, nil, Options{})
	if a.PromptFull || len([]rune(a.Prompt)) > PromptLimit+1 || !a.Truncated || a.PromptChars != len([]rune(long)) {
		t.Fatalf("summary %+v", a)
	}
	if strings.Contains(a.Prompt, "sk-proj") {
		t.Fatal("secret leaked into summary")
	}
	full := Build("codex", "UserPromptSubmit", p, nil, Options{FullPrompts: true})
	if !full.PromptFull || strings.Contains(full.Prompt, "sk-proj-AbCd") || !strings.Contains(full.Prompt, "[REDACTED]") {
		t.Fatalf("full %+v", full)
	}
	if len([]rune(full.Prompt)) < 400 {
		t.Fatalf("full prompt was cut: %d", len([]rune(full.Prompt)))
	}
}

func TestSessionAndStop(t *testing.T) {
	st := Build("workbuddy", "SessionStart", map[string]any{"hook_event_name": "SessionStart", "source": "startup"}, nil, Options{})
	if st.Source != "startup" {
		t.Fatalf("%+v", st)
	}
	end := Build("codex", "SessionEnd", map[string]any{"reason": "other"}, nil, Options{})
	if end.Reason != "other" {
		t.Fatalf("%+v", end)
	}
	stop := Build("codex", "Stop", map[string]any{"last_assistant_message": "Done. Tests pass.", "stop_hook_active": false}, nil, Options{})
	if stop.Message != "Done. Tests pass." {
		t.Fatalf("%+v", stop)
	}
	if typ, ok := Type("AfterAgent"); !ok || typ != TypeStop {
		t.Fatal("AfterAgent")
	}
	if _, ok := Type("Notification"); ok {
		t.Fatal("Notification is not recorded")
	}
}

// Codex apply_patch PostToolUse: the response text starts with the exit code
// (seen in a live Codex 0.151 run on 2026-11-15).
func TestCodexApplyPatchExitCode(t *testing.T) {
	p := map[string]any{"hook_event_name": "PostToolUse", "tool_name": "apply_patch", "tool_use_id": "exec-d9c6f835",
		"tool_response": "Exit code: 0\nWall time: 0.2 seconds\nOutput:\nSuccess. Updated the following files:\nA /Users/dev/proj/NOTES.md\n"}
	a := Build("codex", "PostToolUse", p, []string{"/Users/dev/proj/NOTES.md"}, Options{})
	if a.ExitCode == nil || *a.ExitCode != 0 || a.Success == nil || !*a.Success || len(a.Files) != 1 {
		t.Fatalf("%+v", a)
	}
}
