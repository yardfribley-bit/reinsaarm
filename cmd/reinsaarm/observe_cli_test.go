package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Observation hooks must never block: exit 0 with neutral stdout even when
// the sidecar socket does not exist. The pre-tool hook still fails closed.
func TestObservationHookNeverBlocks(t *testing.T) {
	bin := buildBin(t)
	sock := filepath.Join(t.TempDir(), "missing.sock")
	run := func(client, payload string) (int, string, string) {
		cmd := exec.Command(bin, "hook", "--client", client, "--socket", sock)
		cmd.Stdin = strings.NewReader(payload)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), out.String(), errb.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, out.String(), errb.String()
	}
	for _, c := range []struct{ client, payload, stdout string }{
		{"codex", `{"session_id":"s","cwd":"/p","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"c1","tool_response":"a\nb","turn_id":"1","model":"m","permission_mode":"default","transcript_path":null}`, ""},
		{"codex", `{"session_id":"s","cwd":"/p","hook_event_name":"UserPromptSubmit","prompt":"hello","turn_id":"1","model":"m","permission_mode":"default","transcript_path":null}`, ""},
		{"workbuddy", `{"session_id":"s","hook_event_name":"SessionStart","source":"startup"}`, ""},
		{"workbuddy", `{"session_id":"s","hook_event_name":"Notification","message":"x"}`, ""},
		{"gemini", `{"session_id":"s","cwd":"/p","hook_event_name":"AfterTool","tool_name":"read_file","tool_input":{},"tool_response":{"llmContent":"x"}}`, "{}\n"},
	} {
		code, out, _ := run(c.client, c.payload)
		if code != 0 || out != c.stdout {
			t.Fatalf("%s %s: exit %d stdout %q", c.client, c.payload[:60], code, out)
		}
	}
	code, out, errText := run("codex", `{"session_id":"s","cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	if code != 2 || !strings.Contains(out, "deny") || strings.TrimSpace(errText) == "" {
		t.Fatalf("pre-tool must fail closed: %d %q %q", code, out, errText)
	}
}
