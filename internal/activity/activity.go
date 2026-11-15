// Package activity turns observation hook payloads (tool results, prompts,
// session start and end, agent stop) into the Activity part of a receipt.
//
// Payload shapes, checked on 2026-11-15 (see docs/activity.md):
//
//   - Codex 0.151 PostToolUse: tool_response is the tool's model-facing
//     output. For Bash it is a string (the command output, no exit code);
//     for apply_patch it is the patch result text.
//   - Claude Code PostToolUse: tool_response is the tool's structured
//     output (Bash: stdout, stderr, interrupted; Write: filePath, type) plus
//     optional duration_ms. PostToolUseFailure carries error, is_interrupt,
//     duration_ms.
//   - Gemini CLI AfterTool: tool_response has llmContent, returnDisplay, and
//     optional error.
//   - WorkBuddy / CodeBuddy PostToolUse: tool_response is the tool's
//     rawResponse. For Bash: exitCode, signal, interrupted, is_error, error
//     (stderr, first 500 chars), no stdout. For Write: filePath, success.
//     WorkBuddy also sends PostToolUseFailure with error and is_interrupt.
package activity

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

// Event types written to the receipt's event_type.
const (
	TypeSessionStart = "session.start"
	TypeSessionEnd   = "session.end"
	TypePrompt       = "prompt.submit"
	TypeToolResult   = "tool.result"
	TypeStop         = "agent.stop"
)

// Limits for stored text, in runes.
const (
	OutputLimit     = 400
	ErrorLimit      = 300
	MessageLimit    = 300
	PromptLimit     = 240
	PromptFullLimit = 8000
	maxFiles        = 20
	maxFileLen      = 256
)

// Options controls what is stored.
type Options struct {
	// FullPrompts stores the whole prompt (secrets still masked, capped at
	// PromptFullLimit runes) instead of a short summary. Off by default; set
	// record_full_prompts: true in config.yaml.
	FullPrompts bool
}

// Type maps a hook event name to a receipt event type. ok is false for
// events ReinsAARM does not record.
func Type(hook string) (string, bool) {
	switch hook {
	case "PostToolUse", "PostToolUseFailure", "AfterTool":
		return TypeToolResult, true
	case "UserPromptSubmit", "BeforeAgent":
		return TypePrompt, true
	case "SessionStart":
		return TypeSessionStart, true
	case "SessionEnd":
		return TypeSessionEnd, true
	case "Stop", "AfterAgent":
		return TypeStop, true
	}
	return "", false
}

// Build summarizes one observation payload. The payload is the hook JSON
// (tool_input may be absent; file paths from it are passed in as paths).
func Build(client, hook string, payload map[string]any, paths []string, opt Options) *ledger.Activity {
	a := &ledger.Activity{Hook: hook}
	a.Model = str(payload, "model")
	a.PermissionMode = str(payload, "permission_mode")
	switch hook {
	case "SessionStart":
		a.Source = str(payload, "source")
		a.Message = clipText(str(payload, "session_title"), MessageLimit, a)
	case "SessionEnd":
		a.Reason = str(payload, "reason")
	case "UserPromptSubmit", "BeforeAgent":
		prompt := str(payload, "prompt")
		a.PromptChars = len([]rune(prompt))
		if opt.FullPrompts {
			p, cut := redact.Truncate(redact.Mask(prompt), PromptFullLimit)
			a.Prompt, a.PromptFull = p, true
			a.Truncated = a.Truncated || cut
		} else {
			a.Prompt = clipText(prompt, PromptLimit, a)
		}
	case "Stop", "AfterAgent":
		msg := str(payload, "last_assistant_message")
		if msg == "" {
			msg = str(payload, "prompt_response")
		}
		a.Message = clipText(msg, MessageLimit, a)
	case "PostToolUse", "PostToolUseFailure", "AfterTool":
		toolResult(client, hook, payload, a)
		a.Files = mergeFiles(paths, responseFiles(payload["tool_response"]))
	}
	return a
}

var exitLine = regexp.MustCompile(`(?m)^\s*(?:Exit code|Process exited with code|exit code|exit status)[:\s]+(-?\d+)`)

func toolResult(client, hook string, payload map[string]any, a *ledger.Activity) {
	resp := payload["tool_response"]
	if ms, ok := num(payload["duration_ms"]); ok {
		d := int64(ms)
		a.DurationMS = &d
		a.DurationFrom = "agent"
	}
	if hook == "PostToolUseFailure" {
		f := false
		a.Success = &f
		errText := str(payload, "error")
		a.Error = clipText(errText, ErrorLimit, a)
		if b, ok := payload["is_interrupt"].(bool); ok && b {
			a.Interrupted = true
		}
		if m := exitLine.FindStringSubmatch(errText); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				a.ExitCode = &n
			}
		}
		return
	}
	switch r := resp.(type) {
	case string:
		a.Output = clipText(r, OutputLimit, a)
	case map[string]any:
		if n, ok := firstNum(r, "exitCode", "exit_code", "returnCode", "return_code", "code"); ok {
			code := int(n)
			a.ExitCode = &code
		}
		if b, ok := r["interrupted"].(bool); ok && b {
			a.Interrupted = true
		}
		isErr := boolOf(r, "is_error") || boolOf(r, "isError")
		errText := firstText(r, "error", "stderr_error")
		if hook == "AfterTool" {
			if e, ok := r["error"].(map[string]any); ok {
				errText = firstText(e, "message")
			}
		}
		if errText != "" && (isErr || hook == "AfterTool" || client == "gemini") {
			a.Error = clipText(errText, ErrorLimit, a)
		}
		out := firstText(r, "stdout", "output", "result", "llmContent", "returnDisplay", "content", "text", "message")
		if se := firstText(r, "stderr"); se != "" && a.Error == "" {
			if out != "" {
				out += "\n"
			}
			out += "stderr: " + se
		}
		a.Output = clipText(out, OutputLimit, a)
		switch {
		case a.ExitCode != nil:
			ok := *a.ExitCode == 0 && !isErr
			a.Success = &ok
		case isErr || (hook == "AfterTool" && errText != ""):
			f := false
			a.Success = &f
		default:
			if b, ok := r["success"].(bool); ok {
				a.Success = &b
			}
		}
	case []any:
		a.Output = clipText(firstText(map[string]any{"content": r}, "content"), OutputLimit, a)
	case nil:
	default:
		a.Output = clipText(fmt.Sprint(r), OutputLimit, a)
	}
	if a.Success == nil && a.Interrupted {
		f := false
		a.Success = &f
	}
	// Claude Code, WorkBuddy, CodeBuddy, and Gemini fire this event only when
	// the tool finished without a tool error. Codex fires it for any produced
	// output, including a shell command that exited non-zero, and does not
	// report the exit code, so Codex results without an explicit signal stay
	// unknown.
	if a.Success == nil && client != "codex" {
		t := true
		a.Success = &t
	}
}

func responseFiles(resp any) []string {
	r, ok := resp.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	for _, k := range []string{"filePath", "file_path", "path"} {
		if s, ok := r[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	for _, k := range []string{"filenames", "files"} {
		if list, ok := r[k].([]any); ok {
			for _, x := range list {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func mergeFiles(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, p := range l {
			p = strings.TrimSpace(p)
			if p == "" || strings.Contains(p, "://") || seen[p] || len(out) >= maxFiles {
				continue
			}
			seen[p] = true
			v, _ := redact.Truncate(redact.Value(p), maxFileLen)
			out = append(out, v)
		}
	}
	return out
}

func clipText(s string, limit int, a *ledger.Activity) string {
	out, cut := redact.Text(s, limit)
	if cut {
		a.Truncated = true
	}
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func boolOf(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func num(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func firstNum(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if n, ok := num(m[k]); ok {
			return n, true
		}
	}
	return 0, false
}

// firstText returns the first non-empty text under keys. A content array of
// {type:"text", text:"..."} blocks (MCP results) is joined.
func firstText(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return v
			}
		case []any:
			var parts []string
			for _, x := range v {
				switch b := x.(type) {
				case string:
					parts = append(parts, b)
				case map[string]any:
					if t, ok := b["text"].(string); ok {
						parts = append(parts, t)
					}
				}
			}
			if len(parts) > 0 {
				return strings.Join(parts, "\n")
			}
		}
	}
	return ""
}
