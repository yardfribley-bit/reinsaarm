package hooks

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Event names that carry an authorization decision. Every other hook event
// is observation only: the hook records it and never blocks.
//
// An empty hook_event_name is treated as a decision event so callers that
// only send tool_name and tool_input keep the fail-closed behaviour.
func IsDecisionEvent(name string) bool {
	switch name {
	case "", "PreToolUse", "BeforeTool":
		return true
	}
	return false
}

// ObservedEvents lists the observation events each client's hook understands.
// Event names and payloads were checked on 2026-11-15:
//   - codex: openai/codex rust-v0.151.0 codex-rs/hooks/schema/generated/*.input.schema.json
//   - claude-code: code.claude.com/docs/en/hooks
//   - gemini: geminicli.com/docs/hooks/reference (Apr 10, 2026)
//   - workbuddy: WorkBuddy AI 5.9.4 bundled CLI (convertToSdkInput,
//     executePostToolUseHooks, SessionHookManager) and bundled docs/en/cli/hooks.md
//   - codebuddy: the same CodeBuddy Code hooks reference bundled with WorkBuddy
var ObservedEvents = map[string][]string{
	ClientCodex:     {"PostToolUse", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"},
	ClientClaude:    {"PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"},
	ClientGemini:    {"AfterTool", "SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent"},
	ClientWorkBuddy: {"PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"},
	ClientCodeBuddy: {"PostToolUse", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"},
}

// Observes reports whether client's hook records event.
func Observes(client, event string) bool {
	for _, e := range ObservedEvents[client] {
		if e == event {
			return true
		}
	}
	return false
}

// NeutralOutput is what an observation hook prints: nothing, except for
// Gemini CLI, which parses stdout as JSON on exit 0, so it gets "{}".
// Codex, Claude Code, and WorkBuddy add plain stdout from SessionStart and
// UserPromptSubmit hooks to the model context, so those stay silent.
func NeutralOutput(client string) []byte {
	if client == ClientGemini {
		return []byte("{}\n")
	}
	return nil
}

// PeekEvent reads hook_event_name from raw hook JSON.
func PeekEvent(raw []byte) (string, error) {
	var head struct {
		Event string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", err
	}
	return head.Event, nil
}

// Clip limits for observation payloads sent to the sidecar.
const (
	clipString = 4096
	clipItems  = 64
	clipDepth  = 6
)

// ClipPayload returns a copy of a hook payload with long strings cut to a few
// KiB, long arrays shortened, and deep nesting dropped. A Read result or a
// long build log is summarized in the sidecar, so the full text never needs
// to cross the socket.
func ClipPayload(v map[string]any) map[string]any {
	out, _ := clip(v, 0).(map[string]any)
	return out
}

func clip(v any, depth int) any {
	if depth > clipDepth {
		return fmt.Sprintf("[nested %T]", v)
	}
	switch t := v.(type) {
	case string:
		if len(t) <= clipString {
			return t
		}
		cut := clipString
		for cut > 0 && !utf8.RuneStart(t[cut]) {
			cut--
		}
		return t[:cut] + "…"
	case []any:
		n := len(t)
		if n > clipItems {
			n = clipItems
		}
		out := make([]any, 0, n)
		for _, x := range t[:n] {
			out = append(out, clip(x, depth+1))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if strings.HasPrefix(k, "_") {
				continue
			}
			out[k] = clip(x, depth+1)
		}
		return out
	default:
		return v
	}
}

// ObserveRequest builds the sidecar request for one observation event.
func ObserveRequest(client string, payload map[string]any) Request {
	str := func(k string) string { s, _ := payload[k].(string); return s }
	input, _ := payload["tool_input"].(map[string]any)
	req := Request{
		Schema:    SchemaObserve,
		Client:    client,
		SessionID: str("session_id"),
		CWD:       str("cwd"),
		Tool:      str("tool_name"),
		Input:     ClipPayload(input),
		ToolUseID: str("tool_use_id"),
		TurnID:    str("turn_id"),
		Event:     str("hook_event_name"),
		Payload:   ClipPayload(payload),
	}
	if req.ToolUseID == "" {
		req.ToolUseID = str("call_id")
	}
	if mc, ok := payload["mcp_context"].(map[string]any); ok {
		sn, _ := mc["server_name"].(string)
		tn, _ := mc["tool_name"].(string)
		req.MCPContext = &MCPContext{ServerName: sn, ToolName: tn}
	}
	if req.Payload != nil {
		delete(req.Payload, "tool_input")
	}
	return req
}
