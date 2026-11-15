// Package hooks parses coding-agent hook input and renders each CLI's documented
// decision JSON.
//
// Field names were checked against public docs on 2026-11-15 and were not
// executed against a live CLI binary. See docs/hooks.md.
package hooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/extract"
)

// Clients the hook binary understands.
const (
	ClientClaude    = "claude-code"
	ClientCodex     = "codex"
	ClientGemini    = "gemini"
	ClientCodeBuddy = "codebuddy"
	// ClientWorkBuddy is Tencent WorkBuddy (desktop). It embeds the
	// CodeBuddy Code CLI hook runner, but its decision parsing differs from
	// the CodeBuddy IDE docs in ways that matter; see renderWorkBuddy and
	// docs/workbuddy.md.
	ClientWorkBuddy = "workbuddy"
)

// Input is the common subset of a pre-tool hook payload.
type Input struct {
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
	HookEvent      string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	PermissionMode string         `json:"permission_mode"`
	// ToolUseID pairs a PreToolUse call with its PostToolUse result. Codex
	// 0.151, Claude Code, and WorkBuddy send it; Gemini CLI does not.
	ToolUseID string `json:"tool_use_id,omitempty"`
	// TurnID is Codex's per-turn id.
	TurnID string `json:"turn_id,omitempty"`
	// MCPDescription is optional. CLIs do not currently put tool descriptions
	// on PreToolUse; callers and tests may set it.
	MCPDescription string `json:"mcp_description,omitempty"`
	// MCPDefinitionHash is optional and not part of the documented hook schema.
	MCPDefinitionHash string `json:"mcp_definition_hash,omitempty"`
	// MCPContext is Gemini CLI's BeforeTool mcp_context (server_name,
	// tool_name, transport details). Other CLIs do not send it.
	MCPContext *MCPContext `json:"mcp_context,omitempty"`
}

// MCPContext is the part of Gemini's mcp_context the sidecar uses.
type MCPContext struct {
	ServerName string `json:"server_name,omitempty"`
	ToolName   string `json:"tool_name,omitempty"`
}

// Request is what the hook sends to the sidecar.
type Request struct {
	Schema            string         `json:"schema"`
	Client            string         `json:"client"`
	SessionID         string         `json:"session_id"`
	CWD               string         `json:"cwd"`
	Intent            string         `json:"intent,omitempty"`
	Tool              string         `json:"tool"`
	Input             map[string]any `json:"input,omitempty"`
	MCPDescription    string         `json:"mcp_description,omitempty"`
	MCPDefinitionHash string         `json:"mcp_definition_hash,omitempty"`
	MCPContext        *MCPContext    `json:"mcp_context,omitempty"`
	ToolUseID         string         `json:"tool_use_id,omitempty"`
	TurnID            string         `json:"turn_id,omitempty"`
	// Event and Payload are set on reinsaarm.observe.v1 requests only:
	// Event is the agent's hook event name and Payload the hook JSON with
	// long strings clipped (see ClipPayload).
	Event   string         `json:"event,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}

// Request schemas.
const (
	SchemaDecide  = "reinsaarm.decide.v1"
	SchemaObserve = "reinsaarm.observe.v1"
)

// Response is the sidecar decision.
type Response struct {
	Schema      string   `json:"schema"`
	Decision    string   `json:"decision"`
	Enforced    string   `json:"enforced"`
	Tier        string   `json:"tier"`
	RuleIDs     []string `json:"rule_ids"`
	Reason      string   `json:"reason"`
	Rewrite     string   `json:"rewrite,omitempty"`
	ApprovalID  string   `json:"approval_id,omitempty"`
	ReceiptSeq  uint64   `json:"receipt_seq"`
	ReceiptHash string   `json:"receipt_hash"`
	LatencyUS   int64    `json:"latency_us"`
	Degraded    bool     `json:"degraded"`
	Shadow      bool     `json:"shadow"`
}

// Parse reads a hook payload from stdin. A missing tool_input becomes an empty map.
func Parse(r io.Reader) (Input, error) {
	var in Input
	dec := json.NewDecoder(r)
	if err := dec.Decode(&in); err != nil {
		return Input{}, err
	}
	if in.ToolInput == nil {
		in.ToolInput = map[string]any{}
	}
	if in.ToolName == "" {
		return Input{}, fmt.Errorf("hook: tool_name is required")
	}
	return in, nil
}

// ToRequest builds a sidecar request. The sidecar re-extracts commands and hosts.
func ToRequest(client string, in Input) Request {
	return Request{
		Schema:            SchemaDecide,
		Client:            client,
		SessionID:         in.SessionID,
		ToolUseID:         in.ToolUseID,
		TurnID:            in.TurnID,
		CWD:               in.CWD,
		Tool:              in.ToolName,
		Input:             in.ToolInput,
		MCPDescription:    in.MCPDescription,
		MCPDefinitionHash: in.MCPDefinitionHash,
		MCPContext:        in.MCPContext,
	}
}

// Exchange dials the sidecar once and returns its decision.
func Exchange(socket string, req Request, timeout time.Duration) (Response, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// RenderResult is stdout JSON plus the process exit code.
type RenderResult struct {
	Stdout   []byte
	Stderr   string
	ExitCode int
}

// ProjectEnforced is the decision the hook process actually applies.
// Codex and Gemini have no fail-closed ask, so STEP_UP and DEFER become DENY.
// Claude Code, CodeBuddy, and WorkBuddy can ask, so STEP_UP stays STEP_UP. DEFER is deny
// on every adapter in this MVP.
func ProjectEnforced(client string, d decision.Decision) decision.Decision {
	switch client {
	case ClientCodex, ClientGemini:
		if d == decision.StepUp || d == decision.Defer {
			return decision.Deny
		}
	case ClientClaude, ClientCodeBuddy, ClientWorkBuddy:
		if d == decision.Defer {
			return decision.Deny
		}
	}
	return d
}

// Render projects an enforced decision onto one CLI's hook output.
// Exit 0 is used for a well-formed decision. Exit 2 is reserved for a sidecar
// failure. Exit 1 is never used: these CLIs continue the tool call on a generic
// non-zero status. Codex treats exit 2 with empty stderr as a hook failure and
// then continues, so FailClosed always writes a reason to stderr.
func Render(client string, in Input, resp Response) (RenderResult, error) {
	enforced := decision.Decision(resp.Enforced)
	if enforced == "" {
		enforced = decision.Decision(resp.Decision)
	}
	reason := resp.Reason
	if resp.ApprovalID != "" && !strings.Contains(reason, resp.ApprovalID) {
		reason = fmt.Sprintf("%s (approval %s; reinsaarm approve %s)", reason, resp.ApprovalID, resp.ApprovalID)
	}
	switch client {
	case ClientClaude:
		return renderClaude(in, enforced, reason, resp.Rewrite)
	case ClientCodex:
		return renderCodex(in, enforced, reason, resp.Rewrite)
	case ClientGemini:
		return renderGemini(in, enforced, reason, resp.Rewrite)
	case ClientCodeBuddy:
		return renderCodeBuddy(in, enforced, reason, resp.Rewrite)
	case ClientWorkBuddy:
		return renderWorkBuddy(in, enforced, reason, resp.Rewrite)
	default:
		return RenderResult{}, fmt.Errorf("hook: unknown client %q", client)
	}
}

// FailClosed is the output when the sidecar cannot be reached.
// Codex 0.151 fails open on exit 2 when stderr is empty, so stderr is never empty.
func FailClosed(client, reason string) RenderResult {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "reinsaarm hook failed"
	}
	resp := Response{Decision: string(decision.Deny), Enforced: string(decision.Deny), Reason: "reinsaarm sidecar unavailable: " + reason, Tier: "T0", RuleIDs: []string{"R-SIDECAR-DOWN"}}
	in := Input{ToolInput: map[string]any{}}
	out, err := Render(client, in, resp)
	if err != nil {
		out = RenderResult{ExitCode: 2}
	}
	out.Stderr = "reinsaarm: " + reason + "\n"
	out.ExitCode = 2
	return out
}

func renderClaude(in Input, d decision.Decision, reason, rewrite string) (RenderResult, error) {
	spec := map[string]any{"hookEventName": "PreToolUse"}
	switch d {
	case decision.Allow:
		spec["permissionDecision"] = "allow"
	case decision.Modify:
		spec["permissionDecision"] = "allow"
		spec["permissionDecisionReason"] = reason
		spec["updatedInput"] = rewrittenInput(in.ToolInput, rewrite)
	case decision.StepUp:
		// ask is documented for PreToolUse. defer needs non-interactive -p and
		// is not used here; see docs/hooks.md.
		spec["permissionDecision"] = "ask"
		spec["permissionDecisionReason"] = reason
	case decision.Defer, decision.Deny:
		spec["permissionDecision"] = "deny"
		spec["permissionDecisionReason"] = reason
	default:
		spec["permissionDecision"] = "deny"
		spec["permissionDecisionReason"] = reason
	}
	return marshalOut(map[string]any{"hookSpecificOutput": spec})
}

func renderCodex(in Input, d decision.Decision, reason, rewrite string) (RenderResult, error) {
	// Codex 0.151 rejects a bare permissionDecision "allow" and continues the
	// tool call (permission_decision_allow_without_updated_input_fails_open).
	// Silence on stdout with exit 0 leaves Codex's own permission flow in place.
	// "ask" is parsed and then ignored the same way, so STEP_UP is deny.
	switch d {
	case decision.Allow:
		return RenderResult{ExitCode: 0}, nil
	case decision.Modify:
		if strings.TrimSpace(rewrite) == "" {
			return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			}})
		}
		return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "allow",
			"permissionDecisionReason": reason,
			"updatedInput":             rewrittenInput(in.ToolInput, rewrite),
		}})
	default:
		return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		}})
	}
}

func renderGemini(in Input, d decision.Decision, reason, rewrite string) (RenderResult, error) {
	// Gemini has decision allow/deny. There is no ask. Rewrite is a merge of
	// hookSpecificOutput.tool_input, so only the command key is sent.
	switch d {
	case decision.Allow:
		return marshalOut(map[string]any{"decision": "allow"})
	case decision.Modify:
		body := map[string]any{"decision": "allow", "reason": reason}
		if rewrite != "" {
			body["hookSpecificOutput"] = map[string]any{"tool_input": map[string]any{"command": rewrite}}
		}
		return marshalOut(body)
	default:
		return marshalOut(map[string]any{"decision": "deny", "reason": reason})
	}
}

func renderCodeBuddy(in Input, d decision.Decision, reason, rewrite string) (RenderResult, error) {
	// CodeBuddy IDE docs use modifiedInput, not Claude's updatedInput, and
	// permissionDecision allow/deny/ask. Exit code 2 ignores stdout, so a
	// normal decision stays on exit 0.
	spec := map[string]any{"hookEventName": "PreToolUse"}
	cont := true
	switch d {
	case decision.Allow:
		spec["permissionDecision"] = "allow"
	case decision.Modify:
		spec["permissionDecision"] = "allow"
		spec["permissionDecisionReason"] = reason
		spec["modifiedInput"] = rewrittenInput(in.ToolInput, rewrite)
	case decision.StepUp:
		spec["permissionDecision"] = "ask"
		spec["permissionDecisionReason"] = reason
	default:
		cont = false
		spec["permissionDecision"] = "deny"
		spec["permissionDecisionReason"] = reason
	}
	return marshalOut(map[string]any{"continue": cont, "hookSpecificOutput": spec})
}

func renderWorkBuddy(in Input, d decision.Decision, reason, rewrite string) (RenderResult, error) {
	// Checked against the CLI bundled in WorkBuddy 5.5.6 and WorkBuddy AI
	// 5.9.4 (app.asar.unpacked/cli/dist), see docs/workbuddy.md:
	//   - ALLOW is empty stdout with exit 0. permissionDecision "allow" would
	//     bypass WorkBuddy's own permission prompt and sandbox approval; an
	//     empty answer leaves them in place, so ReinsAARM only ever tightens.
	//   - "continue": false sets preventContinuation and ends the whole
	//     agent turn, so DENY never sends it. A deny blocks this tool call and
	//     hands permissionDecisionReason back to the model.
	//   - ask shows WorkBuddy's confirmation dialog. In headless (-p) runs
	//     WorkBuddy auto-denies an ask because there is no approval UI.
	//   - The PreToolUse result reads hookSpecificOutput.updatedInput; the
	//     command-hook parser also copies modifiedInput. MODIFY sends both
	//     with the full input.
	switch d {
	case decision.Allow:
		return RenderResult{ExitCode: 0}, nil
	case decision.Modify:
		full := rewrittenInput(in.ToolInput, rewrite)
		return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "allow",
			"permissionDecisionReason": reason,
			"updatedInput":             full,
			"modifiedInput":            full,
		}})
	case decision.StepUp:
		return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "ask",
			"permissionDecisionReason": reason,
		}})
	default:
		return marshalOut(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		}})
	}
}

func rewrittenInput(in map[string]any, command string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	if command != "" {
		out["command"] = command
	}
	return out
}

func marshalOut(v any) (RenderResult, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return RenderResult{}, err
	}
	return RenderResult{Stdout: buf.Bytes(), ExitCode: 0}, nil
}

// ReadStdin parses hook JSON from stdin.
func ReadStdin() (Input, error) {
	return Parse(os.Stdin)
}

// KindOf is a convenience for tests and the daemon.
func KindOf(tool string) string { return extract.Kind(tool) }
