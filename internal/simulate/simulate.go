// Package simulate evaluates one input against a policy without running it.
// It never opens the audit ledger, never creates or consumes an approval, and
// never calls the judge. The CLI (`reinsaarm policy test`) and the console
// (POST /api/policy/test) share it.
package simulate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/hooks"
	"github.com/yardfribley-bit/reinsaarm/internal/normalize"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

// Input is one thing to test. Either Payload (a raw PreToolUse hook payload)
// or Kind plus its fields. An empty Kind with a Command is a shell command.
type Input struct {
	Command string          `json:"command,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	Paths   []string        `json:"paths,omitempty"`
	URL     string          `json:"url,omitempty"`
	Server  string          `json:"server,omitempty"`
	Tool    string          `json:"tool,omitempty"`
	Args    map[string]any  `json:"args,omitempty"`
	Agent   string          `json:"agent,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	CWD     string          `json:"cwd,omitempty"`
}

// ActionView is the normalized action shown to the user.
type ActionView struct {
	Client    string   `json:"client,omitempty"`
	Tool      string   `json:"tool"`
	Kind      string   `json:"kind"`
	Command   string   `json:"command,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	GitOps    []string `json:"git_ops,omitempty"`
	MCPServer string   `json:"mcp_server,omitempty"`
	MCPTool   string   `json:"mcp_tool,omitempty"`
	CWD       string   `json:"cwd,omitempty"`
}

// Result is the simulated decision.
type Result struct {
	Decision      string     `json:"decision"`
	Enforced      string     `json:"enforced"`
	Agent         string     `json:"agent,omitempty"`
	AgentEnforced string     `json:"agent_enforced,omitempty"`
	Tier          string     `json:"tier"`
	RuleIDs       []string   `json:"rule_ids"`
	Reason        string     `json:"reason"`
	Rewrite       string     `json:"rewrite,omitempty"`
	Shadow        bool       `json:"shadow,omitempty"`
	Degraded      bool       `json:"degraded,omitempty"`
	PolicyVersion string     `json:"policy_version"`
	Mode          string     `json:"mode"`
	Action        ActionView `json:"action"`
	Notes         []string   `json:"notes,omitempty"`
}

var errNoJudge = errors.New("simulation does not call the judge")

// AgentName maps aliases to a hooks client name. Empty stays empty.
func AgentName(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "codex":
		return hooks.ClientCodex, nil
	case "claude", "claude-code", "claudecode":
		return hooks.ClientClaude, nil
	case "gemini", "gemini-cli":
		return hooks.ClientGemini, nil
	case "codebuddy":
		return hooks.ClientCodeBuddy, nil
	case "workbuddy", "workbuddy-ai":
		return hooks.ClientWorkBuddy, nil
	default:
		return "", fmt.Errorf("unknown agent %q (codex, claude-code, gemini, codebuddy, workbuddy)", s)
	}
}

// Call turns an Input into a normalization call.
func Call(in Input) (normalize.Call, error) {
	agent, err := AgentName(in.Agent)
	if err != nil {
		return normalize.Call{}, err
	}
	if len(bytes.TrimSpace(in.Payload)) > 0 {
		hin, err := hooks.Parse(bytes.NewReader(in.Payload))
		if err != nil {
			return normalize.Call{}, fmt.Errorf("payload: %w", err)
		}
		if hin.CWD == "" {
			hin.CWD = in.CWD
		}
		req := hooks.ToRequest(agent, hin)
		c := normalize.Call{
			Client: agent, Tool: req.Tool, Input: req.Input, CWD: req.CWD,
			MCPDescription: req.MCPDescription, MCPDefinitionHash: req.MCPDefinitionHash,
		}
		if req.MCPContext != nil {
			c.MCPContext = &normalize.MCPContext{ServerName: req.MCPContext.ServerName, ToolName: req.MCPContext.ToolName}
		}
		return c, nil
	}
	c := normalize.Call{Client: agent, CWD: in.CWD, Input: map[string]any{}}
	paths := nonEmpty(in.Paths)
	setPaths := func(key string) error {
		switch len(paths) {
		case 0:
			return fmt.Errorf("kind %s needs a path", in.Kind)
		case 1:
			c.Input[key] = paths[0]
		default:
			arr := make([]any, len(paths))
			for i, p := range paths {
				arr[i] = p
			}
			c.Input["paths"] = arr
		}
		return nil
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	switch kind {
	case "", "shell":
		if strings.TrimSpace(in.Command) == "" {
			return c, errors.New("a shell command is required")
		}
		c.Tool = orDefault(in.Tool, "Bash")
		c.Input["command"] = in.Command
	case "file_read":
		c.Tool = orDefault(in.Tool, "Read")
		if err := setPaths("file_path"); err != nil {
			return c, err
		}
	case "file_write":
		c.Tool = orDefault(in.Tool, "Write")
		if err := setPaths("file_path"); err != nil {
			return c, err
		}
	case "file_edit":
		c.Tool = orDefault(in.Tool, "Edit")
		if err := setPaths("file_path"); err != nil {
			return c, err
		}
	case "web_fetch", "network":
		if in.URL == "" {
			return c, errors.New("kind web_fetch needs a url")
		}
		c.Tool = "WebFetch"
		c.Input["url"] = in.URL
	case "mcp":
		if in.Server == "" || in.Tool == "" {
			return c, errors.New("kind mcp needs a server and a tool")
		}
		c.Tool = "mcp__" + in.Server + "__" + in.Tool
		for k, v := range in.Args {
			c.Input[k] = v
		}
	case "other":
		if in.Tool == "" {
			return c, errors.New("kind other needs a tool name")
		}
		c.Tool = in.Tool
		for k, v := range in.Args {
			c.Input[k] = v
		}
		if len(paths) == 1 {
			c.Input["path"] = paths[0]
		}
	default:
		return c, fmt.Errorf("unknown kind %q (%s)", in.Kind, strings.Join(normalize.Kinds, ", "))
	}
	if in.Command != "" && kind != "" && kind != "shell" {
		c.Input["command"] = in.Command
	}
	return c, nil
}

// Run evaluates in against a compiled policy. It performs no I/O.
func Run(eng *policy.Engine, prof *policy.Profile, in Input) (Result, error) {
	call, err := Call(in)
	if err != nil {
		return Result{}, err
	}
	a := normalize.Action(call)
	out := eng.Evaluate(a, policy.Context{Intent: ""})
	var jerr error
	notes := []string{"simulation only: nothing ran, no receipt was written, no approval was created or used"}
	if out.Decision == decision.Gray {
		if prof.Spec.Judge.Enabled {
			jerr = errNoJudge
			notes = append(notes, "gray zone: the judge is not called in simulation; the result shows the no-verdict path")
		} else {
			notes = append(notes, "gray zone: judge disabled; failMode decides")
		}
	}
	comp := policy.Compose(out, nil, jerr, prof.Spec.Mode, prof.Spec.FailMode, prof.Spec.Unattended, prof.Spec.Judge.MinConfidence)
	res := Result{
		Decision:      string(comp.Decision),
		Enforced:      string(comp.Enforced),
		Tier:          comp.Tier,
		RuleIDs:       comp.RuleIDs,
		Reason:        comp.Reason,
		Rewrite:       comp.Rewrite,
		Shadow:        comp.Shadow,
		Degraded:      comp.Degraded,
		PolicyVersion: eng.Version(),
		Mode:          prof.Spec.Mode,
		Action: ActionView{
			Client: a.Client, Tool: a.Tool, Kind: a.Kind, Command: a.Command,
			Paths: a.Paths, Hosts: a.Hosts, GitOps: a.GitOps,
			MCPServer: a.MCPServer, MCPTool: a.MCPTool, CWD: a.CWD,
		},
	}
	if call.Client != "" {
		res.Agent = call.Client
		res.AgentEnforced = string(hooks.ProjectEnforced(call.Client, comp.Enforced))
	}
	if comp.Enforced == decision.StepUp {
		notes = append(notes, "a real call would get a one-time approval id; an already approved grant for the same arguments would turn it into ALLOW")
	}
	if a.Kind == "other" {
		notes = append(notes, "unknown tool: normalized as other; only path and URL arguments are checked")
	}
	res.Notes = notes
	return res, nil
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if p := strings.TrimSpace(s); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
