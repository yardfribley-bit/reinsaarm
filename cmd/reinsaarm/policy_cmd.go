package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/policy"
	"github.com/yardfribley-bit/reinsaarm/internal/simulate"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: reinsaarm policy test [flags] [shell command]")
	}
	switch args[0] {
	case "test", "simulate":
		return cmdPolicyTest(args[1:], os.Stdin, os.Stdout)
	default:
		return fmt.Errorf("unknown policy subcommand %q (test)", args[0])
	}
}

// cmdPolicyTest evaluates one input against the current profile. It reads the
// profile only; it does not contact the sidecar, write a receipt, or touch
// approvals.
func cmdPolicyTest(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlag("policy test")
	home := fs.String("home", "", "state directory")
	profile := fs.String("profile", "", "profile YAML (default: the state directory's profile, else the built-in profile)")
	kind := fs.String("kind", "", "shell|file_read|file_write|file_edit|web_fetch|mcp|other (default shell)")
	var paths multiFlag
	fs.Var(&paths, "path", "file path (repeatable)")
	url := fs.String("url", "", "URL for --kind web_fetch")
	server := fs.String("server", "", "MCP server for --kind mcp")
	tool := fs.String("tool", "", "MCP tool for --kind mcp, or the tool name for --kind other")
	argsJSON := fs.String("args", "", "JSON object of tool arguments for --kind mcp|other")
	agent := fs.String("agent", "", "codex|claude-code|gemini|codebuddy|workbuddy: show how that agent's hook enforces the result")
	payload := fs.String("json", "", "raw PreToolUse hook payload: JSON text, @file, or - for stdin")
	cwd := fs.String("cwd", "", "workspace directory (default: current directory)")
	output := fs.String("output", "text", "text|json")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	in := simulate.Input{
		Command: strings.Join(fs.Args(), " "),
		Kind:    *kind,
		URL:     *url,
		Server:  *server,
		Tool:    *tool,
		Agent:   *agent,
		CWD:     *cwd,
	}
	for _, p := range paths {
		for _, part := range strings.Split(p, ",") {
			if s := strings.TrimSpace(part); s != "" {
				in.Paths = append(in.Paths, s)
			}
		}
	}
	if *argsJSON != "" {
		if err := json.Unmarshal([]byte(*argsJSON), &in.Args); err != nil {
			return fmt.Errorf("--args: %w", err)
		}
	}
	if *payload != "" {
		raw, err := readPayload(*payload, stdin)
		if err != nil {
			return err
		}
		in.Payload = raw
	}
	if in.CWD == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		in.CWD = wd
	}
	eng, prof, source, err := loadPolicyForTest(*home, *profile)
	if err != nil {
		return err
	}
	res, err := simulate.Run(eng, prof, in)
	if err != nil {
		return err
	}
	if *output == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(struct {
			simulate.Result
			Profile string `json:"profile"`
		}{res, source})
	}
	printResult(stdout, res, source)
	return nil
}

func readPayload(v string, stdin io.Reader) ([]byte, error) {
	switch {
	case v == "-":
		return io.ReadAll(io.LimitReader(stdin, 1<<20))
	case strings.HasPrefix(v, "@"):
		return os.ReadFile(strings.TrimPrefix(v, "@"))
	default:
		return []byte(v), nil
	}
}

func loadPolicyForTest(home, profilePath string) (*policy.Engine, *policy.Profile, string, error) {
	devHome, _ := os.UserHomeDir()
	source := profilePath
	if source == "" {
		if cfg, err := loadConfig(home); err == nil {
			source = cfg.Profile
			if cfg.DeveloperHome != "" {
				devHome = cfg.DeveloperHome
			}
		}
	}
	if source != "" {
		if _, err := os.Stat(source); err == nil {
			p, raw, err := policy.LoadFile(source)
			if err != nil {
				return nil, nil, "", err
			}
			return policy.Compile(p, devHome, raw), p, source, nil
		} else if profilePath != "" {
			return nil, nil, "", err
		}
	}
	raw := policy.DefaultYAML()
	p, err := policy.Load(raw)
	if err != nil {
		return nil, nil, "", err
	}
	return policy.Compile(p, devHome, raw), p, "built-in default profile", nil
}

func printResult(w io.Writer, r simulate.Result, source string) {
	fmt.Fprintf(w, "decision: %s\n", r.Decision)
	if r.Enforced != r.Decision {
		fmt.Fprintf(w, "enforced: %s\n", r.Enforced)
	}
	if r.Agent != "" {
		fmt.Fprintf(w, "agent:    %s enforces %s\n", r.Agent, r.AgentEnforced)
	}
	fmt.Fprintf(w, "rules:    %s\n", strings.Join(r.RuleIDs, ", "))
	fmt.Fprintf(w, "reason:   %s\n", r.Reason)
	if r.Rewrite != "" {
		fmt.Fprintf(w, "rewrite:  %s\n", r.Rewrite)
	}
	fmt.Fprintf(w, "kind:     %s (%s)\n", r.Action.Kind, r.Action.Tool)
	if r.Action.Command != "" {
		fmt.Fprintf(w, "command:  %s\n", r.Action.Command)
	}
	if len(r.Action.Paths) > 0 {
		fmt.Fprintf(w, "paths:    %s\n", strings.Join(r.Action.Paths, ", "))
	}
	if len(r.Action.Hosts) > 0 {
		fmt.Fprintf(w, "hosts:    %s\n", strings.Join(r.Action.Hosts, ", "))
	}
	if len(r.Action.GitOps) > 0 {
		fmt.Fprintf(w, "git:      %s\n", strings.Join(r.Action.GitOps, ", "))
	}
	if r.Action.MCPServer != "" || r.Action.MCPTool != "" {
		fmt.Fprintf(w, "mcp:      %s / %s\n", r.Action.MCPServer, r.Action.MCPTool)
	}
	fmt.Fprintf(w, "policy:   %s (mode %s, %s)\n", r.PolicyVersion, r.Mode, source)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note:     %s\n", n)
	}
}
