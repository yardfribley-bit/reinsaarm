package policy

import (
	"fmt"
	"path"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/extract"
)

// MCPRule matches an MCP call by server and tool name. Server and Tool are
// shell-style globs (path.Match), compared case-insensitively. An empty
// pattern matches anything, but at least one of them must be set.
type MCPRule struct {
	ID       string `yaml:"id" json:"id"`
	Server   string `yaml:"server" json:"server,omitempty"`
	Tool     string `yaml:"tool" json:"tool,omitempty"`
	Decision string `yaml:"decision" json:"decision"`
	Reason   string `yaml:"reason" json:"reason,omitempty"`
}

func (r *MCPRule) normalize(i int) error {
	r.Server = strings.ToLower(strings.TrimSpace(r.Server))
	r.Tool = strings.ToLower(strings.TrimSpace(r.Tool))
	if r.Server == "" && r.Tool == "" {
		return fmt.Errorf("profile: mcp.rules[%d] needs server or tool", i)
	}
	for _, pat := range []string{r.Server, r.Tool} {
		if pat == "" {
			continue
		}
		if _, err := path.Match(pat, ""); err != nil {
			return fmt.Errorf("profile: mcp.rules[%d] bad pattern %q", i, pat)
		}
	}
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.Decision), "-", "_")) {
	case "allow":
		r.Decision = string(decision.Allow)
	case "deny", "block":
		r.Decision = string(decision.Deny)
	case "step_up", "stepup", "ask":
		r.Decision = string(decision.StepUp)
	default:
		return fmt.Errorf("profile: mcp.rules[%d] decision %q (allow, deny, or step_up)", i, r.Decision)
	}
	if strings.TrimSpace(r.ID) == "" {
		r.ID = fmt.Sprintf("R-MCP-RULE-%d", i+1)
	}
	return nil
}

// Matches reports whether the rule applies to an MCP server and tool. When the
// caller could not split the name, raw is parsed with extract.MCPName.
func (r MCPRule) Matches(server, tool, raw string) bool {
	if server == "" && tool == "" {
		server, tool, _ = extract.MCPName(raw)
	}
	server, tool = strings.ToLower(server), strings.ToLower(tool)
	return globMatch(r.Server, server) && globMatch(r.Tool, tool)
}

func (r MCPRule) decision() decision.Decision { return decision.Decision(r.Decision) }

func (r MCPRule) reasonText() string {
	if r.Reason != "" {
		return r.Reason
	}
	switch decision.Decision(r.Decision) {
	case decision.Deny:
		return "mcp tool is blocked by policy"
	case decision.StepUp:
		return "mcp tool needs approval"
	default:
		return "mcp tool is allowed by policy"
	}
}

func globMatch(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}
