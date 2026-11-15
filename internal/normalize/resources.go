package normalize

import (
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

const (
	maxResources = 16
	maxResLen    = 256
)

// Resources is the receipt form of an action's resources. Paths that look like
// URLs are dropped (their hosts are already listed), KEY=value secrets are
// redacted, and each list is capped. It returns nil when there is nothing to
// record.
func Resources(a policy.Action) *ledger.Resources {
	r := &ledger.Resources{
		MCPServer: clip(a.MCPServer),
		MCPTool:   clip(a.MCPTool),
	}
	for _, p := range a.Paths {
		if strings.Contains(p, "://") || len(r.Paths) >= maxResources {
			continue
		}
		r.Paths = append(r.Paths, clip(redact.Value(p)))
	}
	for _, h := range a.Hosts {
		if len(r.Hosts) >= maxResources {
			break
		}
		r.Hosts = append(r.Hosts, clip(h))
	}
	for _, g := range a.GitOps {
		if len(r.GitOps) >= maxResources {
			break
		}
		r.GitOps = append(r.GitOps, clip(g))
	}
	if len(r.Paths) == 0 && len(r.Hosts) == 0 && len(r.GitOps) == 0 && r.MCPServer == "" && r.MCPTool == "" {
		return nil
	}
	return r
}

func clip(s string) string {
	if len(s) > maxResLen {
		return s[:maxResLen] + "…"
	}
	return s
}

// Summary is a one-line description for approvals and previews: the shell
// line when there is one, otherwise the tool and its resources.
func Summary(a policy.Action) string {
	if a.Command != "" {
		return a.Command
	}
	parts := []string{a.Tool}
	if a.MCPServer != "" || a.MCPTool != "" {
		parts = append(parts, "mcp "+a.MCPServer+"/"+a.MCPTool)
	}
	if len(a.Paths) > 0 {
		parts = append(parts, strings.Join(a.Paths, ", "))
	}
	if len(a.Hosts) > 0 {
		parts = append(parts, strings.Join(a.Hosts, ", "))
	}
	return strings.Join(parts, " ")
}
