// Package normalize maps one PreToolUse payload from Codex, Claude Code,
// Gemini CLI, or CodeBuddy onto the common action model the policy engine
// evaluates: a kind (shell, file_read, file_write, file_edit, web_fetch, mcp,
// other) plus the resources the call touches (paths, hosts, git operations,
// MCP server and tool).
//
// Tool names and argument keys were checked against public docs and source on
// 2026-11-15 (see docs/hooks.md, "Normalized action model"). An unknown tool
// becomes kind "other"; its path-like and URL-like arguments are still
// checked, and the hook's failure behaviour does not change.
package normalize

import (
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/extract"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

// Kinds lists the normalized kinds.
var Kinds = []string{"shell", "file_read", "file_write", "file_edit", "web_fetch", "mcp", "other"}

// MCPContext is Gemini CLI's optional BeforeTool mcp_context. Only the two
// name fields are used.
type MCPContext struct {
	ServerName string `json:"server_name,omitempty"`
	ToolName   string `json:"tool_name,omitempty"`
}

// Call is the raw input to normalization.
type Call struct {
	Client            string
	Tool              string
	Input             map[string]any
	CWD               string
	MCPContext        *MCPContext
	MCPDescription    string
	MCPDefinitionHash string
}

// File argument keys. Claude Code: file_path, notebook_path, path (Glob, Grep,
// LS). Gemini CLI: file_path, dir_path, include (read_many_files),
// include_pattern (grep_search), legacy path and paths. CodeBuddy IDE:
// target_file, path. Codex view_image: path.
var fileKeys = []string{
	"file_path", "filepath", "path", "paths", "dir_path", "notebook_path",
	"target_file", "absolute_path", "include", "include_pattern", "glob",
}

// MCP argument keys that name a file. MCP servers have no shared schema, so
// only common names are read; other arguments are not treated as paths.
var mcpPathKeys = []string{
	"path", "paths", "file_path", "filepath", "filename", "file", "files",
	"dir", "directory", "dir_path", "source", "destination", "src", "dst",
	"target_file", "absolute_path",
}

// Action normalizes one call.
func Action(c Call) policy.Action {
	input := c.Input
	if input == nil {
		input = map[string]any{}
	}
	kind := extract.Kind(c.Tool)
	a := policy.Action{
		Client:            c.Client,
		Tool:              c.Tool,
		Kind:              kind,
		CWD:               c.CWD,
		MCPDescription:    c.MCPDescription,
		MCPDefinitionHash: c.MCPDefinitionHash,
	}
	if c.MCPContext != nil && (c.MCPContext.ServerName != "" || c.MCPContext.ToolName != "") {
		// Gemini sends mcp_context only for MCP tools. Trust it over the name.
		a.Kind = "mcp"
		kind = "mcp"
	}
	switch kind {
	case "shell":
		a.Command = extract.Command(input)
		a.Paths = extract.Paths(c.CWD, a.Command, input)
		a.Hosts = extract.Hosts(a.Command, nil)
		a.GitOps = extract.GitOps(a.Command)
	case "file_read", "file_write", "file_edit":
		if strings.EqualFold(c.Tool, "apply_patch") {
			// Codex apply_patch carries the patch in tool_input.command. It is
			// a file edit, not a shell line: only the header file names count.
			a.Body = extract.Command(input)
			if a.Body == "" {
				a.Body, _ = input["patch"].(string)
			}
			a.Paths = extract.PatchPaths(a.Body)
			break
		}
		keys := fileKeys
		if isGlobTool(c.Tool) {
			keys = append(append([]string{}, fileKeys...), "pattern")
		}
		a.Paths = extract.PathsFromKeys(input, keys...)
	case "web_fetch":
		// Claude WebFetch: url. Gemini web_fetch: prompt with URLs, or url.
		// Search tools take a query and have no target host.
		a.Hosts = extract.HostsFromKeys(input, "prompt")
	case "mcp":
		a.MCPServer, a.MCPTool, _ = extract.MCPName(c.Tool)
		if c.MCPContext != nil {
			if c.MCPContext.ServerName != "" {
				a.MCPServer = c.MCPContext.ServerName
			}
			if c.MCPContext.ToolName != "" {
				a.MCPTool = c.MCPContext.ToolName
			}
		}
		// An MCP tool that takes a shell line gets the shell rules too.
		if cmd := extract.Command(input); cmd != "" {
			a.Command = cmd
			a.GitOps = extract.GitOps(cmd)
		}
		a.Paths = extract.PathsFromKeys(input, mcpPathKeys...)
		a.Hosts = extract.HostsFromKeys(input)
		if a.Command != "" {
			a.Hosts = appendUniq(a.Hosts, extract.Hosts(a.Command, nil)...)
		}
	default:
		a.Paths = extract.PathsFromKeys(input, append(append([]string{}, fileKeys...), mcpPathKeys...)...)
		a.Hosts = extract.HostsFromKeys(input)
	}
	return a
}

func isGlobTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "glob", "search_file":
		return true
	}
	return false
}

func appendUniq(dst []string, more ...string) []string {
	seen := map[string]bool{}
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range more {
		if s != "" && !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

// HashCommand is the string bound into an approval hash: the shell line, or
// the non-shell body (an apply_patch) when there is no shell line.
func HashCommand(a policy.Action) string {
	if a.Command != "" {
		return a.Command
	}
	return a.Body
}
