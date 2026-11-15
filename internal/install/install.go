// Package install writes hook configuration for the supported coding agents.
package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Target is one CLI.
type Target struct {
	Name     string
	RelPath  string
	UserPath string
}

// Targets lists install locations. RelPath is relative to a project.
// UserPath is under the developer home.
func Targets() map[string]Target {
	return map[string]Target{
		"claude-code": {Name: "claude-code", RelPath: filepath.Join(".claude", "settings.json"), UserPath: filepath.Join(".claude", "settings.json")},
		"codex":       {Name: "codex", RelPath: filepath.Join(".codex", "hooks.json"), UserPath: filepath.Join(".codex", "hooks.json")},
		"gemini":      {Name: "gemini", RelPath: filepath.Join(".gemini", "settings.json"), UserPath: filepath.Join(".gemini", "settings.json")},
		"codebuddy":   {Name: "codebuddy", RelPath: filepath.Join(".codebuddy", "settings.json"), UserPath: filepath.Join(".codebuddy", "settings.json")},
	}
}

// Plan describes one file write.
type Plan struct {
	Path    string
	Payload []byte
	Note    string
}

// Plans builds the files for one client. scope is "project" or "user".
func Plans(client, bin, scope, projectDir, home string) ([]Plan, error) {
	t, ok := Targets()[client]
	if !ok {
		return nil, fmt.Errorf("install: unknown client %q", client)
	}
	var path string
	if scope == "user" {
		path = filepath.Join(home, t.UserPath)
	} else {
		path = filepath.Join(projectDir, t.RelPath)
	}
	command := bin + " hook --client " + client
	var doc map[string]any
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("install: %s: %w", path, err)
		}
	}
	if doc == nil {
		doc = map[string]any{}
	}
	switch client {
	case "codex":
		mergeCodex(doc, command)
	case "gemini":
		mergeGemini(doc, command)
	case "codebuddy":
		mergeCodeBuddy(doc, command)
	default:
		mergeClaude(doc, command)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	plans := []Plan{{Path: path, Payload: raw, Note: "hook command reads stdin and writes the CLI's decision JSON"}}
	if client == "codex" {
		snippet := codexRequirements(command)
		plans = append(plans, Plan{
			Path:    filepath.Join(filepath.Dir(path), "reinsaarm-requirements.toml.snippet"),
			Payload: []byte(snippet),
			Note:    "example managed-hook snippet for requirements.toml; not installed automatically",
		})
	}
	return plans, nil
}

// Apply writes plans to disk.
func Apply(plans []Plan) error {
	for _, p := range plans {
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p.Path, p.Payload, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mergeClaude(doc map[string]any, command string) {
	hooks := object(doc, "hooks")
	list := array(hooks, "PreToolUse")
	if containsCommand(list, "reinsaarm hook --client claude-code") {
		return
	}
	list = append(list, map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{
				"type":      "command",
				"command":   command,
				"timeout":   15,
				"onFailure": "block",
			},
		},
	})
	hooks["PreToolUse"] = list
}

func mergeCodex(doc map[string]any, command string) {
	if _, ok := doc["description"]; !ok {
		doc["description"] = "ReinsAARM pre-tool hook. Managed copies belong in requirements.toml."
	}
	hooks := object(doc, "hooks")
	list := array(hooks, "PreToolUse")
	if containsCommand(list, "reinsaarm hook --client codex") {
		return
	}
	list = append(list, map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{
				"type":          "command",
				"command":       command,
				"timeout":       15,
				"statusMessage": "ReinsAARM",
			},
		},
	})
	hooks["PreToolUse"] = list
}

func mergeGemini(doc map[string]any, command string) {
	hooks := object(doc, "hooks")
	list := array(hooks, "BeforeTool")
	if containsCommand(list, "reinsaarm hook --client gemini") {
		return
	}
	list = append(list, map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{
				"name":    "reinsaarm",
				"type":    "command",
				"command": command,
				"timeout": 15000,
			},
		},
	})
	hooks["BeforeTool"] = list
}

func mergeCodeBuddy(doc map[string]any, command string) {
	hooks := object(doc, "hooks")
	list := array(hooks, "PreToolUse")
	if containsCommand(list, "reinsaarm hook --client codebuddy") {
		return
	}
	list = append(list, map[string]any{
		"matcher": "*",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": command,
				"timeout": 15,
			},
		},
	})
	hooks["PreToolUse"] = list
}

func object(doc map[string]any, key string) map[string]any {
	if v, ok := doc[key].(map[string]any); ok {
		return v
	}
	m := map[string]any{}
	doc[key] = m
	return m
}

func array(doc map[string]any, key string) []any {
	switch v := doc[key].(type) {
	case []any:
		return v
	case nil:
		return []any{}
	default:
		return []any{}
	}
}

func containsCommand(list []any, needle string) bool {
	raw, _ := json.Marshal(list)
	return strings.Contains(string(raw), needle)
}

func codexRequirements(command string) string {
	return strings.TrimSpace(fmt.Sprintf(`
# Example only. Field names follow the Codex managed-hook docs as of 2026-11-15.
# Install this through the enterprise requirements channel; do not commit secrets.
allow_managed_hooks_only = true

[features]
hooks = true

[[hooks.PreToolUse]]
matcher = "*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = %q
timeout = 15
statusMessage = "ReinsAARM"
`, command)) + "\n"
}
