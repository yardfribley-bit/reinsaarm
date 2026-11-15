// Package install writes hook configuration for the supported coding agents.
package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/workbuddy"
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
		// WorkBuddy reads project hooks from .codebuddy/settings.json too. Its
		// user file is <data folder>/settings.json; see UserConfigDir.
		"workbuddy": {Name: "workbuddy", RelPath: filepath.Join(".codebuddy", "settings.json"), UserPath: filepath.Join(".workbuddy", "settings.json")},
	}
}

// Plan describes one file write.
type Plan struct {
	Path    string
	Payload []byte
	Note    string
}

// UserConfigDir overrides the WorkBuddy user settings directory for
// --scope user. Empty means $WORKBUDDY_CONFIG_DIR, then every existing
// ~/.workbuddy-ai and ~/.workbuddy.
var UserConfigDir string

// Plans builds the files for one client. scope is "project" or "user".
// stateHome and socket are baked into the hook command so Codex does not
// depend on an inherited REINSAARM_HOME.
func Plans(client, bin, scope, projectDir, home, stateHome, socket string) ([]Plan, error) {
	t, ok := Targets()[client]
	if !ok {
		return nil, fmt.Errorf("install: unknown client %q", client)
	}
	if client == "workbuddy" && scope == "user" {
		var plans []Plan
		for _, dir := range workbuddy.UserConfigDirs(home, UserConfigDir) {
			p, err := planFile(client, filepath.Join(dir, "settings.json"), bin, stateHome, socket)
			if err != nil {
				return nil, err
			}
			plans = append(plans, p...)
		}
		return plans, nil
	}
	var path string
	if scope == "user" {
		path = filepath.Join(home, t.UserPath)
	} else {
		path = filepath.Join(projectDir, t.RelPath)
	}
	return planFile(client, path, bin, stateHome, socket)
}

func planFile(client, path, bin, stateHome, socket string) ([]Plan, error) {
	command := HookCommand(bin, client, stateHome, socket)
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
	case "workbuddy":
		mergeWorkBuddy(doc, command)
	default:
		mergeClaude(doc, command)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	note := "hook command reads stdin and writes the CLI's decision JSON"
	if client == "workbuddy" {
		note = "WorkBuddy snapshots hooks at session start: start a new task (or restart WorkBuddy) and review the hook in /hooks if it asks. Other PreToolUse hooks in this file still run in parallel."
	}
	plans := []Plan{{Path: path, Payload: raw, Note: note}}
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

// Apply writes plans to disk. An existing file whose content changes is
// first copied to <path>.bak.reinsaarm-<timestamp> with its original mode,
// and the new file keeps that mode. Backups are listed in the result.
func Apply(plans []Plan) error {
	_, err := ApplyWithBackup(plans)
	return err
}

// ApplyWithBackup is Apply and returns the backup paths it wrote.
func ApplyWithBackup(plans []Plan) ([]string, error) {
	var backups []string
	stamp := time.Now().Format("20060102150405")
	for _, p := range plans {
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
			return backups, err
		}
		mode := os.FileMode(0o644)
		if old, err := os.ReadFile(p.Path); err == nil {
			if st, err := os.Stat(p.Path); err == nil {
				mode = st.Mode().Perm()
			}
			if bytes.Equal(old, p.Payload) {
				continue
			}
			bak := p.Path + ".bak.reinsaarm-" + stamp
			if err := os.WriteFile(bak, old, mode); err != nil {
				return backups, fmt.Errorf("install: backup %s: %w", p.Path, err)
			}
			backups = append(backups, bak)
		}
		if err := os.WriteFile(p.Path, p.Payload, mode); err != nil {
			return backups, err
		}
	}
	return backups, nil
}

// HookCommand is the argv string stored in a CLI settings file.
func HookCommand(bin, client, stateHome, socket string) string {
	parts := []string{shellQuote(bin), "hook", "--client", client}
	if stateHome != "" {
		parts = append(parts, "--home", shellQuote(stateHome))
	}
	if socket != "" {
		parts = append(parts, "--socket", shellQuote(socket))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func mergeClaude(doc map[string]any, command string) {
	hooks := object(doc, "hooks")
	list := array(hooks, "PreToolUse")
	if replaced := replaceCommand(list, "reinsaarm hook --client claude-code", command); replaced {
		hooks["PreToolUse"] = list
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
	if replaced := replaceCommand(list, "reinsaarm hook --client codex", command); replaced {
		hooks["PreToolUse"] = list
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
	if replaced := replaceCommand(list, "reinsaarm hook --client gemini", command); replaced {
		hooks["BeforeTool"] = list
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
	if replaced := replaceCommand(list, "reinsaarm hook --client codebuddy", command); replaced {
		hooks["PreToolUse"] = list
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

func mergeWorkBuddy(doc map[string]any, command string) {
	hooks := object(doc, "hooks")
	list := array(hooks, "PreToolUse")
	if replaced := replaceCommand(list, "reinsaarm hook --client workbuddy", command); replaced {
		hooks["PreToolUse"] = list
		return
	}
	// WorkBuddy's matcher is a regex tested against tool_name; "*" is
	// special-cased to match every tool, including DeferExecuteTool and
	// mcp__ tools. timeout is in seconds.
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

func replaceCommand(list []any, needle, command string) bool {
	replaced := false
	for _, item := range list {
		group, ok := item.(map[string]any)
		if !ok {
			continue
		}
		handlers, _ := group["hooks"].([]any)
		for _, h := range handlers {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			cmd, _ := hm["command"].(string)
			if strings.Contains(cmd, needle) && cmd != command {
				hm["command"] = command
				replaced = true
			} else if strings.Contains(cmd, needle) {
				replaced = true
			}
		}
	}
	return replaced
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
