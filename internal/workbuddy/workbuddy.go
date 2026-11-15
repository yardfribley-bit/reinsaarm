// Package workbuddy locates Tencent WorkBuddy hook settings and checks
// whether the ReinsAARM pre-tool hook is installed there.
//
// WorkBuddy (com.tencent.workbuddy.mac, data folder ~/.workbuddy) and
// WorkBuddy AI (com.workbuddy.workbuddy-ai, data folder ~/.workbuddy-ai) both
// embed the CodeBuddy Code CLI. Its hook runner reads the user settings file
// from $WORKBUDDY_CONFIG_DIR / $CODEBUDDY_CONFIG_DIR (the desktop app sets
// both to its data folder) and project settings from
// <project>/.codebuddy/settings.json and settings.local.json. Checked against
// app.asar.unpacked/cli/dist of WorkBuddy 5.5.6 and WorkBuddy AI 5.9.4 on
// 2026-11-15; see docs/workbuddy.md.
package workbuddy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Needle identifies the ReinsAARM WorkBuddy hook command.
const Needle = "hook --client workbuddy"

// DataFolders are the per-product data folders under the home directory,
// newest product first.
var DataFolders = []string{".workbuddy-ai", ".workbuddy"}

// UserConfigDirs returns the user settings directories to install into or
// inspect. An explicit dir wins, then $WORKBUDDY_CONFIG_DIR, then every
// existing data folder. When none exists it returns ~/.workbuddy.
func UserConfigDirs(home, explicit string) []string {
	if strings.TrimSpace(explicit) != "" {
		return []string{explicit}
	}
	if v := strings.TrimSpace(os.Getenv("WORKBUDDY_CONFIG_DIR")); v != "" {
		return []string{v}
	}
	var out []string
	for _, f := range DataFolders {
		d := filepath.Join(home, f)
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		out = []string{filepath.Join(home, ".workbuddy")}
	}
	return out
}

// ProjectSettings are the project files WorkBuddy's hook runner reads.
func ProjectSettings(project string) []string {
	return []string{
		filepath.Join(project, ".codebuddy", "settings.json"),
		filepath.Join(project, ".codebuddy", "settings.local.json"),
	}
}

// Status describes one settings file.
type Status struct {
	Path      string   `json:"path"`
	Exists    bool     `json:"exists"`
	Installed bool     `json:"installed"`
	Command   string   `json:"command,omitempty"`
	Matcher   string   `json:"matcher,omitempty"`
	CoversAll bool     `json:"covers_all"`
	Others    []string `json:"others,omitempty"`
	Disabled  string   `json:"disabled,omitempty"`
	// Events lists the observation events (PostToolUse, SessionStart, ...)
	// that also run the ReinsAARM hook in this file.
	Events []string `json:"events,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// Inspect reads one settings file. A missing file is not an error.
func Inspect(path string) Status {
	st := Status{Path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			st.Error = err.Error()
		}
		return st
	}
	st.Exists = true
	if strings.TrimSpace(string(b)) == "" {
		return st
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		st.Error = err.Error()
		return st
	}
	for _, k := range []string{"disableAllHooks", "allowManagedHooksOnly"} {
		if v, _ := doc[k].(bool); v {
			st.Disabled = k
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	st.Events = EventsWith(hooks, Needle)
	list, _ := hooks["PreToolUse"].([]any)
	for _, item := range list {
		group, _ := item.(map[string]any)
		if group == nil {
			continue
		}
		matcher, _ := group["matcher"].(string)
		handlers, _ := group["hooks"].([]any)
		for _, h := range handlers {
			hm, _ := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			if cmd == "" {
				continue
			}
			if strings.Contains(cmd, Needle) {
				st.Installed = true
				st.Command = cmd
				st.Matcher = matcher
				st.CoversAll = MatchesAll(matcher)
			} else {
				st.Others = append(st.Others, cmd)
			}
		}
	}
	return st
}

// MatchesAll reports whether a PreToolUse matcher matches every tool name
// WorkBuddy sends. WorkBuddy treats "", "*" and a regex as matchers; a regex
// is tested with RegExp.test, so ".*" also matches all.
func MatchesAll(m string) bool {
	m = strings.TrimSpace(m)
	if m == "" || m == "*" || m == ".*" || m == "^.*$" {
		return true
	}
	re, err := regexp.Compile(m)
	if err != nil {
		return false
	}
	for _, tool := range []string{"Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch", "DeferExecuteTool", "mcp__github__push_files"} {
		if !re.MatchString(tool) {
			return false
		}
	}
	return true
}

// ObservedEvents are the activity events install-hooks workbuddy adds next
// to PreToolUse.
var ObservedEvents = []string{"PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"}

// EventsWith returns the events in ObservedEvents whose handlers include a
// command containing needle, in ObservedEvents order.
func EventsWith(hooks map[string]any, needle string) []string {
	var out []string
	for _, ev := range ObservedEvents {
		list, _ := hooks[ev].([]any)
		found := false
		for _, item := range list {
			group, _ := item.(map[string]any)
			handlers, _ := group["hooks"].([]any)
			for _, h := range handlers {
				hm, _ := h.(map[string]any)
				if cmd, _ := hm["command"].(string); strings.Contains(cmd, needle) {
					found = true
				}
			}
		}
		if found {
			out = append(out, ev)
		}
	}
	return out
}
