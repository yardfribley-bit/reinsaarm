// Package codextrust computes the Codex unmanaged-hook trust identity.
//
// Codex 0.151 does not run a project or user hook until config.toml contains
// hooks.state."<key>".trusted_hash equal to the current definition hash.
// The key is <absolute hooks.json>:pre_tool_use:<group>:<handler>.
// The hash is SHA-256 of the canonical JSON identity Codex builds in
// version_for_toml (event_name, matcher, and the normalized command handler).
// This package reproduces that identity from the hooks.json we write. It was
// checked against the public Codex source for 0.151, not by executing that binary.
package codextrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/canon"
)

// Hook is one ReinsAARM command handler discovered in a Codex hooks.json.
type Hook struct {
	Path          string
	Key           string
	Hash          string
	Event         string
	Group         int
	Handler       int
	Command       string
	Matcher       string
	MatcherSet    bool
	TimeoutSec    int
	StatusMessage string
}

// FindReins reads hooks.json and returns every reinsaarm command hook.
func FindReins(hooksPath string) ([]Hook, error) {
	abs, err := filepath.Abs(hooksPath)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("codex hooks: %w", err)
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		return nil, nil
	}
	var out []Hook
	for event, groups := range hooks {
		list, _ := groups.([]any)
		label := eventLabel(event)
		for gi, g := range list {
			group, _ := g.(map[string]any)
			if group == nil {
				continue
			}
			matcher, matcherSet := group["matcher"].(string)
			handlers, _ := group["hooks"].([]any)
			for hi, h := range handlers {
				hm, _ := h.(map[string]any)
				if hm == nil {
					continue
				}
				cmd, _ := hm["command"].(string)
				if !strings.Contains(cmd, "reinsaarm hook") {
					continue
				}
				timeout := 600
				if n, ok := number(hm["timeout"]); ok {
					if n < 1 {
						n = 1
					}
					timeout = n
				}
				status, _ := hm["statusMessage"].(string)
				async, _ := hm["async"].(bool)
				sum, err := Hash(label, matcher, matcherSet, cmd, status, timeout, async)
				if err != nil {
					return nil, err
				}
				out = append(out, Hook{
					Path: abs, Key: fmt.Sprintf("%s:%s:%d:%d", abs, label, gi, hi),
					Hash: sum, Event: label, Group: gi, Handler: hi, Command: cmd,
					Matcher: matcher, MatcherSet: matcherSet, TimeoutSec: timeout,
					StatusMessage: status,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Event == "pre_tool_use") != (out[j].Event == "pre_tool_use") {
			return out[i].Event == "pre_tool_use"
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// Hash is sha256 of the canonical hook identity Codex persists as trusted_hash.
func Hash(eventLabel, matcher string, matcherSet bool, command, status string, timeout int, async bool) (string, error) {
	raw, err := identityJSON(eventLabel, matcher, matcherSet, command, status, timeout, async)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func identityJSON(eventLabel, matcher string, matcherSet bool, command, status string, timeout int, async bool) ([]byte, error) {
	handler := map[string]any{
		"async":   async,
		"command": command,
		"timeout": timeout,
		"type":    "command",
	}
	if status != "" {
		handler["statusMessage"] = status
	}
	identity := map[string]any{
		"event_name": eventLabel,
		"hooks":      []any{handler},
	}
	if matcherSet {
		identity["matcher"] = matcher
	}
	return canon.Value(identity)
}

func eventLabel(event string) string {
	switch event {
	case "PreToolUse":
		return "pre_tool_use"
	case "PostToolUse":
		return "post_tool_use"
	case "PermissionRequest":
		return "permission_request"
	case "SessionStart":
		return "session_start"
	case "SessionEnd":
		return "session_end"
	case "Stop":
		return "stop"
	default:
		var b strings.Builder
		for i, r := range event {
			if i > 0 && r >= 'A' && r <= 'Z' {
				b.WriteByte('_')
			}
			if r >= 'A' && r <= 'Z' {
				r = r - 'A' + 'a'
			}
			b.WriteRune(r)
		}
		return b.String()
	}
}

func number(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(n)
		return i, err == nil
	default:
		return 0, false
	}
}

// Status is the trust check for one hook.
type Status struct {
	Hook        Hook
	TrustedHash string
	ConfigPath  string
	State       string // trusted, untrusted, modified
}

// Inspect compares discovered hooks with trusted_hash entries in Codex config files.
func Inspect(hooks []Hook, configPaths []string) []Status {
	var out []Status
	for _, h := range hooks {
		st := Status{Hook: h, State: "untrusted"}
		for _, path := range configPaths {
			hash, ok := trustedHash(path, h.Key)
			if !ok {
				continue
			}
			st.TrustedHash = hash
			st.ConfigPath = path
			if hash == h.Hash {
				st.State = "trusted"
			} else {
				st.State = "modified"
			}
			break
		}
		out = append(out, st)
	}
	return out
}

func trustedHash(configPath, key string) (string, bool) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return "", false
	}
	return trustedHashIn(string(b), key)
}

func trustedHashIn(content, key string) (string, bool) {
	header := `[hooks.state."` + escapeToml(key) + `"]`
	idx := strings.Index(content, header)
	if idx < 0 {
		return "", false
	}
	rest := content[idx+len(header):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	} else {
		rest = ""
	}
	end := len(rest)
	for i, line := range strings.Split(rest, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") {
			end = strings.Index(rest, line)
			if i == 0 {
				end = 0
			}
			break
		}
	}
	block := rest
	if end >= 0 && end <= len(rest) {
		block = rest[:end]
	}
	for _, line := range strings.Split(block, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, "trusted_hash") {
			continue
		}
		_, val, ok := strings.Cut(trim, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		return val, val != ""
	}
	return "", false
}

// WriteTrust upserts the trusted_hash block into a Codex config.toml.
// The rest of the file is preserved.
func WriteTrust(configPath, key, hash string) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	updated := upsert(string(existing), key, hash)
	return writeKeepMode(configPath, []byte(updated))
}

func upsert(content, key, hash string) string {
	header := `[hooks.state."` + escapeToml(key) + `"]`
	block := header + "\nenabled = true\ntrusted_hash = \"" + hash + "\"\n"
	idx := strings.Index(content, header)
	if idx < 0 {
		if content == "" {
			return block
		}
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if !strings.HasSuffix(content, "\n\n") {
			content += "\n"
		}
		return content + block
	}
	rest := content[idx+len(header):]
	rel := len(rest)
	lines := strings.Split(rest, "\n")
	consumed := 0
	for i, line := range lines {
		if i == 0 && line == "" {
			consumed += 1
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			rel = consumed
			break
		}
		consumed += len(line) + 1
	}
	if rel > len(rest) {
		rel = len(rest)
	}
	return content[:idx] + block + rest[rel:]
}

func escapeToml(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// ProjectTrust reads projects."<path>".trust_level from a Codex config.toml.
// Codex will not load a project .codex/hooks.json until this is "trusted".
func ProjectTrust(configPath, project string) (level string, found bool) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return "", false
	}
	return projectTrustIn(string(b), project)
}

func projectTrustIn(content, project string) (string, bool) {
	project = filepath.Clean(project)
	header := `[projects."` + escapeToml(project) + `"]`
	if i := strings.Index(content, header); i >= 0 {
		rest := content[i+len(header):]
		var block strings.Builder
		for _, line := range strings.Split(rest, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "[") {
				break
			}
			block.WriteString(line)
			block.WriteByte('\n')
		}
		if level, ok := trustLevelValue(block.String()); ok {
			return level, true
		}
	}
	dotted := `projects."` + escapeToml(project) + `".trust_level`
	for _, line := range strings.Split(content, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, dotted) {
			if level, ok := trustLevelValue(trim); ok {
				return level, true
			}
		}
	}
	return "", false
}

func trustLevelValue(block string) (string, bool) {
	for _, line := range strings.Split(block, "\n") {
		trim := strings.TrimSpace(line)
		if !strings.Contains(trim, "trust_level") {
			continue
		}
		_, val, ok := strings.Cut(trim, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		if val != "" {
			return val, true
		}
	}
	return "", false
}

// WriteProjectTrust sets projects."<project>".trust_level = "trusted".
func WriteProjectTrust(configPath, project string) error {
	project = filepath.Clean(project)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	content := string(existing)
	if level, ok := projectTrustIn(content, project); ok && level == "trusted" {
		return nil
	}
	header := `[projects."` + escapeToml(project) + `"]`
	block := header + "\ntrust_level = \"trusted\"\n"
	if strings.Contains(content, header) {
		// Replace the table body up to the next header.
		idx := strings.Index(content, header)
		rest := content[idx+len(header):]
		rel := len(rest)
		consumed := 0
		for _, line := range strings.Split(rest, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "[") && consumed > 0 {
				rel = consumed
				break
			}
			consumed += len(line) + 1
		}
		if rel > len(rest) {
			rel = len(rest)
		}
		content = content[:idx] + block + rest[rel:]
	} else {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		if content != "" && !strings.HasSuffix(content, "\n\n") {
			content += "\n"
		}
		content += block
	}
	return writeKeepMode(configPath, []byte(content))
}

// writeKeepMode writes config.toml without widening its permissions. The
// Codex config can hold tokens and is often 0600; a new file is 0600 too.
func writeKeepMode(path string, b []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(path, b, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
