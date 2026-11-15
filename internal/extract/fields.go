package extract

import (
	"net/url"
	"sort"
	"strings"
)

// WalkKeyed visits every string in v with the nearest object key. Strings in an
// array report the key that holds the array. Object keys are visited in sorted
// order so the result, and any hash built from it, is deterministic.
func WalkKeyed(v any, fn func(key, val string)) {
	walkKeyed(v, "", 0, fn)
}

func walkKeyed(v any, key string, depth int, fn func(key, val string)) {
	if depth > 6 || v == nil {
		return
	}
	switch t := v.(type) {
	case string:
		fn(key, t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i >= 64 {
				return
			}
			walkKeyed(t[k], k, depth+1, fn)
		}
	case []any:
		for i, child := range t {
			if i >= 32 {
				return
			}
			walkKeyed(child, key, depth+1, fn)
		}
	}
}

// PathsFromKeys returns string values held under one of keys (case-insensitive).
func PathsFromKeys(input map[string]any, keys ...string) []string {
	want := map[string]bool{}
	for _, k := range keys {
		want[strings.ToLower(k)] = true
	}
	var out []string
	seen := map[string]bool{}
	WalkKeyed(input, func(k, v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || !want[strings.ToLower(k)] {
			return
		}
		seen[v] = true
		out = append(out, v)
	})
	return out
}

// HostsFromKeys returns hosts from values whose key names a network target
// (url, uri, href, endpoint, host, domain, and the same words as suffixes such
// as base_url). Values may be full URLs or bare host names.
func HostsFromKeys(input map[string]any, extraKeys ...string) []string {
	extra := map[string]bool{}
	for _, k := range extraKeys {
		extra[strings.ToLower(k)] = true
	}
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	WalkKeyed(input, func(k, v string) {
		lk := strings.ToLower(k)
		if !extra[lk] && !isNetworkKey(lk) {
			return
		}
		found := false
		for _, m := range urlRe.FindAllString(v, -1) {
			if u, err := url.Parse(m); err == nil && u.Hostname() != "" {
				add(u.Hostname())
				found = true
			}
		}
		for _, m := range scpRe.FindAllStringSubmatch(v, -1) {
			if len(m) == 2 {
				add(m[1])
				found = true
			}
		}
		if !found && isNetworkKey(lk) {
			s := strings.TrimSpace(v)
			if s != "" && !strings.ContainsAny(s, " \t\n") && strings.Contains(s, ".") {
				add(hostOfArg(s))
			}
		}
	})
	return out
}

func isNetworkKey(k string) bool {
	switch k {
	case "url", "uri", "href", "endpoint", "host", "hostname", "domain", "urls", "uris":
		return true
	}
	for _, suf := range []string{"_url", "_uri", "_host", "_endpoint", "_domain", "url", "uri"} {
		if strings.HasSuffix(k, suf) && len(k) > len(suf) {
			return true
		}
	}
	return false
}

// PatchPaths returns the file names in an apply_patch or unified diff body.
// It reads only the header lines, never the patch content.
func PatchPaths(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Update File:", "*** Add File:", "*** Delete File:", "*** Move to:", "+++ b/", "--- a/"} {
			if strings.HasPrefix(line, prefix) {
				p := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if p != "" && p != "/dev/null" && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// GitOps returns git subcommands in a shell command, in order, without
// duplicates. Global options such as -C DIR and -c k=v are skipped.
func GitOps(command string) []string {
	if command == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, seg := range splitSegments(Tokenize(command)) {
		for i := 0; i < len(seg); i++ {
			if seg[i] != "git" && !strings.HasSuffix(seg[i], "/git") {
				continue
			}
			for j := i + 1; j < len(seg); j++ {
				a := seg[j]
				if a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" {
					j++
					continue
				}
				if strings.HasPrefix(a, "-") {
					continue
				}
				if !seen[a] {
					seen[a] = true
					out = append(out, a)
				}
				break
			}
			break
		}
	}
	return out
}

// MCPName splits an MCP tool name into server and tool.
// Claude Code, Codex, and CodeBuddy use mcp__<server>__<tool>. Gemini CLI uses
// mcp_<server>_<tool>, which is ambiguous when the server name has an
// underscore; Gemini also sends mcp_context.server_name, which callers should
// prefer. ok is false when the name is not an MCP name.
func MCPName(tool string) (server, name string, ok bool) {
	l := strings.TrimSpace(tool)
	if strings.HasPrefix(strings.ToLower(l), "mcp__") {
		rest := l[len("mcp__"):]
		if s, t, found := strings.Cut(rest, "__"); found {
			return s, t, true
		}
		return rest, "", true
	}
	if strings.HasPrefix(strings.ToLower(l), "mcp_") {
		rest := l[len("mcp_"):]
		if s, t, found := strings.Cut(rest, "_"); found {
			return s, t, true
		}
		return rest, "", true
	}
	return "", "", false
}
