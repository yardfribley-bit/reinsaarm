// Package extract pulls commands, paths, and hosts out of coding-agent tool inputs.
package extract

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Kind classifies a tool name from Codex, Claude Code, Gemini CLI, CodeBuddy, or WorkBuddy
// into shell, file_read, file_write, file_edit, web_fetch, mcp, or other.
// Names that differ between IDE and CLI builds are all accepted.
// Verified against public docs on 2026-11-15; not against a live binary.
// See docs/hooks.md "Normalized action model" for the table.
func Kind(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "shell", "run_shell_command", "exec_command", "execute_command", "powershell":
		return "shell"
	case "read", "read_file", "read_many_files", "glob", "grep", "grep_search", "ls",
		"list_directory", "list_dir", "list_files", "search_content", "search_file",
		"search_file_content", "view_image", "viewimage":
		return "file_read"
	case "write", "write_file", "write_to_file", "create_file", "delete_file":
		return "file_write"
	case "edit", "multiedit", "apply_patch", "replace", "replace_in_file",
		"notebookedit", "editnotebook":
		return "file_edit"
	case "webfetch", "web_fetch", "websearch", "web_search", "google_web_search":
		return "web_fetch"
	default:
		l := strings.ToLower(tool)
		if strings.HasPrefix(l, "mcp__") || strings.HasPrefix(l, "mcp_") {
			return "mcp"
		}
		return "other"
	}
}

// IsWrite reports whether a kind changes files.
func IsWrite(kind string) bool { return kind == "file_write" || kind == "file_edit" }

var (
	urlRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>|]+`)
	scpRe = regexp.MustCompile(`(?i)(?:^|[\s'"=])git@([A-Za-z0-9._-]+):`)
)

// Command returns the shell command from a tool input, if any.
func Command(input map[string]any) string {
	if input == nil {
		return ""
	}
	for _, k := range []string{"command", "cmd", "script"} {
		if s, ok := input[k].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// Paths collects file paths from known tool fields and from shell tokens.
func Paths(cwd, command string, input map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	walkStrings(input, 0, func(k, v string) {
		lk := strings.ToLower(k)
		switch lk {
		case "file_path", "filepath", "path", "dir_path", "notebook_path", "target_file", "pattern", "include":
			add(v)
		}
	})
	if command != "" {
		for _, tok := range Tokenize(command) {
			if looksLikePath(tok) {
				add(tok)
			}
		}
		for _, line := range strings.Split(command, "\n") {
			line = strings.TrimSpace(line)
			for _, prefix := range []string{"*** Update File:", "*** Add File:", "*** Delete File:", "+++ b/", "--- a/"} {
				if strings.HasPrefix(line, prefix) {
					add(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
				}
			}
		}
	}
	_ = cwd
	return out
}

// Hosts collects network hosts from URLs, git@ scp syntax, and curl/wget arguments.
func Hosts(command string, input map[string]any) []string {
	var blobs []string
	if command != "" {
		blobs = append(blobs, command)
	}
	walkStrings(input, 0, func(_, v string) {
		blobs = append(blobs, v)
	})
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, blob := range blobs {
		for _, m := range urlRe.FindAllString(blob, -1) {
			if u, err := url.Parse(m); err == nil {
				add(u.Hostname())
			}
		}
		for _, m := range scpRe.FindAllStringSubmatch(blob, -1) {
			if len(m) == 2 {
				add(m[1])
			}
		}
	}
	if command != "" {
		for _, seg := range splitSegments(Tokenize(command)) {
			for i, tok := range seg {
				if tok != "curl" && tok != "wget" && tok != "fetch" {
					continue
				}
				for _, arg := range seg[i+1:] {
					if strings.HasPrefix(arg, "-") {
						continue
					}
					add(hostOfArg(arg))
					break
				}
			}
			for i, tok := range seg {
				if tok == "dig" || tok == "nslookup" || tok == "host" {
					for _, arg := range seg[i+1:] {
						if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "@") {
							continue
						}
						add(hostOfArg(arg))
					}
				}
			}
		}
	}
	return out
}

func hostOfArg(arg string) string {
	arg = strings.Trim(arg, `"'`)
	if strings.Contains(arg, "://") {
		if u, err := url.Parse(arg); err == nil {
			return u.Hostname()
		}
	}
	arg = strings.TrimPrefix(arg, "@")
	if i := strings.IndexAny(arg, "/?"); i >= 0 {
		arg = arg[:i]
	}
	if h, _, ok := strings.Cut(arg, ":"); ok && !strings.Contains(h, "]") {
		// host:port, but not an scp path with no scheme. curl args use host:port.
		if _, err := strconvAtoi(arg[len(h)+1:]); err == nil {
			arg = h
		}
	}
	return arg
}

func strconvAtoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, strconvErr
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, strconvErr
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

var strconvErr = errStr("not a port")

type errStr string

func (e errStr) Error() string { return string(e) }

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.ContainsAny(h, " \t'\"") {
		return ""
	}
	return h
}

func looksLikePath(tok string) bool {
	tok = strings.Trim(tok, `"'`)
	if tok == "" || tok == "|" || tok == ";" || tok == "&&" || tok == "||" {
		return false
	}
	if strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "~") && !strings.HasPrefix(tok, ".") {
		return false
	}
	base := filepath.Base(tok)
	if strings.Contains(tok, "/") || strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, ".") {
		return true
	}
	switch base {
	case ".env", ".npmrc", ".netrc", ".pypirc", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa":
		return true
	default:
		return strings.HasPrefix(base, ".env.")
	}
}

// Tokenize splits a shell command enough to find commands, pipes, and paths.
// It is not a shell parser. Quotes are honored; expansions are not evaluated.
func Tokenize(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\'', '"':
			q := r
			for i+1 < len(rs) && rs[i+1] != q {
				i++
				b.WriteRune(rs[i])
			}
			if i+1 < len(rs) && rs[i+1] == q {
				i++
			}
		case ' ', '\t', '\n', '\r':
			flush()
		case '|':
			flush()
			if i+1 < len(rs) && rs[i+1] == '|' {
				out = append(out, "||")
				i++
			} else {
				out = append(out, "|")
			}
		case '&':
			flush()
			if i+1 < len(rs) && rs[i+1] == '&' {
				out = append(out, "&&")
				i++
			} else {
				out = append(out, "&")
			}
		case ';':
			flush()
			out = append(out, ";")
		case '<', '>', '(', ')':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

func splitSegments(tokens []string) [][]string {
	var segs [][]string
	var cur []string
	for _, t := range tokens {
		if t == "|" || t == ";" || t == "&&" || t == "||" || t == "&" {
			if len(cur) > 0 {
				segs = append(segs, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
	}
	return segs
}

func walkStrings(v any, depth int, fn func(key, val string)) {
	if depth > 6 || v == nil {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		n := 0
		for k, child := range t {
			if n > 64 {
				return
			}
			n++
			if s, ok := child.(string); ok {
				fn(k, s)
			} else {
				walkStrings(child, depth+1, fn)
			}
		}
	case []any:
		for i, child := range t {
			if i > 32 {
				return
			}
			if s, ok := child.(string); ok {
				fn("", s)
			} else {
				walkStrings(child, depth+1, fn)
			}
		}
	}
}
