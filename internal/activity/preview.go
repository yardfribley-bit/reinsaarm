package activity

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

// Limits for previews, in runes.
const (
	QueryLimit     = 200
	linkTitleLimit = 120
	maxLinks       = 8
	// writeValueLimit caps each string inside a file_write / file_edit input
	// preview, so file contents are not copied into the audit log.
	writeValueLimit = 160
)

// queryKeys are input fields that hold search text.
var queryKeys = map[string]bool{
	"q": true, "query": true, "queries": true, "search_query": true, "search": true,
	"pattern": true, "term": true, "keywords": true, "question": true,
}

// ArgsPreview summarizes one tool input for the receipt. For shell calls it
// returns the masked command line only when it is longer than the 180
// character command_preview; for other kinds it returns indented JSON with
// secrets masked. It also returns the search text found in the input.
// limit 0 turns the preview off.
func ArgsPreview(kind, command string, input map[string]any, limit int) (preview, query string, truncated bool) {
	if limit <= 0 {
		return "", "", false
	}
	if kind == "shell" {
		if len([]rune(command)) > 180 {
			preview, truncated = redact.Truncate(redact.Mask(command), limit)
		}
		return preview, "", truncated
	}
	if len(input) == 0 {
		return "", "", false
	}
	v := any(input)
	if kind == "file_write" || kind == "file_edit" {
		v = shorten(v, 0)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", "", false
	}
	preview, truncated = redact.Truncate(redact.Mask(strings.TrimSpace(buf.String())), limit)
	var qs []string
	collectQueries(input, 0, &qs)
	if len(qs) > 0 {
		query, _ = redact.Text(strings.Join(qs, " · "), QueryLimit)
	}
	return preview, query, truncated
}

func shorten(v any, depth int) any {
	switch t := v.(type) {
	case string:
		if s, cut := redact.Truncate(t, writeValueLimit); cut {
			return s + " (" + itoa(len([]rune(t))) + " 字)"
		}
		return t
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = shorten(x, depth+1)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = shorten(x, depth+1)
		}
		return out
	}
	return v
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func collectQueries(v any, depth int, out *[]string) {
	if depth > 5 || len(*out) >= 6 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			x := t[k]
			if queryKeys[strings.ToLower(k)] {
				switch q := x.(type) {
				case string:
					if s := strings.TrimSpace(q); s != "" {
						*out = append(*out, s)
						continue
					}
				case []any:
					for _, e := range q {
						if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
							*out = append(*out, strings.TrimSpace(s))
						}
					}
					if len(q) > 0 {
						if _, ok := q[0].(string); ok {
							continue
						}
					}
				}
			}
			collectQueries(x, depth+1, out)
		}
	case []any:
		for _, x := range t {
			collectQueries(x, depth+1, out)
		}
	}
}

var (
	titledURL = regexp.MustCompile(`([^\n()\[\]【】|]{2,160}?)\s*\((https?://[^\s()<>"']+)\)`)
	bareURL   = regexp.MustCompile(`https?://[^\s()<>"'\[\]{}【】,;]+`)
)

// ResultLinks finds URLs in result text, "Title (https://…)" first, then
// bare URLs. Query strings and fragments are dropped, userinfo is masked,
// and at most 8 links are kept.
func ResultLinks(text string) []ledger.Link {
	if text == "" {
		return nil
	}
	var out []ledger.Link
	seen := map[string]bool{}
	add := func(raw, title string) {
		u := cleanURL(raw)
		if u == "" || seen[u] || len(out) >= maxLinks {
			return
		}
		seen[u] = true
		title = strings.TrimSpace(strings.Trim(strings.TrimSpace(title), "-—:：·*#>"))
		if title != "" {
			title, _ = redact.Text(title, linkTitleLimit)
		}
		out = append(out, ledger.Link{URL: u, Title: title})
	}
	for _, m := range titledURL.FindAllStringSubmatch(text, -1) {
		add(m[2], lastTitle(m[1]))
	}
	for _, m := range bareURL.FindAllString(text, -1) {
		add(m, "")
	}
	return out
}

// lastTitle picks the title of a "Title (url)" result: the text after the
// last line break or citation marker, without a trailing " · Site" suffix,
// cut at the first ": " or sentence end.
func lastTitle(s string) string {
	for _, sep := range []string{"\n", "】", "\ue201", "] "} {
		if i := strings.LastIndex(s, sep); i >= 0 {
			s = s[i+len(sep):]
		}
	}
	if i := strings.LastIndex(s, " · "); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ": "); i > 0 && i < 160 {
		return s[:i]
	}
	for _, sep := range []string{"。", ". "} {
		if i := strings.Index(s, sep); i > 0 {
			s = s[:i]
		}
	}
	return s
}

func cleanURL(raw string) string {
	raw = strings.TrimRight(raw, ".,;:!?)】」'\"")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	s := u.String()
	s, _ = redact.Truncate(redact.Mask(s), 240)
	return s
}

// linkKind reports whether results of this kind are scanned for links.
func linkKind(kind string) bool {
	switch kind {
	case "mcp", "web_fetch", "other", "":
		return true
	}
	return false
}

// responseText is the result text used for link extraction.
func responseText(payload map[string]any) string {
	switch r := payload["tool_response"].(type) {
	case string:
		return r
	case map[string]any:
		return firstText(r, "output", "result", "llmContent", "returnDisplay", "content", "text", "stdout", "message")
	case []any:
		return firstText(map[string]any{"content": r}, "content")
	}
	return ""
}

var (
	spaceRun = regexp.MustCompile(`[ \t\f\v]+`)
	blankRun = regexp.MustCompile(`\n{3,}`)
)

// clipLines masks secrets and truncates like clipText but keeps line
// breaks (collapsing runs of spaces and of blank lines), so a stack trace or
// a multi-line answer stays readable.
func clipLines(s string, limit int, a *ledger.Activity) string {
	s = redact.Mask(strings.ReplaceAll(s, "\r\n", "\n"))
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(spaceRun.ReplaceAllString(l, " "), " ")
	}
	s = blankRun.ReplaceAllString(strings.TrimSpace(strings.Join(lines, "\n")), "\n\n")
	out, cut := redact.Truncate(s, limit)
	if cut {
		a.Truncated = true
	}
	return out
}
