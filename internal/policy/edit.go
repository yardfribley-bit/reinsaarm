package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConsoleRulePrefix marks MCP rules added from the local console. Only these
// can be removed from the console.
const ConsoleRulePrefix = "R-MCP-CONSOLE-"

// AddMCPRule returns raw with r inserted into spec.mcp.rules. The edit is a
// text splice, so comments and formatting elsewhere in the file are kept. The
// result is parsed again and must equal the old profile plus r; anything else
// is an error. r is validated and normalized first.
func AddMCPRule(raw []byte, r MCPRule) ([]byte, MCPRule, error) {
	old, err := Load(raw)
	if err != nil {
		return nil, r, err
	}
	if err := r.normalize(len(old.Spec.MCP.Rules)); err != nil {
		return nil, r, err
	}
	for _, have := range old.Spec.MCP.Rules {
		if strings.EqualFold(have.ID, r.ID) {
			return nil, r, fmt.Errorf("rule id %s already exists", r.ID)
		}
		if globKey(have.Server) == globKey(r.Server) && globKey(have.Tool) == globKey(r.Tool) {
			return nil, r, fmt.Errorf("rule %s already matches server %q tool %q (%s)", have.ID, have.Server, have.Tool, have.Decision)
		}
	}
	lines := splitLines(raw)
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, r, err
	}
	root := docRoot(&doc)
	if root == nil {
		return nil, r, fmt.Errorf("profile is not a mapping")
	}
	specKey, spec := mapGet(root, "spec")
	if spec == nil || spec.Kind != yaml.MappingNode || spec.Style&yaml.FlowStyle != 0 || len(spec.Content) == 0 {
		return nil, r, fmt.Errorf("profile spec must be a block mapping")
	}
	childIndent := spec.Content[0].Column - 1
	mcpKey, mcp := mapGet(spec, "mcp")
	var at int // 0-based line index to insert before
	var dash int
	var block []string
	switch {
	case mcp == nil:
		at = specKey.Line // after the spec: line
		dash = childIndent + 4
		block = append(block, pad(childIndent)+"mcp:\n", pad(childIndent+2)+"rules:\n")
	case isEmpty(mcp):
		if err := clearEmptyValue(lines, mcpKey); err != nil {
			return nil, r, err
		}
		at = mcpKey.Line
		dash = mcpKey.Column - 1 + 4
		block = append(block, pad(mcpKey.Column-1+2)+"rules:\n")
	case mcp.Kind == yaml.MappingNode && mcp.Style&yaml.FlowStyle == 0:
		rulesKey, rules := mapGet(mcp, "rules")
		switch {
		case rulesKey == nil:
			at = mcpKey.Line
			ind := mcp.Content[0].Column - 1
			dash = ind + 2
			block = append(block, pad(ind)+"rules:\n")
		case isEmpty(rules):
			if err := clearEmptyValue(lines, rulesKey); err != nil {
				return nil, r, err
			}
			at = rulesKey.Line
			dash = rulesKey.Column - 1 + 2
		case rules.Kind == yaml.SequenceNode && rules.Style&yaml.FlowStyle == 0:
			first := rules.Content[0].Line - 1
			text := lines[first]
			if !strings.HasPrefix(strings.TrimSpace(text), "-") {
				return nil, r, fmt.Errorf("cannot place rule: unexpected layout at line %d", first+1)
			}
			at = first
			dash = len(text) - len(strings.TrimLeft(text, " "))
		default:
			return nil, r, fmt.Errorf("spec.mcp.rules uses flow style; edit the file by hand")
		}
	default:
		return nil, r, fmt.Errorf("spec.mcp uses flow style; edit the file by hand")
	}
	block = append(block, FormatMCPRule(r, dash)...)
	out := make([]string, 0, len(lines)+len(block))
	out = append(out, lines[:at]...)
	out = append(out, block...)
	out = append(out, lines[at:]...)
	next := []byte(strings.Join(out, ""))
	if err := checkRules(old, next, append(append([]MCPRule{}, old.Spec.MCP.Rules...), r)); err != nil {
		return nil, r, err
	}
	return next, r, nil
}

// RemoveMCPRule removes the console-added rule id from spec.mcp.rules.
func RemoveMCPRule(raw []byte, id string) ([]byte, MCPRule, error) {
	var gone MCPRule
	if !strings.HasPrefix(id, ConsoleRulePrefix) {
		return nil, gone, fmt.Errorf("only rules added from the console (%s*) can be removed here", ConsoleRulePrefix)
	}
	old, err := Load(raw)
	if err != nil {
		return nil, gone, err
	}
	var keep []MCPRule
	for _, have := range old.Spec.MCP.Rules {
		if have.ID == id {
			gone = have
			continue
		}
		keep = append(keep, have)
	}
	if gone.ID == "" {
		return nil, gone, fmt.Errorf("rule %s not found", id)
	}
	lines := splitLines(raw)
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, gone, err
	}
	_, spec := mapGet(docRoot(&doc), "spec")
	_, mcp := mapGet(spec, "mcp")
	rulesKey, rules := mapGet(mcp, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode || rules.Style&yaml.FlowStyle != 0 {
		return nil, gone, fmt.Errorf("spec.mcp.rules is not a block list; edit the file by hand")
	}
	idx := -1
	for i, item := range rules.Content {
		if _, v := mapGet(item, "id"); v != nil && v.Value == id {
			idx = i
		}
	}
	if idx < 0 {
		return nil, gone, fmt.Errorf("rule %s not found", id)
	}
	start := rules.Content[idx].Line - 1
	text := lines[start]
	if !strings.HasPrefix(strings.TrimSpace(text), "-") {
		return nil, gone, fmt.Errorf("cannot remove rule: unexpected layout at line %d", start+1)
	}
	dash := len(text) - len(strings.TrimLeft(text, " "))
	end := start + 1
	for end < len(lines) {
		l := lines[end]
		t := strings.TrimSpace(l)
		if t != "" && len(l)-len(strings.TrimLeft(l, " ")) <= dash {
			break
		}
		end++
	}
	for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	out := append(append([]string{}, lines[:start]...), lines[end:]...)
	if len(rules.Content) == 1 {
		i := rulesKey.Line - 1
		l := strings.TrimRight(out[i], "\r\n")
		body, comment, _ := strings.Cut(l, "#")
		body = strings.TrimRight(body, " ") + " []"
		if comment != "" {
			body += "  #" + comment
		}
		out[i] = body + "\n"
	}
	next := []byte(strings.Join(out, ""))
	if err := checkRules(old, next, keep); err != nil {
		return nil, gone, err
	}
	return next, gone, nil
}

// FormatMCPRule renders r as a block list item whose dash is at column dash.
func FormatMCPRule(r MCPRule, dash int) []string {
	p := pad(dash)
	server, tool := r.Server, r.Tool
	if server == "" {
		server = "*"
	}
	if tool == "" {
		tool = "*"
	}
	out := []string{
		p + "- id: " + r.ID + "\n",
		p + "  server: " + quote(server) + "\n",
		p + "  tool: " + quote(tool) + "\n",
		p + "  decision: " + strings.ToLower(r.Decision) + "\n",
	}
	if r.Reason != "" {
		out = append(out, p+"  reason: "+quote(r.Reason)+"\n")
	}
	return out
}

// checkRules parses next and requires it to be old with exactly want as
// its MCP rules.
func checkRules(old *Profile, next []byte, want []MCPRule) error {
	p, err := Load(next)
	if err != nil {
		return fmt.Errorf("edited profile does not parse: %w", err)
	}
	got := p.Spec.MCP.Rules
	if len(got) != len(want) {
		return fmt.Errorf("edited profile has %d mcp rules, want %d", len(got), len(want))
	}
	byID := map[string]MCPRule{}
	for _, r := range got {
		byID[r.ID] = r
	}
	for _, r := range want {
		g, ok := byID[r.ID]
		if !ok || globKey(g.Server) != globKey(r.Server) || globKey(g.Tool) != globKey(r.Tool) || g.Decision != r.Decision || g.Reason != r.Reason {
			return fmt.Errorf("edited profile changed rule %s unexpectedly", r.ID)
		}
	}
	a, b := *old, *p
	a.Spec.MCP.Rules, b.Spec.MCP.Rules = nil, nil
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("edit changed more than spec.mcp.rules")
	}
	return nil
}

func globKey(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSpace(b.String())
}

func pad(n int) string {
	if n < 0 {
		n = 0
	}
	return strings.Repeat(" ", n)
}

// splitLines keeps line endings so the file can be rejoined byte for byte.
func splitLines(raw []byte) []string {
	s := string(raw)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return strings.SplitAfter(s, "\n")[:strings.Count(s, "\n")]
}

func docRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
		return doc.Content[0]
	}
	return nil
}

func mapGet(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// isEmpty is true for a null value, [] or {}.
func isEmpty(n *yaml.Node) bool {
	if n == nil {
		return true
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Tag == "!!null"
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) == 0
	}
	return false
}

// clearEmptyValue rewrites "key: []", "key: {}", "key: ~" or "key: null" on
// the key's line to "key:" so block content can follow.
func clearEmptyValue(lines []string, key *yaml.Node) error {
	i := key.Line - 1
	if i < 0 || i >= len(lines) {
		return fmt.Errorf("cannot find line %d", key.Line)
	}
	l := lines[i]
	nl := ""
	if strings.HasSuffix(l, "\n") {
		nl = "\n"
		l = strings.TrimSuffix(l, "\n")
	}
	if strings.HasSuffix(l, "\r") {
		nl = "\r" + nl
		l = strings.TrimSuffix(l, "\r")
	}
	col := key.Column - 1
	prefix := key.Value + ":"
	if col > len(l) || !strings.HasPrefix(l[col:], prefix) {
		return fmt.Errorf("unexpected layout at line %d", key.Line)
	}
	rest := l[col+len(prefix):]
	val, comment, hasComment := strings.Cut(rest, "#")
	switch strings.TrimSpace(val) {
	case "", "[]", "{}", "~", "null":
	default:
		return fmt.Errorf("unexpected value at line %d", key.Line)
	}
	out := l[:col+len(prefix)]
	if hasComment {
		out += "  #" + comment
	}
	lines[i] = out + nl
	return nil
}
