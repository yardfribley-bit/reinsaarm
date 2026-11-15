package console

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/activity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

// A turn is one user prompt and everything the agent did until it stopped:
// receipts sharing a turn_id (Codex), or, for agents without one, the
// receipts from a prompt to the next prompt.

// Step is one timeline item with what the replay view derives from it.
type Step struct {
	TimelineItem
	// Index numbers tool calls within the turn, from 1.
	Index int `json:"index,omitempty"`
	// Category is web, mcp, read, write, shell, or other for tool calls,
	// else the item type.
	Category string `json:"category"`
	// Label is a short Chinese description of the step.
	Label    string     `json:"label"`
	Server   string     `json:"server,omitempty"`
	ToolName string     `json:"tool_name,omitempty"`
	Query    string     `json:"query,omitempty"`
	Paths    []PathInfo `json:"paths,omitempty"`
	Hosts    []string   `json:"hosts,omitempty"`
	Outside  bool       `json:"outside,omitempty"`
	NoRule   bool       `json:"no_rule,omitempty"`
	Denied   bool       `json:"denied,omitempty"`
	Failed   bool       `json:"failed,omitempty"`
	// FailSource says how the failure is known: exit_code, reported (the
	// agent said so), or output (the output holds an exception or error,
	// used when the agent sends no exit code).
	FailSource string `json:"fail_source,omitempty"`
	FailHint   string `json:"fail_hint,omitempty"`
	Credential bool   `json:"credential,omitempty"`
	// Untrusted marks a web or search result that went back to the model.
	Untrusted bool `json:"untrusted,omitempty"`
	// Sensitive marks a write, a changing shell command, or egress.
	Sensitive bool `json:"sensitive,omitempty"`
	// AfterUntrusted marks a sensitive step that came after untrusted input
	// in the same turn.
	AfterUntrusted bool `json:"after_untrusted,omitempty"`
	// Links are the result's URLs: result_links when captured, else found in
	// the stored output (receipts written before link capture).
	Links []ledger.Link `json:"links,omitempty"`
	// Running is a call with a decision and no result yet in a running turn.
	Running    bool   `json:"running,omitempty"`
	EndTS      string `json:"end_ts,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
}

// PathInfo is one path a step touched.
type PathInfo struct {
	Path    string `json:"path"`
	Outside bool   `json:"outside,omitempty"`
}

// Gap is an interval without hook events: model thinking (between steps)
// or composing the answer (last step to Stop).
type Gap struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
	MS   int64  `json:"ms"`
	// BeforeSeq is the seq of the step that follows the gap (0: Stop or now).
	BeforeSeq uint64 `json:"before_seq,omitempty"`
}

// Risk is one flag on a turn or session.
type Risk struct {
	Code  string   `json:"code"`
	Label string   `json:"label"`
	Count int      `json:"count"`
	Seqs  []uint64 `json:"seqs,omitempty"`
}

// Counts are tool calls by category.
type Counts struct {
	Tools        int `json:"tools"`
	Web          int `json:"web"`
	MCP          int `json:"mcp"`
	Read         int `json:"read"`
	ReadOutside  int `json:"read_outside"`
	Write        int `json:"write"`
	WriteOutside int `json:"write_outside"`
	Shell        int `json:"shell"`
	ShellFailed  int `json:"shell_failed"`
	Other        int `json:"other"`
}

// Turn is one task in a session.
type Turn struct {
	Index      int    `json:"index"`
	ID         string `json:"id,omitempty"`
	Start      string `json:"start"`
	End        string `json:"end,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Status is running, done (Stop seen), no_stop (a later turn or the
	// session end came without a Stop), or decisions_only (only pre-tool
	// receipts: activity events were not installed).
	Status          string        `json:"status"`
	Stale           bool          `json:"stale,omitempty"`
	Prompt          string        `json:"prompt"`
	PromptChars     int           `json:"prompt_chars,omitempty"`
	PromptFull      bool          `json:"prompt_full,omitempty"`
	PromptTruncated bool          `json:"prompt_truncated,omitempty"`
	Title           string        `json:"title"`
	Final           string        `json:"final,omitempty"`
	FinalChars      int           `json:"final_chars,omitempty"`
	FinalTruncated  bool          `json:"final_truncated,omitempty"`
	Commentary      []ledger.Note `json:"commentary,omitempty"`
	Source          string        `json:"source"`
	SourceLabel     string        `json:"source_label"`
	SourceWhy       string        `json:"source_why,omitempty"`
	Trigger         string        `json:"trigger,omitempty"`
	Originator      string        `json:"originator,omitempty"`
	Model           string        `json:"model,omitempty"`
	CWD             string        `json:"cwd,omitempty"`
	Counts          Counts        `json:"counts"`
	Denied          int           `json:"denied"`
	Failed          int           `json:"failed"`
	OneLiner        string        `json:"one_liner"`
	Risks           []Risk        `json:"risks"`
	Gaps            []Gap         `json:"gaps"`
	ThinkMS         int64         `json:"think_ms"`
	SeqFrom         uint64        `json:"seq_from"`
	SeqTo           uint64        `json:"seq_to"`
	Untrusted       int           `json:"untrusted"`
	SensitiveAfter  int           `json:"sensitive_after"`
	// HasPreviews is false when no step carries an input preview (receipts
	// written before previews were captured).
	HasPreviews bool `json:"has_previews"`
	// Coverage lists what the hooks cannot see for this turn.
	Coverage   []string `json:"coverage"`
	Steps      []Step   `json:"steps"`
	Live       *Step    `json:"live,omitempty"`
	ElapsedMS  int64    `json:"elapsed_ms,omitempty"`
	start, end time.Time
}

// replayOpts holds what turn building needs from the server.
type replayOpts struct {
	Home     string
	GapAfter time.Duration
	Now      time.Time
}

func (o replayOpts) gap() time.Duration {
	if o.GapAfter <= 0 {
		return 20 * time.Second
	}
	return o.GapAfter
}

// buildTurns groups a session's timeline into turns.
func buildTurns(items []TimelineItem, sessionEnded bool, cwd string, o replayOpts) []Turn {
	var turns []*Turn
	byID := map[string]*Turn{}
	var pending []TimelineItem
	var cur *Turn
	stepsOf := map[*Turn][]TimelineItem{}
	newTurn := func(id string) *Turn {
		t := &Turn{ID: id}
		turns = append(turns, t)
		if id != "" {
			byID[id] = t
		}
		stepsOf[t] = append(stepsOf[t], pending...)
		pending = nil
		return t
	}
	stopped := map[*Turn]bool{}
	for _, it := range items {
		head := headOf(it)
		tid := ""
		if head != nil {
			tid = head.TurnID
		}
		switch {
		case tid != "":
			t := byID[tid]
			if t == nil {
				t = newTurn(tid)
			}
			cur = t
		case it.Type == "prompt":
			cur = newTurn("")
		case it.Type == "start" && (cur == nil || stopped[cur]):
			pending = append(pending, it)
			continue
		case cur == nil:
			pending = append(pending, it)
			continue
		}
		stepsOf[cur] = append(stepsOf[cur], it)
		if it.Type == "stop" {
			stopped[cur] = true
		}
	}
	if len(pending) > 0 {
		if len(turns) == 0 {
			newTurn("")
		} else {
			last := turns[len(turns)-1]
			stepsOf[last] = append(stepsOf[last], pending...)
		}
	}
	out := make([]Turn, 0, len(turns))
	for i, t := range turns {
		t.Index = i + 1
		its := stepsOf[t]
		sortStepsForDisplay(its)
		last := i == len(turns)-1
		fillTurn(t, its, last && !sessionEnded, cwd, o)
		out = append(out, *t)
	}
	return out
}

func headOf(it TimelineItem) *ledger.Receipt {
	switch {
	case it.Decision != nil:
		return it.Decision
	case it.Result != nil:
		return it.Result
	}
	return it.Event
}

func parseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func fillTurn(t *Turn, its []TimelineItem, mayRun bool, sessCWD string, o replayOpts) {
	t.Risks = []Risk{}
	t.Gaps = []Gap{}
	t.Steps = []Step{}
	risks := map[string]*Risk{}
	addRisk := func(code, label string, seq uint64) {
		r := risks[code]
		if r == nil {
			r = &Risk{Code: code, Label: label}
			risks[code] = r
		}
		r.Count++
		if seq != 0 && len(r.Seqs) < 50 {
			r.Seqs = append(r.Seqs, seq)
		}
	}
	var promptAt, stopAt time.Time
	var firstAt, lastAt time.Time
	stop := false
	observed := false
	var lastActivity time.Time
	untrustedSeen := false
	mcpTools := map[string]bool{}
	var failHints []string
	for _, it := range its {
		head := headOf(it)
		if head == nil {
			continue
		}
		for _, r := range []*ledger.Receipt{it.Decision, it.Result, it.Event} {
			if r == nil {
				continue
			}
			if t.SeqFrom == 0 || r.Seq < t.SeqFrom {
				t.SeqFrom = r.Seq
			}
			if r.Seq > t.SeqTo {
				t.SeqTo = r.Seq
			}
			if ts := parseTS(r.TS); !ts.IsZero() {
				if firstAt.IsZero() || ts.Before(firstAt) {
					firstAt = ts
				}
				if ts.After(lastAt) {
					lastAt = ts
				}
			}
			if a := r.Activity; a != nil && a.Model != "" && t.Model == "" {
				t.Model = a.Model
			}
			if r.CWD != "" && t.CWD == "" {
				t.CWD = r.CWD
			}
		}
		if it.Event != nil || it.Result != nil {
			observed = true
		}
		st := Step{TimelineItem: it, Category: it.Type}
		at := parseTS(it.TS)
		switch it.Type {
		case "prompt":
			a := activityOf(it.Event)
			// Masked again: receipts are masked at capture, this guards older
			// or hand-made ones.
			t.Prompt = redact.Mask(a.Prompt)
			t.PromptChars = a.PromptChars
			t.PromptFull = a.PromptFull
			t.PromptTruncated = a.Truncated
			if a.Trigger != "" {
				t.Trigger = a.Trigger
			}
			if a.Originator != "" {
				t.Originator = a.Originator
			}
			promptAt = at
			lastActivity = at
			st.Label = "用户提示"
		case "stop":
			a := activityOf(it.Event)
			t.Final = redact.Mask(a.Message)
			t.FinalChars = a.MessageChars
			t.FinalTruncated = a.Truncated
			t.Commentary = nil
			for _, n := range a.Commentary {
				t.Commentary = append(t.Commentary, ledger.Note{TS: n.TS, Text: redact.Mask(n.Text)})
			}
			if a.Trigger != "" {
				t.Trigger = a.Trigger
			}
			if a.Originator != "" {
				t.Originator = a.Originator
			}
			stop = true
			stopAt = at
			st.Label = "Agent 完成本轮"
			if !lastActivity.IsZero() && at.Sub(lastActivity) > 0 {
				ms := at.Sub(lastActivity).Milliseconds()
				kind := "compose"
				if t.Counts.Tools == 0 {
					kind = "think"
					t.ThinkMS += ms
				}
				t.Gaps = append(t.Gaps, Gap{Kind: kind, From: fmtTS(lastActivity), To: it.TS, MS: ms})
			}
		case "start":
			a := activityOf(it.Event)
			st.Label = "会话开始"
			if a.Source != "" {
				st.Label += " · " + a.Source
			}
			if a.Model != "" {
				st.Label += " · " + a.Model
			}
		case "end":
			st.Label = "会话结束"
			if a := activityOf(it.Event); a.Reason != "" {
				st.Label += " · " + a.Reason
			}
		case "tool":
			t.Counts.Tools++
			st.Index = t.Counts.Tools
			// A gap before the call is the model thinking.
			if !lastActivity.IsZero() && at.Sub(lastActivity) >= o.gap() {
				ms := at.Sub(lastActivity).Milliseconds()
				t.Gaps = append(t.Gaps, Gap{Kind: "think", From: fmtTS(lastActivity), To: it.TS, MS: ms, BeforeSeq: it.Seq})
				t.ThinkMS += ms
			}
			classify(&st, sessCWD, o.Home)
			if st.Category == "mcp" || (st.Category == "web" && st.Server != "") {
				mcpTools[st.ToolName] = true
			}
			if it.Result != nil {
				st.EndTS = it.Result.TS
				if a := it.Result.Activity; a != nil && a.DurationMS != nil {
					st.DurationMS = a.DurationMS
				}
			}
			end := at
			if e := parseTS(st.EndTS); e.After(end) {
				end = e
			}
			if end.After(lastActivity) {
				lastActivity = end
			}
			switch st.Category {
			case "web":
				t.Counts.Web++
			case "mcp":
				t.Counts.MCP++
			case "read":
				t.Counts.Read++
				if st.Outside {
					t.Counts.ReadOutside++
				}
			case "write":
				t.Counts.Write++
				if st.Outside {
					t.Counts.WriteOutside++
				}
			case "shell":
				t.Counts.Shell++
				if st.Failed {
					t.Counts.ShellFailed++
				}
			default:
				t.Counts.Other++
			}
			seq := it.Seq
			if st.Denied {
				t.Denied++
				addRisk("deny", "拒绝", seq)
			}
			if st.Failed {
				t.Failed++
				addRisk("fail", "失败", seq)
				if st.FailHint != "" {
					failHints = append(failHints, st.FailHint)
				}
			}
			if st.Outside {
				switch st.Category {
				case "read":
					addRisk("outside_read", "项目外读取", seq)
				case "write":
					addRisk("outside_write", "项目外写入", seq)
				default:
					addRisk("outside_path", "项目外路径", seq)
				}
			}
			if st.NoRule {
				addRisk("no_rule_mcp", "无规则放行 MCP", seq)
			}
			if st.Credential {
				addRisk("credential", "命中凭证路径", seq)
			}
			if len(st.Hosts) > 0 && (st.Category == "shell" || st.Category == "web" && st.Server == "") {
				addRisk("egress", "出网", seq)
			}
			if st.Sensitive && untrustedSeen && !st.Denied {
				st.AfterUntrusted = true
				t.SensitiveAfter++
				addRisk("untrusted_then_sensitive", "不可信输入后敏感操作", seq)
			}
			if st.Untrusted {
				untrustedSeen = true
				t.Untrusted++
			}
			if it.Result == nil && it.Decision != nil && !st.Denied && mayRun && !stop {
				st.Running = true
			}
			if a := activityOf(it.Decision); a.ArgsPreview != "" || a.Query != "" {
				t.HasPreviews = true
			}
		}
		t.Steps = append(t.Steps, st)
	}
	if !promptAt.IsZero() {
		t.start = promptAt
		// A session start right before the prompt belongs to the task.
		if !firstAt.IsZero() && firstAt.Before(promptAt) && promptAt.Sub(firstAt) < 5*time.Second {
			t.start = firstAt
		}
	} else {
		t.start = firstAt
	}
	t.Start = fmtTS(t.start)
	switch {
	case stop:
		t.Status = "done"
		t.end = stopAt
		if lastAt.After(stopAt) {
			t.end = lastAt
		}
	case !observed:
		t.Status = "decisions_only"
		t.end = lastAt
	case mayRun:
		t.Status = "running"
		t.end = lastAt
		now := o.Now
		if now.IsZero() {
			now = time.Now()
		}
		if !t.start.IsZero() {
			t.ElapsedMS = now.Sub(t.start).Milliseconds()
		}
		if now.Sub(lastAt) > 30*time.Minute {
			t.Stale = true
		}
		for i := len(t.Steps) - 1; i >= 0; i-- {
			if t.Steps[i].Running {
				s := t.Steps[i]
				t.Live = &s
				break
			}
		}
	default:
		t.Status = "no_stop"
		t.end = lastAt
	}
	if !t.end.IsZero() {
		t.End = fmtTS(t.end)
	}
	if !t.start.IsZero() && !t.end.IsZero() {
		t.DurationMS = t.end.Sub(t.start).Milliseconds()
	}
	if t.Status == "running" && t.ElapsedMS > 0 {
		t.DurationMS = t.ElapsedMS
	}
	t.Source, t.SourceLabel, t.SourceWhy = turnSource(t, clientOf(its))
	t.Title = turnTitle(t.Prompt, t.Source == "automation")
	t.OneLiner = oneLiner(t, mcpTools, failHints)
	t.Coverage = coverageNotes(clientOf(its), *t)
	order := []string{"deny", "fail", "outside_read", "outside_write", "outside_path", "no_rule_mcp", "credential", "egress", "untrusted_then_sensitive"}
	for _, c := range order {
		if r := risks[c]; r != nil {
			t.Risks = append(t.Risks, *r)
		}
	}
}

func fmtTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func clientOf(its []TimelineItem) string {
	for _, it := range its {
		if h := headOf(it); h != nil && h.Client != "" {
			return h.Client
		}
	}
	return ""
}

var emptyActivity = &ledger.Activity{}

func activityOf(r *ledger.Receipt) *ledger.Activity {
	if r == nil || r.Activity == nil {
		return emptyActivity
	}
	return r.Activity
}

var webName = regexp.MustCompile(`(?i)search|web|fetch|brows|http|url|crawl|scrape`)

// classify sets category, label, paths, and flags of a tool step.
func classify(st *Step, sessCWD, home string) {
	d, r := st.Decision, st.Result
	head := d
	if head == nil {
		head = r
	}
	res := head.Resources
	if res == nil && r != nil {
		res = r.Resources
	}
	cwd := head.CWD
	if cwd == "" {
		cwd = sessCWD
	}
	if res != nil {
		st.Server, st.ToolName = res.MCPServer, res.MCPTool
		st.Hosts = res.Hosts
	}
	if a := activityOf(d); a.Query != "" {
		st.Query = a.Query
	}
	var paths []string
	if res != nil {
		paths = append(paths, res.Paths...)
	}
	if r != nil && r.Activity != nil {
		paths = append(paths, r.Activity.Files...)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out := outsideWorkspace(p, cwd, home)
		st.Paths = append(st.Paths, PathInfo{Path: p, Outside: out})
		if out {
			st.Outside = true
		}
	}
	switch head.Kind {
	case "web_fetch":
		st.Category = "web"
	case "mcp":
		if webName.MatchString(st.ToolName) || webName.MatchString(st.Server) {
			st.Category = "web"
		} else {
			st.Category = "mcp"
		}
	case "file_read":
		st.Category = "read"
	case "file_write", "file_edit":
		st.Category = "write"
	case "shell":
		cmd := head.CommandPreview
		if a := activityOf(d); a.ArgsPreview != "" {
			cmd = a.ArgsPreview
		}
		if readOnlyShell(cmd) {
			st.Category = "read"
		} else {
			st.Category = "shell"
		}
	default:
		// Newer Codex builds call the built-in search "webrun" (kind other).
		if webName.MatchString(head.Tool) {
			st.Category = "web"
		} else {
			st.Category = "other"
		}
	}
	if d != nil {
		if d.EnforcedDecision == "DENY" || d.EnforcedDecision == "DEFER" {
			st.Denied = true
		}
		noRule := true
		for _, id := range d.RuleIDs {
			if id != "R-DEFAULT-ALLOW" {
				noRule = false
			}
			if id == "R-CRED-PATH" {
				st.Credential = true
			}
		}
		if head.Kind == "mcp" && d.EnforcedDecision == "ALLOW" && noRule {
			st.NoRule = true
		}
	}
	if r != nil && r.Activity != nil && !st.Denied {
		a := r.Activity
		switch {
		case a.Success != nil && !*a.Success:
			st.Failed = true
			st.FailSource = "reported"
			if a.ExitCode != nil {
				st.FailSource = "exit_code"
			}
			st.FailHint = exceptionName(a.Error + "\n" + a.Output)
		case a.Success == nil && looksFailed(a.Output):
			st.Failed = true
			st.FailSource = "output"
			st.FailHint = exceptionName(a.Output)
		}
	}
	if r != nil && r.Activity != nil && (st.Category == "web" || st.Category == "mcp") {
		st.Links = r.Activity.ResultLinks
		if len(st.Links) == 0 && st.Category == "web" {
			st.Links = activity.ResultLinks(r.Activity.Output)
		}
	}
	if st.Category == "web" && r != nil && !st.Failed {
		st.Untrusted = true
	}
	if st.Category == "write" || st.Category == "shell" || (len(st.Hosts) > 0 && st.Category != "web") {
		st.Sensitive = true
	}
	st.Label = stepLabel(st, head)
}

func stepLabel(st *Step, head *ledger.Receipt) string {
	switch st.Category {
	case "web":
		if st.Server != "" {
			return st.Server + " / " + st.ToolName
		}
		return head.Tool
	case "mcp":
		return st.Server + " / " + st.ToolName
	}
	if head.CommandPreview != "" {
		return head.CommandPreview
	}
	if len(st.Paths) > 0 {
		return head.Tool + " " + st.Paths[0].Path
	}
	return head.Tool
}

// outsideWorkspace reports whether p is outside cwd. Relative paths are
// inside; ~ is expanded with home. Device files are ignored.
func outsideWorkspace(p, cwd, home string) bool {
	if cwd == "" {
		return false
	}
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return true
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	case !filepath.IsAbs(p):
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	if strings.HasPrefix(p, "/dev/") {
		return false
	}
	root := filepath.Clean(cwd)
	return p != root && !strings.HasPrefix(p, root+string(filepath.Separator))
}

var readOnlyCmds = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "ls": true, "find": true,
	"grep": true, "rg": true, "wc": true, "stat": true, "file": true, "nl": true, "tree": true,
	"du": true, "pwd": true, "jq": true, "diff": true, "realpath": true, "readlink": true, "which": true,
	"echo": true, "printf": true, "sort": true, "uniq": true, "cut": true, "basename": true, "dirname": true,
}

var redirect = regexp.MustCompile(`>`)

var shellSplit = regexp.MustCompile(`&&|\|\||[|;\n]`)

// readOnlyShell reports whether every part of a command line only reads:
// cat, ls, grep, sed -n, git status/log/diff/show, ... and no output
// redirection.
func readOnlyShell(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || strings.HasSuffix(cmd, "…") || strings.Contains(cmd, "$(") || strings.Contains(cmd, "`") {
		return false
	}
	if redirect.MatchString(strings.NewReplacer("2>&1", "", "2>/dev/null", "", ">/dev/null", "").Replace(cmd)) {
		return false
	}
	saw := false
	for _, part := range shellSplit.Split(cmd, -1) {
		f := strings.Fields(part)
		for len(f) > 0 && strings.Contains(f[0], "=") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		saw = true
		prog := filepath.Base(f[0])
		switch {
		case readOnlyCmds[prog]:
			if prog == "find" && (strings.Contains(part, "-delete") || strings.Contains(part, "-exec")) {
				return false
			}
		case prog == "sed" && len(f) > 1 && f[1] == "-n":
		case prog == "git" && len(f) > 1 && (f[1] == "status" || f[1] == "log" || f[1] == "diff" || f[1] == "show" || f[1] == "rev-parse"):
		default:
			return false
		}
	}
	return saw
}

var (
	excName   = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*(?:Error|Exception))\b\s*:`)
	failMarks = regexp.MustCompile(`Traceback \(most recent call last\)|\bpanic: |command not found|^\s*(?:error|fatal):`)
)

// looksFailed reports whether output without an exit code shows a failure.
func looksFailed(out string) bool {
	return failMarks.MatchString(out) || excName.MatchString(lastLine(out))
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func exceptionName(s string) string {
	m := excName.FindAllStringSubmatch(s, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1][1]
}

// sortStepsForDisplay puts session start before the prompt and tools before
// stop, even when hook receipt sequence (or timestamps a few milliseconds
// apart) arrive out of that narrative order. Audit seq numbers on each step
// are left as written; this only changes display order.
func sortStepsForDisplay(its []TimelineItem) {
	sort.SliceStable(its, func(a, b int) bool {
		ra, rb := stepRank(its[a].Type), stepRank(its[b].Type)
		if ra != rb {
			return ra < rb
		}
		ta, tb := parseTS(its[a].TS), parseTS(its[b].TS)
		if !ta.IsZero() && !tb.IsZero() && !ta.Equal(tb) {
			return ta.Before(tb)
		}
		return its[a].Seq < its[b].Seq
	})
}

func stepRank(typ string) int {
	switch typ {
	case "start":
		return 0
	case "prompt":
		return 1
	case "stop":
		return 3
	case "end":
		return 4
	default:
		return 2
	}
}

// turnSource says who started the turn: automation (Codex turn_trigger
// automation_*, or a <heartbeat> prompt), desktop, or cli.
func turnSource(t *Turn, client string) (code, label, why string) {
	p := strings.TrimSpace(t.Prompt)
	switch {
	case strings.HasPrefix(t.Trigger, "automation"):
		return "automation", "自动化任务", "turn_trigger=" + t.Trigger
	case strings.HasPrefix(p, "<heartbeat>") || strings.Contains(p, "<automation_id>"):
		return "automation", "自动化任务", "提示以 <heartbeat> 开头"
	}
	o := strings.ToLower(t.Originator)
	switch {
	case strings.Contains(o, "desktop"):
		return "desktop", "桌面版", "originator=" + t.Originator
	case strings.Contains(o, "exec"):
		return "cli", "命令行 exec", "originator=" + t.Originator
	case strings.Contains(o, "cli") || strings.Contains(o, "tui"):
		return "cli", "命令行", "originator=" + t.Originator
	case strings.Contains(o, "vscode") || strings.Contains(o, "ide"):
		return "ide", "编辑器插件", "originator=" + t.Originator
	case t.Originator != "":
		return "other", t.Originator, "originator=" + t.Originator
	}
	switch t.Trigger {
	case "exec":
		return "cli", "命令行 exec", "turn_trigger=exec"
	}
	switch client {
	case "workbuddy":
		return workbuddySource(t)
	case "claude-code", "gemini":
		return "cli", "命令行", client + " 钩子"
	}
	return "unknown", "来源未记录", ""
}

// workbuddyDesktopCWD matches a WorkBuddy desktop task folder
// ("…/WorkBuddy AI/2026-11-12-18-52-21") or the desktop app's virtual
// project path ("…/reinsaarm/~:reinsaarm-workbuddy-accept").
var workbuddyDesktopCWD = regexp.MustCompile(`(?i)(?:^|[/\\])WorkBuddy(?: AI)?[/\\]\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}(?:[/\\]|$)`)

func isWorkBuddyDesktopCWD(p string) bool {
	if p == "" {
		return false
	}
	if strings.Contains(p, "/~:") || strings.Contains(p, "\\~:") || strings.HasPrefix(p, "~:") {
		return true
	}
	return workbuddyDesktopCWD.MatchString(p)
}

// workbuddySource tells desktop from CLI when WorkBuddy sends no originator
// (it currently does not). The previous default labelled every WorkBuddy
// session "桌面版", including bundled-CLI `-p` runs.
func workbuddySource(t *Turn) (code, label, why string) {
	cwd := t.CWD
	if cwd == "" {
		for _, st := range t.Steps {
			if h := headOf(st.TimelineItem); h != nil && h.CWD != "" {
				cwd = h.CWD
				break
			}
		}
	}
	if isWorkBuddyDesktopCWD(cwd) {
		return "desktop", "桌面版", "工作区路径像桌面端任务目录"
	}
	if strings.HasPrefix(strings.ToLower(t.Model), "default-model") {
		return "cli", "命令行", "占位模型 default-model（常见于 CLI -p）"
	}
	return "unknown", "来源未记录", "WorkBuddy 未记录来源，且路径与模型不足以判断"
}

var instrRe = regexp.MustCompile(`(?s)<instructions>\s*(.*?)(?:</instructions>|$)`)

// turnTitle is the prompt's first line, or for automation the first
// sentence of its instructions.
func turnTitle(prompt string, automation bool) string {
	p := strings.TrimSpace(prompt)
	if p == "" {
		return ""
	}
	if automation {
		tag := ""
		if strings.HasPrefix(p, "<heartbeat>") {
			tag = "（heartbeat）"
		}
		if m := instrRe.FindStringSubmatch(p); m != nil {
			s := strings.TrimSpace(m[1])
			if i := strings.IndexAny(s, "。\n"); i > 0 {
				s = s[:i]
			}
			s = strings.TrimSuffix(s, "…")
			return clipRunes(s, 120) + tag
		}
		return clipRunes(p, 120)
	}
	if i := strings.Index(p, "\n"); i > 0 {
		p = p[:i]
	}
	return clipRunes(p, 160)
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func oneLiner(t *Turn, mcpTools map[string]bool, failHints []string) string {
	c := t.Counts
	if c.Tools == 0 {
		parts := []string{"未调用工具"}
		if t.Status == "running" {
			parts = []string{"尚未调用工具"}
		}
		return strings.Join(parts, " · ")
	}
	var parts []string
	if c.Web > 0 {
		parts = append(parts, fmt.Sprintf("搜索网页 %d 次", c.Web))
	}
	if c.MCP > 0 {
		if len(mcpTools) == 1 {
			for name := range mcpTools {
				parts = append(parts, fmt.Sprintf("MCP %s %d 次", name, c.MCP))
			}
		} else {
			parts = append(parts, fmt.Sprintf("MCP 调用 %d 次", c.MCP))
		}
	}
	if c.Read > 0 {
		s := fmt.Sprintf("读取文件 %d 次", c.Read)
		switch {
		case c.ReadOutside == c.Read:
			s += "（项目外）"
		case c.ReadOutside > 0:
			s += fmt.Sprintf("（项目外 %d）", c.ReadOutside)
		}
		parts = append(parts, s)
	}
	if c.Write > 0 {
		s := fmt.Sprintf("写入 / 修改文件 %d 次", c.Write)
		if c.WriteOutside > 0 {
			s += fmt.Sprintf("（项目外 %d）", c.WriteOutside)
		}
		parts = append(parts, s)
	} else {
		parts = append(parts, "未写文件")
	}
	if c.Shell > 0 {
		s := fmt.Sprintf("执行命令 %d 次", c.Shell)
		if c.ShellFailed > 0 {
			if len(failHints) > 0 {
				s += "（返回 " + failHints[0] + "）"
			} else {
				s += fmt.Sprintf("（失败 %d）", c.ShellFailed)
			}
		}
		parts = append(parts, s)
	} else {
		parts = append(parts, "未执行改动命令")
	}
	if c.Other > 0 {
		parts = append(parts, fmt.Sprintf("其他工具 %d 次", c.Other))
	}
	parts = append(parts, fmt.Sprintf("%d 拒绝", t.Denied))
	return strings.Join(parts, " · ")
}
