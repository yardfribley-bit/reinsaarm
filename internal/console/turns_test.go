package console

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

type chain struct {
	t    *testing.T
	seq  uint64
	recs []ledger.Receipt
}

func (c *chain) add(r ledger.Receipt) uint64 {
	c.seq++
	r.Seq = c.seq
	if r.Decision == "" {
		r.Decision, r.EnforcedDecision = "OBSERVE", "OBSERVE"
	}
	if r.Client == "" {
		r.Client, r.SessionID = "codex", "s1"
	}
	if r.CWD == "" {
		r.CWD = "/Users/dev/proj"
	}
	c.recs = append(c.recs, r)
	return r.Seq
}

func ts(sec int) string {
	return time.Date(2026, 11, 15, 13, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second).Format(time.RFC3339Nano)
}

func mcpWeb(c *chain, sec int, turn, q, out string) {
	pre := c.add(ledger.Receipt{TurnID: turn, ToolUseID: "u" + ts(sec), Tool: "mcp__codex_apps__search_service__web_run", Kind: "mcp",
		Resources: &ledger.Resources{MCPServer: "codex_apps", MCPTool: "search_service__web_run"},
		Decision:  "ALLOW", EnforcedDecision: "ALLOW", RuleIDs: []string{"R-DEFAULT-ALLOW"}, EventType: "action.decision", TS: ts(sec),
		Activity: &ledger.Activity{Hook: "PreToolUse", Query: q}})
	c.add(ledger.Receipt{TurnID: turn, ToolUseID: "u" + ts(sec), RefSeq: pre, Tool: "mcp__codex_apps__search_service__web_run", Kind: "mcp", EventType: "tool.result", TS: ts(sec + 4),
		Activity: &ledger.Activity{Hook: "PostToolUse", Output: out}})
}

func opts() replayOpts {
	return replayOpts{Home: "/Users/dev", Now: time.Date(2026, 11, 15, 13, 5, 0, 0, time.UTC)}
}

func TestTurnGroupingAndRisks(t *testing.T) {
	c := &chain{t: t}
	c.add(ledger.Receipt{TurnID: "T1", EventType: "session.start", TS: ts(0), Activity: &ledger.Activity{Source: "startup"}})
	c.add(ledger.Receipt{TurnID: "T1", EventType: "prompt.submit", TS: ts(1), Activity: &ledger.Activity{Prompt: "搜一下 LoopX", PromptChars: 10, Originator: "Codex Desktop", Trigger: "composer"}})
	mcpWeb(c, 40, "T1", "github LoopX", "LoopX (https://github.com/loopx/loopx?utm=1) 【turn0search0】")
	// Read outside the workspace with a read-only shell command.
	pre := c.add(ledger.Receipt{TurnID: "T1", ToolUseID: "r1", Tool: "Bash", Kind: "shell", CommandPreview: "cat /Users/dev/.codex/skills/x/SKILL.md",
		Resources: &ledger.Resources{Paths: []string{"/Users/dev/.codex/skills/x/SKILL.md"}},
		Decision:  "ALLOW", EnforcedDecision: "ALLOW", RuleIDs: []string{"R-DEFAULT-ALLOW"}, EventType: "action.decision", TS: ts(50)})
	c.add(ledger.Receipt{TurnID: "T1", ToolUseID: "r1", RefSeq: pre, Tool: "Bash", EventType: "tool.result", TS: ts(51), Activity: &ledger.Activity{Output: "--- name: x"}})
	// A changing command after untrusted input, and a credential deny.
	pre = c.add(ledger.Receipt{TurnID: "T1", ToolUseID: "w1", Tool: "Bash", Kind: "shell", CommandPreview: "python3 fix.py",
		Decision: "ALLOW", EnforcedDecision: "ALLOW", RuleIDs: []string{"R-DEFAULT-ALLOW"}, EventType: "action.decision", TS: ts(52)})
	c.add(ledger.Receipt{TurnID: "T1", ToolUseID: "w1", RefSeq: pre, Tool: "Bash", EventType: "tool.result", TS: ts(53),
		Activity: &ledger.Activity{Output: "Traceback (most recent call last):\n  File \"fix.py\"\nValueError: not enough values"}})
	c.add(ledger.Receipt{TurnID: "T1", ToolUseID: "d1", Tool: "Read", Kind: "file_read", Resources: &ledger.Resources{Paths: []string{"/Users/dev/.ssh/id_ed25519"}},
		Decision: "DENY", EnforcedDecision: "DENY", RuleIDs: []string{"R-CRED-PATH"}, EventType: "action.decision", TS: ts(54)})
	c.add(ledger.Receipt{TurnID: "T1", EventType: "agent.stop", TS: ts(90), Activity: &ledger.Activity{Message: "done", MessageChars: 4,
		Commentary: []ledger.Note{{TS: ts(30), Text: "先搜索"}}}})
	// Second turn: heartbeat automation, old receipts without turn ids.
	c.add(ledger.Receipt{EventType: "prompt.submit", TS: ts(200), Activity: &ledger.Activity{Prompt: "<heartbeat>\n<instructions>检查远程连接状态。然后汇报。</instructions>\n</heartbeat>"}})
	c.add(ledger.Receipt{Tool: "mcp__codex_apps__read_thread", Kind: "mcp", Resources: &ledger.Resources{MCPServer: "codex_apps", MCPTool: "read_thread"},
		Decision: "ALLOW", EnforcedDecision: "ALLOW", RuleIDs: []string{"R-DEFAULT-ALLOW"}, EventType: "action.decision", TS: ts(201)})

	turns := buildTurns(timeline(c.recs, "codex:s1"), false, "/Users/dev/proj", opts())
	if len(turns) != 2 {
		t.Fatalf("turns %d", len(turns))
	}
	t1 := turns[0]
	if t1.Status != "done" || t1.Source != "desktop" || t1.Steps[0].Type != "start" || t1.Counts.Tools != 4 {
		t.Fatalf("turn1 %+v", t1)
	}
	if t1.Counts.Web != 1 || t1.Counts.Read != 2 || t1.Counts.ReadOutside != 2 || t1.Counts.Shell != 1 || t1.Counts.ShellFailed != 1 {
		t.Fatalf("counts %+v", t1.Counts)
	}
	got := map[string]int{}
	for _, r := range t1.Risks {
		got[r.Code] = r.Count
	}
	for _, want := range []string{"deny", "fail", "outside_read", "no_rule_mcp", "credential", "untrusted_then_sensitive"} {
		if got[want] == 0 {
			t.Fatalf("missing risk %s in %+v", want, t1.Risks)
		}
	}
	var web, sh Step
	for _, s := range t1.Steps {
		if s.Category == "web" {
			web = s
		}
		if s.Category == "shell" {
			sh = s
		}
	}
	if !web.Untrusted || !web.NoRule || web.Query != "github LoopX" || len(web.Links) != 1 || web.Links[0].URL != "https://github.com/loopx/loopx" {
		t.Fatalf("web step %+v", web)
	}
	if !sh.Failed || sh.FailSource != "output" || sh.FailHint != "ValueError" || !sh.AfterUntrusted {
		t.Fatalf("shell step %+v", sh)
	}
	// Thinking gap between the prompt and the first tool call (39 s).
	if len(t1.Gaps) == 0 || t1.Gaps[0].Kind != "think" || t1.Gaps[0].MS != 39000 {
		t.Fatalf("gaps %+v", t1.Gaps)
	}
	if len(t1.Commentary) != 1 || !strings.Contains(t1.OneLiner, "1 拒绝") {
		t.Fatalf("commentary %+v / %s", t1.Commentary, t1.OneLiner)
	}
	t2 := turns[1]
	if t2.Source != "automation" || !strings.Contains(t2.Title, "检查远程连接状态") || !strings.Contains(t2.Title, "heartbeat") {
		t.Fatalf("automation turn %+v", t2)
	}
	if t2.Status != "running" || t2.Live == nil || t2.Live.ToolName != "read_thread" || t2.HasPreviews {
		t.Fatalf("live %+v", t2)
	}
}

func TestTriggerAutomationAndStatus(t *testing.T) {
	c := &chain{t: t}
	c.add(ledger.Receipt{TurnID: "A", EventType: "prompt.submit", TS: ts(0), Activity: &ledger.Activity{Prompt: "x"}})
	c.add(ledger.Receipt{TurnID: "A", EventType: "agent.stop", TS: ts(5), Activity: &ledger.Activity{Message: "ok", Trigger: "automation_heartbeat_scheduled", Originator: "Codex Desktop"}})
	c.add(ledger.Receipt{TurnID: "B", EventType: "prompt.submit", TS: ts(10), Activity: &ledger.Activity{Prompt: "y", Originator: "codex_exec"}})
	// Codex 0.169 built-in search: tool "webrun", kind other.
	pre := c.add(ledger.Receipt{TurnID: "B", ToolUseID: "wr", Tool: "webrun", Kind: "other", Decision: "ALLOW", EnforcedDecision: "ALLOW",
		RuleIDs: []string{"R-DEFAULT-ALLOW"}, EventType: "action.decision", TS: ts(11), Activity: &ledger.Activity{Query: "loopx"}})
	c.add(ledger.Receipt{TurnID: "B", ToolUseID: "wr", RefSeq: pre, Tool: "webrun", Kind: "other", EventType: "tool.result", TS: ts(12),
		Activity: &ledger.Activity{Output: "LoopX (https://github.com/loopx-project/loopx)"}})
	turns := buildTurns(timeline(c.recs, "codex:s1"), false, "", opts())
	if turns[1].Counts.Web != 1 || turns[1].Untrusted != 1 {
		t.Fatalf("webrun %+v", turns[1].Counts)
	}
	if turns[0].Source != "automation" || turns[1].Source != "cli" || turns[1].Status != "running" {
		t.Fatalf("%+v / %+v", turns[0], turns[1])
	}
	o := opts()
	o.Now = o.Now.Add(2 * time.Hour)
	if tt := buildTurns(timeline(c.recs, "codex:s1"), false, "", o); !tt[1].Stale {
		t.Fatal("old running turn not stale")
	}
	// Only pre-tool receipts (activity events not installed).
	d := &chain{t: t}
	d.add(ledger.Receipt{Tool: "Bash", Kind: "shell", CommandPreview: "ls", Decision: "ALLOW", EnforcedDecision: "ALLOW", EventType: "action.decision", TS: ts(0)})
	if tt := buildTurns(timeline(d.recs, "codex:s1"), false, "", opts()); tt[0].Status != "decisions_only" || tt[0].SourceLabel != "来源未记录" {
		t.Fatalf("decisions only %+v", tt[0])
	}
}

func TestReportAndReceiptRange(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "profile.yaml"), policy.DefaultYAML(), 0o644)
	key := filepath.Join(dir, "identity.key")
	pub, priv, _ := identity.LoadOrCreate(key)
	audit := filepath.Join(dir, "audit.jsonl")
	led, _ := ledger.Open(audit, "local", pub, priv)
	c := &chain{t: t}
	c.add(ledger.Receipt{TurnID: "T1", EventType: "prompt.submit", TS: ts(1), Activity: &ledger.Activity{Prompt: "搜一下 LoopX，token sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456"}})
	mcpWeb(c, 3, "T1", "LoopX", "LoopX (https://github.com/loopx/loopx)")
	c.add(ledger.Receipt{TurnID: "T1", EventType: "agent.stop", TS: ts(9), Activity: &ledger.Activity{Message: "LoopX 是一个 agent 框架"}})
	for _, r := range c.recs {
		r.Seq = 0
		r.AgentID = "dev"
		if _, err := led.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	srv, _ := New(Config{Addr: "127.0.0.1:0", AuditPath: audit, ApprovalPath: filepath.Join(dir, "a.json"),
		ProfilePath: filepath.Join(dir, "profile.yaml"), IdentityKey: key, Project: dir, CodexHome: filepath.Join(dir, "nocodex"), Token: "tok"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	base := ts.URL + "/api/sessions/" + url.PathEscape("codex:s1")

	var turns struct{ Turns []Turn }
	getJSON(t, base+"/turns?token=tok", &turns)
	if len(turns.Turns) != 1 || turns.Turns[0].Counts.Web != 1 {
		t.Fatalf("turns %+v", turns.Turns)
	}
	res, err := http.Get(base + "/report?turn=1&format=md&tz=Asia/Singapore&token=tok")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("report %v %v", res, err)
	}
	b, _ := io.ReadAll(res.Body)
	md := string(b)
	if !strings.Contains(res.Header.Get("Content-Disposition"), "attachment") || !strings.Contains(md, "LoopX 是一个 agent 框架") ||
		!strings.Contains(md, "未覆盖") || !strings.Contains(md, "通过") {
		t.Fatalf("markdown report:\n%s", md)
	}
	if strings.Contains(md, "sk-proj-AbCd") {
		t.Fatal("secret in report")
	}
	var rep map[string]any
	getJSON(t, base+"/report?turn=1&format=json&token=tok", &rep)
	if rep["schema"] != "reinsaarm.task_report.v1" {
		t.Fatalf("json report %v", rep["schema"])
	}
	if res, _ := http.Get(base + "/report?turn=9&token=tok"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("missing turn: %d", res.StatusCode)
	}
	// The range view returns every event type.
	var rng struct{ Receipts []ledger.Receipt }
	getJSON(t, ts.URL+"/api/receipts?from=1&to=4&token=tok", &rng)
	if len(rng.Receipts) != 4 || rng.Receipts[0].EventType != "prompt.submit" {
		var got []string
		for _, r := range rng.Receipts {
			got = append(got, r.EventType)
		}
		t.Fatalf("range %v", got)
	}
	_ = json.Marshal
}

func TestWorkBuddySourceDetection(t *testing.T) {
	// Bundled CLI `-p`: real project cwd, placeholder model, no originator.
	// Previously mislabelled "桌面版".
	cli := &chain{t: t}
	cli.add(ledger.Receipt{Client: "workbuddy", SessionID: "01a1dfeb-0568-7880-a636-6bbffa5506c6",
		CWD: "/Users/dev/reinsaarm-workbuddy-accept", EventType: "prompt.submit", TS: ts(0),
		Activity: &ledger.Activity{Prompt: "Reply with exactly the word PONG and do nothing else.", PromptChars: 53, Model: "default-model"}})
	cli.add(ledger.Receipt{Client: "workbuddy", SessionID: "01a1dfeb-0568-7880-a636-6bbffa5506c6",
		CWD: "/Users/dev/reinsaarm-workbuddy-accept", EventType: "session.start",
		TS:       "2026-11-15T13:00:00.011000000Z",
		Activity: &ledger.Activity{Source: "startup", Model: "default-model"}})
	cli.add(ledger.Receipt{Client: "workbuddy", SessionID: "01a1dfeb-0568-7880-a636-6bbffa5506c6",
		CWD: "/Users/dev/reinsaarm-workbuddy-accept", EventType: "agent.stop", TS: ts(1),
		Activity: &ledger.Activity{Message: "Authentication required.", MessageChars: 25, Model: "default-model"}})
	turns := buildTurns(timeline(cli.recs, "workbuddy:01a1dfeb-0568-7880-a636-6bbffa5506c6"), false, "/Users/dev/reinsaarm-workbuddy-accept", opts())
	if len(turns) != 1 {
		t.Fatalf("turns %d", len(turns))
	}
	if turns[0].Source != "cli" || turns[0].SourceLabel != "命令行" {
		t.Fatalf("cli -p labelled %+v / %s (%s)", turns[0].Source, turns[0].SourceLabel, turns[0].SourceWhy)
	}

	// Desktop: dated folder under WorkBuddy AI.
	desk := &chain{t: t}
	desk.add(ledger.Receipt{Client: "workbuddy", SessionID: "7def708b-fc17-493d-a0f2-57c5979e8c8b",
		CWD: "/Users/dev/WorkBuddy AI/2026-11-12-18-52-21", EventType: "prompt.submit", TS: ts(0),
		Activity: &ledger.Activity{Prompt: "hello", PromptChars: 5, Model: "hy4free"}})
	desk.add(ledger.Receipt{Client: "workbuddy", SessionID: "7def708b-fc17-493d-a0f2-57c5979e8c8b",
		CWD: "/Users/dev/WorkBuddy AI/2026-11-12-18-52-21", EventType: "agent.stop", TS: ts(2),
		Activity: &ledger.Activity{Message: "ok", MessageChars: 2, Model: "hy4free"}})
	dt := buildTurns(timeline(desk.recs, "workbuddy:7def708b-fc17-493d-a0f2-57c5979e8c8b"), false, "/Users/dev/WorkBuddy AI/2026-11-12-18-52-21", opts())
	if dt[0].Source != "desktop" || dt[0].SourceLabel != "桌面版" {
		t.Fatalf("desktop folder labelled %+v / %s (%s)", dt[0].Source, dt[0].SourceLabel, dt[0].SourceWhy)
	}

	// Desktop: virtual project path with /~:
	virt := &chain{t: t}
	virt.add(ledger.Receipt{Client: "workbuddy", SessionID: "698d8a04-47a7-44ca-b7b6-b492bf4634fd",
		CWD: "/Users/dev/reinsaarm/~:reinsaarm-workbuddy-accept", EventType: "prompt.submit", TS: ts(0),
		Activity: &ledger.Activity{Prompt: "hi", PromptChars: 2, Model: "hy4free"}})
	virt.add(ledger.Receipt{Client: "workbuddy", SessionID: "698d8a04-47a7-44ca-b7b6-b492bf4634fd",
		CWD: "/Users/dev/reinsaarm/~:reinsaarm-workbuddy-accept", EventType: "agent.stop", TS: ts(1),
		Activity: &ledger.Activity{Message: "ok", MessageChars: 2, Model: "hy4free"}})
	vt := buildTurns(timeline(virt.recs, "workbuddy:698d8a04-47a7-44ca-b7b6-b492bf4634fd"), false, "/Users/dev/reinsaarm/~:reinsaarm-workbuddy-accept", opts())
	if vt[0].Source != "desktop" {
		t.Fatalf("virtual path labelled %+v / %s (%s)", vt[0].Source, vt[0].SourceLabel, vt[0].SourceWhy)
	}

	// Ambiguous WorkBuddy session: no originator, ordinary cwd, real model.
	// Must not default to 桌面版.
	amb := &chain{t: t}
	amb.add(ledger.Receipt{Client: "workbuddy", SessionID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		CWD: "/Users/dev/proj", EventType: "prompt.submit", TS: ts(0),
		Activity: &ledger.Activity{Prompt: "ls", PromptChars: 2, Model: "hy4free"}})
	at := buildTurns(timeline(amb.recs, "workbuddy:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), false, "/Users/dev/proj", opts())
	if at[0].Source != "unknown" {
		t.Fatalf("ambiguous labelled %+v / %s (%s)", at[0].Source, at[0].SourceLabel, at[0].SourceWhy)
	}
}

func TestPromptBeforeSessionStartOrder(t *testing.T) {
	// Observed WorkBuddy / some Codex hooks: UserPromptSubmit is appended
	// (and sometimes timestamped) before SessionStart. Display should still
	// be start → prompt → tools → stop, without rewriting receipt seq.
	c := &chain{t: t}
	c.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-cli", CWD: "/Users/dev/proj",
		EventType: "prompt.submit", TS: "2026-11-15T15:54:46.352395Z",
		Activity: &ledger.Activity{Prompt: "Reply with PONG", PromptChars: 16, Model: "default-model"}})
	c.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-cli",
		EventType: "session.start", TS: "2026-11-15T15:54:46.363164Z",
		Activity: &ledger.Activity{Source: "startup", Model: "default-model"}})
	c.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-cli", CWD: "/Users/dev/proj",
		Tool: "Bash", Kind: "shell", CommandPreview: "echo ok",
		Decision: "ALLOW", EnforcedDecision: "ALLOW", RuleIDs: []string{"R-DEFAULT-ALLOW"},
		EventType: "action.decision", TS: "2026-11-15T15:54:46.400000Z"})
	c.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-cli", CWD: "/Users/dev/proj",
		EventType: "agent.stop", TS: "2026-11-15T15:54:46.802770Z",
		Activity: &ledger.Activity{Message: "PONG", MessageChars: 4, Model: "default-model"}})

	turns := buildTurns(timeline(c.recs, "workbuddy:s-cli"), true, "/Users/dev/proj", opts())
	if len(turns) != 1 {
		t.Fatalf("turns %d", len(turns))
	}
	got := make([]string, len(turns[0].Steps))
	var seqs []uint64
	for i, st := range turns[0].Steps {
		got[i] = st.Type
		seqs = append(seqs, st.Seq)
	}
	want := []string{"start", "prompt", "tool", "stop"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("display order %v want %v (seqs %v)", got, want, seqs)
	}
	if seqs[0] != 2 || seqs[1] != 1 || seqs[2] != 3 || seqs[3] != 4 {
		t.Fatalf("seq numbers rewritten or mis-assigned: %v", seqs)
	}
	if turns[0].SeqFrom != 1 || turns[0].SeqTo != 4 {
		t.Fatalf("seq range %d-%d", turns[0].SeqFrom, turns[0].SeqTo)
	}

	// SessionStart has a later seq but an earlier-looking? No: here prompt
	// ts is first. Also cover start seq first but prompt timestamp slightly
	// earlier (another live ordering).
	d := &chain{t: t}
	d.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-desk",
		EventType: "session.start", TS: "2026-11-15T16:15:00.175427Z",
		Activity: &ledger.Activity{Source: "startup", Model: "hy4free"}})
	d.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-desk",
		CWD: "/Users/dev/reinsaarm/~:proj", EventType: "prompt.submit",
		TS:       "2026-11-15T16:15:00.175236Z",
		Activity: &ledger.Activity{Prompt: "hi", PromptChars: 2, Model: "hy4free"}})
	d.add(ledger.Receipt{Client: "workbuddy", SessionID: "s-desk",
		CWD: "/Users/dev/reinsaarm/~:proj", EventType: "agent.stop",
		TS:       "2026-11-15T16:15:18.296304Z",
		Activity: &ledger.Activity{Message: "ok", MessageChars: 2, Model: "hy4free"}})
	dt := buildTurns(timeline(d.recs, "workbuddy:s-desk"), true, "/Users/dev/reinsaarm/~:proj", opts())
	if len(dt[0].Steps) != 3 || dt[0].Steps[0].Type != "start" || dt[0].Steps[1].Type != "prompt" || dt[0].Steps[2].Type != "stop" {
		var types []string
		for _, st := range dt[0].Steps {
			types = append(types, st.Type)
		}
		t.Fatalf("start-seq-first still wrong display %v", types)
	}
	if dt[0].Steps[0].Seq != 1 || dt[0].Steps[1].Seq != 2 {
		t.Fatalf("seqs %d %d", dt[0].Steps[0].Seq, dt[0].Steps[1].Seq)
	}
}
