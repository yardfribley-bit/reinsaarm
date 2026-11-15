package activity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgsPreviewMasksAndQueries(t *testing.T) {
	in := map[string]any{
		"system2_search_query": []any{map[string]any{"q": "github LoopX trending"}},
		"api_key":              "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456",
		"headers":              map[string]any{"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz0123"},
	}
	pv, q, _ := ArgsPreview("mcp", "", in, 600)
	if strings.Contains(pv, "sk-proj") || strings.Contains(pv, "abcdefghijklmnop") {
		t.Fatalf("secret in preview: %s", pv)
	}
	if !strings.Contains(pv, `"q": "github LoopX trending"`) || q != "github LoopX trending" {
		t.Fatalf("preview %q query %q", pv, q)
	}
	if pv, q, _ := ArgsPreview("mcp", "", in, 0); pv != "" || q != "" {
		t.Fatal("limit 0 must turn previews off")
	}
	// find patterns are search text too.
	_, q, _ = ArgsPreview("mcp", "", map[string]any{"find": []any{map[string]any{"ref_id": "turn0search1", "pattern": "How it works"}}}, 600)
	if q != "How it works" {
		t.Fatalf("pattern query %q", q)
	}
}

func TestArgsPreviewShellAndWrite(t *testing.T) {
	if pv, _, _ := ArgsPreview("shell", "ls", map[string]any{"command": "ls"}, 600); pv != "" {
		t.Fatalf("short command duplicated: %q", pv)
	}
	long := "cat " + strings.Repeat("/very/long/path", 20) + " GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	pv, _, _ := ArgsPreview("shell", long, nil, 600)
	if !strings.HasPrefix(pv, "cat /very") || strings.Contains(pv, "ghp_abc") {
		t.Fatalf("shell preview %q", pv)
	}
	content := strings.Repeat("x", 5000)
	pv, _, _ = ArgsPreview("file_write", "", map[string]any{"file_path": "a.txt", "content": content}, 600)
	if strings.Count(pv, "x") > 200 || !strings.Contains(pv, "5000 字") {
		t.Fatalf("write content not shortened: %d chars", len(pv))
	}
	pv, _, cut := ArgsPreview("mcp", "", map[string]any{"text": strings.Repeat("y", 2000)}, 100)
	if !cut || len([]rune(pv)) > 101 {
		t.Fatalf("not truncated: %d", len([]rune(pv)))
	}
}

func TestResultLinks(t *testing.T) {
	out := `loopx-project/loopx — GitHub Star History & Stats | GitTrend (https://gittrend.io/repo/loopx-project/loopx) 【turn0search0】 [wordlim: 200] Crawled: last week; see https://github.com/loopx-project/loopx/blob/main/docs/architecture.md?token=SECRET123#x and https://user:pw@example.com/a`
	links := ResultLinks(out)
	if len(links) != 3 {
		t.Fatalf("links %+v", links)
	}
	if links[0].URL != "https://gittrend.io/repo/loopx-project/loopx" || links[0].Title == "" {
		t.Fatalf("titled %+v", links[0])
	}
	gh := ResultLinks("GitHub - loopx-project/loopx: Turn long-horizon goals into verifiable results. A local-first plane. · GitHub (https://github.com/loopx-project/loopx)\n\ue200cite\ue202turn0search0\ue201")
	if len(gh) != 1 || gh[0].Title != "GitHub - loopx-project/loopx" {
		t.Fatalf("title %+v", gh)
	}
	for _, l := range links {
		if strings.Contains(l.URL, "SECRET") || strings.Contains(l.URL, "pw@") || strings.Contains(l.URL, "#") {
			t.Fatalf("unsafe url kept: %s", l.URL)
		}
	}
}

func TestClipLinesKeepsLines(t *testing.T) {
	a := Build("codex", "PostToolUse", map[string]any{"tool_response": "Traceback (most recent call last):\n  File \"x.py\", line 1\nValueError: bad   thing\n\n\n\nend"}, nil, Options{})
	if !strings.Contains(a.Output, "line 1\nValueError: bad thing\n\nend") {
		t.Fatalf("output %q", a.Output)
	}
}

const rollout = `{"timestamp":"2026-11-15T13:26:44.952Z","type":"session_meta","payload":{"id":"s1","originator":"Codex Desktop","source":"vscode"}}
{"timestamp":"2026-11-15T13:26:44.952Z","type":"event_msg","payload":{"type":"task_started","turn_id":"T0","turn_attribution":{"turn_id":"T0","turn_trigger":"composer"}}}
{"timestamp":"2026-11-15T13:26:50.000Z","type":"response_item","payload":{"type":"message","role":"assistant","phase":"commentary","content":[{"type":"output_text","text":"old turn note"}]}}
{"timestamp":"2026-11-15T13:28:06.723Z","type":"event_msg","payload":{"type":"task_started","turn_id":"T1","turn_attribution":{"turn_id":"T1","turn_trigger":"automation_heartbeat_scheduled"}}}
{"timestamp":"2026-11-15T13:28:37.139Z","type":"response_item","payload":{"type":"message","role":"assistant","phase":"commentary","content":[{"type":"output_text","text":"我会先确认是哪个 LoopX。token=sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456"}]}}
{"timestamp":"2026-11-15T13:29:32.012Z","type":"response_item","payload":{"type":"message","role":"assistant","phase":"final_answer","content":[{"type":"output_text","text":"final"}]}}
`

func TestReadTranscript(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex", "sessions")
	os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, "rollout-x.jsonl")
	os.WriteFile(p, []byte(rollout), 0o600)
	tr := ReadTranscript(p, home, "T1", true)
	if tr.Originator != "Codex Desktop" || tr.Trigger != "automation_heartbeat_scheduled" {
		t.Fatalf("transcript %+v", tr)
	}
	if len(tr.Commentary) != 1 || !strings.HasPrefix(tr.Commentary[0].Text, "我会先确认") || strings.Contains(tr.Commentary[0].Text, "sk-proj") {
		t.Fatalf("commentary %+v", tr.Commentary)
	}
	if tr := ReadTranscript(p, filepath.Join(home, "other"), "T1", true); tr.Originator != "" {
		t.Fatal("file outside home must not be read")
	}
	if tr := ReadTranscript(filepath.Join(dir, "x.txt"), home, "", true); tr.Originator != "" {
		t.Fatal("non-jsonl must not be read")
	}
	// Stop reads it when transcript capture is on.
	a := Build("codex", "Stop", map[string]any{"transcript_path": p, "turn_id": "T1", "last_assistant_message": "final"}, nil, Options{Transcript: true, Home: home})
	if a.Trigger != "automation_heartbeat_scheduled" || len(a.Commentary) != 1 || a.MessageChars != 5 {
		t.Fatalf("stop %+v", a)
	}
	if a := Build("codex", "Stop", map[string]any{"transcript_path": p, "turn_id": "T1"}, nil, Options{Home: home}); a.Trigger != "" {
		t.Fatal("transcript read while off")
	}
}
