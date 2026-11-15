package activity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

// Transcript is what the sidecar reads from an agent's own transcript.
type Transcript struct {
	Originator string
	Trigger    string
	Commentary []ledger.Note
	// Thinking is plaintext the agent actually wrote into its session file:
	// Codex reasoning summaries and raw reasoning text, or Claude-style
	// thinking blocks (WorkBuddy, Claude Code, CodeBuddy). Encrypted blobs
	// and redacted thinking are not copied.
	Thinking []ledger.Note
}

// Transcript read bounds.
const (
	transcriptHead     = 64 << 10
	transcriptTailStop = 4 << 20
	transcriptTailSub  = 1 << 20
	maxNotes           = 12
	noteLimit          = 300
	maxThinking        = 24
	thinkingLimit      = 4000
)

// Note kinds for thinking. Commentary notes leave Kind empty.
const (
	ThinkSummary = "summary"  // Codex reasoning summary (agent_reasoning / summary_text)
	ThinkRaw     = "raw"      // Codex plaintext reasoning content
	ThinkBlock   = "thinking" // Claude-style thinking block
)

var originatorRe = regexp.MustCompile(`"originator"\s*:\s*"([^"\\]{1,64})"`)

type rollLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Message   json.RawMessage `json:"message"`
}

type rollAttr struct {
	TurnID  string `json:"turn_id"`
	Trigger string `json:"turn_trigger"`
}

type rollBit struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Thinking string `json:"thinking"`
}

type rollPayload struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Phase   string          `json:"phase"`
	TurnID  string          `json:"turn_id"`
	Text    string          `json:"text"`
	Delta   string          `json:"delta"`
	Attr    *rollAttr       `json:"turn_attribution"`
	Content json.RawMessage `json:"content"`
	Summary []rollBit       `json:"summary"`
}

// ReadTranscript reads a Codex rollout file (JSON lines) named by a hook's
// transcript_path, or a Claude-style session file (WorkBuddy, Claude Code,
// CodeBuddy). It reads the first 64 KiB for session_meta.originator and the
// last few MiB for the turn: turn_trigger from task_started, and, when
// withNotes is set, the assistant's commentary messages and any plaintext
// thinking of that turn. The file must be a regular .jsonl file under home.
// Any error gives an empty result: this is best effort and never blocks.
func ReadTranscript(path, home, turnID string, withNotes bool) Transcript {
	var t Transcript
	if !transcriptAllowed(path, home) {
		return t
	}
	f, err := os.Open(path)
	if err != nil {
		return t
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return t
	}
	head := make([]byte, transcriptHead)
	n, _ := io.ReadFull(f, head)
	if m := originatorRe.FindSubmatch(head[:n]); m != nil {
		t.Originator, _ = redact.Truncate(string(m[1]), 64)
	}
	size := int64(transcriptTailSub)
	if withNotes {
		size = transcriptTailStop
	}
	off := st.Size() - size
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return t
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256<<10), 8<<20)
	first := off > 0
	inTurn := false
	sawTask := false
	var notes []ledger.Note
	var think []ledger.Note
	var claude []ledger.Note
	for sc.Scan() {
		b := sc.Bytes()
		if first {
			first = false
			continue // partial line at the seek point
		}
		if len(b) == 0 || b[0] != '{' {
			continue
		}
		if !lineMayMatter(b, inTurn, withNotes) {
			continue
		}
		var l rollLine
		if json.Unmarshal(b, &l) != nil {
			continue
		}
		var p rollPayload
		if len(l.Payload) > 0 && l.Payload[0] == '{' {
			_ = json.Unmarshal(l.Payload, &p)
		}
		if p.Type == "task_started" {
			sawTask = true
			id := p.TurnID
			trig := ""
			if p.Attr != nil {
				if id == "" {
					id = p.Attr.TurnID
				}
				trig = p.Attr.Trigger
			}
			if turnID == "" || id == turnID {
				inTurn = true
				notes = nil
				think = nil
				t.Trigger = trig
			} else {
				inTurn = false
			}
			continue
		}
		if sawTask {
			if !(inTurn && withNotes) {
				continue
			}
			if l.Type == "response_item" && p.Type == "message" && p.Role == "assistant" && p.Phase == "commentary" {
				text := joinBitText(decodeBits(p.Content))
				if text == "" || len(notes) >= maxNotes {
					continue
				}
				text, _ = redact.Text(text, noteLimit)
				notes = append(notes, ledger.Note{TS: l.Timestamp, Text: text})
				continue
			}
			think = append(think, codexThinking(l.Timestamp, l.Type, p)...)
			continue
		}
		if !withNotes {
			continue
		}
		// Claude-style session (WorkBuddy, Claude Code, CodeBuddy): no
		// task_started. Keep only the thinking after the latest real user
		// prompt, which is the turn the hook is firing for.
		role, bits, ok := claudeMessage(l)
		if !ok {
			continue
		}
		if role == "user" && userPrompt(bits) {
			claude = nil
			continue
		}
		if role != "assistant" {
			continue
		}
		for _, bit := range bits {
			text := ""
			switch bit.Type {
			case "thinking", "reasoning":
				text = bit.Thinking
				if strings.TrimSpace(text) == "" {
					text = bit.Text
				}
			default:
				continue
			}
			if strings.TrimSpace(text) == "" {
				continue
			}
			clipped, cut := clipThinking(text)
			claude = append(claude, ledger.Note{TS: l.Timestamp, Text: clipped, Kind: ThinkBlock, Cut: cut})
		}
	}
	t.Trigger, _ = redact.Truncate(t.Trigger, 64)
	t.Commentary = notes
	if sawTask {
		t.Thinking = compactThinking(think)
	} else {
		t.Thinking = compactThinking(claude)
	}
	return t
}

func lineMayMatter(b []byte, inTurn, withNotes bool) bool {
	if bytes.Contains(b, []byte(`"task_started"`)) {
		return true
	}
	if !withNotes {
		return false
	}
	if inTurn && bytes.Contains(b, []byte(`"commentary"`)) {
		return true
	}
	return bytes.Contains(b, []byte(`"agent_reasoning"`)) ||
		bytes.Contains(b, []byte(`"reasoning"`)) ||
		bytes.Contains(b, []byte(`"thinking"`)) ||
		bytes.Contains(b, []byte(`"user"`)) ||
		bytes.Contains(b, []byte(`"assistant"`))
}

func codexThinking(ts, lineType string, p rollPayload) []ledger.Note {
	// Streaming deltas are fragments of a later completed item. They are
	// not stored as a second copy of the thinking.
	if strings.Contains(p.Type, "delta") {
		return nil
	}
	var out []ledger.Note
	add := func(kind, text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		clipped, cut := clipThinking(text)
		out = append(out, ledger.Note{TS: ts, Text: clipped, Kind: kind, Cut: cut})
	}
	switch {
	case lineType == "event_msg" && p.Type == "agent_reasoning":
		add(ThinkSummary, p.Text)
	case lineType == "event_msg" && p.Type == "agent_reasoning_raw_content":
		add(ThinkRaw, p.Text)
	case lineType == "response_item" && p.Type == "reasoning":
		for _, s := range p.Summary {
			add(ThinkSummary, s.Text)
		}
		for _, c := range decodeBits(p.Content) {
			switch c.Type {
			case "reasoning_text", "text":
				add(ThinkRaw, c.Text)
			}
		}
	}
	return out
}

func decodeBits(raw json.RawMessage) []rollBit {
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var bits []rollBit
	if json.Unmarshal(raw, &bits) != nil {
		return nil
	}
	return bits
}

func joinBitText(bits []rollBit) string {
	var parts []string
	for _, c := range bits {
		if strings.TrimSpace(c.Text) != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func claudeMessage(l rollLine) (role string, bits []rollBit, ok bool) {
	raw := l.Message
	if len(raw) == 0 || raw[0] != '{' {
		return "", nil, false
	}
	var msg struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		return "", nil, false
	}
	role = msg.Role
	if role == "" {
		role = l.Type
	}
	if role != "user" && role != "assistant" {
		return "", nil, false
	}
	if len(msg.Content) == 0 {
		return role, nil, true
	}
	if msg.Content[0] == '"' {
		var s string
		if json.Unmarshal(msg.Content, &s) == nil && strings.TrimSpace(s) != "" {
			return role, []rollBit{{Type: "text", Text: s}}, true
		}
		return role, nil, true
	}
	return role, decodeBits(msg.Content), true
}

func userPrompt(bits []rollBit) bool {
	if len(bits) == 0 {
		return false
	}
	for _, b := range bits {
		if b.Type == "tool_result" || b.Type == "tool_use" {
			return false
		}
	}
	for _, b := range bits {
		if strings.TrimSpace(b.Text) != "" && (b.Type == "text" || b.Type == "") {
			return true
		}
	}
	return false
}

func clipThinking(text string) (string, bool) {
	text = redact.Mask(strings.ReplaceAll(text, "\r\n", "\n"))
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(spaceRun.ReplaceAllString(l, " "), " ")
	}
	text = blankRun.ReplaceAllString(strings.TrimSpace(strings.Join(lines, "\n")), "\n\n")
	return redact.Truncate(text, thinkingLimit)
}

// compactThinking drops duplicates Codex writes twice (an agent_reasoning
// event and the same summary on the response item, or a short snapshot
// followed by the full text). A summary that is already inside a raw note
// is dropped. Encrypted text never reaches this function.
func compactThinking(in []ledger.Note) []ledger.Note {
	var out []ledger.Note
	for _, n := range in {
		n.Text = strings.TrimSpace(n.Text)
		if n.Text == "" {
			continue
		}
		replaced := false
		skip := false
		for i := range out {
			if out[i].Text == n.Text {
				if rankKind(n.Kind) > rankKind(out[i].Kind) {
					out[i].Kind = n.Kind
				}
				skip = true
				break
			}
			if strings.HasPrefix(n.Text, out[i].Text) && len(n.Text) > len(out[i].Text) {
				out[i] = n
				replaced = true
				break
			}
			if strings.HasPrefix(out[i].Text, n.Text) && len(out[i].Text) > len(n.Text) {
				skip = true
				break
			}
			if out[i].Kind == ThinkRaw && n.Kind != ThinkRaw && strings.Contains(out[i].Text, n.Text) {
				skip = true
				break
			}
			if n.Kind == ThinkRaw && out[i].Kind != ThinkRaw && strings.Contains(n.Text, out[i].Text) {
				out[i] = n
				replaced = true
				break
			}
		}
		if !skip && !replaced {
			out = append(out, n)
		}
	}
	if len(out) > maxThinking {
		out = out[len(out)-maxThinking:]
	}
	return out
}

func rankKind(k string) int {
	switch k {
	case ThinkRaw, ThinkBlock:
		return 2
	case ThinkSummary:
		return 1
	default:
		return 0
	}
}

func transcriptAllowed(path, home string) bool {
	if path == "" || home == "" || !filepath.IsAbs(path) || filepath.Ext(path) != ".jsonl" {
		return false
	}
	clean := filepath.Clean(path)
	h := filepath.Clean(home) + string(filepath.Separator)
	if !strings.HasPrefix(clean, h) {
		return false
	}
	fi, err := os.Lstat(clean)
	return err == nil && fi.Mode().IsRegular()
}
