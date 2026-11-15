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
}

// Transcript read bounds.
const (
	transcriptHead     = 64 << 10
	transcriptTailStop = 4 << 20
	transcriptTailSub  = 1 << 20
	maxNotes           = 12
	noteLimit          = 300
)

var (
	originatorRe = regexp.MustCompile(`"originator"\s*:\s*"([^"\\]{1,64})"`)
)

// ReadTranscript reads a Codex rollout file (JSON lines) named by a hook's
// transcript_path. It reads the first 64 KiB for session_meta.originator and
// the last few MiB for the turn: turn_trigger from task_started, and, when
// withNotes is set, the assistant's commentary messages of that turn. The
// file must be a regular .jsonl file under home. Any error gives an empty
// result: this is best effort and never blocks.
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
	type line struct {
		Timestamp string          `json:"timestamp"`
		Type      string          `json:"type"`
		Payload   json.RawMessage `json:"payload"`
	}
	type payload struct {
		Type   string `json:"type"`
		Role   string `json:"role"`
		Phase  string `json:"phase"`
		TurnID string `json:"turn_id"`
		Attr   *struct {
			TurnID  string `json:"turn_id"`
			Trigger string `json:"turn_trigger"`
		} `json:"turn_attribution"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	inTurn := false
	var notes []ledger.Note
	for sc.Scan() {
		b := sc.Bytes()
		if first {
			first = false
			continue // partial line at the seek point
		}
		if len(b) == 0 || b[0] != '{' {
			continue
		}
		// Cheap filter before decoding large lines.
		if !bytes.Contains(b, []byte(`"task_started"`)) && !(inTurn && withNotes && bytes.Contains(b, []byte(`"commentary"`))) {
			continue
		}
		var l line
		if json.Unmarshal(b, &l) != nil {
			continue
		}
		var p payload
		if json.Unmarshal(l.Payload, &p) != nil {
			continue
		}
		if p.Type == "task_started" {
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
				t.Trigger = trig
			} else {
				inTurn = false
			}
			continue
		}
		if inTurn && withNotes && l.Type == "response_item" && p.Type == "message" && p.Role == "assistant" && p.Phase == "commentary" {
			var parts []string
			for _, c := range p.Content {
				if c.Text != "" {
					parts = append(parts, c.Text)
				}
			}
			text := strings.TrimSpace(strings.Join(parts, "\n"))
			if text == "" || len(notes) >= maxNotes {
				continue
			}
			text, _ = redact.Text(text, noteLimit)
			notes = append(notes, ledger.Note{TS: l.Timestamp, Text: text})
		}
	}
	t.Trigger, _ = redact.Truncate(t.Trigger, 64)
	t.Commentary = notes
	return t
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
