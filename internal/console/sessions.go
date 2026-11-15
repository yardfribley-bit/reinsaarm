package console

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
)

// sessionScan bounds how many receipts the sessions view reads.
const sessionScan = 20000

// SessionSummary is one row on the 会话 page.
type SessionSummary struct {
	Key       string `json:"key"`
	Client    string `json:"client"`
	SessionID string `json:"session_id"`
	Project   string `json:"project"`
	CWD       string `json:"cwd"`
	Started   string `json:"started"`
	LastTS    string `json:"last_ts"`
	Prompts   int    `json:"prompts"`
	Tools     int    `json:"tools"`
	Denied    int    `json:"denied"`
	Failed    int    `json:"failed"`
	Ended     bool   `json:"ended"`
	Running   bool   `json:"running"`
	LastEvent string `json:"last_event"`
}

// TimelineItem is one step in a session: a prompt, a tool call (decision and
// result together), an approval, a stop, or a session boundary.
type TimelineItem struct {
	Type     string          `json:"type"`
	TS       string          `json:"ts"`
	Seq      uint64          `json:"seq"`
	Decision *ledger.Receipt `json:"decision,omitempty"`
	Result   *ledger.Receipt `json:"result,omitempty"`
	Event    *ledger.Receipt `json:"event,omitempty"`
}

func sessionKey(client, id string) string { return client + ":" + id }

// agentClients are the clients whose receipts belong to a coding session.
var agentClients = map[string]bool{"codex": true, "claude-code": true, "gemini": true, "codebuddy": true, "workbuddy": true}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	recs, err := s.tail(sessionScan)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"sessions": summarize(recs, r.URL.Query().Get("agent"))})
}

func summarize(recs []ledger.Receipt, agent string) []SessionSummary {
	by := map[string]*SessionSummary{}
	var order []string
	// Decisions seen per session, so a result counts as a tool call only
	// when no pre-tool receipt covers it.
	seenSeq := map[string]map[uint64]bool{}
	seenUse := map[string]map[string]bool{}
	for i := range recs {
		rec := &recs[i]
		if !agentClients[rec.Client] || (agent != "" && rec.Client != agent) {
			continue
		}
		key := sessionKey(rec.Client, rec.SessionID)
		ss := by[key]
		if ss == nil {
			ss = &SessionSummary{Key: key, Client: rec.Client, SessionID: rec.SessionID, Started: rec.TS}
			by[key] = ss
			order = append(order, key)
			seenSeq[key] = map[uint64]bool{}
			seenUse[key] = map[string]bool{}
		}
		if ss.CWD == "" && rec.CWD != "" {
			ss.CWD = rec.CWD
			ss.Project = filepath.Base(rec.CWD)
		}
		ss.LastTS = rec.TS
		ss.LastEvent = rec.EventType
		switch rec.EventType {
		case "session.start":
			ss.Started = rec.TS
			ss.Ended = false
		case "session.end":
			ss.Ended = true
		case "prompt.submit":
			ss.Prompts++
			ss.Running = true
		case "agent.stop":
			ss.Running = false
		case "action.decision", "":
			ss.Tools++
			seenSeq[key][rec.Seq] = true
			if rec.ToolUseID != "" {
				seenUse[key][rec.ToolUseID] = true
			}
			if rec.EnforcedDecision == "DENY" || rec.EnforcedDecision == "DEFER" {
				ss.Denied++
			}
		case "tool.result":
			paired := (rec.RefSeq != 0 && seenSeq[key][rec.RefSeq]) || (rec.ToolUseID != "" && seenUse[key][rec.ToolUseID])
			if !paired {
				ss.Tools++
			}
			if a := rec.Activity; a != nil && a.Success != nil && !*a.Success {
				ss.Failed++
			}
		}
	}
	out := make([]SessionSummary, 0, len(order))
	for _, k := range order {
		ss := by[k]
		if ss.Ended {
			ss.Running = false
		}
		out = append(out, *ss)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastTS > out[j].LastTS })
	return out
}

func (s *Server) sessionDetail(w http.ResponseWriter, r *http.Request) {
	key, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api/sessions/"))
	if err != nil || key == "" {
		http.Error(w, "session key required", http.StatusBadRequest)
		return
	}
	recs, err := s.tail(sessionScan)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var sum *SessionSummary
	for _, ss := range summarize(recs, "") {
		if ss.Key == key {
			v := ss
			sum = &v
		}
	}
	if sum == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"session": sum, "items": timeline(recs, key)})
}

// timeline orders a session's receipts and attaches each tool result to its
// decision: by ref_seq (set by the sidecar), else by tool_use_id.
func timeline(recs []ledger.Receipt, key string) []TimelineItem {
	var items []TimelineItem
	bySeq := map[uint64]int{}
	byUseID := map[string]int{}
	for i := range recs {
		rec := recs[i]
		if sessionKey(rec.Client, rec.SessionID) != key {
			continue
		}
		switch rec.EventType {
		case "action.decision", "":
			items = append(items, TimelineItem{Type: "tool", TS: rec.TS, Seq: rec.Seq, Decision: &rec})
			bySeq[rec.Seq] = len(items) - 1
			if rec.ToolUseID != "" {
				byUseID[rec.ToolUseID] = len(items) - 1
			}
		case "tool.result":
			idx, ok := bySeq[rec.RefSeq]
			if !ok || rec.RefSeq == 0 {
				idx, ok = byUseID[rec.ToolUseID]
				ok = ok && rec.ToolUseID != ""
			}
			if ok && items[idx].Result == nil {
				items[idx].Result = &rec
				continue
			}
			items = append(items, TimelineItem{Type: "tool", TS: rec.TS, Seq: rec.Seq, Result: &rec})
		case "prompt.submit":
			items = append(items, TimelineItem{Type: "prompt", TS: rec.TS, Seq: rec.Seq, Event: &rec})
		case "agent.stop":
			items = append(items, TimelineItem{Type: "stop", TS: rec.TS, Seq: rec.Seq, Event: &rec})
		case "session.start":
			items = append(items, TimelineItem{Type: "start", TS: rec.TS, Seq: rec.Seq, Event: &rec})
		case "session.end":
			items = append(items, TimelineItem{Type: "end", TS: rec.TS, Seq: rec.Seq, Event: &rec})
		default:
			items = append(items, TimelineItem{Type: "other", TS: rec.TS, Seq: rec.Seq, Event: &rec})
		}
	}
	return items
}
