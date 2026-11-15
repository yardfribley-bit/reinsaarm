package daemon

import (
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/activity"
	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/hooks"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/normalize"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
)

// Observe records one observation event (tool result, prompt, session start
// or end, agent stop) as a receipt in the same signed chain. It never
// returns a blocking decision; the hook exits 0 whatever happens here.
func (s *Server) Observe(req hooks.Request) hooks.Response {
	start := time.Now()
	resp := hooks.Response{
		Schema: "reinsaarm.observe.v1", Decision: string(decision.Observe),
		Enforced: string(decision.Observe), Tier: "T0", RuleIDs: []string{},
	}
	evType, ok := activity.Type(req.Event)
	if !ok {
		resp.Reason = "event not recorded: " + req.Event
		return resp
	}
	if req.SessionID == "" {
		req.SessionID = "default"
	}
	payload := req.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	s.mu.Lock()
	ver := ""
	if s.eng != nil {
		ver = s.eng.Version()
	}
	s.mu.Unlock()

	rec := ledger.Receipt{
		EventID:          newID(),
		AgentID:          s.cfg.AgentID,
		Client:           req.Client,
		SessionID:        req.SessionID,
		CWD:              req.CWD,
		TurnID:           req.TurnID,
		ToolUseID:        req.ToolUseID,
		Decision:         string(decision.Observe),
		EnforcedDecision: string(decision.Observe),
		Tier:             "T0",
		RuleIDs:          []string{},
		PolicyVersion:    ver,
		EventType:        evType,
		TS:               time.Now().UTC().Format(time.RFC3339Nano),
	}
	var paths []string
	if evType == activity.TypeToolResult {
		action := actionFrom(req)
		rec.Tool = action.Tool
		rec.Kind = action.Kind
		rec.ActionDigest = redact.Digest(action.Tool, normalize.HashCommand(action), action.Paths, action.Hosts)
		rec.CommandPreview = redact.Preview(action.Command, 180)
		rec.Resources = normalize.Resources(action)
		switch action.Kind {
		case "file_read", "file_write", "file_edit":
			if rec.Resources != nil {
				paths = rec.Resources.Paths
			}
		}
	} else {
		rec.Tool = req.Event
		rec.Kind = "session"
	}
	rec.Activity = activity.Build(req.Client, req.Event, payload, paths, activity.Options{FullPrompts: s.cfg.FullPrompts})
	if evType == activity.TypeToolResult {
		if ref, ok := s.takeCall(callKey(req.Client, req.SessionID, req.ToolUseID, rec.ActionDigest)); ok {
			rec.RefSeq = ref.Seq
			if rec.Activity.DurationMS == nil {
				d := time.Since(ref.At).Milliseconds()
				rec.Activity.DurationMS = &d
				rec.Activity.DurationFrom = "hooks"
			}
		}
	}
	rec.Reason = summary(evType, rec.Activity)
	rec.LatencyUS = time.Since(start).Microseconds()
	written, err := s.led.Append(rec)
	if err != nil {
		resp.Degraded = true
		resp.Reason = "audit append failed"
		return resp
	}
	resp.ReceiptSeq = written.Seq
	resp.ReceiptHash = written.ReceiptHash
	resp.Reason = rec.Reason
	resp.LatencyUS = time.Since(start).Microseconds()
	return resp
}

func summary(evType string, a *ledger.Activity) string {
	switch evType {
	case activity.TypeSessionStart:
		if a.Source != "" {
			return "session started (" + a.Source + ")"
		}
		return "session started"
	case activity.TypeSessionEnd:
		if a.Reason != "" {
			return "session ended (" + a.Reason + ")"
		}
		return "session ended"
	case activity.TypePrompt:
		return "user prompt"
	case activity.TypeStop:
		return "agent finished the turn"
	case activity.TypeToolResult:
		switch {
		case a.Success == nil:
			return "tool returned"
		case *a.Success:
			return "tool succeeded"
		default:
			return "tool failed"
		}
	}
	return evType
}

func callKey(client, session, toolUseID, digest string) string {
	if session == "" {
		session = "default"
	}
	if toolUseID != "" {
		return client + "\x00" + session + "\x00id:" + toolUseID
	}
	return client + "\x00" + session + "\x00digest:" + digest
}

func (s *Server) rememberCall(key string, seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.calls[key]; !ok {
		s.callOrder = append(s.callOrder, key)
	}
	s.calls[key] = callRef{Seq: seq, At: time.Now()}
	for len(s.callOrder) > maxCalls {
		delete(s.calls, s.callOrder[0])
		s.callOrder = s.callOrder[1:]
	}
}

func (s *Server) takeCall(key string) (callRef, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.calls[key]
	if ok {
		delete(s.calls, key)
	}
	return ref, ok
}
