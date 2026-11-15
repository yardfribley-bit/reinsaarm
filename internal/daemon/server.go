// Package daemon is the local sidecar. Hooks, the egress proxy, and the sensor
// all talk to one policy engine and one hash-chained log.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/approve"
	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/egress"
	"github.com/yardfribley-bit/reinsaarm/internal/extract"
	"github.com/yardfribley-bit/reinsaarm/internal/hooks"
	"github.com/yardfribley-bit/reinsaarm/internal/judge"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
	"github.com/yardfribley-bit/reinsaarm/internal/redact"
	"github.com/yardfribley-bit/reinsaarm/internal/sensor"
)

// Config is the on-disk sidecar configuration plus runtime keys.
type Config struct {
	Socket       string
	ProfilePath  string
	AuditPath    string
	ApprovalPath string
	ChainID      string
	AgentID      string
	Home         string
	Web          string
	Egress       string
	Sensor       bool
	SensorEvery  time.Duration
	PublicKey    ed25519.PublicKey
	PrivateKey   ed25519.PrivateKey
	Judge        judge.Judge
}

// Server is safe for concurrent hook connections.
type Server struct {
	cfg Config

	mu       sync.Mutex
	eng      *policy.Engine
	profile  *policy.Profile
	loaded   time.Time
	modTime  time.Time
	sessions map[string]*sessionState
	seenFD   map[string]bool

	led *ledger.Ledger
}

type sessionState struct {
	Intent string
	Taints map[string]bool
	Recent []string
}

// New loads the profile and opens the ledger.
func New(cfg Config) (*Server, error) {
	if cfg.ChainID == "" {
		cfg.ChainID = "local"
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "dev-coding-agent"
	}
	if cfg.SensorEvery <= 0 {
		cfg.SensorEvery = 2 * time.Second
	}
	led, err := ledger.Open(cfg.AuditPath, cfg.ChainID, cfg.PublicKey, cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		led:      led,
		sessions: map[string]*sessionState{},
		seenFD:   map[string]bool{},
	}
	if err := s.reload(true); err != nil {
		return nil, err
	}
	return s, nil
}

// Engine returns the current compiled policy.
func (s *Server) Engine() *policy.Engine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eng
}

// Serve accepts hook connections until ctx is cancelled. It also starts the
// optional web view, egress proxy, and sensor when configured.
func (s *Server) Serve(ctx context.Context) error {
	if err := os.Remove(s.cfg.Socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", s.cfg.Socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.cfg.Socket, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	defer ln.Close()

	errc := make(chan error, 3)
	go func() { errc <- s.serveConn(ctx, ln) }()
	if s.cfg.Web != "" {
		if err := requireLoopback(s.cfg.Web); err != nil {
			return err
		}
		go func() { errc <- s.serveWeb(ctx) }()
	}
	if s.cfg.Egress != "" {
		if err := requireLoopback(s.cfg.Egress); err != nil {
			return err
		}
		go func() { errc <- s.serveEgress(ctx) }()
	}
	if s.cfg.Sensor {
		go s.sensorLoop(ctx)
	}
	select {
	case <-ctx.Done():
		_ = ln.Close()
		return nil
	case err := <-errc:
		_ = ln.Close()
		if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) serveConn(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req hooks.Request
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(hooks.Response{
			Schema:   "reinsaarm.decision.v1",
			Decision: string(decision.Deny),
			Enforced: string(decision.Deny),
			Reason:   "malformed hook request",
			RuleIDs:  []string{"R-BAD-REQUEST"},
			Tier:     "T0",
		})
		return
	}
	_ = json.NewEncoder(conn).Encode(s.Decide(req))
}

// Decide evaluates one tool call, appends a receipt, and returns the hook response.
func (s *Server) Decide(req hooks.Request) hooks.Response {
	start := time.Now()
	if err := s.reload(false); err != nil {
		return hooks.Response{
			Schema: "reinsaarm.decision.v1", Decision: string(decision.Deny), Enforced: string(decision.Deny),
			Reason: "profile reload failed", RuleIDs: []string{"R-PROFILE"}, Tier: "T0", Degraded: true,
		}
	}
	s.mu.Lock()
	eng := s.eng
	prof := s.profile
	s.mu.Unlock()

	action := actionFrom(req)
	if req.SessionID == "" {
		req.SessionID = "default"
	}
	ctxSnap := s.sessionContext(req.SessionID, req.Intent)
	hash := approve.ArgsHash(action.Tool, action.Command, action.Paths, action.Hosts)

	out := eng.Evaluate(action, ctxSnap)
	var verdict *judge.Verdict
	var jerr error
	if out.Decision == decision.Gray && prof.Spec.Judge.Enabled {
		j := s.judge()
		if j != nil {
			v, err := j.Evaluate(context.Background(), judge.Input{
				Remit: prof.Spec.Remit, Intent: ctxSnap.Intent, Tool: action.Tool,
				Command: action.Command, Paths: action.Paths, Hosts: action.Hosts,
				Reason: out.Reason, RuleIDs: out.RuleIDs,
			})
			verdict = &v
			jerr = err
		}
	}
	comp := policy.Compose(out, verdict, jerr, prof.Spec.Mode, prof.Spec.FailMode, prof.Spec.Unattended, prof.Spec.Judge.MinConfidence)

	approvalID := ""
	if comp.Enforced == decision.StepUp {
		if g, ok, err := approve.Consume(s.cfg.ApprovalPath, hash, time.Now().UTC()); err == nil && ok {
			comp.Decision = decision.Allow
			comp.Enforced = decision.Allow
			comp.RuleIDs = append(comp.RuleIDs, "R-APPROVAL-GRANT")
			comp.Reason = "one-time approval " + g.ID + " matched these arguments"
			comp.Tier = "T3"
		} else {
			approvalID = newID()
			_ = approve.Put(s.cfg.ApprovalPath, approve.Grant{
				ID: approvalID, ArgsHash: hash,
				Expires: time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339),
				Tool:    action.Tool, Reason: comp.Reason,
			})
		}
	}

	rec := ledger.Receipt{
		EventID:          newID(),
		AgentID:          s.cfg.AgentID,
		Client:           req.Client,
		SessionID:        req.SessionID,
		Tool:             action.Tool,
		Kind:             action.Kind,
		ActionDigest:     redact.Digest(action.Tool, action.Command, action.Paths, action.Hosts),
		CommandPreview:   redact.Preview(action.Command, 180),
		Decision:         string(comp.Decision),
		EnforcedDecision: string(comp.Enforced),
		Tier:             comp.Tier,
		RuleIDs:          comp.RuleIDs,
		Reason:           comp.Reason,
		PolicyVersion:    eng.Version(),
		EventType:        "action.decision",
		Degraded:         comp.Degraded,
		Shadow:           comp.Shadow,
		TS:               time.Now().UTC().Format(time.RFC3339Nano),
	}
	if verdict != nil {
		rec.JudgeVerdict = verdict.Verdict
		rec.JudgeModel = verdict.Model
		rec.PromptVersion = verdict.PromptVersion
	}
	written, err := s.led.Append(rec)
	if err != nil {
		comp.Degraded = true
	}
	s.noteSession(req.SessionID, req.Intent, action, comp.Enforced)

	return hooks.Response{
		Schema:      "reinsaarm.decision.v1",
		Decision:    string(comp.Decision),
		Enforced:    string(comp.Enforced),
		Tier:        comp.Tier,
		RuleIDs:     comp.RuleIDs,
		Reason:      comp.Reason,
		Rewrite:     comp.Rewrite,
		ApprovalID:  approvalID,
		ReceiptSeq:  written.Seq,
		ReceiptHash: written.ReceiptHash,
		LatencyUS:   time.Since(start).Microseconds(),
		Degraded:    comp.Degraded,
		Shadow:      comp.Shadow,
	}
}

func (s *Server) judge() judge.Judge {
	if s.cfg.Judge != nil {
		return s.cfg.Judge
	}
	s.mu.Lock()
	prof := s.profile
	s.mu.Unlock()
	if prof == nil || !prof.Spec.Judge.Enabled || prof.Spec.Judge.Endpoint == "" {
		return nil
	}
	return &judge.Client{
		Endpoint: prof.Spec.Judge.Endpoint,
		Model:    prof.Spec.Judge.Model,
		Timeout:  time.Duration(prof.Spec.Judge.TimeoutMs) * time.Millisecond,
	}
}

func (s *Server) reload(force bool) error {
	st, err := os.Stat(s.cfg.ProfilePath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force && st.ModTime().Equal(s.modTime) && s.eng != nil {
		return nil
	}
	p, raw, err := policy.LoadFile(s.cfg.ProfilePath)
	if err != nil {
		return err
	}
	s.profile = p
	s.eng = policy.Compile(p, s.cfg.Home, raw)
	s.modTime = st.ModTime()
	s.loaded = time.Now()
	return nil
}

func (s *Server) sessionContext(id, intent string) policy.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sessions[id]
	c := policy.Context{Intent: intent, Taints: map[string]bool{}}
	if st == nil {
		return c
	}
	if c.Intent == "" {
		c.Intent = st.Intent
	}
	for k, v := range st.Taints {
		c.Taints[k] = v
	}
	return c
}

func (s *Server) noteSession(id, intent string, a policy.Action, enforced decision.Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.sessions[id]
	if st == nil {
		st = &sessionState{Taints: map[string]bool{}}
		s.sessions[id] = st
	}
	if intent != "" && st.Intent == "" {
		st.Intent = intent
	}
	st.Recent = append(st.Recent, a.Tool+":"+string(enforced))
	if len(st.Recent) > 32 {
		st.Recent = st.Recent[len(st.Recent)-32:]
	}
	if enforced == decision.Allow && a.Kind == "web_fetch" {
		st.Taints["external_content"] = true
	}
	if len(s.sessions) > 256 {
		for k := range s.sessions {
			delete(s.sessions, k)
			break
		}
	}
}

func actionFrom(req hooks.Request) policy.Action {
	cmd := extract.Command(req.Input)
	return policy.Action{
		Tool:              req.Tool,
		Kind:              extract.Kind(req.Tool),
		Command:           cmd,
		Paths:             extract.Paths(req.CWD, cmd, req.Input),
		Hosts:             extract.Hosts(cmd, req.Input),
		CWD:               req.CWD,
		MCPDescription:    req.MCPDescription,
		MCPDefinitionHash: req.MCPDefinitionHash,
	}
}

func (s *Server) serveWeb(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleWeb)
	srv := &http.Server{Addr: s.cfg.Web, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request) {
	recs, err := ledger.Tail(s.cfg.AuditPath, 40)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>ReinsAARM</title><style>body{font:14px/1.4 ui-sans-serif,sans-serif;margin:24px}table{border-collapse:collapse;width:100%%}td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}code{font-size:12px}</style>")
	fmt.Fprintf(w, "<h1>ReinsAARM</h1><p>Recent decisions. Refresh to update.</p><table><tr><th>seq</th><th>decision</th><th>enforced</th><th>tool</th><th>rules</th><th>reason</th></tr>")
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		fmt.Fprintf(w, "<tr><td>%d</td><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>",
			rec.Seq, html.EscapeString(rec.Decision), html.EscapeString(rec.EnforcedDecision),
			html.EscapeString(rec.Tool), html.EscapeString(fmt.Sprint(rec.RuleIDs)), html.EscapeString(rec.Reason))
	}
	fmt.Fprintf(w, "</table>")
}

func (s *Server) serveEgress(ctx context.Context) error {
	p := &egress.Proxy{Allow: s.allowHost, OnDecision: s.recordEgress}
	srv := &http.Server{Addr: s.cfg.Egress, Handler: p}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) allowHost(host string) (bool, string, string) {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return false, "R-PROFILE", "policy not loaded"
	}
	out := eng.Evaluate(policy.Action{Tool: "web_fetch", Kind: "web_fetch", Hosts: []string{host}}, policy.Context{})
	rule := "R-DEFAULT-ALLOW"
	if len(out.RuleIDs) > 0 {
		rule = out.RuleIDs[0]
	}
	if out.Decision == decision.Deny {
		return false, rule, out.Reason
	}
	return true, rule, out.Reason
}

func (s *Server) recordEgress(d egress.Decision) {
	if d.Allowed {
		return
	}
	s.mu.Lock()
	ver := ""
	if s.eng != nil {
		ver = s.eng.Version()
	}
	s.mu.Unlock()
	_, _ = s.led.Append(ledger.Receipt{
		EventID: newID(), AgentID: s.cfg.AgentID, Client: "egress", SessionID: "egress",
		Tool: "proxy", Kind: "web_fetch",
		ActionDigest:   redact.Digest("proxy", d.Host, nil, []string{d.Host}),
		CommandPreview: d.Host,
		Decision:       string(decision.Deny), EnforcedDecision: string(decision.Deny),
		Tier: "T0", RuleIDs: []string{d.RuleID}, Reason: d.Reason, PolicyVersion: ver,
		EventType: "egress.decision", TS: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) sensorLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.SensorEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scanOnce()
		}
	}
}

func (s *Server) scanOnce() {
	s.mu.Lock()
	eng := s.eng
	s.mu.Unlock()
	if eng == nil {
		return
	}
	findings := sensor.Scan(eng.CredentialPrefixes())
	for _, f := range findings {
		key := fmt.Sprintf("%d:%s", f.PID, f.Path)
		s.mu.Lock()
		seen := s.seenFD[key]
		if !seen {
			s.seenFD[key] = true
		}
		s.mu.Unlock()
		if seen {
			continue
		}
		_, _ = s.led.Append(ledger.Receipt{
			EventID: newID(), AgentID: s.cfg.AgentID, Client: "sensor", SessionID: "sensor",
			Tool: "fd", Kind: "file_read", ActionDigest: redact.Digest("fd", f.Path, []string{f.Path}, nil),
			CommandPreview: redact.Preview(f.Path, 180), Decision: string(decision.Observe),
			EnforcedDecision: string(decision.Observe), Tier: "T0", RuleIDs: []string{"S-CRED-FD"},
			Reason:        fmt.Sprintf("pid %d (%s) has %s open via %s", f.PID, f.Comm, f.Path, f.Via),
			PolicyVersion: eng.Version(), EventType: "sensor.observation",
			TS: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %s is not a loopback IP", addr)
	}
	return nil
}
