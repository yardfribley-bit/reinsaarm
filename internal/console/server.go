// Package console serves the local ReinsAARM web UI.
// It binds to loopback, requires a random token, and embeds its static files.
package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/approve"
	"github.com/yardfribley-bit/reinsaarm/internal/codextrust"
	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
	"github.com/yardfribley-bit/reinsaarm/internal/simulate"
	"github.com/yardfribley-bit/reinsaarm/internal/workbuddy"
)

//go:embed static
var staticFS embed.FS

// Config is everything the UI reads. Paths come from the state directory.
type Config struct {
	Addr         string
	AuditPath    string
	ApprovalPath string
	ProfilePath  string
	IdentityKey  string
	ChainID      string
	AgentID      string
	Socket       string
	Project      string
	CodexHome    string
	Token        string
	// Home expands ~ in policy paths for /api/policy/test. Default: the
	// current user's home.
	Home string
}

// Server is the HTTP handler. Tests use Handler without listening.
type Server struct {
	cfg   Config
	token string
}

// New validates the bind address and token.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if err := requireLoopback(cfg.Addr); err != nil && !strings.HasSuffix(cfg.Addr, ":0") {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("console must bind to a loopback address, got %s", cfg.Addr)
	}
	if cfg.Token == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		cfg.Token = hex.EncodeToString(b[:])
	}
	if cfg.ChainID == "" {
		cfg.ChainID = "local"
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "dev-coding-agent"
	}
	return &Server{cfg: cfg, token: cfg.Token}, nil
}

// Token is the URL/cookie secret.
func (s *Server) Token() string { return s.token }

// Handler is the authenticated mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/api/bootstrap", s.bootstrap)
	mux.HandleFunc("/api/receipts", s.receipts)
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/approvals", s.approvals)
	mux.HandleFunc("/api/approvals/", s.approvalAction)
	mux.HandleFunc("/api/policy", s.policyView)
	mux.HandleFunc("/api/policy/test", s.policyTest)
	mux.HandleFunc("/api/audit/verify", s.verify)
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/sessions", s.sessions)
	mux.HandleFunc("/api/sessions/", s.sessionDetail)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(w, r) {
			http.Error(w, "reinsaarm: missing or invalid token", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Listen binds the loopback address. Addr may use port 0.
func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.cfg.Addr)
}

// Serve blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler()}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query().Get("token")
	if q == s.token {
		http.SetCookie(w, &http.Cookie{
			Name: "reinsaarm_token", Value: s.token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		return true
	}
	c, err := r.Cookie("reinsaarm_token")
	return err == nil && c.Value == s.token
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.status())
}

func (s *Server) status() map[string]any {
	items := s.healthItems()
	pending := s.pendingGrants()
	hook, project := "untrusted", "untrusted"
	var hookKey, detail string
	for _, it := range items {
		if it.ID == "hook_trust" && it.OK {
			hook = "trusted"
		}
		if it.ID == "project_trust" && it.OK {
			project = "trusted"
		}
		if it.ID == "hook_trust" {
			hookKey = it.Key
			detail = it.Detail
		}
	}
	sidecar := "down"
	for _, it := range items {
		if it.ID == "sidecar" && it.OK {
			sidecar = "running"
		}
	}
	auditOK := false
	for _, it := range items {
		if it.ID == "audit" && it.OK {
			auditOK = true
		}
	}
	return map[string]any{
		"sidecar":        sidecar,
		"hook_trust":     hook,
		"project_trust":  project,
		"hook_key":       hookKey,
		"hook_detail":    detail,
		"fix_command":    "reinsaarm install-hooks codex --trust",
		"latency_p50_us": s.latencyP50(),
		"audit_ok":       auditOK,
		"pending":        len(pending),
		"untrusted":      hook != "trusted" || project != "trusted",
	}
}

func (s *Server) receipts(w http.ResponseWriter, r *http.Request) {
	recs, err := s.tail(400)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filter := r.URL.Query().Get("filter")
	var out []ledger.Receipt
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		if rec.EventType != "" && rec.EventType != "action.decision" && rec.EventType != "approval.granted" && rec.EventType != "approval.denied" {
			continue
		}
		if !matchFilter(filter, rec) {
			continue
		}
		out = append(out, rec)
	}
	writeJSON(w, map[string]any{"receipts": out})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	var last uint64
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		recs, err := s.tail(50)
		if err == nil {
			for _, rec := range recs {
				if rec.Seq > last {
					last = rec.Seq
					b, _ := json.Marshal(rec)
					fmt.Fprintf(w, "data: %s\n\n", b)
				}
			}
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) approvals(w http.ResponseWriter, r *http.Request) {
	grants, err := approve.Load(s.cfg.ApprovalPath)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var pending, resolved []approve.Grant
	now := time.Now().UTC()
	for _, g := range grants {
		if g.Denied || g.Used || g.Approved {
			resolved = append(resolved, g)
			continue
		}
		if g.Expires != "" {
			if exp, err := time.Parse(time.RFC3339, g.Expires); err == nil && now.After(exp) {
				resolved = append(resolved, g)
				continue
			}
		}
		pending = append(pending, g)
	}
	writeJSON(w, map[string]any{"pending": pending, "resolved": resolved})
}

func (s *Server) approvalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
	id, action, ok := strings.Cut(path, "/")
	if !ok || id == "" {
		http.NotFound(w, r)
		return
	}
	var g approve.Grant
	var err error
	switch action {
	case "approve":
		g, err = approve.Approve(s.cfg.ApprovalPath, id)
	case "deny":
		g, err = approve.Deny(s.cfg.ApprovalPath, id)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	led, err := s.openLedger()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var rec ledger.Receipt
	if action == "approve" {
		rec, err = approve.AppendReceipt(led, s.cfg.AgentID, g)
	} else {
		rec, err = approve.AppendDenial(led, s.cfg.AgentID, g)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"grant": g, "receipt": rec})
}

func (s *Server) policyView(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.cfg.ProfilePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	p, err := policy.Load(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"remit":               strings.TrimSpace(p.Spec.Remit),
		"mode":                p.Spec.Mode,
		"network_mode":        p.Spec.Network.Mode,
		"allow":               p.Spec.Network.Allow,
		"protected_branches":  p.Spec.ProtectedBranches,
		"credential_prefixes": p.Spec.Credentials.DenyPrefixes,
		"allow_basenames":     p.Spec.Credentials.AllowBasenames,
		"yaml":                string(raw),
		"adapters": []map[string]string{
			{"client": "Codex", "allow": "空 stdout，退出码 0", "step_up": "deny + 审批号", "note": "不支持 ask；裸 allow 会被拒绝并放行"},
			{"client": "Claude Code", "allow": "permissionDecision allow", "step_up": "ask", "note": "onFailure=block 时启动失败才阻断"},
			{"client": "Gemini CLI", "allow": "decision allow", "step_up": "deny + 审批号", "note": "非 0/2 退出码会放行"},
			{"client": "CodeBuddy", "allow": "permissionDecision allow", "step_up": "ask", "note": "改写字段是 modifiedInput"},
			{"client": "WorkBuddy", "allow": "空 stdout，退出码 0（保留 WorkBuddy 自己的确认）", "step_up": "ask", "note": "deny 不带 continue:false；改写同时写 updatedInput/modifiedInput；拆包 DeferExecuteTool"},
		},
	})
}

// policyTest simulates one input against the profile on disk. It reads the
// profile only: no receipt, no approval, no sidecar call.
func (s *Server) policyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var in simulate.Input
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	p, raw, err := policy.LoadFile(s.cfg.ProfilePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	home := s.cfg.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if in.CWD == "" {
		in.CWD = s.cfg.Project
	}
	res, err := simulate.Run(policy.Compile(p, home, raw), p, in)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, res)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	pub, err := identity.LoadPublic(s.cfg.IdentityKey)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	n, problem, err := ledger.Verify(s.cfg.AuditPath, pub)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if problem != nil {
		writeJSON(w, map[string]any{"ok": false, "count": n, "seq": problem.Seq, "error": problem.Reason})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "count": n})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"items": s.healthItems()})
}

type healthItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Key    string `json:"key,omitempty"`
}

func (s *Server) healthItems() []healthItem {
	var items []healthItem
	sidecarOK := false
	detail := "套接字不存在"
	if s.cfg.Socket != "" {
		conn, err := net.DialTimeout("unix", s.cfg.Socket, 200*time.Millisecond)
		if err == nil {
			sidecarOK = true
			detail = s.cfg.Socket
			_ = conn.Close()
		} else {
			detail = err.Error()
		}
	}
	items = append(items, healthItem{ID: "sidecar", Name: "sidecar 运行中", OK: sidecarOK, Detail: detail})

	project := s.cfg.Project
	if project == "" {
		project, _ = os.Getwd()
	}
	project, _ = filepath.Abs(project)
	codexHome := s.cfg.CodexHome
	if codexHome == "" {
		if v := os.Getenv("CODEX_HOME"); v != "" {
			codexHome = v
		} else if h, err := os.UserHomeDir(); err == nil {
			codexHome = filepath.Join(h, ".codex")
		}
	}
	var hooks []codextrust.Hook
	installed := false
	for _, path := range []string{filepath.Join(project, ".codex", "hooks.json"), filepath.Join(codexHome, "hooks.json")} {
		found, err := codextrust.FindReins(path)
		if err == nil && len(found) > 0 {
			installed = true
			hooks = append(hooks, found...)
		}
	}
	items = append(items, healthItem{ID: "hooks_installed", Name: "钩子已安装", OK: installed, Detail: fmt.Sprintf("%d 个 reinsaarm 钩子", len(hooks))})

	userCfg := filepath.Join(codexHome, "config.toml")
	statuses := codextrust.Inspect(hooks, []string{userCfg, filepath.Join(project, ".codex", "config.toml")})
	hookOK := len(statuses) > 0
	hookKey := ""
	hookDetail := "未安装"
	var activityOn, activityOff []string
	for _, st := range statuses {
		if st.Hook.Event != "pre_tool_use" {
			if st.State == "trusted" {
				activityOn = append(activityOn, st.Hook.Event)
			} else {
				activityOff = append(activityOff, st.Hook.Event+"("+st.State+")")
			}
			continue
		}
		hookKey = st.Hook.Key
		if st.State != "trusted" {
			hookOK = false
			hookDetail = st.State + " " + st.Hook.Key
			break
		}
		hookDetail = "trusted " + st.Hook.Key
	}
	if len(statuses) == 0 {
		hookOK = false
	}
	items = append(items, healthItem{ID: "hook_trust", Name: "Codex 钩子信任", OK: hookOK, Detail: hookDetail, Key: hookKey})
	actDetail := "未安装活动事件：reinsaarm install-hooks codex --trust"
	if len(activityOn) > 0 {
		actDetail = "已记录 " + strings.Join(activityOn, ", ")
	}
	if len(activityOff) > 0 {
		actDetail += "；未信任 " + strings.Join(activityOff, ", ")
	}
	items = append(items, healthItem{ID: "codex_activity", Name: "Codex 活动事件", OK: len(activityOn) == 5 && len(activityOff) == 0, Detail: actDetail})

	level, found := codextrust.ProjectTrust(userCfg, project)
	projOK := found && level == "trusted"
	projDetail := "trust_level 缺失"
	if found {
		projDetail = "trust_level=" + level
	}
	items = append(items, healthItem{ID: "project_trust", Name: "Codex 项目信任", OK: projOK, Detail: projDetail})

	auditOK := false
	auditDetail := "未初始化"
	if pub, err := identity.LoadPublic(s.cfg.IdentityKey); err == nil {
		n, problem, err := ledger.Verify(s.cfg.AuditPath, pub)
		if err != nil {
			auditDetail = err.Error()
		} else if problem != nil {
			auditDetail = fmt.Sprintf("seq %d: %s", problem.Seq, problem.Reason)
		} else {
			auditOK = true
			auditDetail = fmt.Sprintf("%d 条回执校验通过", n)
		}
	}
	items = append(items, healthItem{ID: "audit", Name: "审计链", OK: auditOK, Detail: auditDetail})
	if it, ok := workBuddyHealth(project); ok {
		items = append(items, it)
	}
	items = append(items, healthItem{
		ID: "adapter", Name: "适配器退出约定", OK: true,
		Detail: "Codex ALLOW 无 stdout；STEP_UP 执行为 DENY；exit 2 必写 stderr",
	})
	return items
}

func (s *Server) pendingGrants() []approve.Grant {
	grants, err := approve.Load(s.cfg.ApprovalPath)
	if err != nil {
		return nil
	}
	var out []approve.Grant
	now := time.Now().UTC()
	for _, g := range grants {
		if g.Denied || g.Used || g.Approved {
			continue
		}
		if g.Expires != "" {
			if exp, err := time.Parse(time.RFC3339, g.Expires); err == nil && now.After(exp) {
				continue
			}
		}
		out = append(out, g)
	}
	return out
}

func (s *Server) latencyP50() int64 {
	recs, err := s.tail(80)
	if err != nil {
		return 0
	}
	var vals []int64
	for _, r := range recs {
		if r.LatencyUS > 0 {
			vals = append(vals, r.LatencyUS)
		}
	}
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	return vals[len(vals)/2]
}

func (s *Server) tail(n int) ([]ledger.Receipt, error) {
	return ledger.Tail(s.cfg.AuditPath, n)
}

func (s *Server) openLedger() (*ledger.Ledger, error) {
	pub, priv, err := identity.LoadOrCreate(s.cfg.IdentityKey)
	if err != nil {
		return nil, err
	}
	_ = pub
	return ledger.Open(s.cfg.AuditPath, s.cfg.ChainID, pub, priv)
}

func matchFilter(filter string, rec ledger.Receipt) bool {
	switch filter {
	case "", "all", "全部":
		return true
	case "deny", "拒绝":
		return rec.Decision == "DENY" || rec.EnforcedDecision == "DENY"
	case "step", "需审批":
		return rec.Decision == "STEP_UP" || rec.Decision == "DEFER"
	case "allow", "放行":
		return rec.EnforcedDecision == "ALLOW" || rec.Decision == "ALLOW"
	default:
		return true
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("console must bind to loopback")
	}
	return nil
}

// OpenPublic is used by tests that already hold a key.
func OpenPublic(path string) (ed25519.PublicKey, error) {
	return identity.LoadPublic(path)
}

// Drain copies a body for tests.
func Drain(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// workBuddyHealth reports the WorkBuddy hook when WorkBuddy is present on
// this machine (a data folder exists) or a project file names the hook.
func workBuddyHealth(project string) (healthItem, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return healthItem{}, false
	}
	present := false
	for _, f := range workbuddy.DataFolders {
		if st, err := os.Stat(filepath.Join(home, f)); err == nil && st.IsDir() {
			present = true
		}
	}
	paths := workbuddy.ProjectSettings(project)
	for _, d := range workbuddy.UserConfigDirs(home, "") {
		paths = append(paths, filepath.Join(d, "settings.json"))
	}
	var where []string
	ok := false
	for _, p := range paths {
		st := workbuddy.Inspect(p)
		if st.Installed {
			present = true
			if st.CoversAll && st.Disabled == "" {
				ok = true
				where = append(where, fmt.Sprintf("%s（活动事件 %d/%d）", p, len(st.Events), len(workbuddy.ObservedEvents)))
			} else {
				where = append(where, p+"（matcher 不全或 hooks 被禁用）")
			}
		}
	}
	if !present {
		return healthItem{}, false
	}
	detail := "未安装：reinsaarm install-hooks workbuddy"
	if len(where) > 0 {
		detail = strings.Join(where, "；")
	}
	return healthItem{ID: "workbuddy_hook", Name: "WorkBuddy 钩子", OK: ok, Detail: detail}, true
}
