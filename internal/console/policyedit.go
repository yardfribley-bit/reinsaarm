package console

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

// mcpRuleRequest is the body of POST /api/policy/mcp-rules.
//
// op "add" inserts a rule into spec.mcp.rules; op "remove" deletes a rule the
// console added earlier. With dry_run the response carries the diff and the
// version of the file it was computed against; a real write must send that
// version back as base_version, so the confirmed diff is what gets written.
type mcpRuleRequest struct {
	Op          string `json:"op"`
	DryRun      bool   `json:"dry_run"`
	BaseVersion string `json:"base_version"`
	ID          string `json:"id"`
	Server      string `json:"server"`
	Tool        string `json:"tool"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
}

var ruleIDChars = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

var globChars = regexp.MustCompile(`^[A-Za-z0-9_.:*?\-\[\]!]*$`)

// profileVersion matches policy.Engine.Version for the same bytes.
func profileVersion(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// sameOrigin rejects cross-site requests. Browsers send Origin on POST and
// Sec-Fetch-Site on modern versions; scripts on this machine send neither.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func cleanRuleText(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	for _, c := range s {
		if unicode.IsControl(c) {
			return "", fmt.Errorf("control characters are not allowed")
		}
	}
	if len([]rune(s)) > max {
		return "", fmt.Errorf("too long (max %d)", max)
	}
	return s, nil
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) mcpRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if !sameOrigin(r) {
		jsonError(w, http.StatusForbidden, "cross-site request refused")
		return
	}
	var in mcpRuleRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	target, err := filepath.EvalSymlinks(s.cfg.ProfilePath)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	st, err := os.Stat(target)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	base := profileVersion(raw)

	var next []byte
	var rule policy.MCPRule
	var preview string
	switch in.Op {
	case "add":
		server, err1 := cleanRuleText(in.Server, 128)
		tool, err2 := cleanRuleText(in.Tool, 128)
		reason, err3 := cleanRuleText(in.Reason, 200)
		for _, e := range []error{err1, err2, err3} {
			if e != nil {
				jsonError(w, http.StatusBadRequest, e.Error())
				return
			}
		}
		if !globChars.MatchString(server) || !globChars.MatchString(tool) {
			jsonError(w, http.StatusBadRequest, "server/tool may use letters, digits, _ . : - and glob * ? [ ]")
			return
		}
		if (server == "" || server == "*") && (tool == "" || tool == "*") {
			jsonError(w, http.StatusBadRequest, "server 和 tool 不能都是 *（会匹配所有 MCP 调用）")
			return
		}
		switch strings.ToUpper(in.Decision) {
		case "ALLOW", "STEP_UP", "DENY":
		default:
			jsonError(w, http.StatusBadRequest, "decision must be ALLOW, STEP_UP or DENY")
			return
		}
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// The dry run picks the id; the save sends it back so the written
		// file is exactly the confirmed diff.
		id := in.ID
		if id == "" {
			id = policy.ConsoleRulePrefix + hex.EncodeToString(b[:])
		}
		if !strings.HasPrefix(id, policy.ConsoleRulePrefix) || !ruleIDChars.MatchString(id) {
			jsonError(w, http.StatusBadRequest, "bad rule id")
			return
		}
		next, rule, err = policy.AddMCPRule(raw, policy.MCPRule{ID: id, Server: server, Tool: tool, Decision: in.Decision, Reason: reason})
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		preview = fmt.Sprintf("add mcp rule %s server=%s tool=%s decision=%s", rule.ID, rule.Server, rule.Tool, rule.Decision)
	case "remove":
		next, rule, err = policy.RemoveMCPRule(raw, in.ID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		preview = fmt.Sprintf("remove mcp rule %s server=%s tool=%s decision=%s", rule.ID, rule.Server, rule.Tool, rule.Decision)
	default:
		jsonError(w, http.StatusBadRequest, `op must be "add" or "remove"`)
		return
	}
	resp := map[string]any{
		"op": in.Op, "rule": rule, "path": target,
		"base_version": base, "version": profileVersion(next),
		"diff": lineDiff(string(raw), string(next)),
	}
	if in.DryRun {
		resp["dry_run"] = true
		writeJSON(w, resp)
		return
	}
	if in.BaseVersion == "" || in.BaseVersion != base {
		resp["error"] = "策略文件在预览之后被改过，请重新预览"
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	backup, err := writeBackup(target, raw, st.Mode().Perm())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "backup: "+err.Error())
		return
	}
	if err := atomicWrite(target, next, st.Mode().Perm()); err != nil {
		jsonError(w, http.StatusInternalServerError, "write: "+err.Error())
		return
	}
	rec, err := s.appendPolicyReceipt(in.Op, rule, preview, raw, next, backup)
	if err != nil {
		// Without a receipt the change is not accountable: put the old file back.
		if rerr := atomicWrite(target, raw, st.Mode().Perm()); rerr != nil {
			jsonError(w, http.StatusInternalServerError, "audit: "+err.Error()+"; restore failed: "+rerr.Error()+"; backup at "+backup)
			return
		}
		jsonError(w, http.StatusInternalServerError, "audit: "+err.Error()+"; policy change rolled back")
		return
	}
	resp["backup"] = backup
	resp["receipt_seq"] = rec.Seq
	resp["reload"] = "sidecar 在下一次工具调用前发现文件变化并重新加载（无需重启）"
	writeJSON(w, resp)
}

func (s *Server) appendPolicyReceipt(op string, rule policy.MCPRule, preview string, oldRaw, newRaw []byte, backup string) (ledger.Receipt, error) {
	led, err := s.openLedger()
	if err != nil {
		return ledger.Receipt{}, err
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	sum := sha256.Sum256(newRaw)
	verb := "added"
	if op == "remove" {
		verb = "removed"
	}
	return led.Append(ledger.Receipt{
		EventID:          "pol_" + hex.EncodeToString(b[:]),
		AgentID:          s.cfg.AgentID,
		Client:           "reinsaarm",
		SessionID:        "policy",
		Tool:             "console",
		Kind:             "policy",
		ActionDigest:     "sha256:" + hex.EncodeToString(sum[:]),
		CommandPreview:   preview,
		Decision:         "ALLOW",
		EnforcedDecision: "ALLOW",
		Tier:             "T3",
		RuleIDs:          []string{rule.ID},
		Reason:           fmt.Sprintf("console %s mcp rule %s (policy %s → %s, backup %s)", verb, rule.ID, profileVersion(oldRaw), profileVersion(newRaw), filepath.Base(backup)),
		PolicyVersion:    profileVersion(newRaw),
		EventType:        "policy.changed",
		TS:               time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// writeBackup copies raw next to path as path.bak-YYYYmmdd-HHMMSS[-n].
func writeBackup(path string, raw []byte, perm os.FileMode) (string, error) {
	stamp := path + ".bak-" + time.Now().Format("20060102-150405")
	name := stamp
	for i := 1; ; i++ {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if os.IsExist(err) && i < 100 {
			name = fmt.Sprintf("%s-%d", stamp, i)
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(raw); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return "", err
		}
		return name, f.Close()
	}
}

// atomicWrite replaces path with data via a temp file in the same directory.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// lineDiff is a small unified-style diff (no hunk headers) for preview.
// Unchanged lines are shown only within 3 lines of a change.
func lineDiff(a, b string) string {
	al := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	bl := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	n, m := len(al), len(bl)
	// LCS table; profiles are a few hundred lines.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type line struct {
		op   byte
		text string
	}
	var ops []line
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			ops = append(ops, line{' ', al[i]})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, line{'-', al[i]})
			i++
		default:
			ops = append(ops, line{'+', bl[j]})
			j++
		}
	}
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.op != ' ' {
			for d := k - 3; d <= k+3; d++ {
				if d >= 0 && d < len(ops) {
					keep[d] = true
				}
			}
		}
	}
	var out strings.Builder
	gap := false
	for k, o := range ops {
		if !keep[k] {
			gap = true
			continue
		}
		if gap && out.Len() > 0 {
			out.WriteString("  …\n")
		}
		gap = false
		out.WriteByte(o.op)
		out.WriteByte(' ')
		out.WriteString(o.text)
		out.WriteByte('\n')
	}
	return out.String()
}
