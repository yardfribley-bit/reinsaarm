package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/extract"
)

// Action is one tool call after normalization. The engine does not read the clock or the network.
type Action struct {
	Tool              string
	Kind              string
	Command           string
	Paths             []string
	Hosts             []string
	CWD               string
	MCPDescription    string
	MCPDefinitionHash string
}

// Context is the session snapshot required by AARM R2 and R3.
type Context struct {
	Intent string
	Taints map[string]bool
}

// Hit is one rule match.
type Hit struct {
	ID       string
	Decision decision.Decision
	Reason   string
	Rewrite  string
}

// Outcome is the fast-path result before judge composition.
type Outcome struct {
	Decision decision.Decision
	RuleIDs  []string
	Reason   string
	Rewrite  string
	Hits     []Hit
	Risk     string
}

// Engine is a compiled remit. Evaluate allocates little and does no I/O.
type Engine struct {
	home             string
	version          string
	profile          *Profile
	denyPrefixes     []string
	allowPrefixes    []string
	denyBases        map[string]bool
	allowBases       map[string]bool
	denyBasePrefixes []string
	allowHosts       map[string]bool
	denyHosts        map[string]bool
	protected        map[string]bool
	networkMode      string
	confineWrites    bool
	ciPaths          []string
	mcpPins          map[string]string
}

// Compile builds an engine. home is the developer home used to expand ~.
// versionRaw is hashed into the policy version stored on receipts.
func Compile(p *Profile, home string, versionRaw []byte) *Engine {
	sum := sha256.Sum256(versionRaw)
	e := &Engine{
		home:          home,
		version:       hex.EncodeToString(sum[:8]),
		profile:       p,
		denyBases:     map[string]bool{},
		allowBases:    map[string]bool{},
		allowHosts:    map[string]bool{},
		denyHosts:     map[string]bool{},
		protected:     map[string]bool{},
		networkMode:   p.Spec.Network.Mode,
		confineWrites: p.Spec.Workspace.ConfineWrites,
		mcpPins:       p.Spec.MCPPins,
	}
	for _, pfx := range p.Spec.Credentials.DenyPrefixes {
		e.denyPrefixes = append(e.denyPrefixes, e.expand(pfx, ""))
	}
	for _, pfx := range p.Spec.Credentials.AllowPrefixes {
		e.allowPrefixes = append(e.allowPrefixes, e.expand(pfx, ""))
	}
	for _, b := range p.Spec.Credentials.DenyBasenames {
		e.denyBases[b] = true
	}
	for _, b := range p.Spec.Credentials.AllowBasenames {
		e.allowBases[b] = true
	}
	e.denyBasePrefixes = append(e.denyBasePrefixes, p.Spec.Credentials.DenyBasenamePrefixes...)
	for _, h := range p.Spec.Network.Allow {
		e.allowHosts[strings.ToLower(h)] = true
	}
	for _, h := range p.Spec.Network.DenyAlways {
		e.denyHosts[strings.ToLower(h)] = true
	}
	for _, b := range p.Spec.ProtectedBranches {
		e.protected[b] = true
	}
	e.ciPaths = append(e.ciPaths, p.Spec.CIPaths...)
	return e
}

// Version is a short hash of the profile bytes.
func (e *Engine) Version() string { return e.version }

// Profile returns the compiled remit.
func (e *Engine) Profile() *Profile { return e.profile }

// Evaluate applies deterministic rules. It is safe for concurrent use.
func (e *Engine) Evaluate(a Action, c Context) Outcome {
	if a.Kind == "" {
		a.Kind = extract.Kind(a.Tool)
	}
	if a.Command != "" {
		a.Hosts = uniq(append(append([]string{}, a.Hosts...), extract.Hosts(a.Command, nil)...))
	}
	var hits []Hit
	add := func(id string, d decision.Decision, reason, rewrite string) {
		hits = append(hits, Hit{ID: id, Decision: d, Reason: reason, Rewrite: rewrite})
	}

	paths := a.Paths
	if a.Command != "" {
		for _, tok := range extract.Tokenize(a.Command) {
			if tok == "|" || tok == ";" || tok == "&&" || tok == "||" || tok == "&" {
				continue
			}
			if strings.Contains(tok, "/") || strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, ".") || strings.Contains(tok, "$HOME") {
				paths = append(paths, tok)
			}
		}
	}

	cred := false
	for _, p := range paths {
		if e.isCredential(p, a.CWD) {
			cred = true
			break
		}
	}
	if cred {
		add("R-CRED-PATH", decision.Deny, "credential path is not on the allowlist", "")
	}
	if a.Command != "" && isKeychainCommand(a.Command) {
		add("R-KEYCHAIN", decision.Deny, "keychain query is blocked", "")
	}

	if a.Kind == "shell" || a.Command != "" {
		rm := analyzeRm(a.Command)
		if rm.found {
			if len(rm.paths) == 0 {
				add("R-RM-OUTSIDE", decision.StepUp, "rm -rf with no explicit path needs approval", "")
			}
			for _, p := range rm.paths {
				abs := e.expand(p, a.CWD)
				if isCatastrophic(abs, e.home, p) || p == "*" || p == "./*" {
					add("R-RM-ROOT", decision.Deny, "rm -rf of a root, home, or glob is blocked", "")
					continue
				}
				if p == "." || p == "./" {
					add("R-RM-OUTSIDE", decision.StepUp, "rm -rf of the workspace root needs approval", "")
					continue
				}
				if outsideWorkspace(abs, a.CWD) {
					add("R-RM-OUTSIDE", decision.StepUp, "rm -rf outside the workspace needs approval", "")
				}
			}
		}
		gp := analyzeGitPush(a.Command)
		if gp.found {
			protected := false
			for _, d := range gp.dests {
				if e.protected[d] {
					protected = true
					break
				}
			}
			switch {
			case gp.force && protected:
				add("R-GIT-FORCE-PROTECTED", decision.Deny, "force-push to a protected branch is blocked", "")
			case gp.force && !protected && !gp.unspecified:
				add("R-GIT-STRIP-FORCE", decision.Modify, "force flags removed; non-protected push rewritten to a regular push", stripForce(a.Command))
			case protected:
				add("R-GIT-PUSH-PROTECTED", decision.StepUp, "push to a protected branch needs approval", "")
			case gp.unspecified:
				add("R-GIT-PUSH-UNSPECIFIED", decision.StepUp, "git push without an explicit non-protected refspec needs approval", "")
			}
		}
		anyShell, fromCurl := pipeToShell(a.Command)
		if fromCurl {
			add("R-CURL-PIPE", decision.StepUp, "piping a remote script into a shell needs approval", "")
		} else if anyShell {
			add("R-PIPE-SHELL", decision.StepUp, "piping a command into a shell needs approval", "")
		}
		if isObfuscated(a.Command) {
			add("R-OBFUSCATED", decision.Gray, "obfuscated command is a gray zone", "")
		}
	}

	for _, h := range a.Hosts {
		hl := strings.ToLower(h)
		if e.denyHosts[hl] || isMetadata(hl) {
			add("R-EGRESS-METADATA", decision.Deny, "cloud metadata address is blocked", "")
			continue
		}
		if e.networkMode == "off" {
			continue
		}
		if !e.hostAllowed(hl) {
			if e.networkMode == "strict" {
				add("R-EGRESS-HOST", decision.Deny, "host is not on the network allowlist", "")
			} else if e.networkMode == "audit" {
				add("R-EGRESS-OBSERVED", "", "host is not on the network allowlist (audit)", "")
			}
		}
	}
	if (a.Kind == "shell" || a.Command != "") && dnsExfil(a.Command) && e.networkMode == "strict" {
		// Hosts() already recorded dig/nslookup targets. This catches a bare
		// lookup tool when no host token survived parsing.
		if len(a.Hosts) == 0 {
			add("R-EGRESS-DNS", decision.StepUp, "dns lookup tool needs approval", "")
		}
	}

	if a.Kind == "file_write" {
		for _, p := range a.Paths {
			abs := e.expand(p, a.CWD)
			if e.confineWrites && a.CWD != "" && outsideWorkspace(abs, a.CWD) && !e.isCredential(p, a.CWD) {
				add("R-WRITE-OUTSIDE", decision.Deny, "write outside the workspace is blocked", "")
			}
			if e.isCI(abs, a.CWD) {
				add("R-CI-MUTATION", decision.StepUp, "changing CI configuration needs approval", "")
			}
		}
	}

	if a.Kind == "mcp" {
		blob := strings.ToLower(a.MCPDescription + " " + a.Command)
		if strings.Contains(blob, "<important>") || strings.Contains(blob, "ignore previous") || strings.Contains(blob, "ignore all previous") {
			add("R-MCP-POISON", decision.Defer, "mcp tool text looks like a hidden instruction; quarantined", "")
		}
		if pin, ok := e.mcpPins[a.Tool]; ok && a.MCPDefinitionHash != "" && pin != a.MCPDefinitionHash {
			add("R-MCP-DEFINITION", decision.Defer, "mcp tool definition hash changed; quarantined", "")
		}
	}

	if c.Taints != nil && c.Taints["external_content"] {
		_, fromCurl := pipeToShell(a.Command)
		if fromCurl || postsData(a.Command) {
			add("R-INJECT-EXFIL", decision.Deny, "possible exfiltration after untrusted content was read", "")
		}
	}

	return composeHits(hits, riskOf(a))
}

func composeHits(hits []Hit, risk string) Outcome {
	best := decision.Allow
	bestRank := decision.Rank(best)
	var rewrite string
	for _, h := range hits {
		if h.Decision == "" {
			continue
		}
		r := decision.Rank(h.Decision)
		if r > bestRank {
			best = h.Decision
			bestRank = r
			rewrite = h.Rewrite
		}
	}
	if best != decision.Modify {
		rewrite = ""
	} else {
		for _, h := range hits {
			if h.Decision == decision.Modify && h.Rewrite != "" {
				rewrite = h.Rewrite
			}
		}
	}
	ids := make([]string, 0, len(hits)+1)
	var primary, extra []string
	for _, h := range hits {
		ids = append(ids, h.ID)
		if h.Reason == "" || h.Decision == "" {
			continue
		}
		if h.Decision == best {
			primary = append(primary, h.Reason)
		} else {
			extra = append(extra, h.Reason)
		}
	}
	reasons := append(primary, extra...)
	if len(hits) == 0 || (best == decision.Allow && len(reasons) == 0) {
		ids = append(ids, "R-DEFAULT-ALLOW")
		reasons = append(reasons, "no blocking rule matched")
	}
	return Outcome{
		Decision: best,
		RuleIDs:  ids,
		Reason:   strings.Join(reasons, "; "),
		Rewrite:  rewrite,
		Hits:     hits,
		Risk:     risk,
	}
}

func riskOf(a Action) string {
	if a.Kind == "shell" {
		return "irreversible"
	}
	if a.Kind == "web_fetch" || a.Kind == "mcp" || len(a.Hosts) > 0 {
		return "external"
	}
	if a.Kind == "file_write" {
		return "write"
	}
	return "read"
}

func (e *Engine) isCredential(raw, cwd string) bool {
	abs := e.expand(raw, cwd)
	base := filepath.Base(abs)
	if e.allowBases[base] {
		return false
	}
	for _, p := range e.allowPrefixes {
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return false
		}
	}
	for _, p := range e.denyPrefixes {
		if abs == p || strings.HasPrefix(abs, p+string(filepath.Separator)) {
			return true
		}
	}
	if e.denyBases[base] {
		return true
	}
	for _, pre := range e.denyBasePrefixes {
		if strings.HasPrefix(base, pre) && base != strings.TrimSuffix(pre, ".") && !e.allowBases[base] {
			return true
		}
	}
	return false
}

func (e *Engine) hostAllowed(host string) bool {
	if e.allowHosts[host] {
		return true
	}
	for allow := range e.allowHosts {
		if strings.HasSuffix(host, "."+allow) {
			return true
		}
	}
	return false
}

func (e *Engine) isCI(abs, cwd string) bool {
	rel := abs
	if cwd != "" {
		if r, err := filepath.Rel(filepath.Clean(cwd), abs); err == nil {
			rel = r
		}
	}
	rel = filepath.ToSlash(rel)
	for _, c := range e.ciPaths {
		c = filepath.ToSlash(c)
		if rel == c || strings.HasPrefix(rel, strings.TrimSuffix(c, "/")+"/") || strings.Contains(rel, "/"+strings.Trim(c, "/")+"/") {
			return true
		}
	}
	return false
}

func (e *Engine) expand(path, cwd string) string {
	path = strings.Trim(path, `"'`)
	if path == "" {
		return ""
	}
	switch {
	case path == "~":
		path = e.home
	case strings.HasPrefix(path, "~/"):
		path = filepath.Join(e.home, strings.TrimPrefix(path, "~/"))
	}
	path = strings.ReplaceAll(path, "$HOME", e.home)
	path = strings.ReplaceAll(path, "${HOME}", e.home)
	if !filepath.IsAbs(path) {
		base := cwd
		if base == "" {
			base = e.home
		}
		if base != "" {
			path = filepath.Join(base, path)
		}
	}
	return filepath.Clean(path)
}

func isMetadata(host string) bool {
	switch host {
	case "169.254.169.254", "169.254.170.2", "metadata.google.internal", "metadata.google.internal.":
		return true
	default:
		return false
	}
}

func postsData(command string) bool {
	l := strings.ToLower(command)
	for _, n := range []string{"--data", " -d ", "-d@", "--upload-file", "--form"} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return strings.Contains(command, "@-")
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dnsExfil(command string) bool {
	for _, t := range extract.Tokenize(command) {
		switch t {
		case "dig", "nslookup":
			return true
		}
	}
	return false
}

// ExpandPath exposes path expansion for the sensor and tests.
func (e *Engine) ExpandPath(path, cwd string) string { return e.expand(path, cwd) }

// CredentialPrefixes are the expanded deny prefixes.
func (e *Engine) CredentialPrefixes() []string {
	out := make([]string, len(e.denyPrefixes))
	copy(out, e.denyPrefixes)
	return out
}
