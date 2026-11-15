package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var secretAssign = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|KEY|CREDENTIAL)[A-Z0-9_]*)=([^\s]+)`)

// Preview returns a short command string safe to store in a receipt.
func Preview(command string, limit int) string {
	if limit <= 0 {
		limit = 180
	}
	s := secretAssign.ReplaceAllString(command, "$1=[REDACTED]")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return s
}

// Digest is a SHA-256 of the unredacted action fields.
func Digest(tool, command string, paths, hosts []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(command))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.Join(paths, "\n")))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.Join(hosts, "\n")))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Value redacts KEY=value secrets in a short string such as a path.
func Value(s string) string {
	return secretAssign.ReplaceAllString(s, "$1=[REDACTED]")
}

// Secret shapes masked by Text. They cover the common token formats seen in
// prompts and tool output; anything else still passes through KEY=value
// masking. Each match is replaced, not dropped, so the reader can see that a
// secret was there.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`\b(?:sk|rk|pk)-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_\-]{16,}`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9\-]{10,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
}

var (
	authScheme  = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]{12,}=*`)
	urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@`)
	urlSecretQS = regexp.MustCompile(`(?i)([?&](?:access_token|token|key|api_key|apikey|secret|password|sig|signature)=)[^&\s#"']+`)
	jsonSecret  = regexp.MustCompile(`(?i)("(?:[a-z0-9_\-]*(?:secret|token|password|passwd|api_?key|credential)[a-z0-9_\-]*)"\s*:\s*")[^"]*(")`)
	yamlSecret  = regexp.MustCompile(`(?im)^(\s*[a-z0-9_\-]*(?:secret|token|password|passwd|api_?key)[a-z0-9_\-]*\s*:\s*)\S.*$`)
)

// Mask replaces secrets in free text: KEY=value assignments, private key
// blocks, common API token formats, bearer credentials, URL userinfo and
// secret query parameters, and secret-named JSON or YAML fields.
func Mask(s string) string {
	s = secretAssign.ReplaceAllString(s, "$1=[REDACTED]")
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	s = authScheme.ReplaceAllString(s, "$1 [REDACTED]")
	s = urlUserinfo.ReplaceAllString(s, "$1[REDACTED]@")
	s = urlSecretQS.ReplaceAllString(s, "$1[REDACTED]")
	s = jsonSecret.ReplaceAllString(s, "$1[REDACTED]$2")
	s = yamlSecret.ReplaceAllString(s, "$1[REDACTED]")
	return s
}

// Text masks secrets, collapses whitespace runs, and truncates to limit runes
// without splitting a UTF-8 sequence. It reports whether it truncated.
func Text(s string, limit int) (string, bool) {
	s = Mask(s)
	s = strings.Join(strings.Fields(s), " ")
	return Truncate(s, limit)
}

// Truncate cuts s to at most limit runes and appends "…" when it cut.
func Truncate(s string, limit int) (string, bool) {
	if limit <= 0 {
		return s, false
	}
	n := 0
	for i := range s {
		if n == limit {
			return s[:i] + "…", true
		}
		n++
	}
	return s, false
}
