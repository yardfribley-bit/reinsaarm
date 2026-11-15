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
