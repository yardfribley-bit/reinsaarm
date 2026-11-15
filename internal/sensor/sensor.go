// Package sensor looks for open file descriptors that point at credential paths.
// It is observe-only. It cannot stop a read that already happened. On systems
// without /proc it returns no findings.
package sensor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding is one process whose fd or command line touches a watched path.
type Finding struct {
	PID  int
	Path string
	Comm string
	Via  string
}

// Scan walks /proc. self is skipped. prefixes are absolute cleaned paths.
func Scan(prefixes []string) []Finding {
	if len(prefixes) == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []Finding
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		comm := readComm(pid)
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if match(target, prefixes) {
				out = append(out, Finding{PID: pid, Path: target, Comm: comm, Via: "fd"})
				break
			}
		}
	}
	return out
}

func readComm(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func match(path string, prefixes []string) bool {
	path = filepath.Clean(path)
	for _, p := range prefixes {
		p = filepath.Clean(p)
		if path == p || strings.HasPrefix(path, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
