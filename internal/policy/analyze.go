package policy

import (
	"path/filepath"
	"strings"

	"github.com/yardfribley-bit/reinsaarm/internal/extract"
)

type gitPush struct {
	found       bool
	force       bool
	dests       []string
	unspecified bool
}

func analyzeGitPush(command string) gitPush {
	tokens := extract.Tokenize(command)
	seenGit := false
	pushAt := -1
	for i, t := range tokens {
		if t == "|" || t == ";" || t == "&&" || t == "||" {
			seenGit = false
			continue
		}
		if t == "git" {
			seenGit = true
			continue
		}
		if seenGit && t == "push" {
			pushAt = i
			break
		}
	}
	if pushAt < 0 {
		return gitPush{}
	}
	force, dests, unspecified := parsePushArgs(tokens[pushAt+1:])
	return gitPush{found: true, force: force, dests: dests, unspecified: unspecified}
}

func parsePushArgs(args []string) (force bool, dests []string, unspecified bool) {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "|" || a == ";" || a == "&&" || a == "||" || a == "&":
			i = len(args)
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case a == "--force" || a == "-f" || a == "--force-with-lease" || a == "--force-if-includes" || strings.HasPrefix(a, "--force-with-lease="):
			force = true
		case a == "-C" || a == "--repo":
			i++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			if strings.Contains(a, "f") {
				force = true
			}
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return force, nil, true
	}
	start := 0
	if !strings.Contains(pos[0], ":") && !strings.HasPrefix(pos[0], "+") && pos[0] != "HEAD" {
		start = 1
	}
	refs := pos[start:]
	if len(refs) == 0 {
		return force, nil, true
	}
	for _, r := range refs {
		if strings.HasPrefix(r, "+") {
			force = true
			r = strings.TrimPrefix(r, "+")
		}
		dest := r
		if i := strings.LastIndex(r, ":"); i >= 0 {
			dest = r[i+1:]
		}
		dest = strings.TrimPrefix(dest, "refs/heads/")
		if dest != "" {
			dests = append(dests, dest)
		}
	}
	if len(dests) == 0 {
		unspecified = true
	}
	return force, dests, unspecified
}

func stripForce(command string) string {
	tokens := extract.Tokenize(command)
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		switch t {
		case "--force", "-f", "--force-with-lease", "--force-if-includes":
			continue
		}
		if strings.HasPrefix(t, "--force-with-lease=") {
			continue
		}
		if strings.HasPrefix(t, "+") && strings.Contains(t, ":") {
			t = strings.TrimPrefix(t, "+")
		}
		if strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && t != "-" && strings.Contains(t, "f") && !strings.ContainsAny(t, "/.~") {
			t = strings.ReplaceAll(t, "f", "")
			if t == "-" {
				continue
			}
		}
		out = append(out, t)
	}
	return strings.Join(out, " ")
}

type rmInfo struct {
	found bool
	paths []string
}

func analyzeRm(command string) rmInfo {
	tokens := extract.Tokenize(command)
	var info rmInfo
	for i := 0; i < len(tokens); i++ {
		if tokens[i] != "rm" {
			continue
		}
		recursive := false
		force := false
		var paths []string
		for j := i + 1; j < len(tokens); j++ {
			a := tokens[j]
			if a == "|" || a == ";" || a == "&&" || a == "||" || a == "&" {
				break
			}
			if a == "--" {
				paths = append(paths, tokens[j+1:]...)
				break
			}
			if a == "--recursive" || a == "-r" || a == "-R" {
				recursive = true
				continue
			}
			if a == "--force" || a == "-f" {
				force = true
				continue
			}
			if strings.HasPrefix(a, "--") {
				continue
			}
			if strings.HasPrefix(a, "-") {
				if strings.ContainsAny(a, "rR") {
					recursive = true
				}
				if strings.Contains(a, "f") {
					force = true
				}
				continue
			}
			paths = append(paths, a)
		}
		if recursive && force {
			info.found = true
			info.paths = append(info.paths, paths...)
		}
	}
	return info
}

func pipeToShell(command string) (anyShell bool, fromCurl bool) {
	tokens := extract.Tokenize(command)
	shells := map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true}
	for i, t := range tokens {
		if t != "|" || i+1 >= len(tokens) {
			continue
		}
		next := tokens[i+1]
		if !shells[next] {
			continue
		}
		anyShell = true
		for j := i - 1; j >= 0; j-- {
			if tokens[j] == "|" || tokens[j] == ";" || tokens[j] == "&&" || tokens[j] == "||" {
				break
			}
			if tokens[j] == "curl" || tokens[j] == "wget" || tokens[j] == "fetch" {
				fromCurl = true
			}
		}
	}
	return anyShell, fromCurl
}

func isObfuscated(command string) bool {
	l := strings.ToLower(command)
	needles := []string{
		"base64 -d",
		"base64 --decode",
		"xxd -r",
		"eval $(",
		"eval `",
		"fromhex",
		"$(curl",
		"`curl",
	}
	for _, n := range needles {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func isKeychainCommand(command string) bool {
	l := strings.ToLower(command)
	return strings.Contains(l, "find-generic-password") ||
		strings.Contains(l, "unlock-keychain") ||
		strings.Contains(l, "secret-tool")
}

func outsideWorkspace(abs, cwd string) bool {
	if cwd == "" {
		return true
	}
	rel, err := filepath.Rel(filepath.Clean(cwd), abs)
	if err != nil {
		return true
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isCatastrophic(abs, home, raw string) bool {
	c := filepath.Clean(abs)
	if c == "/" || c == "/home" || c == "/Users" || c == "/root" {
		return true
	}
	if home != "" && c == filepath.Clean(home) {
		return true
	}
	switch strings.TrimSpace(raw) {
	case "/", "/*", "~", "~/", "$HOME", "${HOME}", "/*/", "//":
		return true
	}
	return false
}
