// Package approve stores one-time, argument-bound human approvals.
package approve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/canon"
)

// Grant is one pending or consumed approval.
type Grant struct {
	ID       string `json:"id"`
	ArgsHash string `json:"args_hash"`
	Expires  string `json:"expires"`
	Approved bool   `json:"approved"`
	Used     bool   `json:"used"`
	Tool     string `json:"tool"`
	Reason   string `json:"reason"`
}

type file struct {
	Grants []Grant `json:"grants"`
}

// ArgsHash binds an approval to the tool and its arguments.
func ArgsHash(tool, command string, paths, hosts []string) string {
	ps := append([]string{}, paths...)
	hs := append([]string{}, hosts...)
	sort.Strings(ps)
	sort.Strings(hs)
	raw, err := canon.Value(map[string]any{
		"tool":    tool,
		"command": command,
		"paths":   ps,
		"hosts":   hs,
	})
	if err != nil {
		sum := sha256.Sum256([]byte(tool + "\n" + command))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Load reads the store. A missing file is an empty store.
func Load(path string) ([]Grant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Grants, nil
}

// Save writes the store atomically.
func Save(path string, grants []Grant) error {
	raw, err := json.MarshalIndent(file{Grants: grants}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Put inserts or refreshes a pending grant with the same id.
func Put(path string, g Grant) error {
	grants, err := Load(path)
	if err != nil {
		return err
	}
	replaced := false
	for i := range grants {
		if grants[i].ID == g.ID {
			if grants[i].Used || grants[i].Approved {
				return nil
			}
			grants[i] = g
			replaced = true
			break
		}
	}
	if !replaced {
		grants = append(grants, g)
	}
	return Save(path, grants)
}

// Approve marks a grant approved. It does not consume it.
func Approve(path, id string) (Grant, error) {
	grants, err := Load(path)
	if err != nil {
		return Grant{}, err
	}
	for i := range grants {
		if grants[i].ID == id {
			grants[i].Approved = true
			if err := Save(path, grants); err != nil {
				return Grant{}, err
			}
			return grants[i], nil
		}
	}
	return Grant{}, os.ErrNotExist
}

// Consume returns a matching unused approved grant and marks it used.
func Consume(path, argsHash string, now time.Time) (Grant, bool, error) {
	grants, err := Load(path)
	if err != nil {
		return Grant{}, false, err
	}
	for i := range grants {
		g := grants[i]
		if g.Used || !g.Approved || g.ArgsHash != argsHash {
			continue
		}
		if g.Expires != "" {
			exp, err := time.Parse(time.RFC3339, g.Expires)
			if err == nil && now.After(exp) {
				continue
			}
		}
		grants[i].Used = true
		if err := Save(path, grants); err != nil {
			return Grant{}, false, err
		}
		grants[i].Used = true
		return grants[i], true, nil
	}
	return Grant{}, false, nil
}
