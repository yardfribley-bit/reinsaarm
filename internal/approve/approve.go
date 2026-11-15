// Package approve stores one-time, argument-bound human approvals.
package approve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/canon"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
)

// Grant is one pending or consumed approval.
type Grant struct {
	ID       string `json:"id"`
	ArgsHash string `json:"args_hash"`
	Expires  string `json:"expires"`
	Approved bool   `json:"approved"`
	Used     bool   `json:"used"`
	Tool     string `json:"tool"`
	Command  string `json:"command,omitempty"`
	Client   string `json:"client,omitempty"`
	Reason   string `json:"reason"`
	Decision string `json:"decision,omitempty"`
	Enforced string `json:"enforced,omitempty"`
	Denied   bool   `json:"denied,omitempty"`
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

// AppendReceipt writes the grant onto the hash chain. Approving is itself
// an audited action, so the next tool receipt does not skip a sequence number.
func AppendReceipt(led *ledger.Ledger, agentID string, g Grant) (ledger.Receipt, error) {
	if led == nil {
		return ledger.Receipt{}, fmt.Errorf("approve: nil ledger")
	}
	if g.ID == "" {
		return ledger.Receipt{}, fmt.Errorf("approve: id required")
	}
	if agentID == "" {
		agentID = "dev-coding-agent"
	}
	tool := g.Tool
	if tool == "" {
		tool = "approve"
	}
	return led.Append(ledger.Receipt{
		EventID:          g.ID,
		AgentID:          agentID,
		Client:           "reinsaarm",
		SessionID:        "approval",
		Tool:             tool,
		Kind:             "approval",
		ActionDigest:     "sha256:" + g.ArgsHash,
		CommandPreview:   "approve " + g.ID,
		Decision:         "ALLOW",
		EnforcedDecision: "ALLOW",
		Tier:             "T3",
		RuleIDs:          []string{"R-APPROVAL-GRANT"},
		Reason:           "granted one-time approval " + g.ID,
		EventType:        "approval.granted",
		TS:               time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// Deny marks a grant rejected so it cannot be consumed, and returns it.
func Deny(path, id string) (Grant, error) {
	grants, err := Load(path)
	if err != nil {
		return Grant{}, err
	}
	for i := range grants {
		if grants[i].ID == id {
			if grants[i].Used {
				return Grant{}, fmt.Errorf("approve: %s already used", id)
			}
			grants[i].Denied = true
			grants[i].Approved = false
			if err := Save(path, grants); err != nil {
				return Grant{}, err
			}
			return grants[i], nil
		}
	}
	return Grant{}, os.ErrNotExist
}

// AppendDenial writes a rejection onto the hash chain.
func AppendDenial(led *ledger.Ledger, agentID string, g Grant) (ledger.Receipt, error) {
	if led == nil {
		return ledger.Receipt{}, fmt.Errorf("approve: nil ledger")
	}
	if agentID == "" {
		agentID = "dev-coding-agent"
	}
	tool := g.Tool
	if tool == "" {
		tool = "approve"
	}
	preview := g.Command
	if preview == "" {
		preview = "deny " + g.ID
	}
	return led.Append(ledger.Receipt{
		EventID:          "deny-" + g.ID,
		AgentID:          agentID,
		Client:           "reinsaarm",
		SessionID:        "approval",
		Tool:             tool,
		Kind:             "approval",
		ActionDigest:     "sha256:" + g.ArgsHash,
		CommandPreview:   preview,
		Decision:         "DENY",
		EnforcedDecision: "DENY",
		Tier:             "T3",
		RuleIDs:          []string{"R-APPROVAL-DENY"},
		Reason:           "denied approval " + g.ID,
		EventType:        "approval.denied",
		TS:               time.Now().UTC().Format(time.RFC3339Nano),
	})
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
