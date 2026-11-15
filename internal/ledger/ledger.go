// Package ledger is an append-only hash-chained audit log. Each receipt is
// canonicalized, SHA-256 linked to the previous receipt, and signed with Ed25519.
package ledger

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/yardfribley-bit/reinsaarm/internal/canon"
)

// Receipt is one audit record. ReceiptHash and Signature are excluded from the
// preimage. IdentityFP binds the receipt to the signing key (AARM R6).
type Receipt struct {
	Schema     string `json:"schema"`
	ChainID    string `json:"chain_id"`
	Seq        uint64 `json:"seq"`
	PrevHash   string `json:"prev_hash"`
	EventID    string `json:"event_id"`
	AgentID    string `json:"agent_id"`
	IdentityFP string `json:"identity_fp"`
	Client     string `json:"client"`
	SessionID  string `json:"session_id"`
	Tool       string `json:"tool"`
	Kind       string `json:"kind"`
	// Resources is what the normalized action touches. It is omitted when
	// empty, so receipts written before it existed still verify.
	Resources        *Resources `json:"resources,omitempty"`
	ActionDigest     string     `json:"action_digest"`
	CommandPreview   string     `json:"command_preview"`
	Decision         string     `json:"decision"`
	EnforcedDecision string     `json:"enforced_decision"`
	Tier             string     `json:"tier"`
	RuleIDs          []string   `json:"rule_ids"`
	Reason           string     `json:"reason"`
	PolicyVersion    string     `json:"policy_version"`
	JudgeVerdict     string     `json:"judge_verdict,omitempty"`
	JudgeModel       string     `json:"judge_model,omitempty"`
	PromptVersion    string     `json:"prompt_version,omitempty"`
	EventType        string     `json:"event_type"`
	Degraded         bool       `json:"degraded"`
	Shadow           bool       `json:"shadow"`
	LatencyUS        int64      `json:"latency_us,omitempty"`
	TS               string     `json:"ts"`
	ReceiptHash      string     `json:"receipt_hash,omitempty"`
	Signature        string     `json:"signature,omitempty"`
}

// Resources lists the paths, hosts, git operations, and MCP server/tool of one
// normalized action. URLs are reduced to hosts so query-string tokens are not
// stored.
type Resources struct {
	Paths     []string `json:"paths,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	GitOps    []string `json:"git_ops,omitempty"`
	MCPServer string   `json:"mcp_server,omitempty"`
	MCPTool   string   `json:"mcp_tool,omitempty"`
}

// Ledger appends to a single file.
type Ledger struct {
	path    string
	chainID string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	fp      string
	mu      sync.Mutex
}

// Open opens or creates a ledger. The private key signs every receipt.
func Open(path, chainID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (*Ledger, error) {
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("ledger: ed25519 key required")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &Ledger{
		path:    path,
		chainID: chainID,
		pub:     pub,
		priv:    priv,
		fp:      Fingerprint(pub),
	}, nil
}

// Fingerprint is the identity string stored on receipts.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:16])
}

// IdentityFP returns this ledger's fingerprint.
func (l *Ledger) IdentityFP() string { return l.fp }

// Append links and signs a receipt. Seq, PrevHash, hashes, and the signature
// are filled in. The caller fills the payload fields.
func (l *Ledger) Append(r Receipt) (Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_RDWR, 0o600)
	if err != nil {
		return Receipt{}, err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return Receipt{}, err
	}
	defer unlockFile(f)
	prev, seq, err := tail(f)
	if err != nil {
		return Receipt{}, err
	}
	r.Schema = "reinsaarm.receipt.v1"
	r.ChainID = l.chainID
	r.Seq = seq
	r.PrevHash = prev
	r.IdentityFP = l.fp
	if r.EventType == "" {
		r.EventType = "action.decision"
	}
	if r.RuleIDs == nil {
		r.RuleIDs = []string{}
	}
	r.ReceiptHash = ""
	r.Signature = ""
	preimage, err := canon.Value(r)
	if err != nil {
		return Receipt{}, err
	}
	sum := sha256.Sum256(preimage)
	r.ReceiptHash = "sha256:" + hex.EncodeToString(sum[:])
	sig := ed25519.Sign(l.priv, []byte(r.ReceiptHash))
	r.Signature = "ed25519:" + base64.RawURLEncoding.EncodeToString(sig)
	line, err := canon.Value(r)
	if err != nil {
		return Receipt{}, err
	}
	if _, err := f.Seek(0, os.SEEK_END); err != nil {
		return Receipt{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// Path returns the log path.
func (l *Ledger) Path() string { return l.path }

func tail(f *os.File) (prev string, seq uint64, err error) {
	if _, err = f.Seek(0, os.SEEK_SET); err != nil {
		return "", 0, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2<<20)
	var last Receipt
	var n uint64
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrim(line)) == 0 {
			continue
		}
		var r Receipt
		if err := json.Unmarshal(line, &r); err != nil {
			return "", 0, fmt.Errorf("ledger: corrupt tail: %w", err)
		}
		last = r
		n = r.Seq
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	if n == 0 && last.ReceiptHash == "" {
		return genesis(), 1, nil
	}
	return last.ReceiptHash, n + 1, nil
}

func genesis() string {
	return "sha256:" + hex.EncodeToString(make([]byte, 32))
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// Problem describes the first broken receipt.
type Problem struct {
	Seq    uint64
	Reason string
}

// Verify walks the log offline. pub may be nil to use only the signatures
// embedded... the signature needs a public key. Pass the pinned key.
func Verify(path string, pub ed25519.PublicKey) (int, *Problem, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	expectPrev := genesis()
	var expectSeq uint64 = 1
	n := 0
	fp := Fingerprint(pub)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrim(line)) == 0 {
			continue
		}
		n++
		var r Receipt
		if err := json.Unmarshal(line, &r); err != nil {
			return n, &Problem{Seq: expectSeq, Reason: "invalid json: " + err.Error()}, nil
		}
		if r.Seq != expectSeq {
			return n, &Problem{Seq: r.Seq, Reason: fmt.Sprintf("seq want %d", expectSeq)}, nil
		}
		if r.PrevHash != expectPrev {
			return n, &Problem{Seq: r.Seq, Reason: "prev_hash mismatch"}, nil
		}
		if r.IdentityFP != fp {
			return n, &Problem{Seq: r.Seq, Reason: "identity fingerprint mismatch"}, nil
		}
		storedHash := r.ReceiptHash
		storedSig := r.Signature
		r.ReceiptHash = ""
		r.Signature = ""
		preimage, err := canon.Value(r)
		if err != nil {
			return n, &Problem{Seq: r.Seq, Reason: err.Error()}, nil
		}
		sum := sha256.Sum256(preimage)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if want != storedHash {
			return n, &Problem{Seq: r.Seq, Reason: "receipt_hash mismatch"}, nil
		}
		rawSig, err := base64.RawURLEncoding.DecodeString(stringsTrimPrefix(storedSig, "ed25519:"))
		if err != nil || !ed25519.Verify(pub, []byte(storedHash), rawSig) {
			return n, &Problem{Seq: r.Seq, Reason: "signature invalid"}, nil
		}
		expectPrev = storedHash
		expectSeq++
	}
	if err := sc.Err(); err != nil {
		return n, nil, err
	}
	return n, nil, nil
}

func stringsTrimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// Tail returns the last n receipts.
func Tail(path string, n int) ([]Receipt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []Receipt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytesTrim(line)) == 0 {
			continue
		}
		var r Receipt
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n <= 0 || n > len(all) {
		return all, nil
	}
	return all[len(all)-n:], nil
}
