package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// File is ~/.reinsaarm/config.yaml, or $REINSAARM_HOME/config.yaml.
type File struct {
	AgentID       string `yaml:"agent_id"`
	ChainID       string `yaml:"chain_id"`
	DeveloperHome string `yaml:"developer_home"`
	Socket        string `yaml:"socket"`
	Profile       string `yaml:"profile"`
	AuditLog      string `yaml:"audit_log"`
	Approvals     string `yaml:"approvals"`
	IdentityKey   string `yaml:"identity_key"`
	WebListen     string `yaml:"web_listen"`
	EgressListen  string `yaml:"egress_listen"`
	Sensor        bool   `yaml:"sensor"`
	// RecordFullPrompts stores whole user prompts (secrets masked, capped at
	// 8000 characters) in activity receipts. Default false: a short redacted
	// summary is stored.
	RecordFullPrompts bool `yaml:"record_full_prompts,omitempty"`
	// Capture sets what the task replay view stores. All text is redacted
	// and truncated. Omit it for the defaults.
	Capture Capture `yaml:"capture,omitempty"`
}

// Capture limits, in characters. A nil limit means the default; 0 turns
// that capture off. Off turns every new capture off at once (tool input
// previews, result links, transcript commentary) and keeps the earlier
// limits for output (400) and the final message (300).
type Capture struct {
	Off           bool  `yaml:"off,omitempty"`
	ArgsPreview   *int  `yaml:"args_preview,omitempty"`
	OutputPreview *int  `yaml:"output_preview,omitempty"`
	FinalMessage  *int  `yaml:"final_message,omitempty"`
	ResultLinks   *bool `yaml:"result_links,omitempty"`
	// Transcript lets the sidecar read the agent's own transcript file
	// (Codex rollout .jsonl, or a Claude-style session file, under the
	// developer home) for the turn trigger, the front end, progress
	// messages, and plaintext thinking.
	Transcript *bool `yaml:"transcript,omitempty"`
}

// Defaults for Capture.
const (
	DefaultArgsPreview   = 600
	DefaultOutputPreview = 800
	DefaultFinalMessage  = 2000
)

// Limits resolves the capture settings.
func (c Capture) Limits() (args, output, final int, links, transcript bool) {
	if c.Off {
		return 0, 400, 300, false, false
	}
	pick := func(p *int, d int) int {
		if p == nil {
			return d
		}
		if *p < 0 {
			return 0
		}
		return *p
	}
	flag := func(p *bool) bool { return p == nil || *p }
	return pick(c.ArgsPreview, DefaultArgsPreview), pick(c.OutputPreview, DefaultOutputPreview),
		pick(c.FinalMessage, DefaultFinalMessage), flag(c.ResultLinks), flag(c.Transcript)
}

// Default builds paths under dir. developerHome is the home used to expand ~.
func Default(dir, developerHome string) File {
	return File{
		AgentID:       "dev-coding-agent",
		ChainID:       "local",
		DeveloperHome: developerHome,
		Socket:        filepath.Join(dir, "reinsaarm.sock"),
		Profile:       filepath.Join(dir, "profile.yaml"),
		AuditLog:      filepath.Join(dir, "audit.jsonl"),
		Approvals:     filepath.Join(dir, "approvals.json"),
		IdentityKey:   filepath.Join(dir, "identity.key"),
		Sensor:        true,
	}
}

// Load reads a config file.
func Load(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("config: %w", err)
	}
	return f, nil
}

// Save writes a config file.
func Save(path string, f File) error {
	raw, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// Path is config.yaml inside a home directory.
func Path(dir string) string { return filepath.Join(dir, "config.yaml") }
