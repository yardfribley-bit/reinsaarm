package policy

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default_profile.yaml
var defaultProfileYAML []byte

// DefaultYAML is the built-in developer remit.
func DefaultYAML() []byte {
	out := make([]byte, len(defaultProfileYAML))
	copy(out, defaultProfileYAML)
	return out
}

// Profile is a developer-agent remit. It is the narrowed form of the
// enterprise Agent Profile: one sentence of remit, expected behaviours,
// known risks, and the structured constraints the fast path can enforce.
type Profile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		ID    string `yaml:"id"`
		Owner string `yaml:"owner"`
		Env   string `yaml:"env"`
	} `yaml:"metadata"`
	Spec Spec `yaml:"spec"`
}

// Spec is the enforceable part of a profile.
type Spec struct {
	Mode               string   `yaml:"mode"`
	FailMode           string   `yaml:"failMode"`
	Unattended         bool     `yaml:"unattended"`
	Remit              string   `yaml:"remit"`
	ExpectedBehaviours []string `yaml:"expectedBehaviours"`
	KnownRisks         []string `yaml:"knownRisks"`
	ProtectedBranches  []string `yaml:"protectedBranches"`
	Workspace          struct {
		ConfineWrites bool `yaml:"confineWrites"`
	} `yaml:"workspace"`
	Credentials struct {
		DenyPrefixes         []string `yaml:"denyPrefixes"`
		DenyBasenames        []string `yaml:"denyBasenames"`
		DenyBasenamePrefixes []string `yaml:"denyBasenamePrefixes"`
		AllowBasenames       []string `yaml:"allowBasenames"`
		AllowPrefixes        []string `yaml:"allowPrefixes"`
	} `yaml:"credentials"`
	Network struct {
		Mode       string   `yaml:"mode"`
		Allow      []string `yaml:"allow"`
		DenyAlways []string `yaml:"denyAlways"`
	} `yaml:"network"`
	CIPaths []string `yaml:"ciPaths"`
	Judge   struct {
		Enabled       bool    `yaml:"enabled"`
		Endpoint      string  `yaml:"endpoint"`
		Model         string  `yaml:"model"`
		TimeoutMs     int     `yaml:"timeoutMs"`
		MinConfidence float64 `yaml:"minConfidence"`
		PromptVersion string  `yaml:"promptVersion"`
	} `yaml:"judge"`
	MCPPins map[string]string `yaml:"mcpPins"`
	// MCP holds rules matched by MCP server and tool name. An MCP call that
	// matches no rule is allowed unless another rule (credential path,
	// egress, poisoning, definition pin) matches its arguments.
	MCP struct {
		Rules []MCPRule `yaml:"rules"`
	} `yaml:"mcp"`
}

// Load parses a profile from YAML bytes.
func Load(raw []byte) (*Profile, error) {
	var p Profile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads a profile from disk.
func LoadFile(path string) (*Profile, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := Load(raw)
	if err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

func (p *Profile) normalize() error {
	if p.APIVersion == "" {
		p.APIVersion = "reinsaarm/v1"
	}
	if p.Kind == "" {
		p.Kind = "AgentProfile"
	}
	if p.Kind != "AgentProfile" {
		return fmt.Errorf("profile: kind %q", p.Kind)
	}
	switch p.Spec.Mode {
	case "":
		p.Spec.Mode = "enforce"
	case "audit", "review", "enforce":
	default:
		return fmt.Errorf("profile: mode %q", p.Spec.Mode)
	}
	switch p.Spec.FailMode {
	case "":
		p.Spec.FailMode = "closed"
	case "open", "closed":
	default:
		return fmt.Errorf("profile: failMode %q", p.Spec.FailMode)
	}
	switch p.Spec.Network.Mode {
	case "":
		p.Spec.Network.Mode = "strict"
	case "off", "audit", "strict":
	default:
		return fmt.Errorf("profile: network.mode %q", p.Spec.Network.Mode)
	}
	if p.Spec.Judge.TimeoutMs <= 0 {
		p.Spec.Judge.TimeoutMs = 4000
	}
	if p.Spec.Judge.MinConfidence <= 0 {
		p.Spec.Judge.MinConfidence = 0.7
	}
	if p.Spec.Judge.Model == "" {
		p.Spec.Judge.Model = "reinsaarm-judge"
	}
	if p.Spec.Judge.PromptVersion == "" {
		p.Spec.Judge.PromptVersion = "judge-v1"
	}
	p.Spec.Remit = strings.TrimSpace(p.Spec.Remit)
	if p.Spec.Remit == "" {
		return fmt.Errorf("profile: remit is required")
	}
	for i := range p.Spec.MCP.Rules {
		if err := p.Spec.MCP.Rules[i].normalize(i); err != nil {
			return err
		}
	}
	if len(p.Spec.ProtectedBranches) == 0 {
		p.Spec.ProtectedBranches = []string{"main", "master"}
	}
	return nil
}
