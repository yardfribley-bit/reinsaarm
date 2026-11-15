package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// existing is the shape of a real ~/.workbuddy/settings.json that already
// carries another vendor's hooks.
const existing = `{
  "sandbox": {"enabled": true},
  "enabledPlugins": {"x": true},
  "hooks": {
    "SessionStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "/opt/other/hook SessionStart"}]}],
    "PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "/opt/other/hook PreToolUse"}]}]
  }
}
`

func TestInstallWorkBuddyUserScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WORKBUDDY_CONFIG_DIR", "")
	ai := filepath.Join(home, ".workbuddy-ai")
	classic := filepath.Join(home, ".workbuddy")
	os.MkdirAll(ai, 0o700)
	os.MkdirAll(classic, 0o700)
	os.WriteFile(filepath.Join(classic, "settings.json"), []byte(existing), 0o600)

	plans, err := Plans("workbuddy", "/Users/dev/bin/reinsaarm", "user", "/proj", home, "/Users/dev/.reinsaarm", "/Users/dev/.reinsaarm/reinsaarm.sock")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 || plans[0].Path != filepath.Join(ai, "settings.json") || plans[1].Path != filepath.Join(classic, "settings.json") {
		t.Fatalf("plans: %+v", plans)
	}
	backups, err := ApplyWithBackup(plans)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || !strings.HasPrefix(backups[0], filepath.Join(classic, "settings.json.bak.reinsaarm-")) {
		t.Fatalf("backups: %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != existing {
		t.Fatal("backup must be the original bytes")
	}
	st, _ := os.Stat(filepath.Join(classic, "settings.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v: settings may hold tokens, keep 0600", st.Mode().Perm())
	}
	b, _ := os.ReadFile(filepath.Join(classic, "settings.json"))
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	pre := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 || doc["sandbox"] == nil || doc["hooks"].(map[string]any)["SessionStart"] == nil {
		t.Fatalf("existing settings lost: %s", b)
	}
	ours := pre[1].(map[string]any)
	h := ours["hooks"].([]any)[0].(map[string]any)
	if ours["matcher"] != "*" || h["timeout"] != float64(15) || !strings.Contains(h["command"].(string), "reinsaarm hook --client workbuddy --home /Users/dev/.reinsaarm --socket /Users/dev/.reinsaarm/reinsaarm.sock") {
		t.Fatalf("hook entry: %v", ours)
	}

	// Re-install: no duplicate, no new backup.
	again, _ := Plans("workbuddy", "/Users/dev/bin/reinsaarm", "user", "/proj", home, "/Users/dev/.reinsaarm", "/Users/dev/.reinsaarm/reinsaarm.sock")
	more, err := ApplyWithBackup(again)
	if err != nil || len(more) != 0 {
		t.Fatalf("idempotent: %v %v", more, err)
	}
	b, _ = os.ReadFile(filepath.Join(ai, "settings.json"))
	if strings.Count(string(b), "--client workbuddy") != 1 {
		t.Fatalf("duplicated: %s", b)
	}

	// Explicit data folder.
	UserConfigDir = filepath.Join(home, "custom")
	defer func() { UserConfigDir = "" }()
	one, _ := Plans("workbuddy", "/b/reinsaarm", "user", "/proj", home, "", "")
	if len(one) != 1 || one[0].Path != filepath.Join(home, "custom", "settings.json") {
		t.Fatalf("config-dir: %+v", one)
	}
}

func TestInstallWorkBuddyProjectScope(t *testing.T) {
	proj := t.TempDir()
	plans, err := Plans("workbuddy", "/b/reinsaarm", "project", proj, t.TempDir(), "/s", "/s/reinsaarm.sock")
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].Path != filepath.Join(proj, ".codebuddy", "settings.json") {
		t.Fatalf("%+v", plans)
	}
	if err := Apply(plans); err != nil {
		t.Fatal(err)
	}
	// codebuddy and workbuddy entries coexist in the same project file.
	cb, _ := Plans("codebuddy", "/b/reinsaarm", "project", proj, t.TempDir(), "/s", "/s/reinsaarm.sock")
	if !strings.Contains(string(cb[0].Payload), "--client workbuddy") || !strings.Contains(string(cb[0].Payload), "--client codebuddy") {
		t.Fatalf("coexist: %s", cb[0].Payload)
	}
}
