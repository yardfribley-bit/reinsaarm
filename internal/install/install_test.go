package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/codextrust"
)

func TestInstallEachClient(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	for _, client := range []string{"claude-code", "codex", "gemini", "codebuddy"} {
		plans, err := Plans(client, "/usr/local/bin/reinsaarm", "project", dir, home, "/state", "/state/reinsaarm.sock")
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(plans); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(plans[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "reinsaarm hook --client "+client) || !strings.Contains(string(b), "--home /state") || !strings.Contains(string(b), "--socket /state/reinsaarm.sock") {
			t.Fatalf("%s: %s", client, b)
		}
		// A second install must not duplicate the command.
		again, err := Plans(client, "/usr/local/bin/reinsaarm", "project", dir, home, "/state", "/state/reinsaarm.sock")
		if err != nil {
			t.Fatal(err)
		}
		// One pre-tool hook plus one handler per activity event.
		if n := strings.Count(string(again[0].Payload), "reinsaarm hook --client "+client); n != 1+len(Observers(client)) {
			t.Fatalf("duplicated %s: %d", client, n)
		}
		if string(again[0].Payload) != string(b) {
			t.Fatalf("%s: second install changed the file", client)
		}
	}
	claude := filepath.Join(dir, ".claude", "settings.json")
	b, _ := os.ReadFile(claude)
	if !strings.Contains(string(b), `"onFailure": "block"`) {
		t.Fatalf("claude onFailure missing: %s", b)
	}
	gem := filepath.Join(dir, ".gemini", "settings.json")
	b, _ = os.ReadFile(gem)
	if !strings.Contains(string(b), "BeforeTool") || !strings.Contains(string(b), "15000") {
		t.Fatalf("gemini: %s", b)
	}
}

func TestCodexActivityHooksTrustKeys(t *testing.T) {
	dir := t.TempDir()
	plans, err := Plans("codex", "/usr/local/bin/reinsaarm", "project", dir, t.TempDir(), "/state", "/state/reinsaarm.sock")
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(plans); err != nil {
		t.Fatal(err)
	}
	found, err := codextrust.FindReins(plans[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]codextrust.Hook{}
	for _, h := range found {
		keys[h.Event] = h
	}
	for _, ev := range []string{"pre_tool_use", "post_tool_use", "session_start", "session_end", "user_prompt_submit", "stop"} {
		if _, ok := keys[ev]; !ok {
			t.Fatalf("missing %s in %v", ev, keys)
		}
	}
	// The pre-tool hook keeps its original definition, so an existing
	// trusted_hash stays valid after the upgrade.
	pre := keys["pre_tool_use"]
	if pre.TimeoutSec != 15 || pre.StatusMessage != "ReinsAARM" || !strings.HasSuffix(pre.Key, ":pre_tool_use:0:0") {
		t.Fatalf("pre %+v", pre)
	}
	if keys["session_end"].TimeoutSec != 3 {
		t.Fatalf("SessionEnd timeout must be within Codex's 3 s clamp: %+v", keys["session_end"])
	}
	if keys["user_prompt_submit"].MatcherSet || keys["stop"].MatcherSet {
		t.Fatal("Codex ignores matchers on UserPromptSubmit/Stop; leave them out")
	}
}
