package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		if strings.Count(string(again[0].Payload), "reinsaarm hook --client "+client) != 1 {
			t.Fatalf("duplicated %s", client)
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
