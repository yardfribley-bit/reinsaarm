package codextrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashMatchesCanonicalIdentity(t *testing.T) {
	command := "/bin/reinsaarm hook --client codex --home /state --socket /state/reinsaarm.sock"
	raw, err := identityJSON("pre_tool_use", "*", true, command, "ReinsAARM", 15, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"/bin/reinsaarm hook --client codex --home /state --socket /state/reinsaarm.sock","statusMessage":"ReinsAARM","timeout":15,"type":"command"}],"matcher":"*"}`
	if string(raw) != want {
		t.Fatalf("preimage\n%s\nwant\n%s", raw, want)
	}
	sum, err := Hash("pre_tool_use", "*", true, command, "ReinsAARM", 15, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sum, "sha256:") || len(sum) != len("sha256:")+64 {
		t.Fatal(sum)
	}
}

func TestDoctorUntrustedThenTrusted(t *testing.T) {
	dir := t.TempDir()
	hooksPath := filepath.Join(dir, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/bin/reinsaarm hook --client codex --home /state --socket /state/reinsaarm.sock",
            "timeout": 15,
            "statusMessage": "ReinsAARM"
          }
        ]
      }
    ]
  }
}
`
	if err := os.WriteFile(hooksPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := FindReins(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || !strings.HasSuffix(found[0].Key, ":pre_tool_use:0:0") {
		t.Fatalf("%+v", found)
	}
	cfg := filepath.Join(dir, "config.toml")
	status := Inspect(found, []string{cfg})
	if status[0].State != "untrusted" {
		t.Fatalf("%+v", status[0])
	}
	if err := WriteTrust(cfg, found[0].Key, found[0].Hash); err != nil {
		t.Fatal(err)
	}
	// A second write must not duplicate the table.
	if err := WriteTrust(cfg, found[0].Key, found[0].Hash); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(text), found[0].Key) != 1 {
		t.Fatalf("duplicated key:\n%s", text)
	}
	status = Inspect(found, []string{cfg})
	if status[0].State != "trusted" {
		t.Fatalf("%+v\n%s", status[0], text)
	}
	if err := WriteTrust(cfg, found[0].Key, "sha256:dead"); err != nil {
		t.Fatal(err)
	}
	status = Inspect(found, []string{cfg})
	if status[0].State != "modified" {
		t.Fatalf("stale hash should be modified, got %s", status[0].State)
	}
}
