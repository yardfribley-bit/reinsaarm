package workbuddy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserConfigDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("WORKBUDDY_CONFIG_DIR", "")
	if got := UserConfigDirs(home, ""); len(got) != 1 || got[0] != filepath.Join(home, ".workbuddy") {
		t.Fatalf("default: %v", got)
	}
	os.MkdirAll(filepath.Join(home, ".workbuddy"), 0o755)
	os.MkdirAll(filepath.Join(home, ".workbuddy-ai"), 0o755)
	got := UserConfigDirs(home, "")
	if len(got) != 2 || got[0] != filepath.Join(home, ".workbuddy-ai") {
		t.Fatalf("both: %v", got)
	}
	t.Setenv("WORKBUDDY_CONFIG_DIR", "/env/dir")
	if got := UserConfigDirs(home, ""); len(got) != 1 || got[0] != "/env/dir" {
		t.Fatalf("env: %v", got)
	}
	if got := UserConfigDirs(home, "/x"); got[0] != "/x" {
		t.Fatalf("explicit: %v", got)
	}
}

func TestInspect(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")
	if st := Inspect(p); st.Exists || st.Installed || st.Error != "" {
		t.Fatalf("missing: %+v", st)
	}
	os.WriteFile(p, []byte(`{"sandbox":{},"disableAllHooks":true,"hooks":{"PreToolUse":[
	 {"matcher":".*","hooks":[{"type":"command","command":"'/Apps/AgentReins v2.app/Contents/MacOS/AgentReinsHook' PreToolUse"}]},
	 {"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/reinsaarm hook --client workbuddy --home /s","timeout":15}]}]}}`), 0o600)
	st := Inspect(p)
	if !st.Installed || st.CoversAll || st.Matcher != "Bash" || len(st.Others) != 1 || st.Disabled != "disableAllHooks" {
		t.Fatalf("%+v", st)
	}
	for m, want := range map[string]bool{"": true, "*": true, ".*": true, "Bash": false, "Bash|Read|Write|Edit": false, "^(?:.*)$": true, "[": false} {
		if MatchesAll(m) != want {
			t.Errorf("MatchesAll(%q) != %v", m, want)
		}
	}
}
