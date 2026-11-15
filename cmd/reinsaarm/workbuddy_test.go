package main

import (
	"reflect"
	"testing"

	"github.com/yardfribley-bit/reinsaarm/internal/install"
)

func TestSplitHookCommand(t *testing.T) {
	cmd := install.HookCommand("/Users/dev/My Tools/reinsaarm", "workbuddy", "/Users/dev/.reinsaarm", "/Users/dev/.reinsaarm/reinsaarm.sock")
	got := splitHookCommand(cmd)
	want := []string{"/Users/dev/My Tools/reinsaarm", "hook", "--client", "workbuddy", "--home", "/Users/dev/.reinsaarm", "--socket", "/Users/dev/.reinsaarm/reinsaarm.sock"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	if got := splitHookCommand(`'/a/it'\''s/reinsaarm' hook`); got[0] != "/a/it's/reinsaarm" {
		t.Fatalf("%q", got)
	}
}
