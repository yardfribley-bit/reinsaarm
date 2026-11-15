package approve

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOneTimeBoundApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	h := ArgsHash("Bash", "git push origin main", nil, nil)
	g := Grant{ID: "abc", ArgsHash: h, Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Tool: "Bash"}
	if err := Put(path, g); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Consume(path, h, time.Now()); err != nil || ok {
		t.Fatalf("unapproved consume ok=%v err=%v", ok, err)
	}
	if _, err := Approve(path, "abc"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := Consume(path, h, time.Now())
	if err != nil || !ok || got.ID != "abc" {
		t.Fatalf("consume %+v ok=%v err=%v", got, ok, err)
	}
	if _, ok, err := Consume(path, h, time.Now()); err != nil || ok {
		t.Fatalf("second consume ok=%v err=%v", ok, err)
	}
	other := ArgsHash("Bash", "git push origin main --force", nil, nil)
	if other == h {
		t.Fatal("hash should change")
	}
}
