package main

import "testing"

func TestApproveFlagsAfterID(t *testing.T) {
	fs := newFlag("approve")
	home := fs.String("home", "", "state directory")
	if err := parseFlags(fs, []string{"abc", "--home", "/tmp/state"}); err != nil {
		t.Fatal(err)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "abc" || *home != "/tmp/state" {
		t.Fatalf("n=%d arg=%q home=%q", fs.NArg(), fs.Arg(0), *home)
	}
}

func TestFlagsBeforeOrAfter(t *testing.T) {
	fs := newFlag("approve")
	home := fs.String("home", "", "")
	if err := parseFlags(fs, []string{"--home=/tmp/a", "id-1"}); err != nil {
		t.Fatal(err)
	}
	if fs.Arg(0) != "id-1" || *home != "/tmp/a" {
		t.Fatalf("arg=%q home=%q", fs.Arg(0), *home)
	}
}
