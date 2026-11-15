package main

import "flag"

func newFlag(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(osStderr())
	return fs
}
