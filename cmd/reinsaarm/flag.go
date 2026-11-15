package main

import (
	"flag"
	"strings"
)

func newFlag(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(osStderr())
	return fs
}

// parseFlags accepts flags before or after positional arguments.
// The standard library stops at the first non-flag, so
// `approve <id> --home DIR` used to ignore --home and then reject the id.
func parseFlags(fs *flag.FlagSet, args []string) error {
	ordered := orderArgs(fs, args)
	return fs.Parse(ordered)
}

func orderArgs(fs *flag.FlagSet, args []string) []string {
	takesValue := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		isBool := false
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
			isBool = b.IsBoolFlag()
		}
		takesValue[f.Name] = !isBool
	})
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		flags = append(flags, a)
		if eq := strings.IndexByte(a, '='); eq < 0 && takesValue[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, pos...)
}
