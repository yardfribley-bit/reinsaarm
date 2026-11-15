package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookProcessExit2WritesStderr(t *testing.T) {
	bin := buildBin(t)
	cmd := exec.Command(bin, "hook", "--client", "codex")
	cmd.Stdin = strings.NewReader("not-json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("exit %v stdout %s stderr %s", err, stdout.String(), stderr.String())
	}
	if strings.TrimSpace(stderr.String()) == "" {
		t.Fatal("Codex fails open on exit 2 with empty stderr")
	}
	if !strings.Contains(stderr.String(), "reinsaarm:") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestDoctorFailsUntilTrusted(t *testing.T) {
	bin := buildBin(t)
	project := t.TempDir()
	state := t.TempDir()
	codex := t.TempDir()
	env := append(os.Environ(),
		"REINSAARM_HOME="+state,
		"CODEX_HOME="+codex,
		"HOME="+t.TempDir(),
	)
	runCLI(t, bin, env, "init")
	runCLI(t, bin, env, "install-hooks", "codex", "--dest", project, "--state", state)
	hookFile := filepath.Join(project, ".codex", "hooks.json")
	body, err := os.ReadFile(hookFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "--home "+state) || !strings.Contains(string(body), "--socket ") {
		t.Fatalf("hook command did not bake state: %s", body)
	}
	if err := runCLIErr(bin, env, "doctor", "--dest", project, "--codex-home", codex); err == nil {
		t.Fatal("doctor should fail while the hook is untrusted")
	}
	runCLI(t, bin, env, "install-hooks", "codex", "--dest", project, "--state", state, "--trust")
	runCLI(t, bin, env, "doctor", "--dest", project, "--codex-home", codex)
	cfg, err := os.ReadFile(filepath.Join(codex, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "trusted_hash") || !strings.Contains(string(cfg), "pre_tool_use:0:0") || !strings.Contains(string(cfg), "trust_level") {
		t.Fatalf("config.toml:\n%s", cfg)
	}
}

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "reinsaarm")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	// Tests run in the package directory.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = wd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func runCLI(t *testing.T, bin string, env []string, args ...string) {
	t.Helper()
	if err := runCLIErr(bin, env, args...); err != nil {
		t.Fatal(err)
	}
}

func runCLIErr(bin string, env []string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(err.Error() + "\n" + string(out))
	}
	return nil
}
