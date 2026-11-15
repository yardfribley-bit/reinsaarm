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

// TestCodexUserScopeKeepsForeignHooks installs into a ~/.codex/hooks.json that
// already has another vendor's hooks (as on a real Mac with an OpenTelemetry
// hook). Their groups stay first with unchanged trust keys, config.toml keeps
// 0600, no project trust is written, and doctor passes in an untrusted folder.
func TestCodexUserScopeKeepsForeignHooks(t *testing.T) {
	bin := buildBin(t)
	home := t.TempDir()
	codex := filepath.Join(home, ".codex")
	state := t.TempDir()
	if err := os.MkdirAll(codex, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"/opt/otel/hook.sh session-start"}]}],` +
		`"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"/opt/otel/hook.sh user-prompt-submit"}]}]}}`
	if err := os.WriteFile(filepath.Join(codex, "hooks.json"), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	otelTrust := "[hooks.state.\"" + filepath.Join(codex, "hooks.json") + ":session_start:0:0\"]\ntrusted_hash = \"sha256:otel\"\n"
	if err := os.WriteFile(filepath.Join(codex, "config.toml"), []byte(otelTrust), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "REINSAARM_HOME="+state, "CODEX_HOME="+codex, "HOME="+home)
	runCLI(t, bin, env, "init")
	other := t.TempDir()
	cmd := exec.Command(bin, "install-hooks", "codex", "--scope", "user", "--home", home, "--state", state, "--trust")
	cmd.Env, cmd.Dir = env, other
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	body, _ := os.ReadFile(filepath.Join(codex, "hooks.json"))
	if strings.Count(string(body), "/opt/otel/hook.sh") != 2 {
		t.Fatalf("foreign hooks lost:\n%s", body)
	}
	cfg, _ := os.ReadFile(filepath.Join(codex, "config.toml"))
	for _, want := range []string{"sha256:otel", "pre_tool_use:0:0", "session_start:1:0", "user_prompt_submit:1:0"} {
		if !strings.Contains(string(cfg), want) {
			t.Fatalf("config.toml missing %s:\n%s", want, cfg)
		}
	}
	if strings.Contains(string(cfg), "trust_level") {
		t.Fatalf("user scope must not trust a project:\n%s", cfg)
	}
	if st, _ := os.Stat(filepath.Join(codex, "config.toml")); st.Mode().Perm() != 0o600 {
		t.Fatalf("config.toml mode %v", st.Mode().Perm())
	}
	runCLI(t, bin, env, "doctor", "--dest", other, "--codex-home", codex)
	// A rerun must not duplicate our handlers.
	cmd = exec.Command(bin, "install-hooks", "codex", "--scope", "user", "--home", home, "--state", state, "--trust")
	cmd.Env, cmd.Dir = env, other
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reinstall: %v\n%s", err, out)
	}
	again, _ := os.ReadFile(filepath.Join(codex, "hooks.json"))
	if strings.Count(string(again), "hook --client codex") != 6 {
		t.Fatalf("want 6 reinsaarm handlers:\n%s", again)
	}
}
