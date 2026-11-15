package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/approve"
	"github.com/yardfribley-bit/reinsaarm/internal/codextrust"
	"github.com/yardfribley-bit/reinsaarm/internal/config"
	"github.com/yardfribley-bit/reinsaarm/internal/console"
	"github.com/yardfribley-bit/reinsaarm/internal/daemon"
	"github.com/yardfribley-bit/reinsaarm/internal/decision"
	"github.com/yardfribley-bit/reinsaarm/internal/hooks"
	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/install"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
	"github.com/yardfribley-bit/reinsaarm/internal/policy"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "hook":
		err = cmdHook(os.Args[2:])
	case "install-hooks":
		err = cmdInstall(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "decide":
		err = cmdDecide(os.Args[2:])
	case "bench":
		err = cmdBench(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "console", "ui":
		err = cmdConsole(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("reinsaarm", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reinsaarm:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `reinsaarm %s — runtime security for coding agents

Usage:
  reinsaarm init [--home DIR]
  reinsaarm run [--home DIR] [--socket PATH] [--web ADDR] [--egress ADDR]
  reinsaarm hook --client claude-code|codex|gemini|codebuddy
  reinsaarm install-hooks <client> [--scope project|user] [--dest DIR] [--trust]
  reinsaarm doctor [--dest DIR]
  reinsaarm console [--addr 127.0.0.1:8787] [--dest DIR]
  reinsaarm decide --tool NAME [--command CMD] [--path PATH] [--cwd DIR]
  reinsaarm approve <approval-id>
  reinsaarm audit verify
  reinsaarm audit tail [-n N]
  reinsaarm bench

The state directory is $REINSAARM_HOME or ~/.reinsaarm.
`, version)
}

func stateDir(flagHome string) (string, error) {
	if flagHome != "" {
		return flagHome, nil
	}
	if v := os.Getenv("REINSAARM_HOME"); v != "" {
		return v, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".reinsaarm"), nil
}

func cmdInit(args []string) error {
	fs := newFlag("init")
	home := fs.String("home", "", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := stateDir(*home)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	devHome, err := os.UserHomeDir()
	if err != nil {
		devHome = dir
	}
	cfg := config.Default(dir, devHome)
	if _, err := os.Stat(cfg.Profile); err != nil {
		if err := os.WriteFile(cfg.Profile, policy.DefaultYAML(), 0o644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(config.Path(dir)); err != nil {
		if err := config.Save(config.Path(dir), cfg); err != nil {
			return err
		}
	}
	if _, _, err := identity.LoadOrCreate(cfg.IdentityKey); err != nil {
		return err
	}
	fmt.Printf("initialized %s\n", dir)
	fmt.Printf("profile %s\n", cfg.Profile)
	fmt.Printf("socket  %s\n", cfg.Socket)
	return nil
}

func cmdRun(args []string) error {
	fs := newFlag("run")
	home := fs.String("home", "", "state directory")
	socket := fs.String("socket", "", "unix socket path")
	web := fs.String("web", "", "loopback address for the decision view, for example 127.0.0.1:8787")
	egress := fs.String("egress", "", "loopback address for the egress proxy, for example 127.0.0.1:18080")
	sensorOff := fs.Bool("no-sensor", false, "do not scan /proc for credential file descriptors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	if *socket != "" {
		cfg.Socket = *socket
	}
	if *web != "" {
		cfg.WebListen = *web
	}
	if *egress != "" {
		cfg.EgressListen = *egress
	}
	if *sensorOff {
		cfg.Sensor = false
	}
	pub, priv, err := identity.LoadOrCreate(cfg.IdentityKey)
	if err != nil {
		return err
	}
	srv, err := daemon.New(daemon.Config{
		Socket: cfg.Socket, ProfilePath: cfg.Profile, AuditPath: cfg.AuditLog,
		ApprovalPath: cfg.Approvals, ChainID: cfg.ChainID, AgentID: cfg.AgentID,
		Home: cfg.DeveloperHome, Web: cfg.WebListen, Egress: cfg.EgressListen,
		Sensor: cfg.Sensor, PublicKey: pub, PrivateKey: priv,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "reinsaarm listening on %s\n", cfg.Socket)
	return srv.Serve(ctx)
}

func cmdHook(args []string) error {
	fs := newFlag("hook")
	client := fs.String("client", "", "claude-code, codex, gemini, or codebuddy")
	home := fs.String("home", "", "state directory")
	socket := fs.String("socket", "", "unix socket")
	if err := fs.Parse(args); err != nil {
		exitHook(*client, err.Error())
	}
	if *client == "" {
		exitHook("codex", "--client is required")
	}
	in, err := hooks.ReadStdin()
	if err != nil {
		exitHook(*client, err.Error())
	}
	sock := *socket
	if sock == "" {
		cfg, err := loadConfig(*home)
		if err != nil {
			exitHook(*client, err.Error())
		}
		sock = cfg.Socket
	}
	resp, err := hooks.Exchange(sock, hooks.ToRequest(*client, in), 8*time.Second)
	if err != nil {
		exitHook(*client, err.Error())
	}
	out, err := hooks.Render(*client, in, resp)
	if err != nil {
		exitHook(*client, err.Error())
	}
	os.Stdout.Write(out.Stdout)
	if resp.Enforced == string(decision.Deny) || resp.Enforced == string(decision.Defer) {
		fmt.Fprintln(os.Stderr, "reinsaarm:", resp.Reason)
	}
	return nil
}

// exitHook always exits 2 with a non-empty stderr reason. Codex 0.151 fails
// open when a hook exits 2 and stderr is empty.
func exitHook(client, reason string) {
	if client == "" {
		client = "codex"
	}
	out := hooks.FailClosed(client, reason)
	if strings.TrimSpace(out.Stderr) == "" {
		out.Stderr = "reinsaarm: hook failed\n"
	}
	os.Stderr.WriteString(out.Stderr)
	if len(out.Stdout) > 0 {
		os.Stdout.Write(out.Stdout)
	}
	os.Exit(2)
}

func cmdInstall(args []string) error {
	fs := newFlag("install-hooks")
	if len(args) == 0 {
		return fmt.Errorf("install-hooks: client name required")
	}
	client := args[0]
	scope := fs.String("scope", "project", "project or user")
	dest := fs.String("dest", "", "project directory")
	bin := fs.String("bin", "", "path to the reinsaarm binary")
	homeFlag := fs.String("home", "", "developer home for --scope user")
	stateFlag := fs.String("state", "", "ReinsAARM state directory baked into the hook command")
	trust := fs.Bool("trust", false, "codex only: write hooks.state trusted_hash into the user config.toml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		*bin = exe
	}
	project := *dest
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		project = wd
	}
	devHome := *homeFlag
	if devHome == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		devHome = h
	}
	stateHome, err := stateDir(*stateFlag)
	if err != nil {
		return err
	}
	socket := filepath.Join(stateHome, "reinsaarm.sock")
	if cfg, err := config.Load(config.Path(stateHome)); err == nil && cfg.Socket != "" {
		socket = cfg.Socket
	}
	plans, err := install.Plans(client, *bin, *scope, project, devHome, stateHome, socket)
	if err != nil {
		return err
	}
	if err := install.Apply(plans); err != nil {
		return err
	}
	for _, p := range plans {
		fmt.Printf("wrote %s\n%s\n", p.Path, p.Note)
	}
	if client == "codex" {
		if err := explainCodexTrust(plans[0].Path, project, *trust); err != nil {
			return err
		}
	}
	return nil
}

func explainCodexTrust(hooksPath, project string, write bool) error {
	found, err := codextrust.FindReins(hooksPath)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("codex hook file %s has no reinsaarm command", hooksPath)
	}
	codexHome := codexConfigDir()
	cfgPath := filepath.Join(codexHome, "config.toml")
	fmt.Println()
	fmt.Println("Codex does not run this unmanaged hook until the current definition is trusted.")
	fmt.Println("Open Codex and run /hooks to review it, or rerun with --trust.")
	fmt.Println("Enterprise managed hooks in requirements.toml are trusted by policy and do not need this entry.")
	for _, h := range found {
		fmt.Printf("hook key: %s\n", h.Key)
		fmt.Printf("trusted_hash: %s\n", h.Hash)
		if write {
			if err := codextrust.WriteTrust(cfgPath, h.Key, h.Hash); err != nil {
				return err
			}
			fmt.Printf("wrote trusted_hash to %s\n", cfgPath)
		}
	}
	if write {
		absProject, err := filepath.Abs(project)
		if err != nil {
			return err
		}
		if err := codextrust.WriteProjectTrust(cfgPath, absProject); err != nil {
			return err
		}
		fmt.Printf("wrote projects.%q.trust_level = trusted to %s\n", absProject, cfgPath)
	}
	if !write {
		fmt.Printf("config checked by `reinsaarm doctor`: %s\n", cfgPath)
	}
	return nil
}

func codexConfigDir() string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return v
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ".codex"
	}
	return filepath.Join(h, ".codex")
}

func cmdConsole(args []string) error {
	fs := newFlag("console")
	home := fs.String("home", "", "state directory")
	addr := fs.String("addr", "127.0.0.1:8787", "loopback listen address")
	dest := fs.String("dest", "", "project directory for Codex trust checks")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	project := *dest
	if project == "" {
		project, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	srv, err := console.New(console.Config{
		Addr: *addr, AuditPath: cfg.AuditLog, ApprovalPath: cfg.Approvals,
		ProfilePath: cfg.Profile, IdentityKey: cfg.IdentityKey, ChainID: cfg.ChainID,
		AgentID: cfg.AgentID, Socket: cfg.Socket, Project: project, CodexHome: codexConfigDir(),
	})
	if err != nil {
		return err
	}
	ln, err := srv.Listen()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "console http://%s/?token=%s\n", ln.Addr().String(), srv.Token())
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx, ln)
}

func cmdDoctor(args []string) error {
	fs := newFlag("doctor")
	dest := fs.String("dest", "", "project directory")
	codexHome := fs.String("codex-home", "", "Codex home (default $CODEX_HOME or ~/.codex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	project := *dest
	if project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		project = wd
	}
	home := *codexHome
	if home == "" {
		home = codexConfigDir()
	}
	candidates := []string{
		filepath.Join(project, ".codex", "hooks.json"),
		filepath.Join(home, "hooks.json"),
	}
	var found []codextrust.Hook
	for _, path := range candidates {
		hooks, err := codextrust.FindReins(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if len(hooks) > 0 {
			found = append(found, hooks...)
		}
	}
	if len(found) == 0 {
		return fmt.Errorf("Codex hook is not installed (looked for .codex/hooks.json in %s and %s). Untrusted or missing hooks do not run, so tool calls are unprotected", project, home)
	}
	configs := []string{
		filepath.Join(home, "config.toml"),
		filepath.Join(project, ".codex", "config.toml"),
	}
	statuses := codextrust.Inspect(found, configs)
	failed := false
	for _, st := range statuses {
		switch st.State {
		case "trusted":
			fmt.Printf("trusted %s\n", st.Hook.Key)
		case "modified":
			failed = true
			fmt.Fprintf(os.Stderr, "UNTRUSTED Codex hook was modified after trust and will not run\nkey: %s\ncurrent: %s\nconfig %s has %s\nRun /hooks in Codex, or `reinsaarm install-hooks codex --trust`.\n", st.Hook.Key, st.Hook.Hash, st.ConfigPath, st.TrustedHash)
		default:
			failed = true
			fmt.Fprintf(os.Stderr, "UNTRUSTED Codex hook will not run\nkey: %s\ntrusted_hash: %s\nNo matching trusted_hash in %s\nOpen Codex and run /hooks, or `reinsaarm install-hooks codex --trust`.\nManaged requirements.toml hooks do not need this entry.\n", st.Hook.Key, st.Hook.Hash, strings.Join(configs, " or "))
		}
	}
	projectAbs, err := filepath.Abs(project)
	if err != nil {
		return err
	}
	userCfg := filepath.Join(home, "config.toml")
	level, foundTrust := codextrust.ProjectTrust(userCfg, projectAbs)
	if !foundTrust || level != "trusted" {
		failed = true
		shown := level
		if shown == "" {
			shown = "missing"
		}
		fmt.Fprintf(os.Stderr, "UNTRUSTED Codex project %s (trust_level=%s).\nCodex will not load %s/.codex/hooks.json until projects.%q.trust_level = \"trusted\" in %s.\nRun `reinsaarm install-hooks codex --trust` from that project, or set the trust level in Codex.\n", projectAbs, shown, projectAbs, projectAbs, userCfg)
	} else {
		fmt.Printf("project trusted %s\n", projectAbs)
	}
	if failed {
		return fmt.Errorf("codex hook trust check failed")
	}
	return nil
}

func cmdAudit(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("audit: verify or tail")
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:])
	case "tail":
		return cmdTail(args[1:])
	default:
		return fmt.Errorf("audit: %q", args[0])
	}
}

func cmdVerify(args []string) error {
	fs := newFlag("audit verify")
	home := fs.String("home", "", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	pub, err := identity.LoadPublic(cfg.IdentityKey)
	if err != nil {
		return err
	}
	n, problem, err := ledger.Verify(cfg.AuditLog, pub)
	if err != nil {
		return err
	}
	if problem != nil {
		return fmt.Errorf("audit broken at seq %d: %s", problem.Seq, problem.Reason)
	}
	fmt.Printf("ok %d receipts\n", n)
	return nil
}

func cmdTail(args []string) error {
	fs := newFlag("audit tail")
	home := fs.String("home", "", "state directory")
	nflag := fs.Int("n", 20, "number of receipts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	recs, err := ledger.Tail(cfg.AuditLog, *nflag)
	if err != nil {
		return err
	}
	for _, r := range recs {
		fmt.Printf("%d\t%s\t%s\t%s\t%s\t%s\n", r.Seq, r.Decision, r.EnforcedDecision, r.Client, r.Tool, r.Reason)
	}
	return nil
}

func cmdApprove(args []string) error {
	fs := newFlag("approve")
	home := fs.String("home", "", "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("approve: id required")
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	g, err := approve.Approve(cfg.Approvals, fs.Arg(0))
	if err != nil {
		return err
	}
	pub, priv, err := identity.LoadOrCreate(cfg.IdentityKey)
	if err != nil {
		return err
	}
	led, err := ledger.Open(cfg.AuditLog, cfg.ChainID, pub, priv)
	if err != nil {
		return err
	}
	rec, err := approve.AppendReceipt(led, cfg.AgentID, g)
	if err != nil {
		return err
	}
	fmt.Printf("approved %s for tool %s\n", g.ID, g.Tool)
	fmt.Printf("audit seq %d %s\n", rec.Seq, rec.ReceiptHash)
	fmt.Println("the next identical call is allowed once; a changed argument needs a new approval")
	return nil
}

func cmdDecide(args []string) error {
	fs := newFlag("decide")
	home := fs.String("home", "", "state directory")
	client := fs.String("client", "demo", "client name recorded on the receipt")
	tool := fs.String("tool", "Bash", "tool name")
	command := fs.String("command", "", "shell command")
	path := fs.String("path", "", "file path")
	cwd := fs.String("cwd", "", "workspace directory")
	session := fs.String("session", "demo", "session id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*cwd = wd
	}
	input := map[string]any{}
	if *command != "" {
		input["command"] = *command
	}
	if *path != "" {
		input["file_path"] = *path
	}
	cfg, err := loadConfig(*home)
	if err != nil {
		return err
	}
	resp, err := hooks.Exchange(cfg.Socket, hooks.Request{
		Schema: "reinsaarm.decide.v1", Client: *client, SessionID: *session,
		CWD: *cwd, Tool: *tool, Input: input,
	}, 8*time.Second)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

func cmdBench(args []string) error {
	fs := newFlag("bench")
	nflag := fs.Int("n", 20000, "iterations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := policy.Load(policy.DefaultYAML())
	if err != nil {
		return err
	}
	eng := policy.Compile(p, "/home/dev", policy.DefaultYAML())
	st := policy.Measure(eng, *nflag)
	fmt.Printf("fast-path n=%d p50=%s p99=%s max=%s\n", st.N, st.P50, st.P99, st.Max)
	if st.P99 > time.Millisecond {
		return fmt.Errorf("p99 %s exceeds 1ms", st.P99)
	}
	return nil
}

func loadConfig(flagHome string) (config.File, error) {
	dir, err := stateDir(flagHome)
	if err != nil {
		return config.File{}, err
	}
	return config.Load(config.Path(dir))
}
