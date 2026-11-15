package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/approve"
	"github.com/yardfribley-bit/reinsaarm/internal/config"
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
  reinsaarm install-hooks <client> [--scope project|user] [--dest DIR]
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
		return err
	}
	if *client == "" {
		return fmt.Errorf("hook: --client is required")
	}
	in, err := hooks.ReadStdin()
	if err != nil {
		out := hooks.FailClosed(*client, err.Error())
		os.Stderr.WriteString(out.Stderr)
		os.Stdout.Write(out.Stdout)
		os.Exit(out.ExitCode)
	}
	sock := *socket
	if sock == "" {
		cfg, err := loadConfig(*home)
		if err != nil {
			out := hooks.FailClosed(*client, err.Error())
			os.Stderr.WriteString(out.Stderr)
			os.Stdout.Write(out.Stdout)
			os.Exit(out.ExitCode)
		}
		sock = cfg.Socket
	}
	resp, err := hooks.Exchange(sock, hooks.ToRequest(*client, in), 8*time.Second)
	if err != nil {
		out := hooks.FailClosed(*client, err.Error())
		os.Stderr.WriteString(out.Stderr)
		os.Stdout.Write(out.Stdout)
		os.Exit(out.ExitCode)
	}
	out, err := hooks.Render(*client, in, resp)
	if err != nil {
		fail := hooks.FailClosed(*client, err.Error())
		os.Stderr.WriteString(fail.Stderr)
		os.Stdout.Write(fail.Stdout)
		os.Exit(fail.ExitCode)
	}
	os.Stdout.Write(out.Stdout)
	if resp.Enforced == string(decision.Deny) || resp.Enforced == string(decision.Defer) {
		fmt.Fprintln(os.Stderr, "reinsaarm:", resp.Reason)
	}
	return nil
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
	plans, err := install.Plans(client, *bin, *scope, project, devHome)
	if err != nil {
		return err
	}
	if err := install.Apply(plans); err != nil {
		return err
	}
	for _, p := range plans {
		fmt.Printf("wrote %s\n%s\n", p.Path, p.Note)
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
	if err := fs.Parse(args); err != nil {
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
	fmt.Printf("approved %s for tool %s\n", g.ID, g.Tool)
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
