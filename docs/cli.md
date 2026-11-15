# Command reference

`reinsaarm` version 0.1.0. The usage text below is from `cmd/reinsaarm/main.go`.

```
reinsaarm 0.1.0 — runtime security for coding agents

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
```

`reinsaarm console` is also available as `reinsaarm ui`. `reinsaarm version` prints `reinsaarm 0.1.0`.

State lives in `$REINSAARM_HOME` or `~/.reinsaarm`. `init` creates that directory, writes the embedded developer remit if no profile is present, and creates `identity.key` with mode `0600`. The key is not part of the source tree.

## Notes that are easy to miss

- `install-hooks` bakes the path of the binary that ran the command (or `--bin`) plus `--home` and `--socket` into the hook command. Use the same binary you intend to leave installed.
- `--trust` is Codex-only. It writes `hooks.state` `trusted_hash` and `projects."<project>".trust_level = "trusted"` into `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`).
- `doctor` checks that Codex hook and project trust. It looks for `.codex/hooks.json` in `--dest` (default: the current directory) and in the Codex home.
- `console` listens on `127.0.0.1:8787` by default. It prints a URL with a random token and sets the same token as a cookie. `--dest` is the project used for the Codex trust pills.
- `run --web` is a separate loopback decision view on the sidecar, not the console UI. `run --egress` starts the optional egress proxy. `run --no-sensor` disables the Linux `/proc` credential-fd scan.
- `approve` accepts flags before or after the id. A grant allows the next identical call once. The command also appends an `approval.granted` receipt.
- `bench` measures the in-process rule path against the embedded remit and fails if p99 is not under 1ms.

Hook field notes are in [hooks.md](hooks.md). The Codex 0.151 live run is in [acceptance/2026-11-15-codex-0.151.md](acceptance/2026-11-15-codex-0.151.md).
