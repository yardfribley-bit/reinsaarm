# Command reference

`reinsaarm` version 0.1.0. The usage text below is from `cmd/reinsaarm/main.go`.

```
reinsaarm 0.1.0 — runtime security for coding agents

Usage:
  reinsaarm init [--home DIR]
  reinsaarm run [--home DIR] [--socket PATH] [--web ADDR] [--egress ADDR]
  reinsaarm hook --client claude-code|codex|gemini|codebuddy|workbuddy
  reinsaarm install-hooks <client> [--scope project|user] [--dest DIR] [--trust]
                        [--config-dir DIR]   (workbuddy --scope user)
  reinsaarm doctor [--client codex|workbuddy] [--dest DIR]
  reinsaarm console [--addr 127.0.0.1:8787] [--dest DIR]
  reinsaarm decide --tool NAME [--command CMD] [--path PATH] [--cwd DIR]
  reinsaarm policy test [--kind K] [--path P] [--url U] [--server S --tool T]
                        [--args JSON] [--agent A] [--json PAYLOAD|-] [command...]
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
- `install-hooks` copies any settings file it changes to `<file>.bak.reinsaarm-<timestamp>` first and keeps the file's mode. Other hooks and settings in the file are kept; a second run does not add a duplicate.
- `install-hooks <client>` also writes the activity events (`PostToolUse`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `Stop`, plus `PostToolUseFailure` for Claude Code and WorkBuddy; Gemini: `AfterTool`, `BeforeAgent`, `AfterAgent`, `SessionStart`, `SessionEnd`) with the same command. Their hook always exits 0. See [activity.md](activity.md).
- `config.yaml` key `record_full_prompts: true` stores whole prompts (masked, ≤8000 characters) instead of a 240-character summary.
- `install-hooks workbuddy` writes a `PreToolUse` entry with matcher `*` and a 15 s timeout. Project scope writes `<dest>/.codebuddy/settings.json` (WorkBuddy reads project hooks there). `--scope user` writes `<data folder>/settings.json` for `--config-dir`, else `$WORKBUDDY_CONFIG_DIR`, else every existing `~/.workbuddy-ai` (WorkBuddy AI) and `~/.workbuddy` (WorkBuddy). Start a new WorkBuddy task afterwards; hooks are read when a session starts.
- `doctor --client workbuddy [--dest DIR] [--config-dir DIR] [--home STATE]` reads the project and user WorkBuddy settings files and reports: whether the ReinsAARM hook is there, whether its matcher covers every tool, `disableAllHooks` / `allowManagedHooksOnly`, other `PreToolUse` hooks that also run, a missing hook binary (WorkBuddy would treat its exit 127 as allow), and whether the sidecar socket answers. It changes nothing.
- `console` listens on `127.0.0.1:8787` by default. It prints a URL with a random token and sets the same token as a cookie. `--dest` is the project used for the Codex trust pills.
- `run --web` is a separate loopback decision view on the sidecar, not the console UI. `run --egress` starts the optional egress proxy. `run --no-sensor` disables the Linux `/proc` credential-fd scan.
- `approve` accepts flags before or after the id. A grant allows the next identical call once. The command also appends an `approval.granted` receipt.
- `bench` measures the in-process rule path against the embedded remit and fails if p99 is not under 1ms.

## `policy test`

Evaluates one input against the current profile and prints the decision (`ALLOW`, `DENY`, `STEP_UP`, `MODIFY`, `DEFER`), the matched rule ids, the reason, any rewrite, and the normalized action. It does not run anything, does not contact the sidecar, writes no receipt, and does not create or consume approvals. Exit status is 0 whatever the decision; use `--output json` in scripts.

| Input | Flags |
|---|---|
| Shell command (default) | positional words, e.g. `reinsaarm policy test git push origin main` |
| File read / write / edit | `--kind file_read\|file_write\|file_edit --path P` (repeatable or comma-separated) |
| Web fetch | `--kind web_fetch --url URL` |
| MCP call | `--kind mcp --server S --tool T [--args '{"path":"..."}']` |
| Unknown tool | `--kind other --tool NAME [--args JSON] [--path P]` |
| Raw hook payload | `--json '{"tool_name":...,"tool_input":{...}}'`, `--json @file`, or `--json -` for stdin |

Other flags: `--agent codex|claude-code|gemini|codebuddy|workbuddy` also shows what that agent's hook enforces (Codex and Gemini turn `STEP_UP` into `DENY`; WorkBuddy keeps it as `ask`). With `--agent workbuddy --json`, a `DeferExecuteTool` payload is evaluated as the tool it wraps. `--cwd` sets the workspace (default: the current directory). `--profile FILE` tests a profile other than the one in the state directory; with no state directory the built-in profile is used. A gray-zone result never calls the judge; the output says so.

The console exposes the same evaluation as `POST /api/policy/test` (token required, `Content-Type: application/json`, same fields as JSON: `command`, `kind`, `paths`, `url`, `server`, `tool`, `args`, `agent`, `payload`, `cwd`), and the policy page has a test box.

Hook field notes are in [hooks.md](hooks.md). The Codex 0.151 live run is in [acceptance/2026-11-15-codex-0.151.md](acceptance/2026-11-15-codex-0.151.md).
