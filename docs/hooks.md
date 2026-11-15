# Hook contracts

Checked against public documentation on **2026-11-15**. None of these adapters
were executed against a live Codex, Claude Code, Gemini CLI, or WorkBuddy /
CodeBuddy binary. Field names that the docs already show moving between
versions are called out below. Treat them as verified against the cited pages,
not against a particular CLI build.

The hook process is `reinsaarm hook --client <name>`. It reads one JSON object
from stdin, asks the local sidecar, and writes one JSON object to stdout.
Diagnostics go to stderr. A normal decision exits 0. If the sidecar cannot be
reached, the process writes a deny document and exits **2**.

Exit 2 is the only non-zero status these CLIs treat as a block:

| CLI | Exit 0 + deny JSON | Exit 2 | Any other exit, timeout, or malformed JSON |
|---|---|---|---|
| Claude Code | Blocks when `permissionDecision` is `deny` | Blocks | Continues, unless the hook sets `onFailure: "block"` (Claude Code v2.1.295+) |
| Codex | Blocks when `permissionDecision` is `deny` | Blocks | The tool call can continue. `permissionDecision: "ask"` is in this bucket: Codex parses it, marks the hook failed, and continues |
| Gemini CLI | Blocks when `decision` is `deny` | Blocks (`stderr` is the reason) | Warning only; the tool call continues |
| CodeBuddy IDE | Blocks when `permissionDecision` is `deny` and the process exits 0 | Blocks, and the docs say stdout is ignored | Continues. The page describes exit 1 and "other" as non-blocking. What a timeout does, beyond "the hook stops", is not stated |
| WorkBuddy (bundled CLI) | Blocks when `hookSpecificOutput.permissionDecision` is `deny` | Blocks (`blockSource: "exit2"`, stderr is the message) | Allowed: `parseHookOutput` sets `allowed = true` for any other non-zero exit and only logs stderr |

`install-hooks` therefore sets Claude Code `onFailure` to `block`, keeps every
normal decision on exit 0, and uses exit 2 only when the sidecar is down.

## Claude Code

Docs: <https://code.claude.com/docs/en/hooks>

- Event: `PreToolUse`. Matcher `"*"` matches every tool.
- Input includes `session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`. A Bash call puts the shell line in `tool_input.command`.
- Deny / ask / allow: `hookSpecificOutput.permissionDecision` is `deny`, `ask`, or `allow`, with `permissionDecisionReason`.
- Modify: `updatedInput` **replaces** the tool input. The adapter copies every original field and replaces `command`.
- `defer` exists and ends the turn, and it requires non-interactive `-p`. This MVP maps DEFER to `deny` so an interactive session does not depend on that flag.
- Timeout unit in settings: seconds. The installed hook uses 15.
- Project file: `.claude/settings.json`. User file: `~/.claude/settings.json`. Enterprise example: `examples/enterprise/claude-managed-settings.json` (`allowManagedHooksOnly`).

## Codex CLI

Docs: <https://learn.chatgpt.com/docs/hooks> and the `PreToolUse` tests in `openai/codex` `codex-rs/hooks/src/events/pre_tool_use.rs` (read 2026-11-15).

- Event: `PreToolUse`. Matcher `"*"`, `""`, or omitting the matcher matches every occurrence. Shell tools are reported as `Bash`. `apply_patch` is also matched by `Edit` or `Write`, but the input still says `tool_name: "apply_patch"` and carries `tool_input.command`.
- Deny: `hookSpecificOutput.permissionDecision = "deny"`. An older `{"decision":"block","reason":"..."}` shape is also accepted. The adapter uses the current shape.
- Allow: Codex 0.151 rejects a bare `permissionDecision: "allow"` (`permission_decision_allow_without_updated_input_fails_open` in `codex-rs/hooks/src/events/pre_tool_use.rs`). The hook logs `PreToolUse Failed` and the tool call continues. ReinsAARM therefore prints **no stdout** and exits 0 on ALLOW, which leaves Codex's own permission check in place. It does not skip that prompt.
- Modify: `permissionDecision: "allow"` plus `updatedInput`. For Bash and `apply_patch`, `updatedInput.command` must be a string. Allow is only sent together with `updatedInput`.
- `ask` is not supported. Codex parses it, marks the hook failed, and continues the tool call. STEP_UP and DEFER are enforced as `deny`. The receipt keeps the policy decision (`STEP_UP`) in `decision` and records `enforced_decision: DENY`. The reason contains the approval id. `reinsaarm approve <id>` writes an `approval.granted` receipt and allows one later call with the same argument hash.
- Exit 2 blocks only when stderr is non-empty. Empty stderr on exit 2 fails open. Every ReinsAARM exit 2 path writes `reinsaarm: <reason>` to stderr, including malformed stdin and a dead sidecar.
- Timeout unit: seconds. Default in Codex is 600. The installed hook uses 15.
- Project file: `.codex/hooks.json`. The command bakes `--home` and `--socket`, because Codex does not inherit `REINSAARM_HOME` and an unset value falls back to `~/.reinsaarm`.
- Unmanaged hooks do not run until they are trusted. Codex stores `hooks.state."<abs path>/.codex/hooks.json:pre_tool_use:<group>:<handler>".trusted_hash = "sha256:..."`. `install-hooks codex` prints the key and hash. Trust it with Codex `/hooks`, or pass `--trust` to write the entry into `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`). `reinsaarm doctor` fails if the hash is missing or stale.
- Managed hooks from `requirements.toml` are trusted by policy and do not need `trusted_hash`. Example: `examples/enterprise/codex-requirements.toml`.

## Gemini CLI

Docs: <https://geminicli.com/docs/hooks/reference/> (page last-updated line: Apr 10, 2026) and the tool argument table in `google-gemini/gemini-cli` `docs/reference/tools.md`.

- Event: `BeforeTool`. Matcher `"*"` matches every tool. Timeout unit is **milliseconds** (default 60000). The installed hook uses 15000.
- Input: `session_id`, `cwd`, `hook_event_name`, `timestamp`, `tool_name`, `tool_input`. Shell is `run_shell_command` with `tool_input.command`. File tools in current source use `file_path`. Older file-system docs used `path`, `offset`, and `limit`. The extractor accepts `file_path`, `path`, `dir_path`, and `pattern`.
- `web_fetch` takes `prompt` (a prompt that contains URLs) or, in direct mode, `url`. Hosts are scraped from both.
- Deny: `{"decision":"deny","reason":"..."}` on exit 0. `decision: "block"` is a documented alias. Exit 2 also blocks.
- Modify: `hookSpecificOutput.tool_input` is documented as a **merge**. The adapter sends only `{"command": "..."}` so other fields stay. If a build treats it as a replacement, the command is still present and other fields would be dropped. That difference is unverified.
- There is no ask. STEP_UP is deny plus the approval id.
- Project file: `.gemini/settings.json`. A system-settings example is `examples/enterprise/gemini-system-settings.json`. Whether `/etc/gemini-cli/settings.json` is still the system path was not re-checked in a live install.

## CodeBuddy / WorkBuddy

See [workbuddy.md](workbuddy.md). Short version: the CodeBuddy IDE settings hook is real, looks like Claude Code, and documents `modifiedInput`. WorkBuddy has its own adapter (`--client workbuddy`): it embeds the CodeBuddy Code CLI, whose PreToolUse result reads `updatedInput` (the adapter sends both), treats `continue: false` as "end the whole turn" (the adapter never sends it), and wraps deferred and MCP tools in `DeferExecuteTool` (unwrapped before policy). Tencent docs say hooks are snapshotted at session start and that an external edit needs `/hooks` review; a live WorkBuddy AI 5.9.4 desktop session on 2026-11-15 re-read a user-level `settings.json` change within about four minutes, with no new task, no restart, and no review seen. A new task is still the reliable way to be sure hooks are loaded. `/hooks` review may still appear.

## Activity events

`PostToolUse`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `Stop` (and each CLI's equivalents) are recorded, never enforced. The hook dispatches on `hook_event_name`: `PreToolUse`, `BeforeTool`, or no event name take the decision path above; everything else is observed and exits 0. Field sources and per-agent details are in [activity.md](activity.md).

None of these hook payloads include the model's reasoning. When `transcript_path` points at a session file under the developer home, the sidecar copies plaintext thinking that file already contains (Codex reasoning summary or raw text; WorkBuddy / Claude Code / CodeBuddy `thinking` blocks). Encrypted or redacted reasoning is left unread. Gemini CLI does not expose thinking on these hooks. See [activity.md](activity.md).

## Normalized action model

The hook forwards `tool_name`, `tool_input`, and (Gemini only) `mcp_context`. The sidecar's `internal/normalize` maps them onto one action: a kind plus resources. Unknown tools become `other`; the hook's failure behaviour does not change.

| Kind | Tool names accepted | Resources read from |
|---|---|---|
| `shell` | `Bash` (Claude, Codex, CodeBuddy CLI), `run_shell_command` (Gemini), `execute_command` (CodeBuddy IDE), `exec_command`, `shell`, `powershell` | `command`: paths and hosts from tokens, git subcommands |
| `file_read` | `Read`, `Glob`, `Grep`, `LS`, `read_file`, `read_many_files`, `glob`, `grep_search`, `search_file_content`, `list_directory`, `list_dir`, `list_files`, `search_content`, `search_file`, `view_image` | `file_path`, `path`, `paths`, `dir_path`, `notebook_path`, `target_file`, `absolute_path`, `include`, `include_pattern`, `glob`; `pattern` only for glob tools (a `Grep` pattern is a regex, not a path) |
| `file_write` | `Write`, `write_file`, `write_to_file`, `create_file`, `delete_file` | same keys; file `content` is not scanned for hosts or paths |
| `file_edit` | `Edit`, `MultiEdit`, `NotebookEdit`, `replace`, `replace_in_file`, `apply_patch` | same keys; for `apply_patch` only the patch header lines (`*** Update File:`, `*** Add File:`, `*** Delete File:`, `*** Move to:`, `+++ b/`, `--- a/`) |
| `web_fetch` | `WebFetch`, `web_fetch`, `WebSearch`, `web_search`, `google_web_search` | hosts from `url`-like keys and Gemini's `prompt`; search queries have no target host |
| `mcp` | `mcp__<server>__<tool>` (Claude Code, Codex, CodeBuddy, WorkBuddy; WorkBuddy usually sends it inside `DeferExecuteTool{toolName, params}`), `mcp_<server>_<tool>` (Gemini), or any tool when Gemini sends `mcp_context` | server / tool from `mcp_context.server_name` / `tool_name` when present, else from the name; paths from `path`, `file_path`, `filename`, `file`, `dir`, `directory`, `source`, `destination`, …; hosts from `url`, `uri`, `endpoint`, `host`, `domain`, `*_url`; a `command` / `cmd` argument is analysed as shell |
| `other` | anything else (Claude `Task`, Codex `update_plan`, …) | the file and MCP path keys above, and URL-like keys |

Sources: Claude Code hooks reference; Codex hooks page (tool coverage: `Bash`, `apply_patch` with `tool_input.command`, MCP names like `mcp__fs__read`; hosted tools such as `WebSearch` do not reach the hook); Gemini CLI hooks reference (MCP naming `mcp_<server_name>_<tool_name>`, optional `mcp_context`) and `packages/core/src/tools/definitions/base-declarations.ts` / `hooks/types.ts` for parameter names; CodeBuddy IDE hooks page for the IDE / CLI name pairs. All read on 2026-11-15. Unit tests in `internal/normalize` and `internal/simulate` feed each CLI's documented payload shape; none of the non-shell paths were run inside a live CLI.

Receipts record `kind` and a `resources` object (`paths`, `hosts`, `git_ops`, `mcp_server`, `mcp_tool`). URLs are reduced to hosts so query-string tokens are not stored, and `KEY=value` secrets in paths are redacted. The field is omitted when empty, so receipts written before it existed still verify.

## What the sidecar re-derives

The hook forwards `tool_name` and `tool_input`. The sidecar, not the hook, classifies the kind and pulls commands, paths, and hosts out of the payload. A hook that omitted a host from a side channel would still be caught if the host is in the command string. A hook that never starts is not caught by this path; that is why the egress proxy and the `/proc` sensor exist.

## Codex: user-level install and Codex Desktop

`reinsaarm install-hooks codex --scope user --trust` merges the six ReinsAARM
handlers into `~/.codex/hooks.json`. Groups that other tools already put there
(for example an OpenTelemetry hook) stay first, so their `hooks.state` trust
keys (`…:session_start:0:0`) and hashes do not change; ReinsAARM's handlers
take the next index (`…:session_start:1:0`). User-level hooks load in every
folder, so the installer writes no project `trust_level`, and `doctor` only
asks for project trust when the project's own `.codex/hooks.json` has a
ReinsAARM hook. `config.toml` keeps its file mode (often 0600).

If a project also has a ReinsAARM `.codex/hooks.json`, Codex runs both and
every event is recorded twice. Remove the project copy after a user-level
install.

Codex Desktop starts its `codex app-server` once and reads hooks per session.
Restart the app after installing, then start a new thread.

Code mode (Codex Desktop, `features.code_mode_host`): the model sends one
`exec` cell of JavaScript that calls `tools.exec_command(...)` and other
tools. Codex runs PreToolUse/PostToolUse for each nested tool call, not for
the `exec` cell, and reports a nested shell call as `tool_name: "Bash"` with
the command line. So shell policy applies inside code mode without extra
normalization. Checked with Codex 0.163.0-alpha.10.2 on 2026-11-15.
