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
- Modify: `permissionDecision: "allow"` plus `updatedInput`. For Bash and `apply_patch`, `updatedInput.command` must be a string.
- `ask` must not be emitted. Codex marks that hook run failed and continues the tool call, which is fail-open.
- STEP_UP and DEFER are therefore projected to `deny`. The reason contains the approval id. `reinsaarm approve <id>` allows one later call with the same argument hash.
- An explicit `allow` skips Codex's own permission prompt. That is what enforce mode means. Audit mode still returns allow to the CLI while the receipt records `shadow: true` and the policy decision.
- Timeout unit: seconds. Default in Codex is 600. The installed hook uses 15.
- Project file: `.codex/hooks.json`. A managed-hook example is `examples/enterprise/codex-requirements.toml`. Non-managed hooks need a user trust review; managed hooks from `requirements.toml` do not.

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

See [workbuddy.md](workbuddy.md). Short version: the IDE settings hook is real, it looks like Claude Code, and the rewrite field is `modifiedInput`, not `updatedInput`.

## What the sidecar re-derives

The hook forwards `tool_name` and `tool_input`. The sidecar, not the hook, classifies the kind and pulls commands, paths, and hosts out of the payload. A hook that omitted a host from a side channel would still be caught if the host is in the command string. A hook that never starts is not caught by this path; that is why the egress proxy and the `/proc` sensor exist.
