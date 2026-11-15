# Activity monitoring (sessions)

ReinsAARM's pre-tool hook decides whether a tool call may run. The activity
events record what happened around those decisions, so you can see what a
Codex or WorkBuddy session actually did: what the user asked, which tools ran,
what each decision was, how each call ended, and when the agent stopped.

Activity events are **observation only**. Their hook always exits 0 with no
output (Gemini gets `{}`), even when the sidecar is down, and never changes a
tool call. Blocking still happens only in `PreToolUse` / `BeforeTool`.

## What is recorded

Every event becomes a receipt in the same signed hash chain as the decisions.
New receipt types (`event_type`):

| `event_type` | Hook events | Stored in `activity` |
|---|---|---|
| `session.start` | `SessionStart` | `source` (startup / resume / clear / compact), `model` |
| `prompt.submit` | `UserPromptSubmit`, Gemini `BeforeAgent` | prompt **summary**: secrets masked, whitespace collapsed, first 240 characters; `prompt_chars` |
| `tool.result` | `PostToolUse`, `PostToolUseFailure`, Gemini `AfterTool` | `success`, `exit_code`, `interrupted`, `duration_ms` + `duration_from`, `files`, `output` (≤400 chars) or `error` (≤300 chars), all masked |
| `agent.stop` | `Stop`, Gemini `AfterAgent` | last assistant message, masked, ≤300 chars |
| `session.end` | `SessionEnd` | `reason` |

Decision receipts (`action.decision`) now also carry `cwd`, `turn_id` (Codex)
and `tool_use_id`. A `tool.result` receipt points back at its decision with
`ref_seq`; the sidecar pairs them by `tool_use_id` (Codex, Claude Code,
WorkBuddy) or, when the agent sends none (Gemini), by the action digest. The
console also pairs by `tool_use_id`, so pairing survives a sidecar restart.

The new fields are omitted when empty: receipts written by older versions
still verify (`internal/ledger/testdata/pre-activity.jsonl` is checked in a
test), and new receipts chain onto old ones.

### Full prompts

Off by default. To store whole prompts (secrets still masked, capped at 8000
characters), add to `config.yaml` in the state directory and restart
`reinsaarm run`:

```yaml
record_full_prompts: true
```

### Masking

`internal/redact.Mask` replaces `KEY=value` secrets, private key blocks,
`sk-…`, `ghp_…` / `github_pat_…`, Slack `xox?-…`, AWS `AKIA…`, Google `AIza…`,
JWTs, `Bearer` / `Basic` credentials, URL user:password, secret query
parameters, and secret-named JSON / YAML fields. It is a pattern list, not a
guarantee: an unusual secret format can still reach a summary.

## What each agent sends

Checked on 2026-11-15.

| Agent | Events installed | Result details available | Source |
|---|---|---|---|
| Codex 0.151 | `PostToolUse`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `Stop` | Bash: output text only, **no exit code**, so `success` stays unknown. `apply_patch`: text starting `Exit code: N`, parsed. No duration: `duration_ms` is the time between the pre and post hooks (`duration_from: hooks`, shown as "约"). `tool_use_id` pairs pre and post. | `openai/codex` `rust-v0.151.0` `codex-rs/hooks/schema/generated/*.command.input.schema.json`, `core/src/tools/context.rs` (`post_tool_use_response`); live run below |
| WorkBuddy / WorkBuddy AI | the Codex set plus `PostToolUseFailure` | Bash `rawResponse`: `exitCode`, `interrupted`, `is_error`, `error` (stderr, first 500 chars), no stdout. Write: `filePath`, `success`. `tool_use_id` (= `call_id`). `SessionStart` has no `cwd`. | WorkBuddy AI 5.9.4 bundled CLI (`convertToSdkInput`, `executePostToolUseHooks`, Bash tool `rawResponse`, `SessionHookManager`) and bundled `docs/en/cli/hooks.md` |
| Claude Code | the WorkBuddy set | Structured `tool_response` (Bash `stdout` / `stderr`), `duration_ms`, failure `error` with `Exit code N` first line | code.claude.com/docs/en/hooks |
| Gemini CLI | `AfterTool`, `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent` | `tool_response.llmContent` / `returnDisplay` / `error`; no tool id | geminicli.com/docs/hooks/reference |
| CodeBuddy (IDE) | `PostToolUse`, `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `Stop` | as WorkBuddy | CodeBuddy Code hooks reference bundled with WorkBuddy; the IDE itself was not checked |

Codex notes: `UserPromptSubmit` and `Stop` take no matcher, so none is
written (it would not be part of the trust hash). `SessionEnd` is written with
`timeout: 3` because Codex clamps it to 3 s and hashes the clamped value. Each
event has its own trust key (`…/hooks.json:post_tool_use:0:0`, …);
`install-hooks codex --trust` writes all of them. An untrusted activity hook
does not weaken blocking; `doctor` reports it as a note, not a failure.

## Install and check

`install-hooks codex|workbuddy|claude-code|gemini|codebuddy` now writes the
activity events next to the pre-tool hook, with the same command. A rerun
updates the command in place and adds nothing; the file is backed up first
when it changes. Other hooks in the file are kept.

`doctor` (Codex and WorkBuddy) lists the activity events found and which are
missing. The console health page has a "Codex 活动事件" item, and the WorkBuddy
item shows `活动事件 n/6`.

## Console: 会话

The 会话 page lists sessions (agent, project = last part of `cwd`, start,
last activity, prompts, tool calls, denials, failures, state). Click one for
its timeline: session start → prompt → each tool call with its decision and
result → agent stop → session end. Denied calls show the rule ids and have no
result. The decision stream and audit pages are unchanged and do not show
activity receipts.

![Sessions list](img/activity-sessions-list.png)

![A live Codex 0.151 session](img/activity-codex-live.png)

## Live check (macOS, 2026-11-15)

Throwaway project and separate state directory (`~/rmon`), separate sidecar
and console; the user's real `~/.codex/config.toml` and WorkBuddy settings
were not changed.

- A real `codex exec` (Codex 0.151.0) in the throwaway repo, with hook and
  project trust passed as `-c hooks.state={…}` / `-c projects={…}` overrides
  instead of writing `config.toml`. Codex fired `SessionStart`,
  `UserPromptSubmit`, three `PreToolUse` / `PostToolUse` pairs (`ls`,
  `go build ./...`, `apply_patch`), `Stop`, and `SessionEnd`; every result was
  paired with its decision by `tool_use_id`, and the chain verified.
- WorkBuddy-shaped and Codex-shaped payloads (including denied calls) fed to
  the installed hook command: allow / deny output unchanged, activity
  receipts written, chain verified.
- A WorkBuddy desktop session driving the hooks was **not** run (its bundled
  CLI needs a separate `/login`).
