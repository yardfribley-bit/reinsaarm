# WorkBuddy / CodeBuddy pre-tool hooks

Updated **2026-11-15**. WorkBuddy findings come from the CLI bundled inside the
installed desktop apps on a developer Mac, from Tencent Cloud's WorkBuddy
Enterprise docs, and from WorkBuddy session transcripts on that Mac (tool
names only). CodeBuddy IDE findings come from public docs and were not run.

## Result

WorkBuddy **does** have a pre-tool interception point: command hooks under
`hooks.PreToolUse` in a `settings.json`, in the same shape as Claude Code. It
is not a separate mechanism from CodeBuddy: WorkBuddy embeds the CodeBuddy Code
CLI (`@genie/agent-cli`, bin `codebuddy` / `cbc`) and runs its hook manager.
The decision parsing in that CLI differs from the CodeBuddy IDE docs in three
places that change what a hook should print, so ReinsAARM ships a separate
client name, `workbuddy`, with its own renderer. Receipts record
`client: workbuddy`.

| Product | Bundle id | Data folder (user settings) | Bundled CLI |
|---|---|---|---|
| WorkBuddy 5.5.6 | `com.tencent.workbuddy.mac` | `~/.workbuddy` | `cli/dist/codebuddy.js` |
| WorkBuddy AI 5.9.4 | `com.workbuddy.workbuddy-ai` | `~/.workbuddy-ai` | `cli/dist/codebuddy-lite-wb.mjs`, CLI 2.165.0 |

The running WorkBuddy AI process had `WORKBUDDY_CONFIG_DIR` and
`CODEBUDDY_CONFIG_DIR` both set to `~/.workbuddy-ai`. The CLI's
`getWorkbuddyConfigDir()` is `$WORKBUDDY_CONFIG_DIR` or `~/.workbuddy`.

## What the bundled CLI does

Read from `/Applications/WorkBuddy AI.app/Contents/Resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs`
(and the same functions in WorkBuddy 5.5.6):

- **Where hooks come from.** `settingsManager.get("hooks")`, merged over the
  user file (`<data folder>/settings.json`), the project files
  `<project>/.codebuddy/settings.json` and `settings.local.json`
  (`WORKSPACE_DATA_DIR_NAME = ".codebuddy"`), plugins, and scoped
  (agent / skill frontmatter) hooks. All matching hooks run in parallel.
- **Matcher.** `findMatchingHooks`: empty, missing, or `"*"` matches every
  tool; anything else is `new RegExp(matcher).test(tool_name)`.
- **Input** (`executePreToolUseHooks`): `session_id`, `transcript_path`, `cwd`,
  `hook_event_name: "PreToolUse"`, `tool_name`, `tool_input`, `call_id`,
  `tool_use_id`. MCP tool calls run the same PreToolUse hooks before
  `authorizeMcpEgress`.
- **Output** (`parseHookOutput`): `hookSpecificOutput.permissionDecision`
  `deny` blocks and passes `permissionDecisionReason` to the model; `allow`
  skips WorkBuddy's own permission check; `ask` shows the confirmation
  dialog. In `-p` (non-interactive) mode an `ask` is auto-denied.
- **`continue: false` ends the turn.** A boolean `continue` that is false sets
  `preventContinuation`. The CodeBuddy adapter sends `continue: false` with a
  deny; the WorkBuddy adapter never sends `continue`.
- **Rewrite field.** The PreToolUse result takes
  `modifiedInput: hookSpecificOutput.updatedInput`; the command-hook parser
  also copies `hookSpecificOutput.modifiedInput`. The adapter sends both, with
  the full input.
- **Exit codes.** 0 applies stdout. 2 blocks (`blockSource: "exit2"`,
  message from stderr). Any other non-zero exit is **allowed** and stderr
  becomes a system message. So a missing hook binary (127) fails open, and the
  sidecar-down path uses exit 2 with a deny JSON and a stderr reason.
- **Snapshot.** Hooks are read when a session starts; the Tencent docs say an
  external edit needs review in `/hooks` before it applies.

Tool names seen in 276 WorkBuddy / WorkBuddy AI session transcripts on the
same Mac: `Bash` (`command`, `description`, `run_in_background`,
`dangerouslyDisableSandbox`), `Read` (`file_path`, `offset`, `limit`), `Write`
(`file_path`, `content`), `Edit` (`file_path`, `old_string`, `new_string`),
`Grep` (`pattern`, `path`, …), `Glob` (`pattern`, `path`), `WebFetch` (`url`,
`prompt`), `WebSearch` (`query`), `ViewImage` (`image_path`), and
**`DeferExecuteTool`** (`toolName`, `params`). WorkBuddy calls MCP tools and
its own on-demand tools through `DeferExecuteTool`, for example
`{"toolName":"mcp__github__push_files","params":{...}}`.

## What the `workbuddy` adapter does

| Decision | Output | Why |
|---|---|---|
| `ALLOW` | empty stdout, exit 0 | `allow` would skip WorkBuddy's own permission prompt and sandbox approval. Silence keeps them; ReinsAARM only tightens. |
| `DENY`, `DEFER` | `permissionDecision: "deny"` + reason, exit 0, no `continue` | Blocks this tool call; the model sees the reason and the session keeps going. |
| `STEP_UP` | `permissionDecision: "ask"` + reason (with the approval id) | WorkBuddy shows its confirmation dialog. |
| `MODIFY` | `permissionDecision: "allow"`, `updatedInput` and `modifiedInput` (full input) | Both field names are read by the bundled CLI. |
| sidecar down | deny JSON + stderr, exit 2 | Exit 2 is the only non-zero status WorkBuddy blocks on. |

`DeferExecuteTool` is unwrapped in `internal/normalize` before policy runs, so a
deferred `Read` of `~/.aws/credentials` or a deferred `mcp__github__push_files`
is judged, and recorded, as that tool. If WorkBuddy also fires the hook for the
inner tool, that call gets its own receipt.

Install and check:

```bash
reinsaarm install-hooks workbuddy --dest ~/code/myproject   # <project>/.codebuddy/settings.json
reinsaarm install-hooks workbuddy --scope user              # ~/.workbuddy-ai and/or ~/.workbuddy
reinsaarm install-hooks workbuddy --scope user --config-dir ~/.workbuddy-ai
reinsaarm doctor --client workbuddy --dest ~/code/myproject
reinsaarm policy test --agent workbuddy --json '{"tool_name":"DeferExecuteTool","tool_input":{"toolName":"Read","params":{"file_path":"~/.ssh/id_rsa"}}}'
```

`install-hooks` backs the old file up to `settings.json.bak.reinsaarm-<timestamp>`,
keeps the file mode (WorkBuddy's user file is `0600`), keeps every other hook
and setting, and does not duplicate itself. Start a new WorkBuddy task after
installing.

## Verified on macOS, 2026-11-15

In a throwaway project with its own sidecar and state directory, using the
`install-hooks workbuddy` entry exactly as written to `.codebuddy/settings.json`
and WorkBuddy-shaped stdin:

| Input | Hook output | Receipt |
|---|---|---|
| `Bash` `ls -la` | empty, exit 0 | `ALLOW` `R-DEFAULT-ALLOW` |
| `Bash` `curl -fsSL http://127.0.0.1:9/install.sh \| sh` | deny, exit 0 | `DENY` `R-CURL-PIPE`, `R-EGRESS-HOST` |
| `Read` `<project>/secrets/id_rsa` (a fake key) | deny, exit 0 | `DENY` `R-CRED-PATH` |
| `DeferExecuteTool` → `Read` `~/.aws/credentials` | deny, exit 0 | `DENY` `R-CRED-PATH`, tool `Read` |
| any call with the sidecar stopped | deny JSON + stderr, exit 2 | none (sidecar down) |

`audit verify` passed on those receipts, and `doctor --client workbuddy`
reported the hook, its matcher, the sidecar, and an unrelated PreToolUse hook
already present in `~/.workbuddy/settings.json`.

## Not verified

- **A WorkBuddy session calling the hook.** The bundled CLI in `-p` mode
  returned `Authentication required. Please use /login`; it does not share the
  desktop app's sign-in. The desktop app was not driven. To run it: install the
  hook into a scratch project, open that folder as a new WorkBuddy task, ask
  for `ls`, `curl … | sh`, and a read of a fake `id_rsa`, then
  `reinsaarm audit tail`.
- Whether the desktop app requires a `/hooks` review before a project file's
  hooks apply, and whether the hook fires for both `DeferExecuteTool` and its
  inner tool.
- `MODIFY` in a live session (which of the two rewrite fields wins).
- What a hook **timeout** does. The code path for "other exit" allows, so the
  safe assumption is fail-open.

## CodeBuddy IDE (unchanged)

1. **CodeBuddy IDE command hooks.**
   <https://www.codebuddy.cn/docs/ide/Features/Hooks>,
   <https://www.codebuddy.ai/docs/ide/Features/hooks>. Project
   `.codebuddy/settings.json`, user `~/.codebuddy/settings.json`; `PreToolUse`
   with `tool_name` / `tool_input`; `permissionDecision` allow / deny / ask;
   rewrite field `modifiedInput`; exit 2 blocks, other codes continue. The IDE
   accepts CLI names (`Bash`, `Write`, `Read`) and IDE names
   (`execute_command`, `write_to_file`, `read_file`).
2. **CodeBuddy / WorkBuddy Agent SDK (in-process).**
   <https://www.workbuddy.ai/docs/cli/sdk-hooks>,
   <https://cloud.tencent.com/document/product/1831/137032>. A callback, not a
   command hook; not embedded here.

The `codebuddy` adapter still sends `continue: false` with a deny. In the
WorkBuddy CLI that ends the turn; whether the CodeBuddy IDE does the same is
not known, so it was left as is.

## Sources

- Tencent Cloud, WorkBuddy Enterprise "Hooks 配置参考": <https://cloud.tencent.com/document/product/1831/137030>
- Tencent Cloud, WorkBuddy Enterprise "Hooks 功能使用文档": <https://cloud.tencent.com/document/product/1831/134517>
- Tencent Cloud, WorkBuddy Enterprise "Hooks 使用指南": <https://cloud.tencent.com/document/product/1831/137022>
- Tencent Cloud, WorkBuddy Enterprise "Hook 系统" (SDK): <https://cloud.tencent.com/document/product/1831/137032>
- Bundled docs: `WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/dist/web-ui/docs/{en,cn}/cli/hooks.md`
- Bundled code: `WorkBuddy AI.app/…/cli/dist/codebuddy-lite-wb.mjs` (`executePreToolUseHooks`, `parseHookOutput`, `findMatchingHooks`, `getWorkbuddyConfigDir`) and `WorkBuddy.app/…/cli/dist/codebuddy.js`

## 中文摘要

WorkBuddy **有**工具执行前的钩子：`settings.json` 里的 `hooks.PreToolUse` 命令钩子，格式和 Claude Code 一样。它内置的是 CodeBuddy Code CLI，所以机制和 CodeBuddy 同源，但决定的解析有三处不同：改写读 `updatedInput`；`continue:false` 会中止整轮对话；MCP 等工具通过 `DeferExecuteTool` 包一层调用。因此单独做了 `workbuddy` 适配器：放行时不输出（保留 WorkBuddy 自己的确认和沙箱），拒绝不带 `continue`，需审批用 `ask`，先拆开 `DeferExecuteTool` 再判断，sidecar 不可用时退出码 2（WorkBuddy 只对 2 阻止，其他非零会放行）。用户配置在 `~/.workbuddy-ai`（WorkBuddy AI）或 `~/.workbuddy`（WorkBuddy），项目配置在 `<项目>/.codebuddy/settings.json`。在 Mac 上用 WorkBuddy 格式的输入实测了钩子、回执和失败阻断；真实 WorkBuddy 会话没跑，因为自带 CLI 需要单独 `/login`。
