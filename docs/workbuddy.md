# WorkBuddy / CodeBuddy pre-tool hooks

Checked on **2026-11-15** against public docs. Not executed against a live
WorkBuddy or CodeBuddy build.

## Result

WorkBuddy / CodeBuddy **does** expose a pre-tool extension point. ReinsAARM
ships a command-hook adapter (`reinsaarm hook --client codebuddy` and
`reinsaarm install-hooks codebuddy`) and still treats the sidecar egress proxy
and the credential sensor as a second line, because a hook that fails to start
does not block the tool.

Tencent uses both product names for this coding agent. The pages below did not
describe a separate WorkBuddy binary with a different hook schema. This MVP
treats them as one family.

## What was found

1. **CodeBuddy IDE command hooks.**  
   Chinese: <https://www.codebuddy.cn/docs/ide/Features/Hooks>  
   English: <https://www.codebuddy.ai/docs/ide/Features/hooks>  
   - Config: project `.codebuddy/settings.json`, user `~/.codebuddy/settings.json`. The Chinese page says the project file overrides the user file.
   - Event: `PreToolUse`, before any tool runs. Matcher is `tool_name`, and `*` or an empty string matches all.
   - Input JSON uses `session_id`, `cwd`, `hook_event_name`, `tool_name`, `tool_input`. A shell example is `tool_name: "Bash"` and `tool_input.command`.
   - Output uses `hookSpecificOutput.permissionDecision` of `allow`, `deny`, or `ask`, plus `permissionDecisionReason`.
   - Rewrites use **`modifiedInput`**, not Claude Code's `updatedInput`. The published example sends the whole input object. The adapter does the same. Whether the IDE merges or replaces is not stated beyond that example, so the adapter sends a full copy.
   - Exit codes on the same page: 0 applies stdout; 1 and any other code are non-blocking and the tool continues; 2 blocks and the page says stdout is ignored, with stderr passed to the agent. A normal deny therefore stays on exit 0. Sidecar failure uses exit 2 and also writes the reason to stderr.
   - Timeout in the settings examples is documented as **seconds**.
   - The same page's tool table says the matcher accepts either CLI names (`Bash`, `Write`, `Read`) or IDE names (`execute_command`, `write_to_file`, `read_file`), but the `tool_name` inside the hook payload depends on the host: Craft Agent IDE names, CLI names. The extractor accepts both. The page footer in the fetched copy did not include a last-updated date.

2. **CodeBuddy Agent SDK (in-process).**  
   <https://www.workbuddy.cn/docs/cli/sdk-typescript>  
   <https://www.workbuddy.ai/docs/cli/sdk-hooks>  
   Tencent Cloud, "WorkBuddy Enterprise Hook 系统", updated 2026-08-26: <https://cloud.tencent.com/document/product/1831/137032>  
   - The SDK lists `PreToolUse` and takes a callback, not a command hook.
   - A callback returns `decision: "block"` to stop a tool. The docs also show `continue: true`.
   - This MVP does not embed that SDK. A host that only has the SDK would call the sidecar's unix socket itself; the wire format is the same JSON document `reinsaarm decide` sends (`reinsaarm.decide.v1`).

## What was not found

- A WorkBuddy-only hook schema that differs from CodeBuddy.
- A statement of what happens when a command hook **times out**. Exit 1 and "other" continue, so the safe assumption is fail-open, and it is marked unverified.
- A live IDE in this environment, so `modifiedInput`, the IDE/CLI tool-name switch, and the project-over-user precedence were not executed.

## 中文摘要

公开文档表明 WorkBuddy / CodeBuddy **有**工具执行前的扩展点，不是只能走旁路。IDE 使用 `.codebuddy/settings.json` 里的 `PreToolUse` 命令钩子，决定字段与 Claude Code 相近，但改写字段是 `modifiedInput`。进程内 SDK 另有 `PreToolUse` 回调，本 MVP 不嵌入 SDK。钩子在退出码不是 0 或 2 时会放行，因此 egress 代理和凭据文件传感器仍然是第二条防线。以上均核对自 2026-11-15 的公开页面，没有在真实 IDE 里跑过。
