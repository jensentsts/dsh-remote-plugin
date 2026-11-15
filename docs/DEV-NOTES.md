# 开发信息

> 这份是给**以后回来改这个插件的人**（多半是未来的我）看的。
> 记的是「怎么想出来的」「API 长什么样」「踩过哪些坑」，不是使用说明。
> 使用说明见 [`GUIDE.md`](GUIDE.md)，协议与威胁模型见 [`SECURITY.md`](SECURITY.md)。

---

## 1. 为什么要做成"静态插件对"，而不是别的形态

| 形态 | 为什么不行 |
|---|---|
| 让远端跑一个独立进程（Python 代理） | 能跑，但**拿不到 DSH 的 agent 能力**——只能执行命令，没法以「用户」身份驱动一个会话 |
| 用创造模式的动态插件（`cordis_define`） | 官方文档明确：**Dynamic Plugins are temporary and process-local**。监听器要常驻、要跟 DSH 一起启动，动态插件做不到 |
| 只做一半（本地 MCP 工具 + 远端裸进程） | 远端那半还是拿不到 agent；而且 MCP 不是「成对插件」的形态 |
| **静态插件对（本方案）** | 两半都是真插件：server 端能注入 `agents`/`sessions`/`workspaceRegistry`，client 端能 `ctx.tools.register`。零外部依赖，一个 `file:///` patch 行就能装 |

**关键判据**：需要 `ctx.*` 服务的能力必须住在插件里；只需要文件/进程的能力才可以用裸进程。

---

## 2. DSH 插件 API 备忘

> 这一节是从**能跑通的实现**里总结的：同类 DSH 插件（消息收发、IM 桥接等）的源码，
> 以及 checkout 里的 `packages/webhook/`。
> 官方生成的 API 目录在 `docs/config-catalog.md` 与 `docs/subsystems/*.md`。

### 插件骨架

```ts
export const name = 'my-plugin'
export const inject = ['agents', 'sessions']        // 硬依赖，缺失则等待
export interface Config { /* … */ }
export const Config: z<Config> = z.object({          // @deepseek-ai/schemastery
  secret: z.string().role('secret').default(''),     // 不回显到设置传输层
  port: z.number().default(11325),
})
export function apply(ctx: Context, config: Config = {}): void { /* … */ }
```

装载（profile 的 `cordis.patch.yml`），TS 源码直接加载，无需构建：

```yaml
- insert:
    - id: my-plugin
      name: 'file:///C:/path/to/src/index.ts'
      config: { port: 11325 }
```

### 设置区（GUI 可改，`settings.yaml` 落盘）

```ts
ctx.inject(['settings'], (settingsCtx) => {
  settingsCtx.settings.installSection(ctx, NAMESPACE, Config, config, {
    // 存**取值函数**而不是值：之后设置一改，read() 立刻看到新值
    setSource: (current) => { source = current },
    onChange: () => { /* 需要重建的东西（监听器、连接）在这里重启 */ },
    validate: (value) => { /* 提交时的跨字段校验 */ },
  })
})
const read = () => source()
```

**要点**：`setSource` 拿到的是**活取值函数**。存下来、每次用的时候调 `read()`，
设置改动就热生效——不需要重载模块。这是本插件让 `workspace` 可远程改的原理。

### 驱动一个 agent 会话（本插件的核心）

```ts
const handle = await agents.resume({ resumeSessionId: SessionId(id), setup })
// 或者对不存在的会话：
const handle = await agents.create({
  sessionId: SessionId(id),
  meta: { cwd, agentPreset: presetId },
  setup: async (agentCtx) => {
    installModelSelection(agentCtx, { current: defaults, assembled: undefined })  // ← 必须
    await ctx.agentPresets.mount(agentCtx, presetId)
  },
})

const agent = handle.agent
await agent.whenIdle()
const firstSeq = agent.session.seq
agent.followup(createUserMessage({
  content: [{ type: 'text', text }],
  source: { kind: 'user' },
}))
await agent.whenIdle()
await ctx.sessions.flush(agent.session)
const outcome = summarize(agent.session.snapshotEvents(), firstSeq)
```

- `agent.session.snapshotEvents()` 给完整事件流；`{seq, type, data}`。
- `turn/end` 的 `data.reason` 形如 `{ kind: 'completed' | 'error', error?: { code, message } }`。
- **注意**：`reason.kind === 'error'` 时 `reply` 可能是空的，必须把 `reason.error` 也带出来，
  否则排查时只看到一句 `reason: error`。

### 注册模型可见的工具

```ts
import { defineTool } from '@deepseek-ai/dsh-tools'

ctx.inject(['tools'], (toolsCtx) => {
  toolsCtx.tools.register(defineTool({
    name: 'my_tool',
    description: '…',
    parameters: { x: { type: 'string', required: true, description: '…' } },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => [{ type: 'text', text: String(value) }],
    },
    async execute(args) { return { /* JsonValue */ } as unknown as JsonValue },
  }))
})
```

`ctx.inject(['tools'])` 是**惰性等待**：composition 里没有 tools 注册表时插件仍能加载。

### 会话要在 GUI 里可见，必须登记工作区属主

```ts
const workspace = await ctx.workspaceRegistry.create(path)   // create-or-get，返回规范路径
const handle = await ctx.agents.create({ sessionId, meta: { cwd: workspace.path, … }, setup })
await workspace.attachSession(sessionId)                     // ← 漏了就"磁盘上有、界面上没有"
ctx.get('sessionTitle')?.rename(handle.agent.session, 'remote: …')   // 可选，便于识别
```

`packages/webhook/webhook/src/session.ts` 是「从 Web 之外创建会话」的权威范例，
本插件的 server 端就是照它写的。

### 服务清单（这个部署里可用的）

| 服务 | 用途 |
|---|---|
| `agents` | `resume` / `create` → `AgentHandle` |
| `sessions` | `flush(session)` 落盘 |
| `agentPresets` | `list` / `resolve(id)` / `mount(agentCtx, id)` / `defaultId` |
| `agentDefaultModel` | `currentSelection()` —— 新会话的模型路由来源 |
| `workspaceRegistry` | `create(path)` / `list()` → `Workspace.attachSession` |
| `sessionTitle` | `rename(session, title)` |
| `permissionPresets` | `resolve` / `set(session, preset)` |
| `settings` | `installSection` |
| `tools` | `register(tool)` |
| `loader` | `await()` —— 等整个应用装配完再动 agent |

### 内置 preset（本部署实测）

`standard`（默认）/ `ptc` / `minimal` / **`cordis`（创造模式）**
（各个部署还可能加上自己的 preset；**实际有哪些用 `remote_preset_list` 问对端**）

创造模式 = 标准模式的全部能力 + `cordis_*` 工具族（运行时读接口、定义/运行/停止动态插件）
+ 两个 skill（`cordis-plugin-development`、`editing-cordis-compositions`）。
定义在 `packages/preset/agent-presets/presets/cordis/`。

---

## 3. 踩过的坑

> 全部是实测撞出来的，不是推测。按"症状 → 根因 → 处理"记。

### 3.1 新会话第一轮瞬间 `reason: error`

- **症状**：`remote_agent_prompt` 建会话成功，但 130 ms 就结束、`reply` 空。
- **根因**：新会话没有**模型路由**。`agents.create` 不会自动继承部署默认模型。
- **处理**：`setup` 里必须 `installModelSelection(agentCtx, {current: ctx.get('agentDefaultModel')?.currentSelection(), assembled: undefined})`。
- **教训**：同类插件（IM 桥接那类）里都有这一行，一开始没意识到它是必需的，只当是"切换模型"用的。

### 3.2 会话在磁盘上有，GUI 里看不见

- **症状**：`example-session.json` 确实躺在 `storages/session_projcache/sessions/`，
  但侧边栏没有。
- **根因**：`agents.create` 建的会话**无工作区属主**。GUI 渲染的是
  「工作区 + 它的 `sessionIds`」，而这张表只由 Web 自己的建会话路径维护。
- **处理**：`workspaceRegistry.create` + `agents.create({meta:{cwd: workspace.path}})` + `workspace.attachSession(sessionId)`。
- **教训**：「落盘」和「可见」是两件事。

### 3.3 改了 `src/*.ts` 行为不变

- **根因**：DSH **不会重新 import 已加载的模块**。
- **处理**：① 重启 `dsh web`（最干净）；② 给 patch 行的 `file:///` URL 加 `?v=N`——
  ESM 把带不同查询串的 URL 视为不同模块，于是真的会重新加载。
- **配套**：`server.ts` 里加了 `BUILD` 常量并放进 `sysinfo`，
  这样「加载的是哪一版」变成一次 `remote_ping` 就能确认的事实。
  **没有这个标记时，我在这件事上浪费了好几轮。**

### 3.4 热重载之后 `sysinfo` 正常、所有 agent op 报错

- **症状**：`cannot create effect on inactive context`。
- **根因**：loader 在热重载时**把旧 context 置为失活**，但旧模块的监听 socket 还活着并继续服务。
  于是不需要 `ctx` 的 op（`sysinfo`）正常，需要 `ctx` 的 op（`agents.create` / `presets.mount`
  都要在 context 上建 effect）全挂。
- **处理**：
  - 短期：换一个新端口 + 新 URL，让新模块在**全新 context** 上绑一个新 socket（绕过僵死的那个）。
  - 长期：**重启 `dsh web`**。
  - 代码侧：把 `ctx.effect(...)` 包进 try/catch——它在失活 context 上会抛，
    而抛在 `apply` 里会让整个插件注册不上。
- **教训**：`ctx.effect()` 不是"注册个清理函数"那么无害，它是个可能失败的操作。

### 3.5 两端发送密钥用了同一把

- **症状**：握手看起来成功，第一帧解密就 `InvalidTag`，服务端静默关连接
  （客户端只看到"agent closed the connection"，非常误导）。
- **根因**：`Session` 构造里两端都从**同一个** `" send"` 标签派生发送密钥，
  但两端是往**相反方向**发的。
- **处理**：改成方向密钥 `kC2S` / `kS2C`，再按角色选：
  发起方 send 用 `kC2S`，响应方 send 用 `kS2C`。
- **教训**：先写 `test/protocol.test.ts` 的本地回环自测就对了——
  这个 bug 在隧道上排查会痛苦十倍。

### 3.6 `?v=3`/`?v=4` 重载把运行实例弄成半死状态

- 见 3.4。追加一条操作经验：**一旦发现 context 失活，别再连续试重载**，
  直接换端口（或重启）。连续重载会叠加僵死 socket，把排查彻底搅浑。

### 3.7 指纹算法两端不一致

- **症状**：Python 密钥生成器算 `server = aa11:bb22:cc33:dd44`，
  插件报 `server = 1f3c:9d80:5ba7:0e12`。两者都**稳定但互不相同**，
  于是「两端指纹对不上」的排查步骤永远失败。
- **根因**：Python 用 `sha256(pub)`，TS 用了 `HMAC-SHA256(空密钥, pub)`。
- **处理**：TS 改成 `createHash('sha256')`（r7）。
- **教训**：跨语言实现一个"校验和"式的小函数，也要**先对齐定义**再各写各的。

### 3.8 patch 行的 `config` 改了但没生效

- **根因**：改 `config` 不会让已加载模块重新 `apply`，闭包里捕获的还是旧 config 对象。
- **处理**：
  - 真正的热路径是**设置层**（`settings.yaml` / GUI）——`setSource` 会推新的取值函数。
  - 所以把「每次调用会变的东西」（workspace）做成**调用参数**，
    把「部署级不变的东西」（端口、密钥）留在 `config`。
- **教训**：分清楚哪些配置是"装配期"的、哪些是"运行期"的。

### 3.9 环境侧的两个大坑（不在插件里，但会伪装成插件故障）

| 坑 | 症状 | 真相 |
|---|---|---|
| **frp 隧道归属冲突** | 隧道"通"，但连到的是**本机**自己的服务 | 隧道 ID 是**独占槽位**，两台机器配置同源就变成"谁先连上谁占用" |
| **DNS 污染** | `frpc 登录节点失败 … EOF`，而 TCP 连通性测试却正常 | 远端把**隧道节点的域名**解析成了 `.com` 顶级域根服务器地址。用 hosts 锁死真实 IP 解决 |

### 3.10 命令输出被按错误编码解码（中文变 U+FFFD）

- **症状**：`remote_exec` 跑 `whoami` / `ipconfig`，中文全变成 `����`；
  但 `remote_ping` 返回的 `hostname`（读的是 `$env:COMPUTERNAME`）却是好的。
- **根因**：Windows 上**两种编码混在同一个管道里**——PowerShell 自己的 cmdlet 输出是 .NET 字符串
  （按控制台编码写出），而 `whoami.exe` / `ipconfig.exe` 这类**原生程序**按 ANSI/OEM 代码页
  直接写字节。原实现把子进程输出**无条件按 UTF-8 解码**，原生那一半就烂了。
  另一种"想当然的修法"（在 PowerShell 里强制 `[Console]::OutputEncoding=UTF8`）**更糟**：
  它让 PowerShell 把原生程序的 GBK 字节当 UTF-8 解，信息在插件看到之前就已经丢了。
- **处理**：用 `encoding: 'buffer'` 收**原始字节**，然后
  **utf-8 严格 → gbk → big5 → shift_jis → windows-1252 → 有损回退** 依次尝试。
  cmdlet 输出是合法 UTF-8，命中第一档；原生输出命中 GBK 档。
- **教训**：`hostname.exe` 是**另一个**坑——它是 ANSI 程序，系统非 Unicode 代码页表示不出中文机名，
  所以远端 `hostname` 永远输出垃圾，换个算法也救不回来。**要机名就读 `$env:COMPUTERNAME`**。
- **验证**：远端 `remote_exec` 一次跑 cmdlet 中文 / `whoami` / `ipconfig` / `cmd` 四路中文，
  全部正确（远端 `build: r8`）。

### 3.11 不传 `session_id` 时，每次调用都在对端新开一个会话

- **症状**：`remote_ping` 返回的对端 `sessions` 列表越用越长：
  `remote-muomaz7k`、`remote-muombvrm`、`remote-muomc2ov`… 每次调用加一个；
  对端侧边栏堆满一次性会话，而且**上下文不连续**——上一轮说的东西这一轮就没了。
- **根因**：`remote_agent_prompt` 在没有 `session_id` 时生成
  `` `${prefix}-${Date.now().toString(36)}` ``：一个**每次都不一样**的 id。
  对端 `ensureAgent` 的 `agents.resume` 因此永远命中不了已存在的会话，
  只能走 `agents.create`——于是"新开一个"是必然结果，不是偶然。
- **关键事实**（实测，对着 r10 对端）：
  - 同一个 `session_id` 连调两次：第一次 `created`，第二次没有 `created`，
    并且**上一轮让它记住的数字能答出来**——`agents.resume` 确实恢复了上下文；
  - 所以"复用"**不需要**对端改代码，只要 client 别再每次造新 id。
- **处理**（`src/reuse.ts` + client 侧，策略抽成纯函数以便自测）：
  1. **记忆**：每个作用域（`prefix` + 本机会话 + `workspace` + `preset`）上一次用的会话记在
     `${DSH_HOME}/dsh-remote/client-sessions.json`，重启后继续用；文件损坏/删掉只当没有记忆；
  2. **对端发现**：没有记忆时问对端要一份已有会话（新 op `agent.sessions`，按最近优先；
     老对端只会给 `sysinfo.sessions` 的活跃 id，那就反转当"最新在后"用）；
  3. **确定性锚点**：都没有才用**不带时间戳**的 id——下次调用自然接到同一个会话。
- **几个刻意的取舍**：
  - 作用域里带**本机会话 id**：本机两段对话不该共用同一个对端会话——不只是上下文会串，
    client 侧的中继提问表 `inFlight` 就是按 session id 路由的，两个活着的调用者共用一个 id 会串线；
  - 复用会跳过"已经有调用在飞"的会话，并跳过**别的作用域已认领**的会话；
  - 对端发现失败、记忆写不进去，**一律退回锚点 id**——复用的每一步都只是优化，
    绝不能让一次 prompt 因为记账失败而失败。
- **验证**：
  - `test/session-reuse.test.ts`（纯逻辑，45 项全过）；
  - `test/live-reuse.ts --host … --port …`（真对端只读检查）：r10 对端没有 `ops` 字段，
    走 `sysinfo.sessions` 回退，正确跳过 `ieee-probe-001` / `reuse-probe-…`，
    选中 `remote-mur42c5x`；加 `--prompt` 实打一轮，对端回 `created=false`——**确实续上了**。
- **教训**：把"复用"做成**默认**、把"新开"做成需要显式的选择（`new_session=true`），
  否则模型/人都会不自觉地每次都新开；而"上一次用的那个"这种记忆必须**落盘**，
  否则重启就等于失忆，等于又回到每次新开。

### 3.12 一个 chat 会在对端攒出好几段对话；打断只有半条通路

- **症状**（上一条修完还剩下的）：
  - 同一个本机 chat，只要 `workspace`/`preset` 变过一次，对端就多一段会话——
    "复用"复用的不是**这个 chat 的**；
  - 本机用户按停：本机这轮停了，**对端那一轮还在跑**；
  - 对端用户按停：controller 完全不知道，本地 agent 还在等一个永远不会来的回复。
- **根因**：
  1. 复用键里带了 `workspace`/`preset`，身份不是"chat"，是"chat + 参数"；
  2. client 侧没有观察 `exec.signal`，本地中断只是本地中止；
  3. server 侧只读了 `turn/end` 的 `reason.kind`（`'aborted'`），丢掉了下一层
     `reason.reason.kind`，也没把"对端用户按停/插话"推给 controller。
- **处理**：
  1. **身份 = 纯函数(本机 chat id)**：`anchorSessionId(prefix, localSession)` →
     `remote-<sha256(chatId)[0:12]>`。同一个 chat 永远是同一个 id、不同 chat 必然不同，
     跨进程重启、跨记忆文件丢失都成立；落盘记忆只用来记"用户显式选的那个"
     （显式 `session_id` / `new_session`）。对端 `agents.resume` 命中即续接——
     **复用不再依赖任何记账**。
     > 实测：本机 chat 第一次 `created=true`，同 id 第二次 `created=false`，就是这一点。
  2. **两侧提示**（`systemPrompt.section`；作用域由"用哪个 ctx 注册"决定）：
     - 本地（plugin ctx → 全局）：把远端对话当 subagent/task、**本机优先**、
       非必要不开新对话、打断优先、本 chat 的远端会话 id 是多少；
     - 远端（在 `setup(agentCtx)` 里注册到**该 agent 的 ctx** → 只影响这个会话）：
       你正被远端当 task 驱动、交付要自成一体、本机可能有真人插话/按停、
       需要拍板用 `ask_user_question`。
  3. **本地中断 → 远端中断**：`remote_agent_prompt` 观察 `exec.signal`，中止时
     **先 `inFlight.delete`**（否则对端回显的自中断会被误读成"对端用户按停"），
     再 `link.request('agent.interrupt')`（不 await，10s 上限），最后抛 `AbortError`。
  4. **远端中断 → 本地**：server 用 `ctx.on('session/event', …, {global:true})` 盯自己那几个会话：
     `turn/end` 且 `reason.kind === 'aborted'` → 推 `{kind:'interrupt', origin:'remote-user'}`；
     真人消息 → 推 `{kind:'note'}`；同时 reply 里带 `interrupted` + `interruptCause`（拉取路径）。
     controller 侧把停着的调用立刻结算成"被远端打断了，停下等用户指示"；
     没有停着的调用就记成 pending，下一次调用先告诉模型。
- **只有读源码才知道的几条**（都在这条上踩过）：
  - 取消原因在**下一层**：`reason = {kind:'aborted', reason:{kind:'user'|'parent'|'hook'|'disposed'|'legacy'}}`；
  - **controller 的 `agent.interrupt` 与本机真人按停产生完全相同的 reason**，
    所以 server 必须自己记 `selfInterrupted`，否则会告诉 controller"你打断了自己"；
  - 区分"我们注入的消息"和"界面真人发的"：**`source.rpcId` 是 Web GUI 的请求 id**
    （我们注入的永远没有）；更保险的是记住自己注入的 `MessageId`；
  - `await agent.whenIdle()` 是**整个 agent 静默**：真人中途插话会把它延长，
    `summarize()` 可能把真人的 `turn/end` 当成"你的回复"——严格起来要按 turn 记（本版先记进 note）。
- **实测：`agent.cancel` 什么时候真的能停住**（真对端 r10，同一会话三次实验）：
  | 场景 | 结果 |
  |---|---|
  | 打断一个**卡在工具里**的轮次（`Start-Sleep 15`，2s 时打断） | +2.1s 就结算，`reason=aborted`、回复为空 ✅ |
  | 打断一个**跑得很快的模型轮次**（1.2s 时打断） | 仍然 `reason=completed`，整段答案照出 |
  | 打断一个**还没真正开始**的轮次（`Start-Sleep 60`，6s 时打断） | 整条命令跑完，`reason=completed` ❌ |
  - 机制原因：`cancel()` 只 `abort()` 当前 phase 的 signal，循环在**步边界**检查；
    而且 **idle 阶段的 `cancel()` 是文档里明说的 no-op**。于是"停在模型推理中途"和
    "停在还没开始的轮次"都可能白停——这不是本插件的 bug，是平台语义。
  - 因此 server 端加了**停止闩存**：`agent.interrupt` 除了 `cancel` 还记一个 30s 的 latch，
    `prompt()` 在 `whenIdle()` 之后、注入之前消费它——被停的那一轮**干脆不开始**；
    已跑起来的轮次由 `turn/end(aborted)` 消费掉闩存，避免误伤下一次 prompt。
  - 教训：**"打断"要按"可能还没开始"来设计**，而不是假设目标一定在跑。
- **顺手查到的部署/前端事实**（为"设置面板"铺路，别再踩）：
  - `plugins.row.config` 的 key 是 `<bundle 包名>#<bundle patch 声明的 row id>`，
    且**要求该 row id 由 bundle patch 声明**；浏览器半只对"精确包名行 / 包内 file:// 行"附着——
    `name: 'dsh-remote/server'` 这种**子路径行没有浏览器半**，被控机因此看不到配置页；
  - 同一个包里"精确包名行 + file:// 行"同时活跃 = **两个来源解析到同一个包名**，
    是启动期硬错误（bundle 图会炸），不要这么装；
  - `form` 按 **row id** 查，所以 row id 必须等于 settings namespace（本插件一直如此）；
  - 本版本的 `ConfigFormSnapshot` **没有 `secrets` 字段**，
    于是 `client.js` 里的 `form.state.secrets` 永远 `undefined`：
    "已设置/未设置/清除"实际不工作，要显示得自己去读 `ctx.configForms.describe()`；
  - 面板想显示**实时链路状态**，静态 bundle 拿不到 `host.call`，需要一条
    typert/`@Remote` 贡献（或把插件做成动态 cordis 包）。
- **验证**：
  - `test/session-reuse.test.ts`：身份是 chat 的纯函数、跨调用稳定、不同 chat 不同；
  - `test/live-reuse.ts --session <本机 chat id> --prompt`：第一次 `created=true`，
    同 chat 第二次 `created=false`（真对端 r10 实测）；
  - 对端重启后 `sysinfo.sessions` 为空，锚点方案照样命中——这正是它比"从活跃列表里挑"强的地方。

### 3.13 让远端对话在本地"像个 subagent"：能做什么、代价是什么

- **背景**：用户要求"远端对话在本地被视为 subagent/task"。查了 DSH 的 subagent seam，
  结论很明确：**可以，但只能是 one-shot 委派**。
- **能做的（R1，已实现成 provider，默认关）**：
  - `SubagentProvider.start()` 允许 `localAgent: undefined`——"子会话不在本进程"是
    seam 明说的形态，codex / claude-code / acp / dsh-sdk 四个内置 provider 都这么干；
  - 于是 `createRemoteProvider()`（`src/remote-provider.ts`）把一次委派实现成
    "在本机 chat 对应的对端会话上跑一轮"，工具结果用 `subprocessRunHandle` +
    `settleRunResult` 走官方收尾（**结果发布后绝不 reject**）；
  - 好处：本地聊天把 `subagent_remote` 调用**按 subagent 分组**、后台跑变成
    `subagent-N` 任务、本地 Stop 经 `dispose() → teardown()` 转发 `agent.interrupt`。
- **做不到的（别指望，也别硬做）**：
  - 没有本地子会话 ⇒ **不出现在 `list_agents`/subagent 目录里、不可打开**；
  - `send_message` / 续接（`startContinuable`）是 continuation manager 的，
    它会**建一个真正的本地 agent**——给远端 provider 声明 `prepareContinuable`
    等于凭空造一个不是对端的本地子 agent，属于错误用法；
  - 工具卡片只有 Generic/Terminal/Diff 三种，**没有 subagent 卡片**可画。
- **因此的接线方式**（**c5 起已改为默认开、无需 composition**，见 3.13b；
  下面是当初的形态，保留以便理解为什么这么设计）：
  开启需要三件事：① 把它打开；② composition 里加一行 `tool-subagent`
  （`provider: remote`, `toolName: subagent_remote`, `backgroundMode: one-shot`,
  `maxDepth: provider-managed`——没有 `depthLimit` 能力时**必须** `provider-managed`，
  否则那一行直接拒绝挂载）；③ 本插件的 `node_modules` 里要有
  `@deepseek-ai/dsh-subagent` 的 junction（profile-linked 插件不解析 harness peer）。
  provider 的 kit 用**动态 import** 拿：静态 import 会让没链接该包的机器**整个插件加载失败**，
  这类"可选能力"的依赖必须懒加载 + try/catch 降级。
- **一个只有测试才抓得到的 bug**：seam 的 `dispose()` 顺序是
  `requestCancel()` → `teardown()`，所以"普通收尾 dispose"和"用户取消"看起来一模一样。
  第一版因此在**正常跑完之后也去 interrupt 对端**（会把用户接下来的活掐掉）。
  修法：加 `settled` 标志——只有"attempt 还没结束就 dispose"才算取消；
  再按终态决定 `stopNeeded`（completed/对端已打断 → 不停；transport error → 停）。
  `test/remote-provider.test.ts` 用**官方 kit**跑，就是为了守住这条。
- **教训**：接别人的 seam，先读它的**调用顺序**和"哪些字段是契约、哪些是描述"，
  再写自己的状态机；用官方实现做单测，比手写 stub 值钱得多。

### 3.13b 别把"能用"的门槛留给运维：工具自己注册

- 第一版把"远端当 subagent"做成"provider + 你再去 composition 加一行 `tool-subagent`"。
  功能是对的，但**门槛错位**：一个开关能解决的事，被拆成了"改 profile + 重启"。
- 现在插件在注册 provider 的同一个分支里**自己注册 `subagent_remote` 工具**
  （`src/subagent-tool.ts`），于是：开关 = 功能。名字仍然是 `subagent_remote`——
  聊天靠 `subagent_*` 前缀把这次调用归为 subagent 委派，换个名字就丢掉分组。
- 官方那一行仍然有用，但变成**可选的替代**而不是前置条件：它额外给后台运行
  （`subagent-N` 任务行）。两者冲突（同名工具），文档里写明了二选一。
- 顺带把开关做成**热生效**：注册/撤销走一对 `ensureSubagent()` / `dropSubagentIfDisabled()`，
  由 `loader/volatile-update` 驱动。否则面板里能点、点了没反应，等于又一个假开关。
  注册是异步的（懒 import），所以加了 `subagentPending` 防重入，并在关掉时把
  provider 与工具一起撤销（`registerProvider` / `tools.register` 都返回 disposer）。
- **教训**：判断一个功能"做完了没有"，标准是**用户要按几下**，不是"代码能不能跑"。
- 最后把它**默认打开**：目标里"远端对话在本地被视为 subagent/task"是**默认行为**，
  不是"找到开关才有"。敢默认开的根据是：kit 懒加载 + 注册失败只 warn，
  所以默认开**不可能**让插件加载失败；不想要的人在面板里关一下（热生效）。

### 3.13c 部署前先把"兼容"变成事实：拿对端自己的文件跑 tsc

- 被控机那台机器的 `protocol.ts` / `link.ts` 比本仓库**多带修正**（stripfix 那批），
  所以同步时**不能**整目录覆盖，只能拷 `server.ts` + `reuse.ts` + `exec-registry.ts`。
  但"只拷这三个到底行不行"以前只是推理。
- 做法：一次性脚本用插件自己的链路（`fs.read`）把那台机器的
  `protocol.ts` / `link.ts` / `keys.ts` / `peers.ts` 拉回本地，和要拷的三个文件放进同一目录，
  用同一套 tsconfig（paths 指向 harness）跑 `tsc --noEmit`。
- 结果：**整套通过**（程序 342 个文件，含镜像里那 7 个），说明两边接口没有漂移。
  并且用 `--listFilesOnly` 确认镜像文件真的进了编译单元——否则"空程序也能过"就等于没验证。
- **教训**：跨机器部署的"应该没问题"要落成一次可复现的检查；能拿对方的真实文件来验，
  就别拿自己这边的副本验。

### 3.14 被控机的设置面板：为什么按文档装反而没有面板

- **症状**：主控机（装 bundle）有配置页；被控机按模板装 `file:///…/lib/server.js` 或
  `name: 'dsh-remote/server'`，**Plugins 页里没有 Configure**。
- **根因**（两条独立的规则叠加）：
  1. 面板 key 是 `<bundle 包名>#<bundle patch 声明的 row id>`，
     且**只有 bundle patch 声明的 row 才有卡片**；profile 自己 patch 里加的行没有卡片，
     浏览器半注册上去也没人派发；
  2. 浏览器半只对**精确包名行**或**包内 file:// 行**附着；
     `dsh-remote/server`（子路径）**根本不加载浏览器半**。
- **处理**：`cordis.patch.yml` 里把 server 行**声明出来但 `disabled: true`**
  （loader 支持 `disabled`，禁用行是惰性的），被控机上启用它、并保留 client 行
  （`toolEnabled: false`，只为把包和面板带上）。
  **不要**用"精确包名行 + file:// 行"同时活跃——那是"两个来源解析到同一个包名"，
  启动期硬错误。
- **既存缺陷已修**：`ConfigFormSnapshot` 没有 `secrets` 字段，所以面板里现成的
  "已设置/未设置/清除"**其实一直没生效**（那时写入本身是正常的）。现在改读
  `ctx.configForms.describe()` 的 `getSnapshot().view.namespaces[].secrets`，
  并按 namespace 取自己那一行；`describe` 缺失或形状变了就降级成"未知/未设置"，
  绝不让面板渲染失败。两个坑：① `configForms` **不能**写进插件 `inject`
  （硬依赖会让整个半端不 apply），只能可选取用；② 面板要**订阅**这个 mirror，
  否则答案晚到时页面还停在旧状态。守护测试：`test/browser-half.test.mjs`。
- **想要"实时链路状态"面板**：静态 bundle 拿不到 `host.call`，得自己有 typert/`@Remote` 贡献，
  或改成动态 cordis 包。
- **与 DSH 规范的对照（按上面那份清单逐条过了一遍）**：
  | 规范 | 本插件 |
  |---|---|
  | manifest（`platform: web` / `exports["./client"]` / `immediately` / `inject`） | ✓ 本来就有 |
  | 主题只用 `--dsw-alias-*` token，不写死颜色 | ✓ |
  | `:focus-visible` 保留、0.5px 细线 | ✓ |
  | locale 走 `ctx.locale.register` + `locale:` 声明 | ✓ |
  | 页面不画 title/icon/crumb（由 Plugins 页负责） | ✓ |
  | 只有"保存"才写，离开页面丢弃草稿 | ✓ |
  | **每个控件有可访问名**、提示用 `aria-describedby` | **本轮补**：提示从 placeholder 改成真实文本 + id（placeholder 一填就消失、也不保证被朗读） |
  | 写入期间 `aria-busy`、失败 `role="alert"`、成功 `role="status"` | **本轮补** |
  | 静态半端不能用 CSS Modules | 自注入 `<style>`，随半端生命周期挂/卸（已在文件头说明） |

### 3.15 `remote_exec` 停不掉：本地按停，远端的命令照跑

- **症状**：本地用户对一条 `remote_exec` 按停，本机这一轮停了，**对端那条命令继续跑到
  自己的 timeout**（默认 120s）。之前只修了 agent 轮次的打断，命令被漏掉了。
- **根因**（两层，缺一不可）：
  1. client 的 `remote_exec` **根本没看 `exec.signal`**——它只是 await 一个 `link.request`；
  2. 就算看了，服务端也没有"运行中的子进程"这个概念：`execFile(...)` 的句柄拿到就扔了，
     没人能按 id 找到它并 kill。
- **处理**：
  - **server**：`src/exec-registry.ts` 是一个纯对象（可单测），按调用方给的 `execId` 记账；
    `exec` op 接收 `execId`，新增 `exec.cancel` op；Windows 上用
    `taskkill /PID <pid> /T /F` 杀**进程树**（`child.kill()` 只到 powershell/cmd 那个 shell，
    真正干活的孙子进程还活着）；被停的命令返回 `cancelled: true`，不再伪装成 `timedOut`。
  - **client**：`remote_exec` 生成 `exec-<uuid>`，用 `raceAbort` 观察 `exec.signal`，
    中止时**先本地结算**（用户的中断不能被慢链路拖住），再 fire-and-forget 发 `exec.cancel`。
  - **权限**：`exec.cancel` 归到 **level 3**（与 `exec` 同族）。未知 op 默认按只读放行，
    于是只读控制器能停掉人自己起的命令——那不对。
- **兼容**：老对端没有 `exec.cancel` → 回 `unknown op`（link 会重试一次），client 吞掉并记 debug；
  本地取消照常生效，只是远端停不掉。这一点写进了 `remote_exec` 的工具描述。
- **验证**：`test/exec-registry.test.ts`（含迟到 disposer、同 id 复用、拒绝死亡的 shell、
  `cancelAll`、空 id）。真正跑起来还需要 r13 的对端。
- **教训**：做"打断"要清点**所有能长时间占住用户注意力的东西**，而不是只修最显眼的那个；
  在 Windows 上"杀掉一个进程"基本等于"杀掉一棵进程树"。

### 3.17 别把"等对端"当借口：受控端可以在 loopback 上先跑起来

- **背景**：`exec.cancel`、权限栅栏、op 表这些都在 **server 半**，而 server 半只在被控机上跑，
  所以前几轮的说法一直是"等对端升级到 r13 才能实测"。这话只对了一半——
  server 半需要的只是**一个 cordis ctx**，而它跟 ctx 的交互就四个调用：`logger` / `effect` /
  `on` / `get`。把这四个 stub 掉，`apply()` 就能在测试里跑起来：它自己去绑 127.0.0.1 的端口，
  然后测试用**真握手**（`clientHandshake`）连上去发帧。
- **因此能验的**：握手会拒绝没 pin 的客户端；`sysinfo.ops` 自述了新 op；`exec` 真跑；
  **`exec.cancel` 真把一条 `Start-Sleep 30` 停掉**（1.2s 结算、`cancelled: true`、
  不再伪装成 `timedOut`）；`fs` 往返；缺服务时 `agent.prompt` 明确报错而
  `agent.sessions` 给出空列表而不是抛；`maxPermission: 1` 时 `exec` **与 `exec.cancel`** 都被
  `FS_PERMISSION_DENIED` 拒掉。
- **推送通道也能验**：只要假 ctx 里有一套"够用的" `agents`/`agentPresets`/`sessions`
  （让 `agent.prompt` 成功，server 才会把会话记进 `states`），就能直接
  `fire('session/event', …)` 打出真帧，断言 controller **收到**什么：
  正常结束不推；`turn/end(aborted/user)` → `{kind:'interrupt', origin:'remote-user'}`；
  带 `rpcId` 的真人消息 → `{kind:'note', human:true, text}`；**我们自己注入的那条**
  （按 MessageId 认出来）不推；controller 自己按的停 → 回显 `origin:'controller'`；
  不是自己驱动的会话 → 完全不推。**这就是"远端用户打断回传本地"的全链路。**
- **仍然验不了的**：真实 DSH 里的 `agents`/`sessions` 行为本身（本测试用的是假服务），
  以及被控机上的**部署与重启**。也就是说：插件侧已经没有"等对端才能测"的空白了。
- **教训**：判断"这个验证是不是真的需要另一台机器"之前，先看清**它到底需要哪些依赖**；
  多数"要环境"的说法，其实是"要四个 stub + 一套够用的假服务"。把能本地化的验证抢回来，
  剩下的待办才真正是"只有对方能做的"。

### 3.18 用 PowerShell 批量改含中文的源码 = 把文件改成乱码

- **症状**：改一个含中文的测试文件，用
  `(Get-Content $f -Raw) -replace '…' | Set-Content $f -Encoding UTF8`，
  改完中文全变成 `鍚屼竴涓湰鏈?…`，而且有个字符串被截断成语法错误，`tsc` 直接报
  `Unterminated string literal`。
- **根因**：这台机器的 shell 是 **Windows PowerShell 5.1**，`Get-Content` / `Set-Content`
  默认按 ANSI/OEM 代码页走：UTF-8 中文读进来就已经错了，写出去又错一次。
- **处理**：含非 ASCII 的文件**一律用编辑工具**改（或先确认编码语义、别做读写往返）。
  改完**扫一遍 mojibake**（`锛|鍚|涓€|鐨|浜`）确认受损范围——这次就是靠扫描确认
  只有那一个文件被毁，其余安然。
- **教训**："看起来改了"和"内容还对"是两件事；对源码做批处理式替换前，
  先想清楚工具链的编码默认值。

### 3.19 远端轨迹：把"换个循环"当成需求来做

- **需求原话**：远端要有一段"对话"，它的轨迹起点不一定是用户输入，由 remote 插件而不是
  `user → llm → tools` 循环产生；要**省模型调用**、**痕迹留全**、上下文**全面且连贯**，并且主控能低成本读。
- **先查了"能不能做成真会话"**（结论决定了实现）：
  - `sessions.create()` **不落盘**：持久化写入器由**拥有写句柄**的一方注册
    （`SessionPersistence.create()` / `.open(id,'write')`，生产里只有 agent 生命周期会开），
    没有句柄的会话，live 事件路由直接丢弃。
  - **可以做**（`prepare` → `sessionPersistence.create(header)` → `enter` + `announce` →
    `session.append` → `sessions.flush`），但有个硬约束：**自定义事件类型重启后不可读**——
    `KNOWN_SESSION_EVENT_TYPES` 是**构建期从仓库 `packages/` 生成**的，插件在仓库外，
    而 `append` 又不能带 `ignorable`。于是"写得进去、重启后打不开"。
  - 不用自定义类型也能写（复用 `user/message` 或 `feedback/record` 当载体），但代价是：
    会话文件只增不减、冷读要**整份解码**（JSONL 的读路径就是全量读再切片）、以及
    `sessionController.follow` 会把**冷会话升级成真 agent** 这个地雷。
- **因此的实现**（`src/journal.ts` + server 侧接线）：
  - 真相源是**插件自己的只追加 JSONL**：`seq` 单调、8 MB 轮转保留上一代、重启后 `load()` 续号；
    记录点两个：`handleRequest`（每个 op 一条）与 `session/event`（被驱动会话的轮次 / 模型回复 / 真人消息）。
  - 每条默认只有**一行摘要**（`kind`/`op`/`ok`/`ms`/`sessionId`），细节 `detail` 只在 `full=true` 时给；
    大块负载（`dataB64`/`content`/`stdout`/`stderr`）**只记长度**——轨迹是上下文，不是垃圾桶。
  - 读是**增量**的：`journal.read {fromSeq, limit, full}`；客户端 `remote_journal` 按 chat 记游标
    （`client-journal.json`），省略 `from_seq` 就只拿新条目，从没读过则给**尾部**而不是开头。
    `journal.read` 自己不入账（否则轮询会喂饱自己）；整条记录路径 best-effort——
    **记录失败绝不能弄坏被记录的工作**。
- **验证**：`test/journal.test.ts`（39 项：续号、增量、细节剥离、轮转、断行、脱敏、摘要、失败不抛）
  + `server-loopback` 新增 14 项（真协议下读轨迹、`journal.read` 不入账、游标推进、追平为空）。
- **两条教训**：
  1. 轨迹**一个进程一份**：`seq` 在内存里分配，同一文件被两个实例写会交错——生产里被控端本
     就独占一个端口，测试里给每个实例单独一份文件才反映真实形态。
  2. 我又一次用 PowerShell `-replace` + `Set-Content` 改了含中文的测试文件，又把中文改成了乱码
     （见 3.18）。**含非 ASCII 的文件只能用编辑工具改**——这次靠 `tsc` 的
     `Unterminated string literal` 才发现，用整文件重写修好。

### 3.20 一次真实的远端部署：strip-only 陷阱、自愈脚本，以及一个还没解开的结

- **编排**（因为用户无法物理接触被控机，安装只能经插件通道 + 对端"创造模式"会话）：
  1. 主控把 4 个文件用 `remote_fs_write` 推到对端 `stage-r14\`（大文件分包，逐文件 SHA256 对齐）；
  2. 起一段 `preset_id: cordis` 的新会话，让它**备份 → 覆盖 → 校验 → 写自愈脚本 → detached 重启 → 先回复再让机器重启**；
  3. 自愈脚本：`Start-Sleep 25` → 杀 DSH → 起 DSH → 90 秒轮询 `127.0.0.1:11325`；**起不来就还原备份、删掉新增文件、再重启一次**，
     结果写进 `deploy-r14-report.txt`。
- **陷阱（对端会话发现并拒停）**：对端以 Node **strip-only** 模式加载 `file://` 的 TS，
  而 `reuse.ts` 用了 TS **参数属性**（`constructor(private readonly file: string)`）——擦不掉，报
  `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`。它没有"先重启再说"，而是**回滚并把机器留在可用的 r10**，
  还从 `src.bak-before-stripfix-*` 找到证据：这台机器上 r9→r10 时已经做过同类改写。
  **这是本地/远端运行时的不对称**：esbuild 会把参数属性编成赋值，所以本地永远看不出问题。
  修法：把参数属性改成字段 + 赋值（`reuse.ts`/`link.ts`/`protocol.ts`），
  并在 `tsconfig.json` 打开 **`erasableSyntaxOnly`**，再加一个不依赖 tsconfig 的
  **`tools/check-strip-safe.mjs`**（可在对端机器上直接跑，负样本能复现上面那句报错）。
- **还没解开的结**：修好后重新校验全部通过（长度、`BUILD = 'r14'`、4 文件 strip 检查、6 个受保护文件哈希未变），
  自愈脚本按设计启动并重建；**此后对端不再应答**——`remote_*` 全部 `peer closed during handshake`，
  而从本机直连 frp：TCP 能连上，对端在 **~2.07 秒**后以 0 字节关闭（三次一致）。两端都是 `0.2.0-rc.2`，
  所以不是版本差。这个形状更像"隧道本地侧或 DSH 应用没在服务"，但**从外部无法区分**，而插件通道就是唯一通道。
- **三条教训（写给下一次）**：
  1. **先把"对端能不能加载"验掉，再拷贝**：现在由 `check-strip-safe.mjs` + `erasableSyntaxOnly` 保证，
     这一步本该在第一次推送前跑。
  2. **"端口在监听"不等于"插件活着"**：上一版自愈脚本的判据只有监听，无法区分"应用没起来""插件加载失败""应用卡在对话框"。
     **已修**：`server.ts` 现在在**监听成功**与**每次握手成功后**写心跳
     （`${DSH_HOME}/dsh-remote/server-heartbeat.json`，含 `build`/`at`/`pid`/`port`/`controllers`/`journalSeq`），
     脚本改为判"心跳里的 build == 期望值且是新的"（r15 起）。loopback 里 8 项断言覆盖了它。
  3. **不要用即将被重启的通道去重启它，除非有带外恢复路径**：这次唯一的通道就是被重启的 DSH 本身；
     一旦应用没回来，主控就彻底失联，而使用者又无法物理接触——**带外恢复必须在动手前就确认存在**。
     固定流程已写进 **`docs/DEPLOY-PEER.md`**（含心跳版自愈脚本模板、分包推送、只覆盖 4 个文件的规则）。
- **状态**：对端当前不可达；`stage-r14\`、`backup-r10-server*.ts`、`restart-r14.ps1`、`deploy-r14-report.txt`
  都留在被控机上，报告文件里会写 `OK r14` 或 `ROLLED BACK to r10`。链路一恢复即可据此收尾。

### 3.21 手挂形态的对端：`dsh.bundle` 缺失 = 静默跳过

- **现象**：按"给受控机装 bundle 以获得设置面板"的计划改 profile patch 时，对端会话**拒绝执行**并报告：
  磁盘上那台的 `package.json` **没有 `dsh` 键**，`cordis.patch.yml` 还是带 `<you>` 占位符的**模板**
  （不是真正的行声明）。它从 `app.asar` 里定位到实现：
  ```js
  const bundle = bundleManifest.dsh?.bundle;
  if (bundle === void 0) throw new Error(`… declares no dsh.bundle in its package.json`);
  ```
  而且 `dsh.profile.bundles` 里每一项都走这条路径，**抛出的 bundle 会被 catch 进 `skippedBundles`
  并只往 stderr 打一行**——于是：bundle 不加载 → 两个 row id 都没人声明 → profile 的 id 定向覆盖指向空气
  → **重启后受控端不再监听，机器失联**。这正是它拦下来的原因（否则就是那 20 分钟事故的重演）。
- **根因**：那台机器是**手挂形态**的旧落地（`file://` 指到 `src/server.ts`），
  它的 `package.json` 与 `cordis.patch.yml` 停在"模板 + 无 dsh.bundle"的年代；
  而本仓库是**打包形态**（v0.2.0：`dsh.bundle.patch` + `dsh.client` + 预编译 `lib/` + 浏览器半 `client.js`）。
- **处理**：整套换装打包形态（7 个文件 ≈187 KB：`lib/{client,server}.js`、`client.js`、`package.json`、
  `cordis.patch.yml`、`locale/{zh,en}.json`），profile 侧加 junction + `bundles`/`dependencies`，
  把原来的 `file://` insert 换成 id 定向覆盖。顺带的收益：**对端从此加载预编译 JS，
  strip-only 那条限制（3.20）从升级路径里彻底消失**。
- **教训**：
  1. 升级前先**确认对端是哪种装法**（看 patch 行是 `file://…/src/*.ts` 还是包名 + junction），
     两种形态要同步的文件完全不同（GUIDE §2.5）。
  2. "配置行写在 profile patch 里"和"行的 id 由 bundle patch 声明"是**两件事**；
     卡片只认后者，而后者要求 `dsh.bundle` 存在。
  3. 对端会话的"先复核、发现矛盾就停下"是这套流程里最值钱的一环——它两次把失联拦在动手之前。

### 3.22 「取消」的验收标准是"它起的东西也停了"，不是"API 返回了 cancelled"

- **怎么发现的**：写了一个**真机**检查 `test/live-control.ts`（不需要 DSH，直接用插件自己的 `LinkClient`
  连对端；只跑它自己起的命令 + 读轨迹，不碰任何会话）：让对端执行一条"启动一个**分离**的 powershell
  （20 秒后写一个标记文件）+ 自己睡 90 秒"的命令，几秒后发 `exec.cancel`。
- **⚠️ 我先报错了，这里必须留档订正**：该检查一开始报告"孙进程活下来了"，我据此改写了 `killTree`。
  后来发现是**检查自己有 bug**：`fs.stat` 对**不存在的路径**返回的是**成功的 op + `{exists:false}`**，
  而我读的是 `ok !== false` —— 于是"文件不存在"被读成了"文件存在"，**这个断言永远报失败**。
  在同一台机器上补做的对照实验还显示：**单用 `taskkill /T /F` 在这种形状下也能把分离的孙进程一起杀掉**。
  所以"旧代码会漏杀孙进程"这个结论**没有证据支持，撤回**。
- **保留的东西**：
  - `killTree` 保持"**先快照后代树、再杀，`taskkill` 兜底**"——它在那台机器上用两种命令形状都实测正确，
    作为加固保留（`child.kill()` 只到直接子进程这一点仍然是事实）；
  - `test/kill-tree.test.ts` 保留，但**改写了措辞**：它钉的是"停止必须带走命令起的一切"这个**不变量**，
    不是"旧代码会失败"；其他平台明确 skip；
  - 真机检查的断言改成读 `exists`，并把这个坑写进注释。
- **教训（比上面几条更重要）**：**先怀疑自己的断言，再怀疑被测系统**。一个把 `ok` 当"文件存在"的读法，
  足以凭空造出一个"真机缺陷"、并让随后一串改动看起来有理有据；只有**换一种方式独立测量**
  （对照实验 + 直接 `Test-Path`）才能把它挖出来。
- **同一轮还查出第二件事**：`agent.interrupt` 之前**无条件**返回 `interrupted: true`，
  而 `cancel()` 在 idle agent 上是**文档明说的 no-op**——于是"打断一个早已结束的轮次"也会被告知"已打断"
  （真机上就是这么复现的：轮次 completed，controller 仍收到 interrupted）。现在先探测 `whenIdle()`
  再回答；idle 时返回 `interrupted: false, latched: true, reason: …`（停止闩存仍然生效）。
  两个分支都有 loopback 断言。
- **补充语义**：`interruptCause` 在"主控按停"和"那台机器的真人按停"两种情况下**都是 `user`**
  （控制器发的就是 `cancel({kind:'user'})`）；区分"谁按的"靠**推送帧的 `origin`**
  （`controller` / `remote-user`）。真机检查里我把这一点写成注释，而不是硬凑断言。
- **客户端侧的接线现在也有测试**：GUI 按停走的是"先本地结算、再按 `execId` 让对端杀进程"这条路径，
  它没法从 DSH 侧被触发，于是抽成 `src/exec-client.ts` 并由 `test/exec-client.test.ts`（12 项）覆盖：
  无信号照跑、按停时**取消的就是那个 execId**、**先收到回复就绝不补发取消**（否则会误杀对端下一个命令）、
  传输错误不算本地停止、已经 abort 的信号也仍然发取消。

### 3.23 远端费用：走 cost-meter 的官方外部用量入口，不改它的账本

**需求**：本机装了 `dsh-cost-meter`，但远端每一轮花的是**对端账户**的 token；本机账本天然看不到。
要求"远端的费用回传本地，并作为本机整个对话的总费用计算"，同时**不许把 cost 插件搞崩**。

- **先查接口，再选方案**。翻 `dsh-cost-meter@1.8.36` 源码后确认：
  - 它**没有**第三方「会话费用注入」接口；账本（`storages/cost-meter/ledger.json`）只由它自己的
    `llm/stream` 钩子与**会话日志回放**填充，外部改账本会撞上它的三向合并/锁，属于"能写坏"的做法；
  - 它**唯一官方**的第三方入口是 `storages/cost-meter/external_usage.json`（`docs/external-usage.md`）：
    整份替换、原子 rename、fail-closed 校验，按来源分栏，并进今日/月/累计合计与余额对账。
  - 因此**不 patch 已安装的 npm 插件**（升级会覆盖、内部接口无保证），而是做它的"生产方"。
- **口径是明确的、也写进了文档**：单会话徽章仍是本机 DSH 账本；远端费用进「外部用量 / 合计」。
  cost-meter 的设计就是这样（DSH 与外部用量分列），不是回传没做够。
- **远端只报 token，不报钱**。价格表、峰谷窗口、长上下文规则都在**本机** cost-meter 里，而且会随官方价格更新；
  把价表搬到对端等于"每次调价都要重新部署被控机"。所以新增 `usage.read`：
  返回每条模型调用的五桶 token + provider/model + 时间戳 + 会话 seq，本机用 **records 模式**让 cost-meter
  按 `at` 时刻计价。——**这是这次唯一的协议增量**，且是只读 op（默认 permission level 1），旧对端不认识时自动跳过。
- **去重规则必须与 cost-meter 回放同构**：它按 `(turn,step)` 折叠"streaming usage chunk + 最终 message"
  的重复上报；回传如果不去重，远端费用直接翻倍。`src/session-usage.ts` 复刻了这条规则（同键、同 provider/model、
  同五桶才算重复），并且**全量扫描建状态、去重后**才按 `fromSeq` 过滤——否则游标正好落在 chunk 与 message 之间时，
  message 会复活成第二笔。
- **游标别用 `seq`**：`usage.read` 响应里的 `seq` 是"会话当前 seq"，不是"这次看到哪"。响应被 `limit` 截断时用它推进
  会**跳过中间未返回的调用**。所以响应带 `nextSeq`（未截断=已扫描最大 seq；截断=最后返回记录的 seq），
  客户端以它为下一轮 `fromSeq`。
- **fail-closed 是双向的**：cost-meter 只要有一条 provider/model 未定价就忽略**整份**快照。所以生产方必须
  在写入前过滤（空路由、本地推理渠道、非法 token 桶）；但它**无法**判断远端冷门 provider 在本机价表里有没有价，
  这一条只能靠文档写清 + `remote_ping.remoteCost` 让用户能自检。
- **验证链（不靠肉眼）**：`test/session-usage.test.ts`（提取/去重/游标边界，43 项）、
  `test/cost-report.test.ts`（快照组装/裁剪/原子写，85 项，并用**已安装 cost-meter 的真实 parser** 做契约回归）、
  `tools/verify-cost-contract.mjs`（本机就能跑，找不到 cost-meter 时 skip）、
  `tools/verify-remote-cost.mjs`（对真实对端会话拉一次 usage、过一遍客户端代码、产出快照）
  → 再用 `verify-cost-contract.mjs <快照>` 交给 cost-meter 自己的 parser 定价。
  真机实测：远端正一轮 deepseek-flash 调用（input 841 / output 1 / cacheRead 15744）→ 快照 →
  cost-meter parser 计出 `$0.000174`，链路成立。
- **部署**：对端是 bundle 形态（`lib/*.js`），只需推 `lib/server.js` + `lib/client.js`；`tools/push-lib.mjs`
  走插件自己的加密通道直传并逐字节核对 sha256，避免把 100 KB 构建塞进模型上下文。对端 `BUILD` r17→**r18**、
  本机 `BUILD` c9→**c10**，`remote_ping` 一眼可验；重启后 `ops` 里出现 `usage.read` 即部署成功。
- **已知边界**（也在 GUIDE §4.7/§8）：只回传被驱动的那一个会话（对端 agent 自己再派的 subagent 不计）；
  对端重启后无活动句柄的会话要等下一轮；外部用量只进合计、不进会话徽章。

### 3.24 大文件传输：先量出瓶颈，再决定只做「分块 + 压缩 + 流水线」

**先量，不猜**。在真隧道上用 `tools/bench-probe.mjs` 对比载荷形状（8 MiB，RTT≈78 ms）：

| 路径 | 线上字节 | 耗时 | 结论 |
|---|---|---|---|
| `exec` 输出 8 MiB 明文（JSON 里的普通字符串） | 8.00 MiB | 22.8 s | ~0.35 MiB/s |
| `fs.write` 8 MiB 原始（base64 JSON） | 10.48 MiB | 24–40 s | base64 让线上多 31% |
| `fs.write` 预压缩 8 MiB 文本 | 0.03 MiB | 0.14 s | 压缩比直接换成吞吐 |
| `fs.read` 8 MiB（256K 窗口） | 8.00 MiB | 26.9 s | ~0.30 MiB/s |

所以这里是**带宽硬上限**（≈2.6 Mbit/s），不是 CPU、不是帧开销；能动的只有三件事：
① 少发字节（压缩、减 base64）② 填满管道（分块并行，别让 RTT 空转）③ 去掉单帧巨大帧的卡顿/超时/内存峰值。
二进制帧能省掉 base64 的 ~33%，但要改帧格式并做两端版本协商——收益小、风险大，这次**明确不做**，
只写进文档当作后续可选项。

**做法**：新增 5 个 op（`fs.put.begin/chunk/commit/abort` + `fs.get`），旧的 `fs.read/write/edit` **一行不改**；
客户端用 `sysinfo.ops` 探测，旧对端自动走老路。关键设计点：

- **去重与幂等**：chunk 带 `index`，服务端按 `index*chunkSize` 位置写临时文件；乱序、重复、并发都安全，
  单块失败可重试，重复块只是覆盖同一段。`fs.put.chunk`/`fs.get` 不进 journal（一次 8 MiB 上传会写 8+ 条）。
- **落盘安全**：服务端先写目标同目录 `<target>.<uuid>.dshremote-upload`，`commit` 时校验 size+sha256，
  再做 `createOnly`/`expectedVersion` 护栏，最后 `rename`；失败/abort/TTL/进程 dispose 都删临时文件。
  Windows 上 `renameSync` 覆盖已存在文件实测可行（MoveFileEx REPLACE）。
- **压缩策略**：逐块 gzip，**只有压到 95% 以下才用**，否则该块回退 raw（服务端 `fs.get` 也是同一策略，
  客户端按响应里的 `encoding` 解码）。这样随机二进制不会被 gzip 浪费时间，文本/代码白赚 2–5×。
- **防 zip bomb**：`gunzipSync(..., { maxOutputLength: expected + 1 })` 且解压长度必须**精确**等于该块
  应有长度，否则丢弃该块。
- **结果未知的 commit**：客户端若在 `commit` 请求上失败（回包丢了但服务端可能已经 rename），
  **绝不**退回旧路径重写——错误会带「目标可能已写入，请先校验」，避免覆盖一个已经正确的文件。
- **阈值是量出来的**：`tools/bench-sizes.mjs` 显示 64–512 KiB 时快路径多出的 begin/commit/fs.hash 往返
  会抵消收益（噪声也大），1 MiB 起快路径稳定更快。所以默认 `transferFastPathBytes = 512 KiB`；
  peer-fs 的 `readText` 先 `stat`，小文件仍走单窗口 `fs.read`（1 RTT），大文件才走并行 `fs.get`。
- **实测收益**（同隧道 8 MiB，改前/改后）：随机 0.17/0.42 → 0.42/0.42（写 2.5×，读受带宽上限）；
  源码类文本 0.44/0.41 → 0.84/0.86（≈2×，即压缩比）；重复文本/全零 → 21–24 MiB/s（50–270×）。
- **工具层**：新增 `remote_put_file`/`remote_get_file`（传路径、流式、不经过模型上下文），
  `remote_fs_write` 大内容自动走快路径，peer-fs provider 的读写也接同一模块（含旧对端回退）。
- **验证**：`test/transfer-client.test.ts`（85 项，假 link 模拟乱序/重试/混合 gzip/取消/sha 不一致）、
  `test/server-loopback.test.ts` 第 10–17 节（真握手分块上传、乱序、createOnly/stale、abort 清理、
  level-1 拒绝、空文件、dispose 清理、journal 降噪）、`test/peer-fs.test.ts` 的快路径小节（真 fake peer
  实现两套 op，断言「广告时走快路径、不广告时绝不尝试」）。

### 3.25 远端当 subagent / worker / 团队成员的边界在哪里

**先读上游源码，再决定"能做到什么"**（`<harness-checkout>/packages\subagent/*`、`packages/experimental/agent-team|tool-agent-team`）：

- `SubagentProvider` 只有 **one-shot** `start()` → `SubagentRun{result, dispose}`；官方 `tool-subagent` 的
  "后台 + send_message"来自 continuation/inbox 管理器，**只服务本机子 Agent**。
- `spawn_teammate` 内部是 `ctx.subagents.startContinuable({provider})`，continuation 管理器**自己**用
  `prepareContinuable` 组装一个**本机** child Agent 并持有 `AgentHandle`。远端 provider 只贡献 seed，
  不可能让远端会话变成 roster 成员——所以"远端当正式 teammate"是**上游限制**，不是本插件少写了一行。
- Agent Teams 的任务板倒是可用的公开服务（`ctx.agentTeams.createTask/updateTask`），任务按
  **调用方（本机成员）**记账；owner 必须是 roster 成员，所以远端工作只能记在调用方名下。

由此分三层实现，每层都不碰上游代码：

1. **后台运行**（`src/remote-runs.ts` + client 接线）：把 `agent.prompt` 的 pending 请求留在内存里，
   工具立即返回 `runId`；`remote_run_status` 取回、`remote_run_cancel` 走 `agent.interrupt`、
   `remote_send_message` 用 r20 新 op `agent.note`（服务端 `agent.followup` 注入 inbox，不等一轮）。
   关键坑：`timeoutMs:0` 在链路层是 `setTimeout(0)` 立即超时——接线里把它映射成近无限期限；
   run 结算时仍走 `collectRemoteUsage`，费用回传不受影响。
2. **worker 池**（`src/remote-pool.ts`）：每个 peer 一条缓存 `LinkClient` + 确定性会话
   （`anchorSessionId(prefix, peer + chat)`，**种子必须含 peer**）；`Promise.allSettled` 并行、
   单台失败隔离、`exec.signal` → 对所有在途 worker `agent.interrupt`。
3. **Agent Teams 看板**（`src/remote-team.ts`）：结构化 `TeamFacade` 注入，不 import 实验包；
   `create → claim → edit(摘要) → complete`，CAS revision 逐步传；任何一步失败只 log，
   绝不影响远端结果（看板是旁路，不是可靠性来源）。

**为什么不在 `client.ts` 里直接写这些**：`remote-runs` / `remote-pool` / `remote-team` 三者都是
"注入依赖的纯模块 + 工具工厂"，client 只做薄接线（每 peer 的 LinkClient、`localSessionOf`、
`ctx.get('agentTeams')`）。好处是单测不需要 cordis/网络（假 link、假时钟、假 team facade），
将来加别的控制面工具也只多一个 spread。

**远端侧只加了一个 op**（r20 `agent.note`）：`followup` 注入 + 记住 message id（打断归因仍算
controller，而不是本机真人）。这正是"remote 变化不大"的原因：会话驱动、事件流、打断、文件、用量
这些原语 r17–r19 已经够了，剩下都是**控制面编排**。

**状态与边界**（都写进了 GUIDE §4.9/§8）：run 注册表是进程内的（本机重启丢未收 run，但远端那轮
结果仍在远端会话里）；`backgroundRuns` 是 volatile 但工具集在 apply 时决定，改后需重启；
Team 看板 owner 是调用方；`remote_send_message` 对旧对端退回"排队但不可观测"。

---

## 4. 版本历史
| 版本 | 改了什么 | 触发原因 |
|---|---|---|
| r1 | 初版：协议 + 两端插件 + 密钥生成 | — |
| r2 | `installModelSelection` | 3.1 |
| r4 | `BUILD` 标记、`workspace`/`preset_id` 改为每次调用可传、`ctx.effect` 容错 | 3.3 / 3.4 / 3.8 |
| r6 | `workspaceRegistry.create` + `attachSession` + 标题 | 3.2 |
| r7 | 指纹改回 `sha256`（与密钥生成器一致） | 3.7 |
| r8 | `exec` 按原始字节 + 多编码回退解码（修中文乱码） | 3.10 |
| r9 | `fs.edit`、写入版本护栏、类型化 FS 错误 | — |
| r11 | `sysinfo.ops`（能力自述）+ `agent.sessions`（列出已有会话，按最近优先） | 3.11 |
| c1（client） | 省略 `session_id` 时**复用已有会话**：记忆 → 对端发现 → 确定性锚点；新增 `new_session`；`remote_ping` 带 `clientBuild` | 3.11 |
| r12（server） | `turn/end` 取消原因（`reason.reason`）进 reply；`session/event` 推送对端用户打断/插话；自中断标记；停止闩存；被驱动会话的 `systemPrompt` 提示（`promptGuidance`） | 3.12 |
| c2（client） | 严格"一 chat 一远端对话"（身份 = f(chat id)）；`adoptExistingSessions`（默认关）；本地中断 → 远端 `agent.interrupt`；远端打断/插话进工具返回；本机 chat 的 `systemPrompt` 提示（`promptGuidance`） | 3.12 |
| c3（client） | 可选：把对端注册成 subagent provider `remote`（`subagentProvider`，默认关）+ `src/remote-provider.ts`；被控机面板的行声明 | 3.13 / 3.14 |
| web（浏览器半） | 面板补齐 5 个新字段；密钥"已设置/清除"改读 settings describe 镜像（原先一直是死的）；提示改为真实文本 + `aria-describedby`、加 `aria-busy`/`role="status"`；新增 `test/browser-half.test.mjs`（37 项，含两个半端面板的可访问性与渲染） | 3.14 |
| r13（server） | `exec.cancel` + `src/exec-registry.ts`：运行中的命令可被主控停掉（Windows 杀进程树），被停的命令报 `cancelled` 而不是 `timedOut` | 3.15 |
| c4（client） | `remote_exec` 观察 `exec.signal`：本地中断时 `raceAbort` 立即结算并 `exec.cancel` 远端命令；新增 `src/async.ts`（`raceAbort`/`abortError`） | 3.15 |
| c5–c7（client） | `subagentProvider` **默认开**：注册 `subagent_remote` 工具（`src/subagent-tool.ts`），无需 composition 那一行；开关热生效；本机提示里加了"整块子任务用 subagent_remote" | 3.13b |
| r14（server） | 远端**轨迹**（`src/journal.ts` + `journal.read`）：每个 op、被驱动轮次、模型回复、真人消息都追加成一行；增量读、8MB 轮转、best-effort；`journal`/`journalFile` 设置项。另：参数属性改写为字段 + `erasableSyntaxOnly` + `tools/check-strip-safe.mjs`（对端 strip-only 加载） | 3.19 / 3.20 |
| r15（server） | **心跳**：`server-heartbeat.json`（`build`/`at`/`pid`/`port`/`controllers`/`journalSeq`），监听成功与每次握手后刷新；`heartbeatFile` 设置项。配套：`tools/check-strip-safe.mjs`、`docs/DEPLOY-PEER.md`（心跳版自愈回滚模板） | 3.20 |
| r16（server） | **停止路径修复**：`killTree` 先用 `Win32_Process` 快照后代树再显式杀掉（`taskkill /T` 边走边杀，会漏掉命令自行 `Start-Process` 分离出去的孙进程——真机实测标记文件仍会出现），`taskkill` 退化为兜底；新增 `test/kill-tree.test.ts`（Windows 专属回归）与 `test/live-control.ts`（真机检查：轨迹增量读 + `exec.cancel` 真杀） | 3.22 |
| r17（server） | `agent.interrupt` 改为**诚实回报**：先探测 `whenIdle()`，idle 时返回 `interrupted:false, latched:true`（`cancel()` 在 idle 上是 no-op，原先无条件回 true 等于谎报）。配套：`test/live-control.ts` 的打断场景（真机 63–79 ms 内 aborted） | 3.22 |
| c9（client） | GUI 按停的接线抽成 `src/exec-client.ts` 并加 `test/exec-client.test.ts`（12 项）：按停取消的就是那个 execId、先收到回复绝不补发取消 | 3.22 |
| c8（client） | `remote_journal` 工具 + 按 chat 的读游标（`client-journal.json`，省略 `from_seq` 只取新条目）；提示里加了"轨迹可以放心反复查" | 3.19 |
| r18（server） | `usage.read`：从活动会话事件流提取逐次 token 用量（`src/session-usage.ts`，去重与 cost-meter 回放同构、`nextSeq` 游标）；只读，level 1 | 3.23 |
| c10（client） | 远端费用回传：`src/cost-report.ts` + 每轮结束增量收集 + 写 cost-meter 官方 `external_usage.json`（原子替换、保留他人 source）；配置 `costReporting`/`costSourcePrefix`/`costStoreFile`/`costSnapshotFile`；`remote_ping.remoteCost` | 3.23 |
| r19（server） | **分块传输快路径**：`fs.put.begin/chunk/commit/abort`（乱序/重复/并发块幂等位置写、逐块 gzip、sha256 校验、createOnly/stale 护栏、原子 rename、TTL/并发上限、dispose 清理）+ `fs.get`（分块压缩读，按 95% 策略决定 gzip/raw）；`src/transfer-server.ts`；新 op 归 level 2（读 level 1），chunk/get 不进 journal | 3.24 |
| c11（client） | **分块传输客户端**：`src/transfer-client.ts`（分块计划/并行流水线/逐块压缩/sha256/重试 2 次/中止清理/本地流式读写）；`remote_put_file`/`remote_get_file` 工具；`remote_fs_write` 大内容快路径；peer-fs 读写接入快路径（小文件仍走单窗口）；4 个传输配置；旧对端自动回退 | 3.24 |
| r20（server） | `agent.note`：把 controller 的一条 user 消息 `followup` 进会话 inbox 但**不等一轮**（供 `remote_send_message` 给运行中的远端任务追加指示）；message id 记入既有注入集合，打断归因仍为 controller；level 3 | 3.25 |
| c12（client） | **后台运行**：`src/remote-runs.ts`（并发上限/结算/list/TTL + `remote_run_start/status/cancel`、`remote_send_message`）；client 抽出 `parkPrompt`、`agent.note` 能力探测与旧对端 fallback、run 结算仍做费用回传；配置 `backgroundRuns`/`maxBackgroundRuns`。**worker 池 + Teams**：`src/remote-pool.ts`（`remote_workers`/`remote_worker_prompt`/`remote_pool_dispatch`/`remote_team_dispatch`、每 peer 确定性会话、并行聚合、取消全量 interrupt）+ `src/remote-team.ts`（create→claim→edit→complete 看板记账，失败只 log） | 3.25 |
| r21（server） | **能力直连（远端内核直调）**：`caps.list`（level 1）用 `agentPresets.acquireScope` 枚举一个 preset 的 tools/schemas + `compositionInventory` + presets + `subagents.list` + 活跃 agents，**不建会话**；`caps.call`/`caps.cancel`（level 3）直接用 `ctx.tools.get(name, presetScope).execute(args, {agent: undefined, signal})` 跑对端工具本体，`maxToolCallTimeoutMs` + callId→AbortController 支持超时/精确打断；`tools/change` → debounce 推 `caps.changed`；默认拒绝 `remote_*` 桥工具与 `ask_user_question`/`exit_plan_mode`/`present`（`deniedTools` 可配）；`caps.list` 不进 journal，`caps.call` 摘要带工具名 | 3.26 |
| c13（client） | **能力镜像**：启动/定时/`caps.changed` push/手动刷新读 `caps.list`，每个 callable 工具以**远端原名**（零前缀）注册（v0.2.0 c13 先注册到本机全局层；本机 preset 同名工具按作用域遮蔽它） | 3.26 |
| c14（client） | **c13 启动崩溃修复 + 作用域定案**：全局层注册会与官方 host 插件抢名字——镜像 `load_workspace_dependencies` 先占住全局名，`dsh-tool-workspace-dependencies` 随后注册直接抛 "already registered" 导致桌面端启动失败。改为**每个 agent 自己的作用域**（`agent.ctx.inject(['tools'])`）安装：先读该 agent 的 `schemas(agent)`，同名（local/host/preset）一律跳过，因此既不覆盖本地、也不可能与任何插件冲突；`agent/created` 装、`agent/disposed` 拆；目录 fingerprint 变化时重建全部 live agent 的镜像；`remote_capabilities` 按调用 agent 标注"本机同名优先、未镜像"。`test/capabilities.test.ts` 增加 agent 作用域/全局零注册/启动崩溃回归断言 | 3.27 |
| peer-fs（`rmt:`） | **联邦 fs 暴露远程路径**：`FederatedFileSystem`（继承 sandbox 后端）新增 `rmt:/…`、`rmt:\…` 别名 → 默认 peer 的绝对路径（`src/remote-path.ts` 统一解析；targetKey 规范化 `\`→`/`，`rmt:\E:\x` 与 `rmt:/E:/x` 同一身份）；`defaultPeer` 配置（缺省=第一个声明的 peer）；`supportsRemotePaths` 能力标记供 file-reference 探测。启用方式是 profile patch 里 disable `fs-sandbox` 并 insert `dsh-remote/peer-fs`（继承 sandbox，本地行为不变）。`test/peer-fs.test.ts` 增补 alias 读写/反斜杠/空路径断言 | 3.28 |
| file-reference（`@rmt:`） | **`@` 补全加入远程命名空间**：`RemoteFileReferenceService extends LocalFileReferenceService`，`rmt:` 查询直接列对端目录（盘符探测缓存 5 分钟；目录 candidate 不带尾斜杠，交给 DSH formatter 补，避免选中后 `//`）；非 `rmt:` 查询原样走本地 provider；仅当 fs 后端带 `supportsRemotePaths` 时生效；按 agent 安装 `@rmt:` 提示段。启用方式：profile patch disable `file-reference-local` 并 insert `dsh-remote/file-reference`。`test/remote-paths.test.ts`（scheme/查询拆解/fake 联邦 fs 端到端/本地回退/无后端静默） | 3.28 |
| 远程路径定案（多机语义 + UI 修复） | **语义**：`rmt:/…` = 默认远端机（`dsh-remote-client.defaultPeer`，热设置；空=第一个 peer），`<peer>:/…` = 指定 peer（scp/rsync 风格，token≥2 字符以免和 `E:/` 盘符混淆，必须是已声明 peer）；peer-fs 通过 `src/remote-path.ts` 的 `parseScpPath` 解析，向 file-reference 暴露 `remotePeerNames()`（default 排最前）与 `remoteDefaultPeerName()`；补全支持 peer 名前缀提示（`@thi` → `home-pc:`）。**UI 空文字根因**：客户端 `ui-reference` 用 `path.slice(lastIndexOf('/')+1)` 当行标题，目录候选若自带尾 `/` 就得到空串（数量对、文字空）；现在候选一律 path-only，由 `formatFileMention` 负责尾斜杠。`test/peer-fs.test.ts`（58 checks）/`test/remote-paths.test.ts` 覆盖 | 3.29 |
| `/rmt/…` 挂载拼写（Markdown 图片全链路） | **根因**：chat 的 Markdown 图片走 host `/api/file?path=`（`packages/api/session-controller/src/media-references.ts`），该路由要求 `path.isAbsolute()`；Windows 上 `rmt:/…` 不是绝对路径 → 400 "absolute path required"，所以图不显示。**修复**：新增 `/rmt/…` 绝对挂载拼写（`/rmt/E:/x` = 默认 peer，`/rmt/<peer>/E:/x` = 指定 peer，`/rmt//home/u` = POSIX 绝对），peer-fs 的 `resolve`/`lstat` 认识它；`/api/file` 的 `fs.resolve`→`fs.stat`→`mime.lookup(displayPath)`→`fs.readBytes` 自然全通（上限 `attachments.imageLimits.maxImageBytes` 20 MiB）。file-reference 补全**统一输出 `/rmt/…`**（`rmt:` / `<peer>:` / `/rmt/` 输入都接受），并把 `REMOTE_REFERENCE_PROMPT` 改成教模型用 `/rmt/…` 写 Markdown 图片。`test/remote-paths.test.ts` 新增 mount parser/补全断言；`test/peer-fs.test.ts` 增加 mount resolve/read/list/stat/lstat/readBytes（65 checks） | 3.30 |

> **热重载会留下僵死 socket**：每次换 `?v=` 都会新建一个监听，旧的不会自己关。
> 自测时换一个干净端口，或用 `Get-NetTCPConnection -State Listen -LocalPort <port>`
> 确认谁在听；正式部署重启 `dsh web` 清干净。

---

## 5. 调试手法（都不依赖看日志）

这套东西最烦的是**看不到 DSH 的 stdout**。所以把关键事实做成"可以被工具观测"的：

1. **`BUILD` 常量进 `sysinfo`** → `remote_ping` 直接告诉你运行时是哪一版
   （对端 `build`，本侧 `clientBuild`；两边都要重启才会换版本）。
2. **监听端口** → `Get-NetTCPConnection -State Listen -LocalPort <port>` 证明插件真的起来了。
3. **`workspace.json`** → 直接看 `sessionIds` 数组成员，判断会话有没有被登记。
4. **会话文件** → `storages/session_projcache/sessions/<id>.json` 判断有没有落盘。
5. **审计日志** → `${DSH_HOME}/dsh-remote/server-audit.log`（JSON 行，含来源/op/成败/耗时）。
6. **本地协议自测** → `test/protocol.test.ts`，改协议后先跑它，别上隧道试。
7. **复用策略自测** → `test/session-reuse.test.ts`（不碰网络）；
   想确认"真对端会接哪段对话"就跑 `test/live-reuse.ts`（默认只读，加 `--prompt` 才发言）。
8. **浏览器半 / 设置面板自测** → `test/browser-half.test.mjs`（纯 node，stub 掉
   `window.__ModuleLoader__` / `document` / React，**真的渲染**两个面板并断言
   密钥"已设置/清除"来自 describe 镜像）。这一半以前完全没有测试，
   于是"面板里的密钥指示是死的"这种问题只能靠人肉点界面发现。
9. **`${DSH_HOME}/dsh-remote/client-sessions.json`** → 直接看"哪个作用域记住了哪个对端会话"，
   怀疑复用没生效时先看它；删掉它等价于"忘掉之前的对话"。
10. **`apply()` 自测** → `test/apply.test.ts`：假 cordis ctx（只 stub `effect`/`inject`/`on`/`plugin`/`logger`）
    跑**真的** `Config` 与 `apply`，断言工具表、系统提示文本、provider 注册，
    并用 `updateVolatile()`（设置层用的同一个入口）驱动 `loader/volatile-update`
    验证**热开关**真的能开/关/再开。
11. **受控端 loopback 自测** → `test/server-loopback.test.ts`：把 `server.ts` 的 `apply()` 拉起来
    （假 ctx + 真监听 + 真握手），用**真协议**在 127.0.0.1 上打它。不需要对端、不需要 DSH。
    这一条最值钱，见 3.17。

---

## 6. 没做 / 可做

按价值排序：

1. **远程自举一个"能改插件"的会话**：现在靠 `preset_id: "cordis"` 显式指定，
   可以再加一个 op：先探测对端有哪些 preset，再挑一个带 `cordis_*` 工具的建会话。
2. **远程触发对端压缩**：加一个 op 包一下 `command-compact`，
   现在上下文压缩是"拉回本机压"。
3. **文件批量同步**：现在只有单文件 `fs.read/write`；可以做成带清单+增量+校验的同步。
4. **执行审批**：在 server 端接 DSH 的审批机制，让敏感 op 需要人批（见 `SECURITY.md` §6.6）。
5. **连接复用与多路**：现在一个 client 一条连接，多个客户端会各连一条（server 是每连接一线程）。
6. **给 `remote_agent_prompt` 加流式**：现在要等整轮结束才返回，
   长任务期间看不到进展（临时办法：同 session 调 `remote_agent_events` 偷看）。

---

## 7. 文件地图

| 文件 | 干什么的 | 什么时候改它 |
|---|---|---|
| `src/protocol.ts` | 握手 + 帧 + 密钥编解码 | 改协议时（**先改 `test/protocol.test.ts`**） |
| `src/keys.ts` | 密钥来源解析（内联/文件/自动生成） | 改密钥设定语义时 |
| `src/reuse.ts` | 「省略 session_id 时接哪段对话」的纯函数 + 落盘记忆 | 改复用策略时（**先改 `test/session-reuse.test.ts`**） |
| `src/async.ts` | `raceAbort` / `abortError`：本地取消的公共机制（传输层没有取消语义） | 改取消语义时 |
| `src/exec-registry.ts` | 运行中子进程的记账（按 execId 可停） | 改 `exec` 可停性时（**有 `test/exec-registry.test.ts`**） |
| `src/remote-provider.ts` | 把对端注册成 subagent provider 的薄适配层 | 改 subagent 呈现方式时（**有 `test/remote-provider.test.ts`**） |
| `src/subagent-tool.ts` | 模型可见的委派工具 `subagent_remote`（名字前缀决定聊天把它归为 subagent） | 改委派入口时（**有 `test/subagent-tool.test.ts`**） |
| `src/server.ts` | 监听 + op 表 + agent 驱动 + 工作区登记 + 审计 + 限流 | 加 op、改 agent 行为时。**记得推 `BUILD`** |
| `src/session-usage.ts` | 从会话事件提取逐次 token 用量（`usage.read` 的纯逻辑） | 改用量提取/去重口径时（**有 `test/session-usage.test.ts`**） |
| `src/transfer-server.ts` | 分块上传/下载 op 的服务端（staging、sha256、原子 rename、TTL） | 改传输线协议/落盘语义时（**有 `test/server-loopback.test.ts` 第 10–17 节**） |
| `src/transfer-client.ts` | 分块计划、并行流水线、逐块 gzip、本地流式读写、重试/校验 | 改传输性能/重试策略时（**有 `test/transfer-client.test.ts`**） |
| `src/remote-runs.ts` | 后台运行注册表 + `remote_run_*` / `remote_send_message` 工具工厂 | 改后台运行语义时（**有 `test/remote-runs.test.ts`**） |
| `src/remote-pool.ts` | 多 peer worker 池 + 两个 dispatch 工具（pool / team） | 改多 worker 调度/聚合时（**有 `test/remote-pool.test.ts`**） |
| `src/remote-team.ts` | Agent Teams 看板记账（结构化 facade，无实验包依赖） | 改 Team 任务生命周期时（**有 `test/remote-pool.test.ts`** 的 Team 小节） |
| `src/cost-report.ts` | 远端用量持久化 + cost-meter 外部用量快照组装/原子写 | 改费用回传口径/上限时（**有 `test/cost-report.test.ts`**） |
| `src/client.ts` | `remote_*` 工具 + 连接复用 + 会话复用接线 + 费用回传钩子 | 加工具、改参数时 |
| `cordis.patch.yml` | 两端 patch 模板 | 改默认配置时 |
| `tools/gen-keys.py` | 生成/安装密钥对 | 改密钥存放约定时 |
| `tools/push-lib.mjs` | 走加密通道把 `lib/` 构建写到对端 stage 并核对 sha256 | 改部署方式时 |
| `tools/verify-cost-contract.mjs` | 用已安装 cost-meter 的真实 parser 校验快照契约 | 改快照格式/对齐 cost-meter 版本时 |
| `tools/verify-remote-cost.mjs` | 对真实对端会话跑一遍"usage.read → store → 快照"链路 | 联调费用回传时 |
| `tools/bench-fs.mjs` | 旧单帧路径吞吐基线（`fs.write` 整文件 / `fs.read` 分窗） | 比较传输优化前后 |
| `tools/bench-transfer.mjs` | 分块快路径吞吐（`uploadBuffer`/`uploadFile`/`download*`） | 联调传输性能 |
| `tools/bench-sizes.mjs` | 按文件大小对比旧/快路径延迟，用来定 `transferFastPathBytes` | 调阈值时 |
| `tools/bench-probe.mjs` | 带宽与载荷形状探针（exec/base64/预压缩） | 怀疑瓶颈时 |
