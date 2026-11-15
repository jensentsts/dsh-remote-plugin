# dsh-remote —— 插件安装与设置参考

> **0.4 升级先读**：[安全与迁移指南](SECURITY.md)。默认不再降级到旧握手；level 1/2 文件读取需要显式配置 `readRoots`。历史单机示例仅说明连接方式，不代替当前安全策略；请使用 DSH bundle manager 管理安装，不手工改活动 profile。

> **一句话**：装完之后，本机的 DSH 可以把**另一台机器的 DSH 当成一个 agent**来用——
> 以"用户"身份对它发言、等它跑完一整轮、取回回复；还能取回/投递它的会话上下文，
> 以及在它上面执行命令、读写文件。
>
> 通道是**单一 TCP 长连接**（典型是 frp 隧道），
> **双向 X25519 认证 + AES-256-GCM 逐帧加密 + 计数器防重放**。

---

本文件只讲**安装与设置**；总览看 [`../README.md`](../README.md)，
协议与威胁模型看 [`SECURITY.md`](SECURITY.md)，内部设计与踩坑看 [`DEV-NOTES.md`](DEV-NOTES.md)。

---

## 1. 插件包内容

```
dsh-remote/                   ← 把整个仓库复制到目标机器（不含任何密钥）
├── package.json
├── cordis.patch.yml          ← 两端 patch 模板，照抄进目标 profile
├── src/
│   ├── protocol.ts           ← 线协议 + 握手（只用 node:crypto，零依赖）
│   ├── keys.ts               ← 密钥解析（内联 / 文件 / 自动生成）
│   ├── server.ts             ← 被控端插件：监听 + 驱动本机 agent + 工作区属主登记
│   └── client.ts             ← 主控端插件：注册 remote_* 工具
├── test/protocol.test.ts     ← 协议四项自测
├── tools/gen-keys.py         ← 生成 / 复用密钥对（纯标准库）
└── docs/                     ← 安装指南 / 安全设计 / 开发信息

keys/                         ← 密钥，由 gen-keys.py 生成，**不进 git**
├── active/
│   ├── server-side/          ← 装到【被控机】: server.key + client.pub
│   └── client-side/          ← 装到【主控机】: client.key + server.pub
└── archive-<name>/           ← 用 --archive 冻结的快照
```

**零外部依赖**：只用 Node 内置模块，不需要 `pnpm add`。
用一个 `file:///` 的 patch 行指到 `src/server.ts` / `src/client.ts` 就能加载
（profile 的 `cordis.patch.yml` 支持直接指向 TS 源码，由运行中的 checkout 转译）。

---

## 2. 装【server 端】（被控机）

### 2.1 放密钥

把 `../keys/active/server-side/` 里的两个文件放到运行端的 DSH 家目录：

```powershell
$dst = "$env:USERPROFILE\.dsh\dsh-remote"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item ..\keys\active\server-side\server.key  $dst\server.key
Copy-Item ..\keys\active\server-side\client.pub  $dst\client.pub
```

> 插件默认就去这里找：`${DSH_HOME}/dsh-remote/server.key` 与 `client.pub`。
> 想换位置见第 5 节的设置项。

### 2.2 加 patch 行

编辑 `%USERPROFILE%\.dsh\profiles\<你的 profile>\cordis.patch.yml`，在**文件末尾**追加：

```yaml
- insert:
    - id: dsh-remote-server
      name: 'file:///C:/Users/<you>/dsh-remote/src/server.ts'
      config:
        host: '127.0.0.1'
        port: 11325
```

> - `name` 里的路径请改成**你实际复制的目录**（注意是 `file:///` 三条斜杠 + 正斜杠）。
> - `port: 11325` 必须和 frp 那条隧道里填的**本地端口**一致。
> - **这个端口必须是这个插件独占的**：如果之前测试用的别的东西还占着 11325，
>   先把它停掉，否则插件会报监听失败。

### 2.3 重启 DSH

```powershell
# 停掉当前的 dsh web，然后重新起
pnpm dsh web
```

启动日志里应该能看到两行：

```
dsh-remote-server: identity fingerprint <xxxx:xxxx:xxxx:xxxx> from C:\Users\<you>\.dsh\dsh-remote\server.key
dsh-remote-server: listening on 127.0.0.1:11325
```

并且会打印它自己的**公钥 PEM**——那一整段（含 `BEGIN PUBLIC KEY` / `END PUBLIC KEY`）
就是主控机要 pin 的东西，贴进 client 的 `peerPublicKey`，或存成文件。

### 2.4 验证监听

```powershell
Get-NetTCPConnection -State Listen -LocalPort 11325
```

看得到 `127.0.0.1  11325` 并且属主是 node 就对了。

### 2.5 把新版受控端同步到被控机

**先看被控机是哪一种装法**（`remote_ping` 看不出，用 `remote_fs_list` / `remote_exec` 看 patch 行）：

- **打包形态（推荐，2026-10-08 起被控机就是这样）**：profile 的 `package.json` 里
  `dsh.profile.bundles` 含 `dsh-remote`，`node_modules\dsh-remote` 是指向插件目录的 junction，
  patch 行是 `name: 'dsh-remote'` / `'dsh-remote/server'`。
  **同步的是预编译产物**：

  | 要拷的文件 | 说明 |
  |---|---|
  | `lib/server.js` | 受控端本体（自包含：reuse / journal / exec-registry 都已 bundle 进去） |
  | `lib/client.js` | host 半（`exports["."]`）；只在它变了才需要 |
  | `client.js` | 浏览器半（设置面板就是它注册的） |
  | `package.json` / `cordis.patch.yml` | 只在导出表或 row 声明变了才需要 |

  好处：**对端不需要 TypeScript 加载器**，也就不受 strip-only 那条限制（见 §2.5b）。
  拷完重启即可，`remote_ping` 的 `build` 应变成新标记。

  **r21+ 可以从本机直接真机验收**（不需要重启本机 DSH，用本机密钥拨过去）：
  ```
  node --import tsx/esm tools/probe-caps.mts <host> <port> [presetId]
  ```
  它会校验 `caps.*` 自述、目录内容、一次真实 `caps.call`、以及"调用前后对端会话集合不变"。

- **源码形态（旧装法）**：patch 行是 `file:///…/src/server.ts`，从磁盘直接加载 TS。
  同步的是源码，而且**必须带齐它新引入的模块**（否则 `import './reuse.ts'` 直接找不到）：

  | 要拷的文件 | 说明 |
  |---|---|
  | `src/server.ts` | 受控端本体 |
  | `src/reuse.ts` | r11 起 `server.ts` 就 import 它（`familyMatches` / `normalizePath` / `orderReusableSessions`） |
  | `src/exec-registry.ts` | r13 新增，`exec.cancel` 的记账对象 |
  | `src/journal.ts` | r14 新增，轨迹 |

  **不要**覆盖被控机自己的 `protocol.ts` / `link.ts` / `peer-fs.ts`：那几份在该机上带有
  本仓库没有的修正（例如 stripfix），而新版 `server.ts` 用到的
  `HandshakeError` / `HANDSHAKE_TIMEOUT_MS` / `fingerprint` / `publicToPem` / `serverHandshake`
  在两边都存在，所以**留着它们是对的**。

  > **兼容性已实测**：把新版 `server.ts` / `reuse.ts` / `exec-registry.ts`
  > 与**该机自己的** `protocol.ts` / `link.ts` / `keys.ts` / `peers.ts` 放在一起跑
  > `tsc --noEmit`，整套通过。

### 2.5b 源码形态的硬限制：对端以 Node **strip-only** 加载 TS

被控端（dsh desktop）加载 `file://` 的 `.ts` 时**没有** `--experimental-transform-types`，
所以**擦不掉的语法会让它加载失败**——参数属性（`constructor(private readonly x: string)`）、
`enum`、`namespace`。而本地用 esbuild 打包时这些都会被编译掉，**本地永远看不出问题**。
2026-10-08 就是这么翻车的：`reuse.ts` 的参数属性让对端报
`ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX`，插件加载不了。

两道闸，改完源码跑一次：
- `tsconfig.json` 里的 `erasableSyntaxOnly`（编译期）；
- `node tools/check-strip-safe.mjs`（不依赖 tsconfig，**可以在对端机器上直接跑**）。

**打包形态没有这个问题**（对端加载的是 `lib/*.js`），所以换装 bundle 也顺手消掉了这条风险。

### 2.6 被控机也要有设置面板？（重要）

Plugins 页只给 **bundle patch 声明的 row** 画卡片，而且浏览器半只对**精确包名行**或
**包内 `file://` 行**附着。所以：

- 按老模板装 `name: 'dsh-remote/server'`（子路径行）→ **不加载浏览器半**，没有配置页；
- 在 profile 自己 patch 里手加 row → 没有 row 卡片，注册了也没人派发；
- **包必须声明 `dsh.bundle`**（`package.json` 的 `"dsh": {"bundle": {"patch": "./cordis.patch.yml"}}`）：
  没有这一项，DSH 会把这个 bundle **静默跳过**（只往 stderr 打一行），行 id 就没人声明，
  重启后受控端根本不加载——**手挂形态的旧机器最容易在这里翻车**。
- **不要**同时挂"精确包名行 + `file://` 行"：两个来源解析到同一个包名是**启动期硬错误**。

正确做法（`cordis.patch.yml` 已经这么声明了）：

1. 被控机也装这个 **bundle**；
2. 保留 `dsh-remote-client` 行（它就是承载面板的那一行），把它设成
   `toolEnabled: false`——它不会拨号、也不注册工具，只为把包和设置页带上；
3. **启用** `dsh-remote-server` 行（默认 `disabled: true`），填它的 `host`/`port`。

这样被控机的 Plugins 页里，`dsh-remote-server` 那一行就有 Configure，可以改监听地址、
密钥、`workspace`、`defaultPreset`、`promptGuidance` 等。

> 密钥类字段的"已设置/未设置/清除"读的是 Host 的 settings describe 镜像
> （设置控件快照本身不带这个标志）；镜像取不到时会显示成"未设置"。
> 密钥留空即保持不变。

---

## 3. 装【client 端】（主控机）

同一份包，装法一样，只是换成另一半密钥、换成 client 行：

```powershell
$dst = "$env:USERPROFILE\.dsh\dsh-remote"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item ..\keys\active\client-side\client.key  $dst\client.key
Copy-Item ..\keys\active\client-side\server.pub  $dst\server.pub
```

```yaml
- insert:
    - id: dsh-remote-client
      name: 'file:///C:/Users/<you>/dsh-remote/src/client.ts'
      config:
        host: 'tunnel.example.com'      # 对端可达地址（隧道给的公网地址、局域网名、Tailscale 名…）
        port: 10000              # 对应端口
        # 注意：这两项**没有默认值**，必须显式设置；
        # 不设时插件启动会打印提示、调用工具会报一条明确的错。
```

client 端**不需要** `--new-session` 之类的东西，它懒连接：
第一次调用工具时才拨号，之后复用同一条已认证会话；隧道断了自己重连。

---

## 4. 工具清单（client 端注册给模型的）

| 工具 | 作用 |
|---|---|
| `remote_ping` | 链路探活：对端版本、主机名、活跃会话、本侧指纹 |
| `remote_exec` | 在对端机器上跑 PowerShell/cmd，回传 stdout/stderr/退出码；本地按停时对端那条命令也会被停掉（`exec.cancel`，对端 r13+） |
| `remote_agent_prompt` | **核心**：把一段用户发言交给对端 agent，等这一轮跑完，取回回复。**不传 `session_id` 时默认复用已有会话**（先续接本机会话上次用的那个，否则挑对端已存在的同名会话）；`session_id` 相同即续接同一会话（保留上下文）；`new_session=true` 强制新开；`preset_id` 与 `workspace` 只在会话首次创建时生效 |
| `remote_agent_ensure` | 先建好/续接一个会话但不发言（可指定 preset） |
| `remote_agent_events` | 读对端某会话的事件流（只含必要字段），用于**上下文取回/压缩/再投递** |
| `remote_journal` | 读**远端的执行轨迹**（见 §4.6）：默认只返回上次读过之后的新条目 |
| `remote_agent_interrupt` | 打断对端正在跑的那一轮 |
| `remote_preset_list` | 列出对端可用 preset（找"创造模式"的 id） |
| `remote_fs_list` / `remote_fs_write` | 列目录 / 写文本文件；内容较大且对端 r19+ 时 `remote_fs_write` 自动走分块快路径（见 §4.8） |
| `remote_put_file` | 把**本机文件**流式上传到远端（一个工具调用，字节不经过模型上下文）；分块 + 逐块 gzip + sha256 校验 + 原子落盘（对端 r19+），旧对端退回整文件 `fs.write` |
| `remote_get_file` | 把**远端文件**流式下载到本机（同上，含 sha256 校验与临时文件 rename）；旧对端退回 `fs.read` 分页 + `fs.hash` 校验 |
| `remote_run_start` / `remote_run_status` / `remote_run_cancel` / `remote_send_message` | **后台运行**：长任务立即返回 `runId`、后台跑；事后取交付 / 追加指示 / 打断（见 §4.9） |
| `remote_workers` / `remote_worker_prompt` / `remote_pool_dispatch` / `remote_team_dispatch` | **多 worker 池 + Agent Teams**：列 peer / 指定一台干 / 并行派发聚合 / 登记到共享任务板（见 §4.9） |
| `remote_capabilities` | **能力目录**：列对端某 preset 可直接 function call 的工具（含参数 schema）、插件清单、preset/子智能体类型、子智能体 provider、活跃会话（只读）。只挂 preset scope，不建会话（见 §4.10） |
| `remote_tool_call` | **按名直调**：在对端直接执行一个已注册工具本体（不建/不续会话、不耗远端模型轮次）；本机同名工具遮挡或未镜像时用它 |

典型用法：

```
remote_agent_ensure  session_id="job-1" preset_id="cordis"
remote_agent_prompt  session_id="job-1" text="读一下这个目录，然后告诉我它是干什么的" \
                     workspace='E:\work\job'
remote_agent_events  session_id="job-1" from_seq=0     # 把中间过程取回来
```

**一个 chat 只对应一个远端对话**（严格，默认行为，可用 `reuseSessions: false` 关掉）：

1. 远端会话 id = `remote-<sha256(本机 chat id) 前 12 位>`，由本机 chat 唯一决定——
   同一个 chat 每次续接同一段，不同 chat 必然不同；
2. 因此**换 `workspace` / `preset` 也不会另开一段**；对端已有该 id 就续接（`created=false`），
   没有才创建一次；
3. `${DSH_HOME}/dsh-remote/client-sessions.json` 只记"用户显式选过的那一个"
   （显式 `session_id` 或 `new_session` 之后），它是缓存，删掉只是忘掉这个选择；
4. `adoptExistingSessions: true`（默认关）才会在本 chat 尚无对话时，接管对端一个
   没人认领的旧会话——用来回收旧版本遗留的会话。

会话行会写明这次是 `(reused: ...)` 还是 `(created)`，一眼能看出复用有没有生效。
想故意另起一段对话（保留多开能力）：传 `new_session=true`。

**打断**：本机用户中断 → 插件用对端自己的 `agent.interrupt` 一起中断远端那一轮，
对**正在跑的 `remote_exec` 命令**则用 `exec.cancel` 停掉（老对端只能停本机这一侧）；
远端用户按停或往会话里插话 → 会回传到本机，本机 agent 立即停下、把决定权交回用户。

> `workspace` / `preset_id` **只在会话首次创建时生效**；会话一旦建好就固定了。
> 想换工作目录又不想污染这个 chat 的对话，就显式换一个新的 `session_id`。
>
> 小坑：如果只改 patch 行里的 `config`，**不会**让已加载的插件重新 `apply`，
> 所以改 `workspace` 更推荐用「每次调用传参」，或者直接改 `settings.yaml`
> 里 `dsh-remote-server:` 那一段（设置层是热生效的）。

---

## 4.5 远端对话就是 subagent / task（默认开）

默认**开**。打开时，本机聊天把远端委派**按 subagent 分组**，本地 Stop 会经 `dispose()`
转发成对端的 `agent.interrupt`。**只需两件事**：

1. **确认开关**：client 侧 `subagentProvider`（默认 `true`；面板里可关，**改完即时生效**）。
   插件会同时注册 subagent provider `remote` **和**工具 `subagent_remote`——
   **不需要改 composition**：
   - provider 让运行时发出 `subagent/start` / `subagent/end`（`local: false`）；
   - 工具名叫 `subagent_remote`，聊天据此把这次调用归为 subagent 委派。
2. **把 `@deepseek-ai/dsh-subagent` 链进插件目录**（profile-linked 插件不解析 harness peer）：

   ```powershell
   New-Item -ItemType Junction `
     -Path "$plugin\node_modules\@deepseek-ai\dsh-subagent" `
     -Target "<harness>\packages\subagent\subagent"
   ```

   没链也能启动：provider 注册失败只记一条 warn，插件本体不受影响。
   kit 是**动态 import** 的——这类可选依赖写成静态 import 会让没链的机器整个插件加载失败。

**想要后台运行（`subagent-N` 任务行）才需要那行 composition**。它和上面的内置工具**二选一**
（两者都用 `subagent_remote` 这个名字，同时存在会撞名）：

```yaml
- insert:
    - id: tool-subagent-remote
      name: '@deepseek-ai/dsh-tool-subagent'
      config:
        provider: remote
        toolName: subagent_remote
        backgroundMode: one-shot
        maxDepth: provider-managed     # 必须：本 provider 没有 depthLimit 能力
```

**边界（先知道再开）**：远端会话**不会**出现在 `list_agents` / subagent 目录里，也**打不开**、
没有 `send_message`；它是 one-shot 委派，一个 run 一个结果。要"能打开的远端子会话"
属于另一档工程（把远端上下文镜像成本地子会话），本插件不做。

---

## 4.6 远端的执行轨迹（journal）

**它是什么**：被控端把**每一次操作**（`exec`、文件读写、驱动会话的轮次、模型调用）以及**本机用户的打断**，
在发生的那一刻追加进一份轨迹文件。它和普通会话的区别在于**循环的形状**：

```
普通会话：  用户 → 模型 → 工具 → 模型 → …        （每一步都花模型调用）
轨迹：     主控 → 插件 → 这台机器               （追加一条记录，不花任何模型调用）
```

所以轨迹是"把痕迹留全"和"省模型调用"同时做到的那半：记录成本只有校验 + 一次批量落盘。

**怎么读**（`remote_journal`）：

| 参数 | 作用 |
|---|---|
| 省略 | 接着**本 chat 上次读到的位置**继续（游标由插件按 chat 记在 `${DSH_HOME}/dsh-remote/client-journal.json`）；从没读过则取**尾部** |
| `from_seq=0` | 从头读（仍然受 `limit` 限制） |
| `limit` | 最多几条，默认 50，上限 500 |
| `full=true` | 带上每条的操作细节（更占上下文） |

每条默认只有一行：`#42 10:31:07 op  exec Get-ChildItem C:\a → exit 0`。**细节是 opt-in**——
这是刻意的：轨迹的价值在于"便宜地知道发生了什么"，而不是把整段输出再塞回上下文。

**保存与轮转**：默认 `${DSH_HOME}/dsh-remote/journal.jsonl`，超过 8 MB 轮转并保留上一代（`.1`）；
`seq` 跨轮转与重启单调递增，所以游标永远有效。`journal.read` 自己**不会被记进轨迹**（否则轮询会喂饱自己）。

**它不是一个 DSH 会话**（这是查过源码后的选择）：会话存储把"持久化写入器"绑在**拥有写句柄**的会话上
（只有 agent 生命周期会开），插件自己 `sessions.create()` 的会话**重启即消失**；而自定义事件类型虽然能追加，
却因为"已知事件类型表"是**构建期从仓库生成的**而会在重启后**不可读**。要两全，代价是维护一份会长大的会话文件
（冷读要整份解码）外加"GUI 打开冷会话会把它升级成真 agent"的地雷。所以轨迹用**插件自己的只追加文件**做真相源，
把"可视化的会话"留作可选（见 DEV-NOTES 3.19）。

---

## 4.7 远端费用回传（与 dsh-cost-meter 兼容）

**它是什么**：本机装了 `dsh-cost-meter` 时，远端每一轮花的是**对端账户**的 token，本机账本看不到。
dsh-remote 把远端的**逐次调用用量**回传，写进 cost-meter **唯一官方支持的第三方入口**
`${DSH_HOME}/storages/cost-meter/external_usage.json`（records 模式）；由 cost-meter 用自己的价表
按每条记录的 `at` 时刻计价（含 DeepSeek 峰谷与长上下文规则），在「设置 → 费用 → 外部用量」里显示为
来源 `remote/<peerName>`，并计入**今日 / 本月 / 累计合计**和官方余额对账。

**数据链**（每轮结束自动跑，全部 best-effort，失败只写 debug 日志，绝不影响工具返回）：

```
远端一轮结束
  → 本机向对端 `usage.read`（只读 op，permission level 1，按会话 seq 增量）
  → 本机持久化 ${DSH_HOME}/dsh-remote/client-cost.json（每会话游标 + 调用记录，≤2000 条，跨重启保留）
  → 原子重写 external_usage.json（临时文件 + rename；保留其他生产者的 source；≤2000 条 / 450 KB）
```

字段映射：`usage.input/output/cacheRead→cached/cacheWrite/reasoning`；记录 id 是
`<远端会话 id>:<seq>`，所以重复拉取、重装、删游标都不会重复计费（快照整份替换）。

**口径与边界（重要）**：

- **会话徽章 / 「本会话」总额仍是本机 DSH 账本口径**，远端费用进入 cost-meter 的「外部用量」与合计区，
  不会掺进单会话徽章——这是 cost-meter 的官方数据契约（它没有第三方「会话费用注入」接口）。
- 费用由**本机** cost-meter 的价表决定。远端若用了本机价表解析不到的 provider/model（冷门渠道），
  cost-meter 会**忽略整份快照**（fail-closed）：先给它加自定义模型价格，或临时 `costReporting=false`。
  已知本地推理渠道（ollama 等）的记录在写入前就被跳过。
- 只回传**被本插件驱动的那一个远端会话**的模型调用；对端 agent 自己再派生的 subagent 会话不计。
- 对端重启后，没有活动句柄的会话返回 `available:false`（不报错），下一轮会补齐——游标保证不丢不重。
- 对端不认识 `usage.read`（旧构建）时自动跳过，不影响任何工具。

**怎么确认在工作**：`remote_ping` 的 `remoteCost`（`enabled` / `source` / `records` / `lastAt`）；
cost-meter 面板的「外部用量」里出现 `remote/<peerName>`。不想回传就把 `costReporting` 设为 `false`。

---

## 4.8 大文件传输（分块 + 压缩 + 流水线）

**问题**：旧路径把整个文件塞进**一个** base64 JSON 帧，在 frp 隧道（≈2.6 Mbit/s、RTT≈78 ms）上，
8 MiB 文件写要几十秒到 100 秒，大帧还容易超时、占内存。

**做法**（对端 r19+，通过 `sysinfo.ops` 能力协商，旧对端零影响）：

```
上传：fs.put.begin → 并行 N×fs.put.chunk(gzip) → fs.put.commit（sha256 校验 + 原子 rename）
下载：fs.stat → 并行 N×fs.get(gzip) → 写临时文件 → fs.hash 校验 → rename
```

- 分块默认 1 MiB、并发 4（可配），**逐块 gzip**（只有压到 95% 以下才用，随机数据自动退回 raw）。
- 双端 sha256 校验；服务端先写同目录 `<target>.<uuid>.dshremote-upload` 临时文件，
  校验通过才 `rename` 覆盖；客户端下载同理。失败自动重试 2 次（短退避），本机按停会中止并清理。
- 服务端有并发上限、上传 TTL（默认 10 分钟）、大小上限（默认 1 GiB），进程退出时清掉在途临时文件。
- `remote_fs_write` 的内容 ≥ **512 KiB**（`transferFastPathBytes`）时走快路径；阈值以下单帧 `fs.write`
  只需 1 个 RTT，反而更快（实测 256–512 KiB 附近快路径多出的 begin/commit 往返会抵消收益）。
- peer 文件系统提供者（`/peers/<name>/…`，如果部署挂了）同样走快路径：大文件读取用并行 `fs.get`、
  写入用分块上传，小文件保持单窗口读取。
- **传大文件不需要经过模型上下文**：用 `remote_put_file` / `remote_get_file` 传路径，字节直接走链路。

**实测**（8 MiB，同一 frp 隧道，r19 部署前后各测一次）：

| 载荷 | 旧路径 写 / 读 (MiB/s) | 快路径 写 / 读 (MiB/s) | 说明 |
|---|---|---|---|
| 随机（不可压缩） | 0.17 / 0.42 | 0.42 / 0.42 | 写 ~2.5×；读受带宽 + base64 硬上限 |
| 源码类文本（约 2× 压缩） | 0.44 / 0.41 | 0.84 / 0.86 | 约 2×，压缩比直接换成吞吐 |
| 重复文本（压缩极高） | 0.25 / 0.42 | 21.06 / 22.33 | 50–80× |
| 全零（压缩极高） | 0.08 / 0.43 | 21.45 / 23.61 | 50–270× |

> 隧道带宽是硬上限：**不可压缩数据**的收益来自"去掉大帧卡顿 + 并行流水线"，不是压缩；
> base64 的 ~33% 线上膨胀仍然存在（协议帧是 JSON；换二进制帧需要协议版本协商，暂未做）。

**配置**（client）：`transferChunkBytes`（1 MiB）、`transferConcurrency`（4）、
`transferCompression`（true）、`transferFastPathBytes`（512 KiB）。
**配置**（server）：`transferMaxBytes`（1 GiB）、`transferMaxChunkBytes`（8 MiB）、
`transferMaxActive`（8）、`transferUploadTtlMs`（10 min）、`transferBeforeMaxBytes`（1 MiB）。

**排查**：`remote_ping.build` 是否 r19+、`sysinfo.ops` 是否含 `fs.put.begin`/`fs.get`；
大文件报 `FS_TOO_LARGE` 就调大 `transferMaxBytes`；想强制走旧路径就把 `transferFastPathBytes` 调大。
**边界**：没有断点续传（失败重传整文件，单块自动重试 2 次）；只传单文件，不做目录递归/增量同步；
`writeText` 的 `before`（旧内容 diff）只对 ≤1 MiB 的原文件返回文本，更大的返回 `null` + `beforeBytes`。

---

## 4.9 后台运行 · worker 池 · Agent Teams

### 4.9.1 后台运行（对齐官方 subagent 语义）

官方 `tool-subagent` 行提供的"后台跑 + send_message"能力，这里由插件自己补齐（不动 composition）：

| 工具 | 作用 |
|---|---|
| `remote_run_start` | 起一个后台运行，**立即**返回 `{runId, sessionId, origin, status:'running'}`；不阻塞本轮 |
| `remote_run_status` | 省略 `run_id` 列出最近运行（先 running 后 finished，最多 32 条/24h）；带 `run_id` 取完整结果，`wait_ms` 可等最多 10 分钟，超时返回 `running` 不抛错 |
| `remote_run_cancel` | 打断：标记 `cancelling` 并调对端 `agent.interrupt`；最终状态等对端结算回来 |
| `remote_send_message` | 给**正在跑的**远端任务追加一条 user 消息（对端 r20+ 用 `agent.note`，注入 inbox 不阻塞；旧对端退回排队 `agent.prompt`） |

- 结果不会自动进本机上下文——用 `remote_run_status` 取回；这是为了"后台运行不占本轮上下文"。
- 上限 `maxBackgroundRuns`（默认 8）；`backgroundRuns: false` 整体关闭（工具集在加载时决定，改后需重启 DSH）。
- 本机按停会把 run 标 `cancelling` 并中断对端；远端轮次里的提问仍走 `remote_answer_question`。
- run 注册表是**进程内**的：本机重启后未收的 run 丢失（远端那一轮的结果仍可从远端会话/`remote_agent_events` 看到）。

### 4.9.2 多远端 worker 池

| 工具 | 作用 |
|---|---|
| `remote_workers` | 列出 `peers` 里声明的每个 peer：连通性、权限、这个 chat 在该 peer 对应的远端会话 id |
| `remote_worker_prompt` | 在指定 peer 上做一次前台 `agent.prompt`（等交付），用于"这台机器专门干这个" |
| `remote_pool_dispatch` | 把同一任务**并行**派给多台 peer（≤8），逐台聚合 `{ok, reply, error, durationMs}`；单台失败不影响其他台；本机按停会中断所有在途 worker |

每个 peer 一段确定性会话（`anchorSessionId(prefix, peer + chatId)`），不同 peer 不会串台；
peer 列表来自 client 配置的 `peers`（单 peer 部署用 legacy `host`/`port` 也照样能用池工具）。

### 4.9.3 Agent Teams 看板

`remote_team_dispatch(description, prompt, peer?)`：在 Agent Teams 会话里把这次远端工作**登记到共享任务板**——
`createTask`（unowned）→ `claim`（owner=调用方）→ 远端前台跑 → `edit` 写回结果摘要 → `complete`，返回 `taskId`。
不在 Team 会话里（或没有 `agentTeams` 服务）时会**明确报错**，不会静默退化；普通并行派发请用 `remote_pool_dispatch`。

> **上游限制**：`spawn_teammate` 只能生成**本机** teammate，远端 peer 不在 roster 里。
> 所以看板任务 owner 是调用方（Lead/某个 teammate），远端 worker 落成"该成员名下的外部工作"。
> 想让它更像队友：Lead 先 `spawn_teammate` 一个本机 teammate，让它用 `remote_pool_dispatch` 指挥远端 worker，
> 这样任务的执行与进度都在团队里可见。

> **费用口径**：后台运行（`remote_run_*`）跑在本 chat 的远端会话上，结算时照常回传 cost-meter；
> 而 worker 池 / team dispatch 用的是**每 peer 独立会话**，这些轮次的 token **暂不进入本机
> cost-meter 的远端回传**（只回传主远端对话）。要统计这部分费用，请看对端自己的会话/用量。

---

## 4.10 能力直连（把远端插件当本地插件用）

**用途**：让本机模型**直接 function call 远端的能力**（远端插件注册的工具、MCP、远端专用工具），
不必为一个工具调用去驱动远端 agent 一整轮；而且**不新建、不续接远端对话**。

### 4.10.1 工作方式

```
本机模型 → 本地 tools 注册表里的镜像（名字 = 远端原名）
        → dsh-remote-client 发 caps.call（带 callId）
        → 对端 dsh-remote-server：
             agentPresets.acquireScope(该 preset)   ← 只挂 preset scope，不是会话
             tools.get(name, scope)
             definition.execute(args, {agent: undefined, signal})  ← 对端插件本体
        ← 渲染好的 content（对端工具自己的 render）
```

- `caps.list`（等级 1，只读）：工具 + 参数 schema、插件清单（`compositionInventory`）、
  preset/子智能体类型、子智能体 provider、对端活跃会话（只读信息）。
- `caps.call`（等级 3 = danger-full-access）：跑一个工具本体；`callId` 由调用方给，
  便于 `caps.cancel` 精确打断；对端 `maxToolCallTimeoutMs` 兜底。
- `caps.cancel`（等级 3）：停掉某个还在跑的直接调用（best effort；不理会 signal 的本体会跑完）。
- 对端 `tools/change` 时推 `caps.changed`；本机重读目录并**增/删/更新镜像**，无需重启。

### 4.10.2 命名与作用域（零前缀，按 agent 隔离）

镜像用**远端原名**注册，但注册进**每个 agent 自己的作用域**（`agent.ctx`），不进全局层：

- 安装时读取该 agent 当前**完整可见面**（host 工具 + 它 preset 的工具），同名就**跳过**：
  两边都有的工具（`pwsh`/`read`/`edit`/`grep`…）本地版本永远优先，不会被覆盖；
- 远端独有的工具（远端插件/MCP/远端专用）：直接以原名补进该 agent，模型无感调用；
- **不碰全局层**：不会和任何 host 插件抢名字（v0.2.0 c13 的启动崩溃正是全局注册
  `load_workspace_dependencies` 与官方插件重名导致的；c14 改成 agent 作用域后这类冲突
  在结构上不可能发生）；
- 被本机同名工具遮住的远端版本，用 `remote_tool_call(name, arguments)` 调；
  `remote_capabilities` 会把"本机同名优先、未镜像"的工具标出来；
- 新 agent 创建时自动安装；远端目录变化（`caps.changed`）时**重建所有 live agent 的镜像**。

### 4.10.3 远端拒绝哪些工具

对端 config `deniedTools`（默认 `ask_user_question`, `exit_plan_mode`, `present`）+
硬性规则：所有 `remote_*`/`remote__*` 桥工具一律不可直调（防套娃）。
目录里会给出 `callable:false` + `reason`。

### 4.10.4 边界

- 一次 `caps.call` **没有 session**：对端 `exec.agent === undefined`。需要 agent 的工具
  （`subagent`/`todo_write`/`goal`…）会以工具自己的错误结束——这是刻意的，不能为了跑工具
  去新建会话。要"让远端 agent 干活"用 `remote_agent_prompt`/`subagent_remote`。
- 直调**绕过对端 tools 的 pre/post-execute 策略链**（超时包装、guards、审批/ask），
  但工具本体内部的检查（如 sandbox 策略活在工具插件里）仍然生效；因此 `caps.call`
  必须是 level 3。
- 目录/镜像是**部署级**的（client 主链路 + 一个 preset），不是"每个远端会话一份"。
- 若对端是 r21 之前的版本：没有 `caps.list`，本机记一行日志、不镜像任何工具。

---

## 4.11 远程路径（`/rmt/…`）

**用途**：把对端文件挂成**本机绝对路径**，于是 `@` 补全、`read`/`write`/`edit`/`read_image`、
以及 chat 里的 Markdown 图片共用同一个写法：

```
/rmt/E:/data/a.jpg                默认远端机（defaultPeer，可在设置里选）
/rmt/home-pc/E:/data/a.jpg       指定 peer=home-pc
/rmt//home/u/a.jpg                   默认机的 POSIX 绝对路径（第二个 / 属于路径）
```

**为什么是 `/rmt/…` 而不是 `rmt:/`**：chat 的 Markdown 图片经 host 的
`/api/file?path=` 读取，该路由只接受 OS 绝对路径；`rmt:/…` 在 Windows 上不是绝对路径，
会被 400 拒绝。`/api/file` 的字节读取本身走 `ctx.fs`，所以只要联邦后端认识 `/rmt/…`，
图片、`@`、文件工具就全通了。`rmt:/…` / `<peer>:/…` 保留为兼容别名。

### 4.11.1 启用（本机 profile `cordis.patch.yml`，重启生效）

远程路径需要换掉本机的两处默认实现：fs 后端与 file-reference provider。

```yaml
- id: fs-sandbox
  disabled: true
- id: file-reference-local
  disabled: true
- insert:
    - id: dsh-remote-peer-fs
      name: dsh-remote/peer-fs
    - id: dsh-remote-file-reference
      name: dsh-remote/file-reference
```

- `dsh-remote/peer-fs`：`FederatedFileSystem`，继承原来的 sandbox 后端；本地路径行为不变，
  另外把 `/peers/<peer>/<绝对路径>`、`/rmt/…`、`rmt:<绝对路径>`、`<peer>:<绝对路径>`
  路由到对端；
- `dsh-remote/file-reference`：继承原来的本地补全 provider，本地查询行为不变；
  `/rmt/…` / `rmt:` / `<peer>:` 查询直接列对端目录（盘符枚举结果按 peer 缓存 5 分钟）。

### 4.11.2 路径写法

| 写法 | 含义 |
|---|---|
| `/rmt/E:/data/a.jpg` | **默认远端机**的 `E:/data/a.jpg`（补全与 Markdown 的标准形式） |
| `/rmt/home-pc/E:/data/a.jpg` | 名为 `home-pc` 的 peer 的同一路径 |
| `/rmt//home/u/a.jpg`、`/rmt/home-pc//home/u/a.jpg` | POSIX 远端绝对路径（第二个 `/` 属于路径） |
| `rmt:/E:/a.jpg`、`rmt:\E:\a.jpg` | 兼容别名 = 默认远端机 |
| `home-pc:/E:/a.jpg` | 兼容别名 = 指定 peer（scp/rsync 风格） |
| `/peers/<peer>/E:/…` | 底层显式挂载点写法 |

- **补全统一输出 `/rmt/…`**：`@` 里输入 `rmt:` / `<peer>:` / `/rmt/` 都可，选中的候选
  一律是 `/rmt/…`（只有它能进 Markdown 图片）；
- **默认远端机**：`dsh-remote-client.defaultPeer`（设置 GUI 可改；留空 = 第一个声明的 peer）。
  `dsh-remote-peer-fs` 行自己的 `defaultPeer` 作为兜底（独立挂载时用）；
- **peer 名**就是 `dsh-remote-client.peers` 里的 key（`peerName` 是 legacy 单 peer 的 key）；
- 选中的目录 mention 由 DSH 的 formatter 补尾斜杠（候选本身**不带**尾斜杠，不会出现 `//`）。

### 4.11.3 权限

- 读/写/编辑都沿用该 peer 的 `maxPermission`：默认与主链路一致（单 peer 部署通常已是最宽），
  越权操作在本机一侧就被拒绝，不会先发到对端；
- 对端仍然独立执行自己的 permission preset（服务端有最终话语权）。

### 4.11.4 边界

- `glob`/`grep` 是**本地 spawn 实现**，不会进入联邦 fs，因此不搜远端路径；查远端目录用
  `read`（目录会报 not a regular file + list 提示）或 `remote_fs_list`；
- `read_image` 与 Markdown 图片走 fs 字节读取，因此可以直接显示远端图片；上限是
  attachment 的 `maxImageBytes`（默认 20 MiB），更大的图会被 413；
- 没启用 `dsh-remote-peer-fs` 的机器上，`@` 不会补全远端路径，`read` 会把 `/rmt/…`
  当普通本地路径。

---

## 5. 设置项（GUI 里可改，`settings.yaml` 落盘）

两个插件各自注册一个设置区，命名空间分别是 `dsh-remote-server` 和
`dsh-remote-client`；字段按下面的表来（GUI 里能改，落盘到 `settings.yaml`）：

**server（`dsh-remote-server:`）**

| 字段 | 默认 | 说明 |
|---|---|---|
| `host` | `127.0.0.1` | 绑定地址；frpc 在同一台机器时保持回环 |
| `port` | `11325` | 绑定端口 = 隧道本地端口 |
| `privateKey` | 空 | 内联私钥（PEM / 64 hex / base64），**secret**，优先于文件 |
| `privateKeyFile` | `${DSH_HOME}/dsh-remote/server.key` | 私钥文件；自动生成时也写这里 |
| `autoGenerateKey` | `true` | 没有密钥时自动生成并落盘 |
| `peerPublicKey` | 空 | 内联对端公钥，优先于文件 |
| `peerPublicKeyFile` | `${DSH_HOME}/dsh-remote/client.pub` | 固定的对端公钥 |
| `workspace` | 空（用进程 cwd） | 远端被创建会话的工作目录 |
| `defaultPreset` | 空（用部署默认） | 远端新会话默认 preset |
| `maxHandshakeFailures` | `8` | 同一来源握手失败多少次后拉黑 |
| `lockoutSeconds` | `900` | 拉黑时长 |
| `maxExecTimeoutMs` | `600000` | 单条 `exec` 的超时上限 |
| `transferMaxBytes` | `1073741824` | 分块上传允许的最大文件（默认 1 GiB） |
| `transferMaxChunkBytes` | `8388608` | 单块原始字节上限（8 MiB） |
| `transferMaxActive` | `8` | 同时进行中的分块上传数上限 |
| `transferUploadTtlMs` | `600000` | 闲置上传的清理 TTL（毫秒） |
| `transferBeforeMaxBytes` | `1048576` | `before`（被覆盖文件旧内容）返回文本的大小上限 |
| `audit` / `auditFile` | `true` / `${DSH_HOME}/dsh-remote/server-audit.log` | 审计日志 |
| `promptGuidance` | `true` | 告诉被驱动的会话：你是远端派来的 task、本机可能有真人插话/按停、打断优先 |
| `superAgentIo` | `false` | 可选：经 `ctx.superAgentIo` v1 准入控制器输入（真实 `super-agent-io` source），并让 IO 把每条 committed assistant 消息逐条交付；服务缺失/关闭/明确 pre-send 拒绝时自动回到原路径 |
| `capabilities` | `true` | 允许控制器读能力目录并直调工具（`caps.*`；见 §4.10）；关掉只保留 `agent.*` 那组 |
| `capabilityPreset` | 空（部署默认 preset） | 目录描述哪个 preset 的工具面 |
| `deniedTools` | `["ask_user_question","exit_plan_mode","present"]` | 额外禁止直调的远端工具（支持 `前缀*`）；`remote_*` 桥工具永远禁止 |
| `maxToolCallTimeoutMs` | `600000` | 单次 `caps.call` 的对端超时上限 |

**client（`dsh-remote-client:`）**

| 字段 | 默认 | 说明 |
|---|---|---|
| `host` / `port` | **无默认值** | 对端可达地址（隧道公网地址）；不设则启动时告警、调用时报错 |
| `privateKey` / `privateKeyFile` | 空 / `${DSH_HOME}/dsh-remote/client.key` | 本侧私钥，**secret** |
| `peerPublicKey` / `peerPublicKeyFile` | 空 / `${DSH_HOME}/dsh-remote/server.pub` | 固定的对端公钥 |
| `autoGenerateKey` | `true` | 自动生成落盘 |
| `timeoutMs` | `120000` | 单次请求超时 |
| `toolEnabled` | `true` | 关掉就只留服务、不注册工具 |
| `sessionPrefix` | `remote` | 会话 id 前缀：也是"哪些对端会话算自己的"的判据 |
| `reuseSessions` | `true` | 一个 chat 只复用它自己那一个远端对话；关掉退回"每次新开一个" |
| `adoptExistingSessions` | `false` | 本 chat 还没有对话时，接管对端一个没人认领的旧会话（回收旧版本遗留用） |
| `sessionMemoryFile` | `${DSH_HOME}/dsh-remote/client-sessions.json` | 记住用户显式选过的那个会话；纯缓存，删掉只是丢这个选择 |
| `promptGuidance` | `true` | 向本机 chat 注入"远端 = subagent/task、本机优先、打断优先"的提示 |
| `superAgentIoInbound` | `false` | 按认证主机及会话前缀匹配既有本机会话，接入无等待 RPC 的异步远端回复；稳定消息 ID 去重，`receiveOnly` 绑定让本地输出留在会话内 |
| `subagentProvider` | `true` | 把对端注册成 subagent `remote` 并注册 `subagent_remote` 工具（见 §4.5，无需改 composition） |
| `costReporting` | `true` | 把远端 token 用量回传本机 cost-meter（写 `external_usage.json`，见 §4.7）；关掉即停止收集与写文件 |
| `costSourcePrefix` | `remote/` | 快照来源名前缀；最终来源名 = `<前缀><peerName>`（默认 `remote/default`） |
| `costStoreFile` | `${DSH_HOME}/dsh-remote/client-cost.json` | 本插件的调用记录 + 每会话游标；删掉等于从 0 重新拉取（不会重复计费） |
| `costSnapshotFile` | `${DSH_HOME}/storages/cost-meter/external_usage.json` | cost-meter 官方外部用量快照文件 |
| `transferChunkBytes` | `1048576` | 分块传输的块大小（1 MiB；对端会再夹到 64 KiB..8 MiB） |
| `transferConcurrency` | `4` | 同时最多几个块在途（1..8）；RTT 越大越值得调高 |
| `transferCompression` | `true` | 逐块 gzip；只有压到 95% 以下才真的压缩，随机数据自动 raw |
| `transferFastPathBytes` | `524288` | 内容 ≥ 512 KiB 才走分块快路径；更小的文件单帧 `fs.write` 更快 |
| `backgroundRuns` | `true` | 注册后台运行 4 个工具（`remote_run_*` / `remote_send_message`）；工具集在加载时决定，改后需重启 DSH |
| `maxBackgroundRuns` | `8` | 同时存在的后台远端运行上限；超过时 `remote_run_start` 报错并提示先收结果 |
| `remoteCapabilities` | `true` | 读对端能力目录并把工具镜像成本机工具（见 §4.10）；关掉则 `remote_capabilities` 也只报"已关闭" |
| `capabilityPreset` | 空（对端默认 preset） | 镜像哪个远端 preset 的工具面；`remote_capabilities(preset_id=…)` 可临时看别的 |
| `capabilityRefreshSeconds` | `300` | 兜底轮询周期（秒，最小 30；`0` = 只靠对端 `caps.changed` push） |
| `capabilityTimeoutMs` | `600000` | 单次直调等待上限（对端 `maxToolCallTimeoutMs` 会再夹一次） |
| `capabilityDeny` | `[]` | 本机额外不镜像的名字或 `前缀*`（对端也已拒绝的不用重复） |
| `peerName` | `default` | legacy 单 peer（`host`/`port`）在 `peers` 里的名字；也是 `@<peer>:/…` 的 token |
| `peers` | `{}` | 多 peer 声明（名字 → host/port/密钥/`maxPermission`/`workspaceRoot`） |
| `defaultPeer` | 空（第一个声明的 peer） | **`@rmt:/…` 指向哪台**（"默认远端机"；设置 GUI 可改，热生效） |

---

## 6. 安全设计（为什么这套可以直接挂在公网端口上）

| 性质 | 怎么实现的 |
|---|---|
| **双向身份认证** | 两端各持 X25519 静态密钥对并 pin 住对方公钥。`tag_s` 只有持有服务端私钥才能算出（`ECDH(c_eph, s_static)` 那一腿），`tag_c` 同理。**知道公网地址拿不到任何东西** |
| **前向保密** | 会话密钥来自每连接新生成的临时密钥对；日后静态密钥泄露也解不开录制下来的历史会话 |
| **抗重放 / 抗乱序** | 每帧带严格递增计数器，计数器绑进 AEAD 的 AAD；重放或丢帧都会直接校验失败 |
| **抗暴力探测** | 同一来源握手失败累计到阈值即拉黑一段时间；每次尝试都进审计日志 |
| **面最小** | 只绑定回环地址（默认），公网唯一的入口是隧道；协议在认证完成前不回应任何业务信息 |
| **密钥不落地明文外** | 私钥字段是 `role('secret')`，设置 GUI 不会把它回显；私钥文件权限收紧到属主 |

已用自动化测试验证过的四条（`test/protocol.test.ts`）：
① 正常配对可通 ② pin 错服务端公钥 → 客户端拒绝（MITM） ③ pin 错客户端公钥 → 拒绝 ④ 两次会话密钥不同（前向保密）。

---

## 7. 排查

| 现象 | 先查 |
|---|---|
| 服务端日志没有 `listening` | 端口被占（`Get-NetTCPConnection -State Listen -LocalPort 11325`）；`host`/`port` 设置 |
| client 报 `server authentication FAILED` | 两侧密钥不配对。服务端日志里的指纹和 client 的 `server.pub` 是否一致 |
| client 报 `no peer public key configured` | `server.pub` 没放到 `${DSH_HOME}/dsh-remote/` |
| 隧道通但连不上 | frp 隧道是否指向了**这台机器**的 `127.0.0.1:11325`（隧道归属冲突是常见坑） |
| `remote_agent_prompt` 回 `reason: error` | 对端新会话没有模型路由。本插件已 `installModelSelection`；若仍复现，看工具返回里的 `error:` 一行 |
| 改了 `src/*.ts` 但行为没变 | DSH 不会重载已 import 的模块。要么重启 `dsh web`，要么给 patch 行里的 URL 加个 `?v=N`（ESM 视为不同模块） |
| cost-meter 面板看不到 `remote/<peer>` | ① 本机 DSH 重启过没有（`clientBuild` 应为 c10+）；② `remote_ping.remoteCost.records` 是否 > 0；③ 对端 `build` 是否 r18+（否则没有 `usage.read`）；④ `client-cost.json` / `external_usage.json` 是否真的写出 |
| 外部用量整份消失（之前有） | 多半是某条记录的 provider/model 本机价表解析不到 → cost-meter fail-closed 忽略整份文件。看 `external_usage.json` 里的 provider/model，给 cost-meter 加自定义模型价格；或临时 `costReporting=false` |
| `remote_put_file` 报 `FS_TOO_LARGE` | 对端 `transferMaxBytes`（默认 1 GiB）不够，调大即可 |
| 大文件传输很慢/像用回旧路径 | `remote_ping.build` 是否 r19+、`ops` 是否含 `fs.put.begin`；`transferCompression` 是否被关掉；随机/已压缩数据本来就不吃压缩，只受带宽限制 |
| 大文件传一半失败 | 单块自动重试 2 次后整条上传作废（不会写坏目标）；看是否隧道抖动或 `timeoutMs` 太小 |
| `remote_run_start` 报"已有 N 个后台远端运行" | 用 `remote_run_status` 收掉已完成的 run，或调大 `maxBackgroundRuns` |
| `remote_team_dispatch` 报"不在 Agent Teams 里" | 该工具只在 Team 会话（有 `agentTeams` 且调用方是 lead/teammate）里可用；普通场景用 `remote_pool_dispatch` / `remote_worker_prompt` |
| `remote_workers` 报"没有声明 peer" | client 配置里 `peers` 为空且 legacy `host`/`port` 未设；二者至少一种 |
| 后台 run 一直 `cancelling` | 对端可能没响应 `agent.interrupt`（隧道已断/对端卡住）；run 会占一个槽，直到对端结算或本机重启 |

---

## 8. 已知边界

- 动态 Cordis 插件（创造模式的 `cordis_define`）是**进程内、临时**的，所以**本插件必须是静态插件**——
  它要常驻、要跟着 DSH 启动。创造模式用来做的是"把某个工具插件化"，不是用来装这个监听器的。
- `remote_agent_events` 只暴露必要字段（消息文本、工具名与参数、turn 结束原因），
  不会把会话的活对象整体序列化——那是运行时对象，不能当业务数据处理。
- 被控机必须有 DSH 在跑。DSH 挂了就没有通道了——本插件驱动的是对端的
  `agents` / `sessions` / `workspaceRegistry` 服务，没有 DSH 就无从谈起。
- 上下文压缩目前是"把事件流取回本机、由本机来压、再投递回去"，用的是本机 agent 的能力；
  对端自己的 `command-compact` 没有被远程触发（需要时可以加一个 op）。
- **费用回传的口径**：只回传本插件驱动的那一个远端会话的模型调用；对端 agent 自己派生的 subagent 会话不计；
  会话徽章仍按本机 DSH 账本，远端费用只进 cost-meter 的「外部用量 / 合计」（cost-meter 没有第三方会话费用注入接口）。
  对端冷门 provider 若本机无价，cost-meter 会忽略整份快照（fail-closed），见 §4.7。
- **大文件传输**：没有断点续传（失败重传整文件，单块自动重试 2 次）；只传单文件，不做目录递归/增量同步；
  线上仍是 base64 JSON（比二进制多 ~33%）；不可压缩数据只受益于分块流水线，不受益于压缩（见 §4.8）。
- **后台运行**：run 注册表在进程内，本机重启后未收的 run 丢失；远端那一轮结束后，可在远端会话里找到结果。
  本地 Stop 只把 run 标为 `cancelling`，最终状态要等对端把那一轮结算回来。
- **Agent Teams**：远端 peer 不在 roster 里（`spawn_teammate` 只造本机 teammate），看板 owner 是调用方；
  `remote_team_dispatch` 之外的池工具不写看板（见 §4.9）。
- **能力直连**：`caps.call` 没有 session（对端 `exec.agent === undefined`），需要 agent 的工具会报错；
  直调不经过对端 tools 的 pre/post-execute 策略链（超时包装/guards/审批），对端用
  `maxToolCallTimeoutMs` 与 `deniedTools` 兜底；目录与镜像走**主链路**（只声明 `peers`、
  没有 `host`/`port` 的部署暂不参与）。详见 §4.10。
