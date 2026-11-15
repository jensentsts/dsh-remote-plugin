# 给被控端部署/升级（含不可物理接触时的自愈回滚）

适用场景：被控机只能经 remote 插件通道接触，使用者**无法物理接触**它。
本文把 2026-10-08 那次失败（见 DEV-NOTES 3.20）的教训写成固定流程。

---

## 0. 动手前必须确认的三件事

1. **带外恢复路径存在**。如果唯一的通道就是"你即将重启的那个 DSH"，那这次重启就是单向门。
   先确认其中至少一条：机器上有其他 DSH / 远程桌面 / 现场有人 / frpc 由独立服务守着。
2. **载荷能被对端加载**。对端有两种装法，判据不同：
   - *源码形态*（patch 行是 `file:///…/src/server.ts`）：跑 `node tools/check-strip-safe.mjs`
     ——对端以 Node strip-only 擦类型，参数属性 / `enum` / `namespace` 会让它**加载失败**，
     而本地 esbuild 完全看不出问题；`tsconfig.json` 的 `erasableSyntaxOnly` 是同一道闸。
   - *打包形态*（`dsh.profile.bundles` 含 `dsh-remote` + junction）：推 `lib/*.js` 即可，
     没有 strip-only 问题。**新部署一律选这种**，见 §1b。
3. **新代码会写心跳**：受控端 `server.ts` 在**监听成功**和**每次握手成功后**写
   `${DSH_HOME}/dsh-remote/server-heartbeat.json`，内容含 `build` / `at` / `pid` / `port` / `controllers`。
   判据是"心跳里的 build == 期望值 且 at 是新的"，**不是"端口在监听"**——
   后者分不清"新版本在服务""旧版本还在""端口被别人占了"。

---

## 1b. 打包形态（推荐）：把对端从"手挂源码"换成 bundle

手挂形态的旧机器有两个坑，2026-10-08 都踩到了：
`package.json` 里**没有 `dsh.bundle`**（DSH 会把这个 bundle **静默跳过**，行 id 无人声明 → 重启即失联），
以及随包的 `cordis.patch.yml` 还是带 `<you>` 占位符的**模板**（不是真正的行声明）。

换装需要的文件（对端插件目录）：

| 文件 | 作用 |
|---|---|
| `lib/server.js` | 受控端本体（自包含） |
| `lib/client.js` | host 半（`exports["."]` 指向它） |
| `client.js` | **浏览器半：设置面板由它注册** |
| `package.json` | 必须有 `dsh.bundle.patch` 与 `dsh.client`（`platform: web`） |
| `cordis.patch.yml` | **真正的行声明**（不是模板）：`dsh-remote-client`（active）与 `dsh-remote-server`（declared, disabled） |
| `locale/{zh,en}.json` | 面板词条 |

profile 侧三处：
1. `node_modules\dsh-remote` → junction 到插件目录；
2. `package.json`：`dependencies` 加 `"dsh-remote": "link:<插件目录>"`，`dsh.profile.bundles` 加 `"dsh-remote"`；
3. `cordis.patch.yml`：**删掉**原来的 `file://` insert，换成 id 定向覆盖（受控机用）：
   ```yaml
   - id: dsh-remote-client
     name: dsh-remote
     config: { toolEnabled: false }      # 只被驱动；保持加载只为让包/设置页存在
   - id: dsh-remote-server
     name: dsh-remote/server
     disabled: false
     config: { host: '127.0.0.1', port: 11325, workspace: '…' }
   ```
   （旧模板里两行都会落到同一个文件，那是"同一包两个 active 行"的 boot-fatal 情形；
   新 `package.json` 的 `exports["."]` 与 `exports["./server"]` 是**不同文件**，才是对的。）

先只改文件、逐项校验（YAML/JSON 解析、`require.resolve('dsh-remote')` 与 `'dsh-remote/server'` 指向两个不同文件、
SHA 与暂存一致、CIM/`junction` 目标正确、全文不再有 `file://…src/server.ts`），**再由使用者重启**，
并在机器上留一个"一键回退"脚本（还原四个备份 + 删 junction）。

## 1. 推送载荷（主控侧）

目标目录：`<对端 DSH_HOME>\dsh-remote\stage-<build>\`

- 只推需要的文件（典型：`server.ts`、`reuse.ts`、`exec-registry.ts`、`journal.ts`）。
  **不要**覆盖对端自己特有的 `protocol.ts` / `link.ts` / `keys.ts` / `peers.ts` / `peer-fs.ts` / `client.ts`。
- 单文件超过约 16 KB 时 `remote_fs_write` 可能被截断：**按行边界分包**，在对端用
  `cmd /c copy /b part1+part2+... file.ts` 合并（**不要**用 `Get-Content`/`Set-Content`，
  被控端多为 PowerShell 5.1，会把 UTF-8 中文按 ANSI 搅坏）。
- 逐个校验：远端长度 == 本地长度，且 `Get-FileHash -Algorithm SHA256` 两边一致。

## 2. 交接给对端"创造模式"会话

以 `preset_id: cordis` 开一段会话（`new_session=true`），让它**在机器本地**执行：

1. 备份 `src\server.ts` → `<DSH_HOME>\dsh-remote\backup-<旧build>-server[-时间戳].ts`（不覆盖历史备份）；
2. 覆盖载荷里的文件到 `...\plugins\dsh-remote-plugin\src\`；
3. 校验：目标长度、`Select-String` 的 `export const BUILD` 必须是新 build、
   `node --experimental-strip-types -e "await import('file:///.../src/reuse.ts')"` 等纯模块能装载、
   `node tools/check-strip-safe.mjs <stage 目录>` 全过；**任何一条不过就停下报告，绝不重启**；
4. 写自愈脚本（**只用 ASCII**，见下）并 **detached** 启动；
5. **先回复主控**（脚本里有起始延迟），再让机器重启。

## 3. 自愈脚本模板（ASCII，PS 5.1 可解析）

```powershell
# restart-<build>.ps1  —  args: local plugin dir, backup file, expected build, heartbeat path
$ErrorActionPreference = 'Continue'
$pluginDir = 'C:\Users\<user>\.dsh\profiles\desktop\plugins\dsh-remote-plugin'
$backup    = 'C:\Users\<user>\.dsh\dsh-remote\backup-r10-server.ts'
$expect    = 'r15'
$beat      = 'C:\Users\<user>\.dsh\dsh-remote\server-heartbeat.json'
$report    = 'C:\Users\<user>\.dsh\dsh-remote\deploy-report.txt'
$app       = 'E:\deepseek harness\DeepSeek Harness.exe'

Start-Sleep -Seconds 25      # let the session reply before the app dies

function Restart-App {
  Stop-Process -Name 'DeepSeek Harness' -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 4
  Start-Process $app
}

function Wait-Heartbeat([int]$seconds) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path $beat) {
      try {
        $j = Get-Content $beat -Raw | ConvertFrom-Json
        if ($j.build -eq $expect) { return $true }
      } catch { }
    }
  }
  return $false
}

Add-Content $report "START $expect $(Get-Date -Format s)"
Restart-App
if (Wait-Heartbeat 120) {
  Add-Content $report "OK $expect $(Get-Date -Format s)"
} else {
  # roll back: restore the previous server half and remove what we added
  Copy-Item $backup (Join-Path $pluginDir 'src\server.ts') -Force
  Remove-Item (Join-Path $pluginDir 'src\reuse.ts')         -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $pluginDir 'src\exec-registry.ts') -Force -ErrorAction SilentlyContinue
  Remove-Item (Join-Path $pluginDir 'src\journal.ts')       -Force -ErrorAction SilentlyContinue
  Restart-App
  Add-Content $report "ROLLED BACK $(Get-Date -Format s)"
}
```

要点：
- **判据是心跳里的 build**，不是端口；`Wait-Heartbeat` 给 120 秒（Electron 冷启动可能很慢，
  90 秒那次可能还没起来就误判）。
- 回滚只还原 `server.ts`、删掉本次**新增**的文件；对端自有文件一个都不碰。
- 报告文件让主控在链路恢复后一眼看懂结局（`OK` / `ROLLED BACK`）。

### ⚠️ 这个脚本的"重启"半边在真机上失败过（2026-10-08 实测）

报告里只留下一行 `START r14 install at 10:49:13`，**没有 `OK` 也没有 `ROLLED BACK`**：
脚本杀掉 DSH 之后就再没能把它拉起来，被控端失联约 20 分钟，最后是使用者手动启动才恢复。
（插件文件本身没问题——恢复后加载的正是新的 r14。）

原因与对策：
- **脚本是被它要杀掉的那个进程拉起来的**（经对端 agent 的 `Start-Process`，属于 DSH 的进程树），
  杀树之后脚本可能一起消失，"启动"那一步根本没跑到。
- 想让"杀 + 起"都由外部执行，用**任务计划程序**（`schtasks /create ... /it` 再 `/run`）：
  它跑在 DSH 进程树之外，脚本能活到重启完成；`/it` 是必需的——GUI 应用需要交互式会话。
- 或者最省事也最安全：**只部署文件、不重启**，由使用者或带外通道重启，再回来验心跳与 build。
  有使用者配合时，**推荐这条**。

## 4. 主控侧收尾

1. `remote_ping` → 对端 `build` 应为新 build；
2. `remote_journal`（默认只取新条目）确认轨迹在被写入；
3. 若报告是 `ROLLED BACK`：先读报告与对端日志，修掉加载失败的原因再重来，
   **不要**在原因不明时反复重启（每次失败都可能计入对端握手锁定计数）。
