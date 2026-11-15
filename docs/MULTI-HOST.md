# 多主机与命名引用（0.3）

所有地址、路径、工作区名均为虚构示例。不要把部署配置或密钥提交到仓库。

## 一台主机可以同时发送和接收

`client`、`server` 是角色，不是互斥的机器类型。A、B、C 都可以启用两者：

```text
A client ──pin B──> B server
B client ──pin A──> A server
A client ──pin C──> C server
C client ──pin B──> B server
```

每条边是显式配置、独立认证的直连。没有隐式转发、跨主机传递权限或自动全网发现；不需要为读取插件目录创建远端会话。安装时仍默认关闭 server，不能因为升级静默打开入站端口。

- **出站**：插件页面 → 多主机互联 → 配置，维护 `peers` 和 `defaultPeer`。
- **入站**：启用「接收入站互联」，配置监听地址/端口和 `authorizedPeers`。
- 每台主机持有自己的私钥；交换并核对公钥，绝不交换私钥。
- 默认监听 `127.0.0.1`。跨机器通过自己已有的隧道、局域网或 VPN 暴露连接；插件不会代开公网端口。

### 兼容原有单机配置

旧 `host` / `port` / `peerName` 仍可用；该连接作为 legacy 主机合入注册表。同名显式 `peers` 优先。默认主机为空时选第一项；显式默认名不存在则报错，绝不偷偷落到另一台机器。

普通 `remote_*` 工具、默认能力镜像、`rmt:` 和无主机名的 `/rmt/` 统一使用默认主机。`remote_capabilities`、`remote_tool_call` 可传 `peer` 指定其他主机。多个主机的同名工具不抢占本地工具名，也不批量把所有主机工具塞入模型上下文。

设置页按字段路径保存，包括 `peers.<name>.privateKey`，不会用打码后的空值覆盖私钥。私钥留空表示保持，仅「清除」明确改为空；删除主机需要确认。修改 endpoint/key 后后续调用使用新连接；工具集合的结构开关需要重新加载/重启。

## @ 语法

不借用 `~`：它已有用户主目录和 `~user` 语义。主机用冒号限定，命名工作区用 DSH 本身的显示名称。

| 输入 | 意义 |
|---|---|
| `@studio:clock` | 检索 studio 上名称为 clock 的插件或工作区 |
| `@studio:/C:/data/report.txt` | studio 的 Windows 绝对路径 |
| `@studio://home/example/report.txt` | studio 的 POSIX 绝对路径（双斜杠保留路径前导 `/`） |
| `@studio:产品` | studio 中名为「产品」的 DSH 工作区目录 |
| `@studio:产品/docs/brief.md` | 该工作区下的文件 |
| `@"studio:设计 笔记/docs/brief.md"` | 名称或路径含空格 |
| `@studio:workspace:ws-example/docs/brief.md` | 按唯一工作区 ID 明确类型 |
| `@studio:plugin:@example/clock` | 按完整包名明确插件类型 |
| `@产品/docs/brief.md` | 本机工作区，需要独立的 dsh-workspace-reference 插件 |

工作区来自 **DSH workspaceRegistry**，不是磁盘目录名称，也不是当前对话临时 `cwd`；重命名后新查询立即使用新名称。同名标题可以合法存在，因此重名返回候选，必须通过完整 ID 或菜单选中的绝对目标区分。插件和工作区同名时也不猜测；使用明确的 `workspace:` / `plugin:` 类型或选择候选。

主机别名使用至少两个 ASCII 字母、数字、点、横线或下划线，不允许 `rmt`、`.`、`..`、单字母、大小写重名或原型属性名，避免与盘符、默认远端别名混淆。

### 补全与可读路径

当前 DSH 的 fileReferences 候选契约只有 `path` / `kind`，并不支持额外类型标签。因此工作区候选以目录图标和确定的 `/rmt/<host>/...` 路径呈现，插件以 `host:plugin:<完整包名>` 呈现；详细的带类型检索由 `remote_references` 返回。选择工作区会插入确定的绝对目标，后续重命名或更换默认主机不会改变已选择目标。

聊天中的 Markdown 文件/图片需使用绝对挂载路径：

```markdown
![远程示例](/rmt/studio/C:/data/sample.png)
```

`host:/...` 和命名工作区表达可以传给文件工具，后端会在所属主机解析为实际路径；Markdown 应使用解析后的 `/rmt/<host>/...`，不能假设浏览器能理解主机别名。

## 无会话的发现与解析

```text
remote_references(query="@studio:产品/docs/brief.md")
remote_references(query="clock", peer="studio", kind="plugin")
remote_capabilities(peer="studio", tool="clock_read")
remote_tool_call(peer="studio", name="clock_read", arguments={})
```

`references.list` 是新的只读协议操作，仅传工作区 `{id,title,path}` 和插件 `{id,name,title?,enabled,presetId?}`。不传 config、secret、私钥或用户消息；查询受数量上限和取消信号约束，不创建 agent/session，不读文件内容。旧端不支持时明确不可用，绝不自动改用 agent prompt。

手写 `@` 在 admitted user 消息中补充路径映射数据，保留原始文本；代码块、行内代码和 email 不触发。映射不是指令，也不表示授权执行。

## 权限与身份隔离

- `peers` 新项默认 level 1，只读；level 2 限定目录写入；level 3 才能 exec、驱动 agent 或直接调用工具。
- 服务端取全局上限与单主机上限的最小值。主控端也检查，不能靠篡改请求越过被控端上限。
- `authorizedPeers` 非空启用多身份模式，只接收表内 pin 的公钥；空表兼容旧单 pin。
- 多身份模式按完整公钥指纹派生 principal，隔离 session IDs、问答、取消、上传及运行资源；重连仍属于同一身份。
- 从旧单 pin 切到多身份模式不会自动接管旧会话。旧历史需要显式迁移，不猜测归属。
- 工作区相对路径拒绝 `..` / 注入盘符；所属主机以规范化路径及 `fs.contains` 检查软链逃逸。工作区引用不是额外的权限授予。

## 升级

两端至少 0.3 才能使用命名插件/工作区检索，推荐双方升级到 0.4。0.4 默认禁止旧握手自动降级；访问 pre-selector 旧端需显式设置 `allowLegacyHandshake: true`，不代表关闭 pin 验证。level 1/2 文件读取还需在受控端配置 `readRoots`，否则默认拒绝读取。完整迁移和安全预算见 [安全指南](SECURITY.md)。包升级需要重启 DSH 重新载入 Host 模块；只刷新浏览器不能更新 Host 代码。完成测试不等于已升级真实远端，部署时请分别确认双方 build 标记。
