# 2026-11-09 更新失败恢复原则

本地验证不能代替远端部署验活。已发现历史更新协调器的恢复路径不可靠，已在源码中移除所有安装、卸载、计时和状态写入路径；尚未同步的远端副本不能因此算已退役，远端操作者必须禁止再次执行 `remote_upgrade_stage start`。

## 已证事实

- 运行包有静态 `@deepseek-ai/cosmokit` 导入，但原发布 manifest 未声明它。已补齐 `^1.8.5`，并声明可选 `dsh-subagent` peer。不能在缺少远端 import 堆栈时把该遗漏直接等同于当次激活失败根因。
- 用户读到的更新状态：旧包卸载成功，新包激活失败，新包被移除，旧源目录回滚安装失败。
- 用户读到的 profile：`dependencies['dsh-remote']` 不存在，bundle 未选中，旧源目录不存在，新版 staged release 和独立 backup archive 均存在。
- pnpm 安装退出码 0 不代表插件 import 或 listener 正常。错误的已删除回滚目录曾被识别为 `dsh-remote-plugin 0.0.0` 空壳；不得再次使用这个位置恢复。

## 后续诊断中的解析环境差异

对端本地代理报告：从 profile package.json 启动的独立 Node 探测，经 Junction 解析到全局 npm 的 `dsh-* 0.1.1-rc.2`、cosmokit 1.8.3、schemastery 3.18.2，后两者不提供 `isVolatile` / `.volatile()`。这些结果证明该 shell 解析环境不支持当前包，尚不能单独证明桌面 Host 内已加载 Service 使用同一份依赖。必须由运行中 Host 的 Config Inspect 返回实际 `packageDir`，并用 Host 文件读取工具检查其 manifest 和 API；不要用 shell 无法读取 ASAR 为由替换成全局 npm 树。

不得用“get 函数鸭子类型”或伪造 `.volatile()` 包装来绕过缺失接口：稳定配置引用、实时授权撤销和宿主设置生命周期需要成套支持。缺少同名文件缓存目录也不能排除进程内 ESM/HMR 旧模块或旧路径映射。

`locale` 元信息 ENOENT 指向已清空旧路径，只能证明当前元信息读取仍使用这个路径；填一个 locale 目录不能修复模块加载、依赖解析或监听器。

## 不可违反的恢复限制

1. 不再运行历史协调器 start，不卸载正在工作的管理入口。
2. 只用官方 plugin_manager 安装/启用；不手改 profile manifest/patch，不在 profile 运行包管理器。
3. 新 package tree 放在 Documents 等独立恢复目录，不在 profile/plugins、node_modules 或唯一回滚位置里。
4. 恢复目录与原备份都保留；任何解包前验证归档条目没有绝对路径、盘符或 `..`，不跟随离开目标的符号链接。
5. 依赖缺失时才直接安装；同名已安装时先核对版本/phase，不能为绕过 already-installed 再删包。
6. 保持原监听地址、端口、公钥信任、私钥和授权配置。不启用中心功能作为故障绕过，不增加网络暴露。
7. 固定端口/公钥、旧 Config override、原 row enablement 和新版安全默认值须在激活前后核对。不得复制或输出私钥。
8. 如返回 failed，收集原始 activation/import 错误后停止；如 restart-required，说明未生效，并由现场操作者按宿主正常退出/重开流程执行，不用强杀循环重启。

## 验证层次

- `release-validation`：检查 emitted JS 运行依赖是否显式声明、静态依赖是否被误标 optional、export 文件是否实际存在。
- `packaged-import`：把运行包复制到独立临时目录，只让已声明的必需运行 peers 可见，导入七个模块；不调用 apply、不打开网络、不生成密钥、不安装 profile。这不是实际 pnpm 安装或目标 DSH API 兼容性验证。
- Loopback regression：既有协议、权限、隔离、relay 与发布回归。测试可验证源码行为，不能证明目标磁盘和运行版本。
- 远端部署：官方 manager result、运行 build、原公钥 pin 下的现代握手、无副作用 ping/sysinfo 以及控制权限拒绝，全部成功才可报告恢复/部署。

本页只记录故障与恢复边界，不包含任何私钥或配置全文。手机代理和中心式功能部署仍需另外验证。
