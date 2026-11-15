# 中心式设备互联（0.5）

一个中心入口即可承载多台设备双向互控。中心只转发字节，不替目标设备执行 RPC，不代替目标设备授予权限。保留原有直连工具、文件系统、命名工作区和插件引用方式。

## 拓扑

```text
设备 A ──主动连接──┐
                 中心 H（现有 VPN/FRP TCP 入口）
设备 B ──主动连接──┘
```

A 和 B 不需要公开入站端口。被控端的 server 仍只监听 `127.0.0.1`；mesh 行在本机把经中心转来的加密字节送入这个固定回环端口。H 若也需要控制或被控制，同样作为一个节点主动连接自己的中心监听口。

本页所有地址、路径和节点名为虚构示例；部署数据不进入源码或仓库。

## 三个不同的授权边界

1. **节点到中心**：mesh 的 `host` / `port` 指向中心，`peerPublicKey` 固定中心公钥，`privateKeyFile` 是该设备自己的接入身份。只接受现代 key selector，不自动降级。
2. **中心转发权限**：中心 server 的 `relayEnabled: true`，并在 `authorizedPeers` 中逐设备固定公钥。节点名来自完成持钥证明的条目键，不能由注册请求自报。双方 `relayTargets` 必须互相包含对方的精确节点名；空列表拒绝转发，不支持通配符。
3. **控制者到目标设备**：普通 client 的 `relayTarget` 指目标节点，`peerPublicKey` 必须固定**目标设备**的 server 公钥，不是中心公钥。目标 server 仍独立校验控制者的公钥、权限等级、操作白名单、期限与文件根。中心可路由不等于获得设备控制权。

中心被控制时可拒绝、延迟、观察连接元数据或中断转发，但仅掌握中心私钥不能伪装成另一个已固定公钥的目标。不要把中心信任等同于信任所有接入节点。

## 中心配置示例

在中心 server 的设置页配置，保持已有监听地址和端口；只需一个原有的 TCP 入口。

```yaml
relayEnabled: true
authorizedPeers:
  studio:
    peerPublicKeyFile: 'C:/keys/studio.pub'
    maxPermission: 1
    relayTargets: ['travel']
  travel:
    peerPublicKeyFile: 'C:/keys/travel.pub'
    maxPermission: 1
    relayTargets: ['studio']
```

`maxPermission: 1` 足以经显式 pair ACL 转发；不因此允许在中心执行命令。若某个节点也要直接控制中心，应由操作者另外明确授予中心侧 level 3，绝不能因为 `relayTargets` 自动提升。

## 每个接入设备

启用 bundle 中默认关闭的 `dsh-remote-mesh` 行，配置：

```yaml
host: 'hub.example.invalid'
port: 41000
privateKeyFile: 'C:/keys/travel.key'
autoGenerateKey: false
peerPublicKeyFile: 'C:/keys/hub.pub'
acceptInbound: true
targetPort: 11325
```

`acceptInbound` 默认 false。只有本设备允许被控制时才打开；本机 server 应绑定 `127.0.0.1:11325` 并固定允许的控制者公钥。对端不能通过 offer 任意指定本机地址或端口。mesh 的配置对象是 volatile：保存变更会关闭旧通道并按新配置重新注册，不会在切换后继续使用旧公钥或旧端点。实际连通必须另行验证，不能只看配置已保存便宣称接入成功。

普通 client 的每个 peer 保留原有权限设置，并选择走中心：

```yaml
peers:
  studio:
    relayTarget: studio
    privateKeyFile: 'C:/keys/travel.key'
    autoGenerateKey: false
    peerPublicKeyFile: 'C:/keys/studio-server.pub'
    maxPermission: 1
```

`relayTarget` 非空时不用 `host` / `port` 直连兜底，不会在中心不可用时悄悄转到另一台机器。命令执行和驱动 agent 仍需两端明确允许 level 3。

## 生命周期与预算

- 注册绑定已认证的外层 Session，不允许第二个连接抢占在线节点身份；断线须在新连接重新注册。
- tunnel ID 不提供权限；只有创建/接受它的原始连接才能读写。逐方向序号从 1 递增，非法编码、乱序、越权或端点失效即关闭通道。
- 默认最多 128 个通道，每身份最多 16 个；打开等待最长 15 秒，空闲最长 10 分钟；每块最多 48 KiB，虚拟 socket 接收缓冲有界。
- 撤销身份、修改路由权限、中心或接入节点重载会关闭旧通道。注册和通道操作不自动重放；命令、工具调用、写入、agent 驱动也保留 0.4 的不重放规则。
- 重连只恢复连接与注册，不恢复中断中的业务操作，也不是文件传输断点续传。

## 新设备与手机

以后每台设备仍需独立身份、中心 pair ACL、目标设备的公钥 pin 和目标权限。删除一台设备时需同时撤销中心入口与各目标授权；不存在“加入互联网就自动完全互控”。

当前实现是 Node.js/Cordis 设备代理，使用 TCP、X25519 和现有 DSHR2。普通手机浏览器不能直接作为此协议节点；手机需要兼容的原生/后台代理，或另行实现受审查的接入层。本文不把原生手机代理、浏览器 WebSocket 接入或后台保活能力算作已经交付。

## 部署和回滚

先本地回归，再部署中心，最后部署节点；保留旧包、原有配置和密钥。不能通过卸载承载唯一管理连接的插件来给自己升级。使用独立于该连接生命周期的部署入口或现场重启；先保存各条目的启用状态，再按正式插件管理器给出的生命周期切换。重启后必须验证运行 build、现代握手、正反向无副作用请求和拒绝测试；磁盘文件版本不是运行版本。
