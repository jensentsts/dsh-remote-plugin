/**
 * dsh-remote — browser half: direct client/server and mesh configuration pages.
 *
 * DSH 0.2 has no "derive a settings page from the Config schema" step. A host
 * plugin that wants its entry editable from the GUI ships a client half that
 * registers into `plugins.row.config` under `<declaring bundle>#<row id>`; the
 * Plugins page then gives that row a configure control and renders the
 * component with `{ view, form }`. `form` is Host-owned: `state` is the
 * redacted, schema-resolved section and `mutate` is the path-addressed write.
 *
 * A machine may mount both client and server for bidirectional connections.
 * Outbound `peers`, inbound `authorizedPeers` and the optional mesh connection
 * have separate identities and trust decisions, never inferred from each other.
 *
 * `privateKey` is `role('secret')`: it never rides a response. Every edit names
 * its exact path, including names containing dots. Blank password inputs stage
 * nothing; only explicit Clear writes an empty inline key. Existing records are
 * never rebuilt from a redacted read, and changing host selection never dials it.
 *
 * Plain JavaScript on purpose — served to the browser as-is, importing only
 * `react` from the module table and styling itself with theme tokens.
 */
window.__ModuleLoader__.load({
  id: 'dsh-remote',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const NS = 'dshRemoteSettings'
    /** `<declaring bundle package>#<row id>` for each configuration page. */
    const CLIENT_KEY = 'dsh-remote#dsh-remote-client'
    const SERVER_KEY = 'dsh-remote#dsh-remote-server'
    const MESH_KEY = 'dsh-remote#dsh-remote-mesh'

    const zh = {
      loading: '正在读取配置…',
      unavailable: '这个 namespace 没有暴露给当前客户端。',
      readOnly: '当前设置源不接受写入（内存模式或只读部署）。',
      noForm: '这一页没有拿到配置表单，无法编辑。',
      save: '保存',
      saving: '保存中…',
      revert: '恢复默认',
      dirty: '有未保存的修改',
      saved: '已保存',
      refused: 'Host 拒绝了这次写入。',
      overridden: '已覆盖',
      keepSecret: '留空表示不修改',
      secretSet: '已设置',
      secretUnset: '未设置',
      clear: '清除',
      unset: '未配置',
      clientNote: '配置只在保存后生效。改地址或密钥会断开旧连接，后续调用使用新配置；本页不探测或连接新主机。私钥留空即保持原值。',
      serverNote: '监听地址或端口保存后重新绑定。仅授权已核验的公钥；实际权限取全局上限与每台主机上限中较低者。',
      outbound: '连接到其他主机',
      inbound: '允许连接本机的主机',
      editingHost: '编辑主机',
      editingController: '编辑授权主机',
      legacy: '兼容单主机配置',
      newHostName: '新主机名称',
      addHost: '添加主机',
      removeHost: '移除主机',
      confirmRemove: '确认移除',
      cancel: '取消',
      discard: '放弃修改',
      removeNote: '移除将在保存后生效。该主机的配置和内联私钥将一并删除。',
      inheritedHost: '这台主机来自基础配置，不能在此移除；可修改字段或在配置源中删除。',
      invalidName: '名称至少 2 位，只能包含英文字母、数字、点、下划线和连字符；不允许保留名称或仅大小写不同的重名。',
      duplicateName: '该主机名称已存在。请使用新名称，不会复制或覆盖原主机的密钥。',
      defaultHost: '默认主机',
      automaticDefault: '自动选择第一台已声明主机',
      removeAuthNote: '保存后删除此入站授权。删除最后一项会恢复兼容单主机 pin；请先核对旧 pin。',
      defaultHint: '未指定主机的 remote_* 调用和远程路径共用此选择。',
      missingDefault: '默认主机已不在配置中，请重新选择。',
      legacyNote: '保留顶层 host/port/peerName 以兼容单主机。新增 peers 不迁移或删除旧配置；同名 peers 条目优先，未被覆盖的旧连接仍保留。',
      legacyPermission: '兼容连接保留权限 3。要限制该主机，请显式添加同名 peers 条目并设置权限上限。',
      authorizationNote: 'authorizedPeers 非空时只接受表内公钥，旧单主机 pin 不再生效；表为空时回退到兼容 pin。',
      bidirectional: '双向互联需要两端分别启用 client 和 server，并互相配置地址与公钥。出站 peers 不会自动授权入站连接。',
      identityFiles: '密钥文件与请求超时',
      listenerIdentity: '本机监听身份',
      capabilities: '能力开关',
      advanced: '高级设置',
      advancedHint: '网络准入、会话、传输、缓存与审计参数；通常无需修改。',
      restartHint: '工具集等结构开关可能需要重启 DSH；修改配置不代表对端已连接。',
      references: '引用格式：@主机:工作区/路径、@主机:插件、@主机:/C:/路径。',
      listHint: '每行一个工具名称，尾随 * 表示前缀匹配。',
      invalidNumber: '请输入范围内的整数。',
      legacyHandshakeWarning: '默认禁止旧握手，连接失败不会自动降级。兼容单主机 pin 只决定信任哪个公钥，不等于允许旧握手；仅在核验旧对端后显式开启。',
      invalidExpiry: '请输入有效的 RFC3339 时间，必须带 Z 或明确的 ±HH:MM 时区；不接受本地时间、未知偏移 -00:00 或不存在的日期。留空表示无期限。',
      invalidAllowedOps: '最多 64 个操作名，每个最多 64 字符；仅支持小写字母开头的点分段（段内可用小写字母和数字），不支持 * 通配符。',
      expiryState: '此授权已过期；保存不会使其重新有效。',
      invalidReadRoots: '最多 32 个绝对读取根目录，每个为 1..4096 字符，不支持控制字符。',
      secretUnknown: '状态未知',
      gEndpoint: '对端连接',
      gKey: '密钥与身份',
      gSession: '会话与工具',
      gListen: '监听',
      gServerSession: '被创建的会话',
      gSecurity: '安全与审计',
      meshNote: '中心接入配置仅在保存后生效：保存会关闭旧隧道并重建中心连接，不会重放操作。本页输入不会探测、连接中心或生成密钥；私钥留空即保持原值。',
      meshTopology: '只有中心设备需要现有 FRP 公网单端口；其他设备主动连接中心，被控设备的 server 仍应监听 127.0.0.1。手机也需要运行兼容的接入 agent；本页不是手机网页控制器。',
      meshTrust: '主动接入不等于自动信任。中心仅转发端到端加密字节，不执行目标 RPC；中心仍可观察流量元数据并中断连接。中心需要核验并显式登记每台设备公钥。',
      meshKeys: '这里的密钥与中心公钥 pin 只认证设备↔中心这一层。目标设备的公钥 pin 必须另填在 client / peers；它不能替换成中心公钥，接入中心不会自动授权控制目标设备。',
      relayPolicy: '中心转发默认关闭。仅 authorizedPeers 内具名且已核验的设备可接入；两个设备的 relayTargets 必须互相包含对方名称，才允许两者之间转发。空列表拒绝全部转发；不支持通配符，也不会从出站 peers 自动生成授权。',
      relayTargetNote: 'relayTarget 留空保持直连；填写后只经中心转发到该名称，不会回退到 host/port。目标 peerPublicKey 必须是目标设备公钥，不是中心公钥；目标 server 也必须独立授权本机控制公钥。',
      relayRoute: '中心转发 →',
      invalidRelayTarget: '目标名称须为 2..128 个 ASCII 字母、数字、点、下划线或连字符，不能使用保留名称或通配符。留空表示直连。',
      invalidRelayTargets: '最多 64 个精确节点名，每行一个，名称为 2..128 个 ASCII 字母、数字、点、下划线或连字符；禁止保留名与通配符。空列表拒绝全部转发。',
    }
    const en = {
      loading: 'Reading configuration…',
      unavailable: 'This namespace is not exposed to this client.',
      readOnly: 'The settings source accepts no writes (memory mode or a read-only deployment).',
      noForm: 'This page received no configuration form, so it cannot be edited.',
      save: 'Save',
      saving: 'Saving…',
      revert: 'Reset to default',
      dirty: 'Unsaved changes',
      saved: 'Saved',
      refused: 'The Host refused this write.',
      overridden: 'overridden',
      keepSecret: 'leave blank to keep',
      secretSet: 'set',
      secretUnset: 'not set',
      clear: 'Clear',
      unset: 'not set',
      clientNote: 'Changes apply only after Save. Changing an endpoint or key drops the old connection; later calls use the new configuration. This page never probes or connects to a new host. Leave a private key blank to keep it.',
      serverNote: 'Saving a bind address or port rebinds the listener. Authorize only verified public keys; the effective permission is the lower of the global and per-host ceilings.',
      outbound: 'Connect to other hosts',
      inbound: 'Hosts allowed to connect here',
      editingHost: 'Edit host',
      editingController: 'Edit authorized host',
      legacy: 'Compatible single-host configuration',
      newHostName: 'New host name',
      addHost: 'Add host',
      removeHost: 'Remove host',
      confirmRemove: 'Confirm removal',
      cancel: 'Cancel',
      discard: 'Discard changes',
      removeNote: 'Removal applies after Save. This host configuration and its inline private key will be deleted together.',
      inheritedHost: 'This host comes from the base configuration and cannot be removed here. Edit its fields or remove it at the configuration source.',
      invalidName: 'Use at least 2 ASCII letters, digits, dots, underscores or hyphens. Reserved names and names differing only by case are not allowed.',
      duplicateName: 'This host name already exists. Choose a new name; the existing host and its keys will not be copied or replaced.',
      defaultHost: 'Default host',
      automaticDefault: 'Automatically choose the first declared host',
      removeAuthNote: 'Save removes this inbound authorization. Removing the last entry restores the compatible single-host pin; verify that old pin first.',
      defaultHint: 'remote_* calls and remote paths without a host use this selection.',
      missingDefault: 'The default host is no longer configured. Select another host.',
      legacyNote: 'Top-level host/port/peerName remain compatible. Adding peers neither migrates nor deletes the old configuration. A same-name peers record takes precedence; an unshadowed legacy connection remains available.',
      legacyPermission: 'The compatible connection retains permission 3. To limit it, explicitly add a same-name peers record with a permission ceiling.',
      authorizationNote: 'A nonempty authorizedPeers table accepts only its listed public keys and disables the legacy pin. An empty table falls back to the compatible pin.',
      bidirectional: 'Bidirectional links need client and server enabled at both ends, with endpoints and public keys configured both ways. Outbound peers never authorize inbound access automatically.',
      identityFiles: 'Key files and request timeout',
      listenerIdentity: 'Local listener identity',
      capabilities: 'Capability switches',
      advanced: 'Advanced settings',
      advancedHint: 'Network admission, session, transfer, cache and audit parameters; normally no changes are needed.',
      restartHint: 'Structural tool switches may require a DSH restart. Saving settings does not establish a peer connection.',
      references: 'Reference formats: @host:workspace/path, @host:plugin, @host:/C:/path.',
      listHint: 'One tool name per line; a trailing * matches a prefix.',
      invalidNumber: 'Enter an integer within the allowed range.',
      legacyHandshakeWarning: 'Legacy handshakes are disabled by default, with no automatic downgrade on failure. A compatible single-host pin selects a trusted public key; it does not enable a legacy handshake. Enable only after verifying an older peer.',
      invalidExpiry: 'Enter a valid RFC3339 timestamp with Z or an explicit ±HH:MM timezone. Local time, unknown offset -00:00 and nonexistent dates are not accepted. Empty means no expiry.',
      invalidAllowedOps: 'Use at most 64 exact operation names of up to 64 characters. Dot-separated segments start with a lowercase letter and contain lowercase letters or digits. No * wildcards.',
      expiryState: 'This authorization has expired. Saving it does not renew it.',
      invalidReadRoots: 'Use at most 32 absolute read-root paths, each 1..4096 characters, without control characters.',
      secretUnknown: 'unknown',
      gEndpoint: 'Peer endpoint',
      gKey: 'Keys and identity',
      gSession: 'Session and tools',
      gListen: 'Listener',
      gServerSession: 'Sessions created on request',
      gSecurity: 'Safety and audit',
      meshNote: 'Mesh settings apply only after Save: saving closes old tunnels and rebuilds the hub connection, without replaying operations. Typing never probes, connects to the hub or generates keys. Leave a private key blank to keep it.',
      meshTopology: 'Only the hub needs the existing single public FRP port. Other devices connect outbound to the hub; each controlled server should still listen on 127.0.0.1. Phones also need a compatible agent; this page is not a phone web controller.',
      meshTrust: 'Connecting never establishes trust automatically. The hub only forwards end-to-end encrypted bytes, not target RPCs; it can still observe traffic metadata and interrupt links. Verify and explicitly register each device public key at the hub.',
      meshKeys: 'Keys and the hub public-key pin here authenticate only the device↔hub layer. Configure the target device pin separately in client / peers. Never replace that target pin with the hub pin; joining a hub never grants control over a target.',
      relayPolicy: 'Hub forwarding starts disabled. Only named, verified authorizedPeers identities may join. Each device must list the other in its relayTargets before traffic can be forwarded between them. Empty denies all forwarding, wildcards are unsupported, and outbound peers never create authorizations.',
      relayTargetNote: 'Leave relayTarget empty for a direct link. A nonempty name routes only through the hub, never falls back to host/port. peerPublicKey must pin the target device, not the hub; the target server must independently authorize this controller public key.',
      relayRoute: 'Hub relay →',
      invalidRelayTarget: 'Use an exact 2..128-character ASCII name containing letters, digits, dots, underscores or hyphens. Reserved names and wildcards are forbidden. Empty keeps direct mode.',
      invalidRelayTargets: 'Use at most 64 exact node names, one per line. Each is 2..128 ASCII letters, digits, dots, underscores or hyphens, without reserved names or wildcards. Empty denies all forwarding.',
    }

    /** `dsh-remote-client`: dial out to the peer. */
    const CLIENT_FIELDS = [
      { name: 'host', type: 'string', group: 'endpoint', zh: '对端地址（域名 / IP）', en: 'Peer host (domain or IP)', hintZh: 'frp 隧道端点、局域网名、Tailscale 名均可。', hintEn: 'A tunnel endpoint, a LAN name, a Tailscale name.' },
      { name: 'port', type: 'number', group: 'endpoint', zh: '对端端口', en: 'Peer port', hintZh: '隧道映射出来的端口。', hintEn: 'The port the tunnel maps to.' },
      { name: 'peerName', type: 'string', group: 'endpoint', zh: '对端名称', en: 'Peer name', hintZh: '只配了 host/port 时用它，默认 default。', hintEn: 'Used when only host/port are set; defaults to default.' },
      { name: 'relayTarget', type: 'string', relayNode: true, default: '', group: 'endpoint', zh: '中心转发目标名称（relayTarget）', en: 'Hub relay target name (relayTarget)', hintZh: zh.relayTargetNote, hintEn: en.relayTargetNote },
      { name: 'timeoutMs', type: 'number', group: 'endpoint', zh: '单次请求超时（毫秒）', en: 'Request timeout (ms)' },

      { name: 'privateKey', type: 'string', secret: true, group: 'key', zh: '本机私钥（内联）', en: 'Local private key (inline)' },
      { name: 'privateKeyFile', type: 'string', group: 'key', zh: '本机私钥文件', en: 'Local private key file' },
      { name: 'autoGenerateKey', type: 'boolean', group: 'key', zh: '缺密钥时自动生成', en: 'Generate a keypair when none exists' },
      { name: 'peerPublicKey', type: 'string', group: 'key', zh: '对端公钥（内联 pin）', en: 'Pinned peer public key (inline)' },
      { name: 'peerPublicKeyFile', type: 'string', group: 'key', zh: '对端公钥文件', en: 'Pinned peer public key file' },

      { name: 'sessionPrefix', type: 'string', group: 'session', zh: '会话 id 前缀', en: 'Session id prefix', hintZh: '也是「哪些对端会话算自己的」的判据。', hintEn: 'Also decides which peer sessions count as ours.' },
      { name: 'reuseSessions', type: 'boolean', group: 'session', zh: '一个 chat 复用一个远端对话', en: 'One remote conversation per chat', hintZh: '默认开。关掉就退回「每次新开一个」。', hintEn: 'On by default; off restores one new session per call.' },
      { name: 'adoptExistingSessions', type: 'boolean', group: 'session', zh: '本 chat 还没有对话时，接管对端一个没人认领的旧对话', en: 'Adopt an unclaimed existing peer conversation', hintZh: '默认关。只在想回收旧版本遗留的会话时打开。', hintEn: 'Off by default; enable to sweep up sessions left by an older build.' },
      { name: 'sessionMemoryFile', type: 'string', group: 'session', zh: '会话记忆文件', en: 'Session memory file', hintZh: '纯缓存，删掉只等于忘掉之前的映射。', hintEn: 'A cache only: deleting it just forgets the mapping.' },
      { name: 'promptGuidance', type: 'boolean', group: 'session', zh: '向本机 chat 注入「远端用法」提示', en: 'Inject remote-usage guidance into local chats', hintZh: '关掉后模型不会被告知本 chat 对应哪个远端会话。', hintEn: 'Off means the model is not told which remote conversation this chat owns.' },
      { name: 'subagentProvider', type: 'boolean', group: 'session', zh: '把对端注册成 subagent（含 subagent_remote 工具）', en: 'Register the peer as a subagent (with the subagent_remote tool)', hintZh: '默认开，**改完即时生效**。开启后无需改 composition：远端对话按 subagent / task 呈现，本地 Stop 会转发打断。缺 @deepseek-ai/dsh-subagent 时只记一条 warn。', hintEn: 'On by default and applied live. No composition edit needed: remote conversations appear as subagents/tasks and a local Stop reaches the peer. Missing @deepseek-ai/dsh-subagent only logs a warning.' },
      { name: 'toolEnabled', type: 'boolean', group: 'session', zh: '注册 remote_* 工具', en: 'Register the remote_* tools' },

      { name: 'costReporting', type: 'boolean', group: 'session', zh: '把远端费用回传本机 cost-meter', en: 'Report remote cost to the local cost-meter', hintZh: '默认开：每轮结束后把远端 token 用量写进 cost-meter 的官方外部用量快照（storages/cost-meter/external_usage.json）。面板「设置 → 费用 → 外部用量」里显示为 remote/<peerName>，计入今日/本月/累计合计；单会话徽章仍是本机口径。需要本机 dsh-cost-meter、对端 r18+。', hintEn: 'On by default: after each turn the peer\'s token usage is written to cost-meter\'s official external-usage snapshot (storages/cost-meter/external_usage.json), shown as remote/<peerName> and folded into today/month/all-time totals. The per-session badge stays local. Needs dsh-cost-meter here and r18+ on the peer.' },
      { name: 'costSourcePrefix', type: 'string', group: 'session', zh: '外部用量来源名前缀', en: 'External-usage source prefix', hintZh: '最终来源名 = 前缀 + peerName，默认 remote/default。', hintEn: 'The shown source is the prefix plus peerName; defaults to remote/default.' },
      { name: 'costStoreFile', type: 'string', group: 'session', zh: '远端用量记录文件', en: 'Remote usage store file', hintZh: '默认 ${DSH_HOME}/dsh-remote/client-cost.json；存每会话游标与逐次调用记录，删掉只会从 0 重拉（不会重复计费）。', hintEn: 'Defaults to ${DSH_HOME}/dsh-remote/client-cost.json: per-session cursors and call records. Deleting it only re-reads from zero (never double-counts).' },
      { name: 'costSnapshotFile', type: 'string', group: 'session', zh: 'cost-meter 外部用量快照路径', en: 'cost-meter external-usage snapshot path', hintZh: '默认 ${DSH_HOME}/storages/cost-meter/external_usage.json。', hintEn: 'Defaults to ${DSH_HOME}/storages/cost-meter/external_usage.json.' },

      { name: 'transferChunkBytes', type: 'number', group: 'session', zh: '传输分块大小（字节）', en: 'Transfer chunk size (bytes)', hintZh: '默认 1048576，夹在 64 KiB..8 MiB。仅在对端 r19+ 且支持分块传输时生效，旧对端自动退回单帧传输。', hintEn: 'Defaults to 1048576, clamped to 64 KiB..8 MiB. Applies only when the peer is r19+ with chunked transfer; an older peer falls back to single-frame transfer automatically.' },
      { name: 'transferConcurrency', type: 'number', group: 'session', zh: '并行块数', en: 'Parallel chunks', hintZh: '默认 4，夹在 1..8。越大越吃隧道带宽、内存约为「并行块数 × 分块大小」；仅在对端支持分块传输时生效。', hintEn: 'Defaults to 4, clamped to 1..8. Higher uses more tunnel bandwidth and about chunks × chunk-size of memory; applies only when the peer supports chunked transfer.' },
      { name: 'transferCompression', type: 'boolean', group: 'session', zh: '传输压缩（gzip）', en: 'Transfer compression (gzip)', hintZh: '默认开：逐块 gzip，只有明显变小时才用。文本/代码通常收益 3–5 倍，已压缩数据自动按原样发送。对端 r19+ 才生效。', hintEn: 'On by default: per-chunk gzip, used only when it clearly shrinks. Text/code usually gains 3–5x; already-compressed data is sent raw. Needs r19+ on the peer.' },
      { name: 'transferFastPathBytes', type: 'number', group: 'session', zh: '走快路径的最小内容字节数', en: 'Fast-path threshold (bytes)', hintZh: '默认 524288（512 KiB）：remote_fs_write 的 UTF-8 内容达到这个字节数且对端支持分块传输时走快路径，否则保持单帧 fs.write。对端 r19+ 才生效，旧对端自动退回单帧传输。', hintEn: 'Defaults to 524288 (512 KiB): remote_fs_write takes the chunked fast path once the UTF-8 content reaches this size and the peer supports it; otherwise it keeps single-frame fs.write. Needs r19+; an older peer falls back automatically.' },
      { name: 'backgroundRuns', type: 'boolean', group: 'session', zh: '后台远端运行（remote_run_* 工具）', en: 'Background remote runs (remote_run_* tools)', hintZh: '默认开：注册 remote_run_start / status / cancel 与 remote_send_message，长任务可后台跑、追加指示、事后取交付。工具集在插件加载时决定，改这一项后需重启 DSH 才增删工具；本机按停会转发成对端 agent.interrupt。', hintEn: 'On by default: registers remote_run_start / status / cancel and remote_send_message, so long tasks can run in the background, receive more instructions, and be collected later. The tool set is fixed at plugin load, so toggling this needs a restart; a local Stop is forwarded as the peer\'s agent.interrupt.' },
      { name: 'maxBackgroundRuns', type: 'number', group: 'session', zh: '并发后台远端运行上限', en: 'Max concurrent background remote runs', hintZh: '默认 8。超过时 remote_run_start 会报错，提示先用 remote_run_status 收取已完成的运行。', hintEn: 'Defaults to 8. Past the cap remote_run_start fails and points at remote_run_status for collecting finished runs.' },
    ]

    /** `dsh-remote-server`: listen for a controller. */
    const SERVER_FIELDS = [
      { name: 'host', type: 'string', group: 'listen', zh: '监听地址', en: 'Bind address', hintZh: 'frpc 跑在本机就保持 127.0.0.1。', hintEn: 'Keep 127.0.0.1 when frpc runs on this machine.' },
      { name: 'port', type: 'number', group: 'listen', zh: '监听端口', en: 'Bind port', hintZh: '必须等于 frp 隧道里填的本地端口，且由本插件独占。', hintEn: 'Must equal the tunnel\u2019s local port, exclusive to this plugin.' },
      { name: 'relayEnabled', type: 'boolean', default: false, group: 'listen', zh: '启用中心转发（relayEnabled）', en: 'Enable hub forwarding (relayEnabled)', hintZh: zh.relayPolicy, hintEn: en.relayPolicy },

      { name: 'privateKey', type: 'string', secret: true, group: 'key', zh: '本机私钥（内联）', en: 'Local private key (inline)' },
      { name: 'privateKeyFile', type: 'string', group: 'key', zh: '本机私钥文件', en: 'Local private key file' },
      { name: 'autoGenerateKey', type: 'boolean', group: 'key', zh: '缺密钥时自动生成', en: 'Generate a keypair when none exists' },
      { name: 'peerPublicKey', type: 'string', group: 'key', zh: '对端公钥（内联 pin）', en: 'Pinned peer public key (inline)' },
      { name: 'peerPublicKeyFile', type: 'string', group: 'key', zh: '对端公钥文件', en: 'Pinned peer public key file' },

      { name: 'workspace', type: 'string', group: 'serverSession', zh: '被创建会话的工作目录', en: 'Workspace for created sessions', hintZh: '留空用部署默认。', hintEn: 'Empty uses the deployment default.' },
      { name: 'defaultPreset', type: 'string', group: 'serverSession', zh: '被创建会话的默认 preset', en: 'Default preset for created sessions', hintZh: '留空用部署默认。', hintEn: 'Empty uses the deployment default.' },
      { name: 'promptGuidance', type: 'boolean', group: 'serverSession', zh: '告诉被驱动会话它是被远端派来的 task', en: 'Tell driven sessions they are a remote task', hintZh: '开（默认）时会话知道：可能有真人插话/按停，打断优先。', hintEn: 'On (default) the session knows a human here may interrupt, and interruptions win.' },
      { name: 'journal', type: 'boolean', group: 'serverSession', zh: '记录执行轨迹（journal）', en: 'Keep the trajectory journal', hintZh: '默认记录操作、被驱动轮次与本机打断，供主控增量读取；不消耗模型调用。', hintEn: 'Records operations, driven turns and local interruptions for incremental controller reads, without model calls.' },
      { name: 'journalFile', type: 'string', group: 'serverSession', zh: '轨迹文件路径', en: 'Journal file', hintZh: '默认 ${DSH_HOME}/dsh-remote/journal.jsonl；超过 8MB 轮转并保留上一代。', hintEn: 'Defaults to ${DSH_HOME}/dsh-remote/journal.jsonl; rotates at 8 MB keeping one generation.' },
      { name: 'heartbeatFile', type: 'string', group: 'serverSession', zh: '心跳文件路径', en: 'Heartbeat file', hintZh: '默认 ${DSH_HOME}/dsh-remote/server-heartbeat.json。成功监听并握手后写入，带构建标记——部署脚本靠它区分"这个版本在服务"和"只是有人在监听"。', hintEn: 'Defaults to ${DSH_HOME}/dsh-remote/server-heartbeat.json. Rewritten after the bind and after each handshake, carrying the build tag: it is how a deploy script tells "this build is serving" from "something is listening".' },

      { name: 'maxPermission', type: 'number', group: 'security', zh: '允许主控做的上限（1/2/3）', en: 'Max permission accepted (1/2/3)', hintZh: '1 只读、2 受限写、3 不限制。默认 3，正式部署建议调低。', hintEn: '1 read-only, 2 confined write, 3 unrestricted. Defaults to 3; lower it for a real deployment.' },
      { name: 'maxHandshakeFailures', type: 'number', group: 'security', zh: '握手失败阈值', en: 'Handshake failure threshold' },
      { name: 'lockoutSeconds', type: 'number', group: 'security', zh: '触发后冷却秒数', en: 'Cool-off seconds after the threshold' },
      { name: 'maxExecTimeoutMs', type: 'number', group: 'security', zh: '单次 exec 超时上限（毫秒）', en: 'Cap on one exec timeout (ms)' },
      { name: 'auditFile', type: 'string', group: 'security', zh: '审计日志路径', en: 'Audit log path' },
      { name: 'audit', type: 'boolean', group: 'security', zh: '记录每个被接受的操作', en: 'Log every accepted operation' },
    ]

    const CAPABILITY_FIELDS = [
      { name: 'remoteCapabilities', type: 'boolean', group: 'capability', default: true, zh: '镜像远端工具能力', en: 'Mirror remote tool capabilities' },
      { name: 'capabilityPreset', type: 'string', group: 'capability', zh: '能力目录 preset', en: 'Capability catalog preset', hintZh: '留空使用对端默认 preset。', hintEn: 'Empty uses the peer default preset.' },
      { name: 'capabilityRefreshSeconds', type: 'number', min: 0, group: 'capability', zh: '目录刷新间隔（秒）', en: 'Catalog refresh interval (seconds)', hintZh: '0 关闭定时刷新。', hintEn: '0 disables periodic refresh.' },
      { name: 'capabilityTimeoutMs', type: 'number', min: 1, group: 'capability', zh: '远端工具调用超时（毫秒）', en: 'Remote tool call timeout (ms)' },
      { name: 'capabilityDeny', type: 'list', group: 'capability', zh: '禁止镜像的工具', en: 'Tools excluded from the mirror' },
    ]
    CLIENT_FIELDS.push(...CAPABILITY_FIELDS)
    // This is not a volatile field, so the Host-owned form cannot mutate it.
    Object.assign(CLIENT_FIELDS.find(field => field.name === 'toolEnabled'), {
      readOnly: true, default: true,
      hintZh: '结构字段：请在配置源中修改并重启 DSH；此表单不能写入。',
      hintEn: 'Structural field: edit the configuration source and restart DSH. This form cannot write it.',
    })
    SERVER_FIELDS.push(
      { name: 'capabilities', type: 'boolean', default: true, group: 'capability', zh: '允许读取并直接调用本机工具', en: 'Allow catalog reads and direct local tool calls' },
      { name: 'capabilityPreset', type: 'string', group: 'capability', zh: '能力目录默认 preset', en: 'Default capability catalog preset' },
      { name: 'deniedTools', type: 'list', group: 'capability', zh: '拒绝直接调用的工具', en: 'Tools denied direct execution' },
      { name: 'maxToolCallTimeoutMs', type: 'number', min: 1, group: 'capability', zh: '直接工具调用超时上限（毫秒）', en: 'Direct tool call timeout ceiling (ms)' },
      { name: 'transferMaxBytes', type: 'number', min: 1, group: 'transfer', zh: '单文件传输大小上限（字节）', en: 'Maximum transfer file size (bytes)' },
      { name: 'transferMaxChunkBytes', type: 'number', min: 1, group: 'transfer', zh: '传输块大小上限（字节）', en: 'Maximum transfer chunk size (bytes)' },
      { name: 'transferMaxActive', type: 'number', min: 1, group: 'transfer', zh: '并发上传上限', en: 'Maximum active uploads' },
      { name: 'transferUploadTtlMs', type: 'number', min: 1, group: 'transfer', zh: '未完成上传保留时间（毫秒）', en: 'Unfinished upload lifetime (ms)' },
      { name: 'transferBeforeMaxBytes', type: 'number', min: 0, group: 'transfer', zh: '返回原内容大小上限（字节）', en: 'Maximum original content returned (bytes)' },
    )
    const PERMISSION_FIELD = {
      name: 'maxPermission', type: 'permission', default: 1, min: 1, max: 3,
      zh: '主机权限上限', en: 'Host permission ceiling',
      hintZh: '1 只读；2 仅限声明目录写入；3 可执行命令并驱动 agent。两端都要授权，较低上限生效。',
      hintEn: '1 read-only; 2 writes inside the declared root; 3 command execution and agent control. Both ends must authorize it; the lower ceiling wins.',
    }
    const ROOT_FIELD = {
      name: 'workspaceRoot', type: 'string', zh: '允许写入的工作区根目录', en: 'Writable workspace root',
      hintZh: '远端绝对路径。权限 2 的写入必须位于此目录；空根不会授予写权限。',
      hintEn: 'An absolute path on the controlled host. Level-2 writes must stay inside it; an empty root does not grant write access.',
    }

    const READ_ROOTS_FIELD = {
      name: 'readRoots', type: 'list', pathRoots: true, default: [], group: 'security',
      zh: '允许读取的根目录（每行一个）', en: 'Readable roots (one path per line)',
      hintZh: '每行一个被控主机上的绝对目录，最多 32 个，每个最多 4096 字符；按原样保存，不支持通配符。空列表禁止权限 1/2 的文件读取；权限 3 明确允许完整访问，不受此列表限制。不会自动复制其他主机的目录。',
      hintEn: 'One absolute directory on the controlled host per line, at most 32 roots of 4096 characters each. Paths are preserved literally, not wildcard patterns. Empty denies level-1/2 file reads. Level 3 explicitly grants full access and is not limited by this list. Other hosts\' roots are never copied automatically.',
    }
    SERVER_FIELDS.push({ ...READ_ROOTS_FIELD })

    const LEGACY_HANDSHAKE_FIELD = {
      name: 'allowLegacyHandshake', type: 'boolean', default: false, group: 'network',
      zh: '允许旧握手（降低安全性）', en: 'Allow legacy handshake (reduced security)',
      hintZh: zh.legacyHandshakeWarning, hintEn: en.legacyHandshakeWarning,
    }
    const SESSION_LIFETIME_FIELD = {
      name: 'maxSessionMs', type: 'number', min: 100, max: 3_600_000, default: 3_600_000, group: 'network',
      zh: '加密连接最长存活时间（毫秒）', en: 'Maximum encrypted connection lifetime (ms)',
      hintZh: '100..3600000，默认 3600000。到期关闭连接；后续请求须重新握手，不是 agent 轮次超时。',
      hintEn: '100..3600000, default 3600000. Expiry closes the link and later requests need a new handshake. This is not an agent turn timeout.',
    }
    CLIENT_FIELDS.push({ ...LEGACY_HANDSHAKE_FIELD }, { ...SESSION_LIFETIME_FIELD })
    SERVER_FIELDS.push({ ...LEGACY_HANDSHAKE_FIELD }, { ...SESSION_LIFETIME_FIELD },
      { name: 'maxConnections', type: 'number', min: 1, max: 1024, default: 64, group: 'network', zh: 'TCP 连接总上限', en: 'Maximum TCP connections' },
      { name: 'maxPendingHandshakes', type: 'number', min: 1, max: 128, default: 8, group: 'network', zh: '并发未完成握手上限', en: 'Maximum pending handshakes' },
      { name: 'maxConnectionsPerAddress', type: 'number', min: 1, max: 256, default: 16, group: 'network', zh: '每来源地址连接上限', en: 'Maximum connections per address' },
      { name: 'maxHandshakesPerMinute', type: 'number', min: 1, max: 6000, default: 120, group: 'network', zh: '每来源地址每分钟握手上限', en: 'Handshakes per address per minute' },
      { name: 'maxTrackedAddresses', type: 'number', min: 16, max: 65536, default: 1024, group: 'network', zh: '最多跟踪来源地址数', en: 'Maximum tracked source addresses' },
      { name: 'handshakeTimeoutMs', type: 'number', min: 50, max: 60000, default: 15000, group: 'network', zh: '握手总超时（毫秒）', en: 'Total handshake timeout (ms)' },
      { name: 'maxInFlightPerPrincipal', type: 'number', min: 1, max: 128, default: 16, group: 'network', zh: '每身份并发请求上限（跨连接合计）', en: 'Maximum in-flight requests per identity (all connections)' },
    )
    /** `dsh-remote-mesh`: a separate device-to-hub identity, not a target pin. */
    const MESH_FIELDS = [
      { name: 'host', type: 'string', default: '', group: 'endpoint', zh: '中心地址（域名 / IP）', en: 'Hub host (domain or IP)', hintZh: '中心设备现有 FRP 隧道的公网地址。只有地址与端口均配置后才连接；不为其他设备新增公网监听。', hintEn: 'The existing public FRP endpoint of the hub. A host and port are both needed to connect; other devices need no public listener.' },
      { name: 'port', type: 'number', min: 0, max: 65535, default: 0, group: 'endpoint', zh: '中心端口', en: 'Hub port', hintZh: '中心设备现有单端口映射。地址为空且端口为 0 时不连接；接入不会自动授权。', hintEn: 'The hub\u2019s existing single-port mapping. An empty host and port 0 keep it disconnected; joining never grants authorization.' },
      { name: 'privateKey', type: 'string', secret: true, group: 'key', zh: '接入中心的本机私钥（内联）', en: 'Local hub-connection private key (inline)' },
      { name: 'privateKeyFile', type: 'string', group: 'key', zh: '接入中心的本机私钥文件', en: 'Local hub-connection private key file' },
      { name: 'autoGenerateKey', type: 'boolean', default: false, group: 'key', zh: '缺接入密钥时自动生成', en: 'Generate a hub-connection keypair when missing', hintZh: '默认关闭。即使生成了密钥，也必须在中心逐台核验并显式授权。', hintEn: 'Off by default. A generated key still needs explicit per-device verification and authorization at the hub.' },
      { name: 'peerPublicKey', type: 'string', group: 'key', zh: '中心公钥（内联 pin）', en: 'Pinned hub public key (inline)', hintZh: zh.meshKeys, hintEn: en.meshKeys },
      { name: 'peerPublicKeyFile', type: 'string', group: 'key', zh: '中心公钥文件', en: 'Pinned hub public key file' },
      { name: 'timeoutMs', type: 'number', min: 1, max: 600_000, default: 15_000, group: 'network', zh: '中心请求超时（毫秒）', en: 'Hub request timeout (ms)' },
      { ...SESSION_LIFETIME_FIELD },
      { ...LEGACY_HANDSHAKE_FIELD },
      { name: 'acceptInbound', type: 'boolean', default: false, group: 'listen', zh: '允许转发到本机 server', en: 'Accept forwarding to this device server', hintZh: '默认关闭。开启后只接到本机固定 127.0.0.1:targetPort；中心 pair ACL 与本机 server 的控制公钥授权仍分别检查。', hintEn: 'Off by default. When enabled, inbound forwarding reaches only local 127.0.0.1:targetPort; hub pair ACLs and local server controller pins remain separate checks.' },
      { name: 'targetPort', type: 'number', min: 1, max: 65535, default: 11325, group: 'listen', zh: '本机 server 端口（targetPort）', en: 'Local server port (targetPort)', hintZh: '对应本机 server 的 loopback 监听端口；远端不能指定目标地址或端口。', hintEn: 'The local server\u2019s loopback port; remote peers cannot choose the target address or port.' },
      { name: 'autoReconnect', type: 'boolean', default: true, group: 'reconnect', zh: '断开后自动重连中心', en: 'Reconnect to the hub after disconnect', hintZh: '仅恢复传输连接，不重放已提交的操作。', hintEn: 'Restores the transport connection only; submitted operations are never replayed.' },
      { name: 'reconnectMinMs', type: 'number', min: 100, max: 60000, default: 1000, group: 'reconnect', zh: '重连最小间隔（毫秒）', en: 'Minimum reconnect delay (ms)' },
      { name: 'reconnectMaxMs', type: 'number', min: 100, max: 60000, default: 30000, group: 'reconnect', zh: '重连最大间隔（毫秒）', en: 'Maximum reconnect delay (ms)' },
    ]
    const RELAY_TARGETS_FIELD = {
      name: 'relayTargets', type: 'list', relayNodes: true, default: [],
      zh: '允许中心转发到的节点（relayTargets）', en: 'Allowed hub relay targets (relayTargets)',
      hintZh: `${zh.relayPolicy} ${zh.invalidRelayTargets}`, hintEn: `${en.relayPolicy} ${en.invalidRelayTargets}`,
    }
    const AUTHORIZATION_FIELDS = [
      { name: 'disabled', type: 'boolean', default: false, zh: '禁用此入站授权', en: 'Disable this inbound authorization',
        hintZh: '禁用后此公钥不能继续连接。关闭此开关不绕过过期、操作或权限规则。', hintEn: 'A disabled public key cannot keep connecting. Re-enabling never bypasses expiry, operation or permission checks.' },
      { name: 'validUntil', type: 'timestamp', default: '', zh: '授权有效截止时间（含时区）', en: 'Authorization valid until (with timezone)',
        hintZh: 'RFC3339，例如 2030-01-02T03:04:05Z 或 2030-01-02T11:04:05+08:00；两者为同一时刻。留空无期限，不能填无时区本地时间。',
        hintEn: 'RFC3339, for example 2030-01-02T03:04:05Z or 2030-01-02T11:04:05+08:00, the same instant. Empty means no expiry. Never enter unzoned local time.' },
      { name: 'allowedOps', type: 'list', exactOps: true, default: [], zh: '允许的精确操作名', en: 'Allowed exact operation names',
        hintZh: '每行一个操作名，例如 fs.read、caps.list；最多 64 项，不支持通配符。空列表沿用既有权限等级规则，不表示提权；非空列表只会进一步限制。',
        hintEn: 'One exact operation per line, e.g. fs.read or caps.list; at most 64 entries, no wildcards. Empty inherits existing permission-level rules, never grants extra rights. A nonempty list only restricts further.' },
    ]

    const GROUPS = {
      endpoint: { zh: zh.gEndpoint, en: en.gEndpoint },
      key: { zh: zh.gKey, en: en.gKey },
      session: { zh: zh.gSession, en: en.gSession },
      listen: { zh: zh.gListen, en: en.gListen },
      serverSession: { zh: zh.gServerSession, en: en.gServerSession },
      security: { zh: zh.gSecurity, en: en.gSecurity },
      network: { zh: '网络准入与连接寿命', en: 'Network admission and connection lifetime' },
      reconnect: { zh: '中心连接恢复', en: 'Hub reconnection' },
    }

    for (const [prefix, fields] of [['client', CLIENT_FIELDS], ['server', SERVER_FIELDS], ['mesh', MESH_FIELDS], ['peer', [PERMISSION_FIELD, ROOT_FIELD, READ_ROOTS_FIELD, RELAY_TARGETS_FIELD, ...AUTHORIZATION_FIELDS]]]) {
      for (const entry of fields) {
        entry.localeKey = `${prefix}.${entry.name}`
        zh[`${entry.localeKey}.label`] = entry.zh
        en[`${entry.localeKey}.label`] = entry.en
        if (entry.hintZh) zh[`${entry.localeKey}.hint`] = entry.hintZh
        if (entry.hintEn) en[`${entry.localeKey}.hint`] = entry.hintEn
      }
    }
    for (const entry of [...CLIENT_FIELDS, ...SERVER_FIELDS]) {
      // New peers have only leaf drafts until the Host resolves their schema.
      if (entry.name === 'autoGenerateKey') entry.default = true
      if (entry.type !== 'number') continue
      if (entry.name === 'port') { entry.min = 0; entry.max = 65535 }
      else if (entry.min === undefined) entry.min = 0
    }
    const SERVER_PERMISSION = SERVER_FIELDS.find(entry => entry.name === 'maxPermission')
    Object.assign(SERVER_PERMISSION, { type: 'permission', min: 1, max: 3, default: 3 })
    zh.permission1 = '1 · 只读'
    zh.permission2 = '2 · 工作区内写入'
    zh.permission3 = '3 · 不限制（命令与 agent）'
    en.permission1 = '1 · Read-only'
    en.permission2 = '2 · Workspace writes'
    en.permission3 = '3 · Unrestricted (commands and agent)'

    for (const [group, labels] of Object.entries(GROUPS)) {
      zh[`group.${group}`] = labels.zh
      en[`group.${group}`] = labels.en
    }
    zh['group.transfer'] = '传输边界'
    en['group.transfer'] = 'Transfer limits'
    zh.hosts = '台主机'
    en.hosts = 'hosts'
    zh.authorized = '已授权'
    en.authorized = 'authorized'

    const tokens = {
      label: 'var(--dsw-alias-label-primary)',
      muted: 'var(--dsw-alias-label-secondary)',
      border: 'var(--dsw-alias-border-l1)',
      borderStrong: 'var(--dsw-alias-border-l2)',
      layer: 'var(--dsw-alias-bg-layer-1)',
      layer2: 'var(--dsw-alias-bg-layer-2)',
      base: 'var(--dsw-alias-bg-base)',
      brand: 'var(--dsw-alias-brand-primary)',
      ok: 'var(--dsw-alias-state-success-primary)',
      error: 'var(--dsw-alias-state-error-primary)',
    }

    const STYLE_ID = 'dsh-remote-config-styles'

    /**
     * The page's CSS.
     *
     * Real stylesheet, not inline styles: inline styles cannot express
     * `:hover`, `:focus-visible` or `:disabled`, so a form built from them has
     * no interaction feedback and no focus ring — that is the bulk of what made
     * this page feel unadapted to the app it lives in.
     *
     * The confirm control is the important line. `ui-primitives`
     * `settings-form .save` is `background: label-primary` with the SURFACE
     * colour as its text, which is contrast-safe in every theme by
     * construction, because `label-primary` is by definition readable on the
     * surface. What this page used before — a `brand-primary` fill with a
     * literal `#FFFFFF` label — is unsafe on both counts: this platform binds
     * `brand-primary` to near-black, so a hard-coded white is only accidentally
     * readable in the light theme and unreadable in the dark one.
     */
    const STYLE_TEXT = `
.fsf-root { display: flex; flex-direction: column; color: ${tokens.label}; font-size: 13px; line-height: 1.5; }
.fsf-group { margin: 16px 0 2px; font-size: 12px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; color: ${tokens.muted}; }
.fsf-root > .fsf-group:first-child { margin-top: 4px; }
.fsf-row { display: flex; align-items: center; gap: 10px; padding: 6px 0; flex-wrap: wrap; }
.fsf-row + .fsf-row { border-top: 0.5px solid ${tokens.border}; }
.fsf-hint { flex: 1 1 100%; margin-top: -4px; font-size: 12px; line-height: 1.5; color: ${tokens.muted}; }
.fsf-label { display: flex; align-items: baseline; gap: 8px; flex: 0 1 230px; min-width: 0; }
.fsf-badge { font-size: 11.5px; color: ${tokens.muted}; }
.fsf-input { flex: 1 1 200px; max-width: 340px; height: 34px; box-sizing: border-box; padding: 0 12px; border: 0.5px solid ${tokens.borderStrong}; border-radius: var(--dsw-radius-md, 8px); background: ${tokens.base}; color: ${tokens.label}; font: inherit; font-size: 13px; line-height: 1.5; }
.fsf-input:hover:not(:disabled) { border-color: ${tokens.brand}; }
.fsf-input:focus-visible { outline: 2px solid ${tokens.brand}; outline-offset: 1px; border-color: ${tokens.brand}; }
.fsf-input:disabled { color: ${tokens.muted}; cursor: default; }
.fsf-input-narrow { flex: 0 1 160px; }
.fsf-check { flex: none; width: 15px; height: 15px; margin: 0; accent-color: ${tokens.brand}; }
.fsf-btn { appearance: none; box-sizing: border-box; display: inline-flex; align-items: center; justify-content: center; flex: none; height: 34px; padding: 0 14px; border: 0.5px solid ${tokens.borderStrong}; border-radius: var(--dsw-radius-md, 8px); background: transparent; color: ${tokens.label}; font: inherit; font-size: 13px; line-height: 1.5; cursor: pointer; }
.fsf-btn:hover:not(:disabled) { background: ${tokens.layer2}; }
.fsf-btn:focus-visible { outline: 2px solid ${tokens.brand}; outline-offset: 1px; }
.fsf-btn:disabled { opacity: 0.4; cursor: default; }
.fsf-btn-sm { height: 26px; padding: 0 10px; font-size: 12px; border-radius: var(--dsw-radius-sm, 6px); }
.fsf-save { border-color: transparent; background: ${tokens.label}; color: ${tokens.base}; }
.fsf-footer { display: flex; align-items: center; gap: 10px; padding-top: 16px; flex-wrap: wrap; }
.fsf-status { font-size: 12.5px; color: ${tokens.muted}; }
.fsf-error { font-size: 12.5px; color: ${tokens.error}; }
.fsf-note { margin: 8px 0 0; font-size: 12.5px; line-height: 1.6; color: ${tokens.muted}; }
.fsf-root .fsf-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: start; gap: 7px 12px; padding: 10px 0; }
.fsf-root .fsf-row + .fsf-row { border-top: 0; }
.fsf-root .fsf-label { grid-column: 1 / -1; font-size: 13px; }
.fsf-root .fsf-input { width: 100%; max-width: none; min-width: 0; }
.fsf-root textarea.fsf-input { min-height: 84px; height: auto; padding: 8px 12px; resize: vertical; }
.fsf-root .fsf-check { align-self: center; }
.fsf-root .fsf-hint { grid-column: 1 / -1; margin-top: 0; }
.fsf-root .fsf-footer { border-top: 0.5px solid ${tokens.border}; margin-top: 16px; }
.fsf-root .fsf-btn { white-space: nowrap; }
.fsf-root .fsf-btn:active:not(:disabled) { transform: translateY(1px); }
.fsf-root .fsf-save:hover:not(:disabled) { background: ${tokens.label}; color: ${tokens.base}; }
.fsf-section { margin: 0 0 18px; min-width: 0; }
.fsf-heading { margin: 0 0 4px; font-size: 14px; font-weight: 600; }
.fsf-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); gap: 0 20px; }
.fsf-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: end; margin: 10px 0; }
.fsf-toolbar > .fsf-row { flex: 1 1 200px; padding: 0; }
.fsf-details { margin-top: 14px; border-top: 0.5px solid ${tokens.border}; padding-top: 10px; }
.fsf-details > summary { cursor: pointer; font-size: 13px; font-weight: 600; color: ${tokens.label}; padding: 4px 0; }
.fsf-details > summary:focus-visible { outline: 2px solid ${tokens.brand}; outline-offset: 2px; }
.fsf-details > .fsf-group { margin-top: 12px; }
.fsf-key-status { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; grid-column: 1 / -1; }
.fsf-confirm { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px 0; }
.fsf-confirm > p { flex-basis: 100%; margin: 0; }
.fsf-root .fsf-group { text-transform: none; letter-spacing: normal; }
.fsf-inline-error { margin: 4px 0 0; }
@media (max-width: 480px) { .fsf-toolbar { align-items: stretch; } .fsf-toolbar > .fsf-row { flex-basis: 100%; } .fsf-footer .fsf-status { flex-basis: 100%; } }
`

    /** Mount the page's stylesheet once for as long as this half is loaded. */
    function injectStyles() {
      if (document.getElementById(STYLE_ID) !== null) return
      const style = document.createElement('style')
      style.id = STYLE_ID
      style.textContent = STYLE_TEXT
      document.head.appendChild(style)
    }

    /** Withdraw the stylesheet with the half that owns it. */
    function dropStyles() {
      document.getElementById(STYLE_ID)?.remove()
    }

    /** Wrap the namespace lookup so a missing dictionary still reads as prose. */
    function translate(lookup) {
      return key => {
        const value = typeof lookup === 'function' ? lookup(key) : undefined
        return typeof value === 'string' && value !== key ? value : (zh[key] ?? key)
      }
    }

    /** All addresses remain arrays: a peer named build.eu is one path segment. */
    const pathKey = path => JSON.stringify(path)
    const containsPath = (parent, child) => parent.length <= child.length && parent.every((part, index) => part === child[index])
    const atPath = (input, path) => path.reduce((node, part) => node !== null && typeof node === 'object' && Object.hasOwn(node, part) ? node[part] : undefined, input)
    const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)
    function stagedAt(value, draft, path) {
      let result = atPath(value, path)
      for (const op of draft) {
        if (containsPath(op.path, path)) result = op.op === 'unset' ? undefined : atPath(op.value, path.slice(op.path.length))
      }
      return result
    }
    function stage(current, path, value, invalid, unset = false) {
      const next = current.filter(op => !containsPath(path, op.path))
      return [...next, unset ? { op: 'unset', path } : { op: 'set', path, value, ...(invalid ? { invalid } : {}) }]
    }
    function recordNames(value, draft, root) {
      const names = new Set(Object.keys(isRecord(value[root]) ? value[root] : {}))
      for (const op of draft) {
        if (op.path[0] !== root || op.path.length < 2) continue
        if (op.path.length === 2 && op.op === 'unset') names.delete(op.path[1])
        else names.add(op.path[1])
      }
      return [...names]
    }
    function validPeerName(name) {
      return /^[A-Za-z0-9._-]{2,}$/.test(name)
        && !['rmt', '.', '..', '__proto__', 'constructor', 'prototype'].includes(name.toLowerCase())
    }
    function validRelayName(name) {
      return typeof name === 'string' && name.length <= 128 && validPeerName(name)
    }
    function validRelayTargets(value) {
      return Array.isArray(value) && value.length <= 64 && value.every(validRelayName)
    }
    function isOverridden(user, path) {
      const parent = atPath(user, path.slice(0, -1))
      return isRecord(parent) && Object.hasOwn(parent, path[path.length - 1])
    }

    /**
     * Whether the Host reports this secret path as set.
     *
     * Two sources, because the first one is empty in this build: the per-entry
     * `form` snapshot has no `secrets` field (the Host strips secret values and,
     * as shipped, the flag with them), so the authoritative answer comes from the
     * settings describe mirror. `flags` is that answer, narrowed to this
     * namespace; `undefined` means "unknown", which the page renders as such
     * rather than claiming the key is missing.
     */
    function secretIsSet(form, path, flags) {
      const address = Array.isArray(path) ? path : [path]
      const secrets = form?.state?.secrets
      if (Array.isArray(secrets)) {
        const match = secrets.find(entry => Array.isArray(entry?.path) && pathKey(entry.path) === pathKey(address))
        if (match !== undefined) return match.set === true
      }
      if (flags === undefined) return undefined
      return flags.has(pathKey(address))
    }

    /** The settings describe face; assigned by `apply`, absent in older hosts. */
    let describeFace

    /** Secret paths the Host reports as set for one namespace, or an empty set. */
    function namespaceSecrets(ns) {
      const flags = new Set()
      try {
        const namespaces = describeFace?.getSnapshot?.()?.view?.namespaces
        if (!Array.isArray(namespaces)) return flags
        const row = namespaces.find(candidate => candidate?.ns === ns)
        for (const entry of row?.secrets ?? []) {
          if (entry?.set === true && Array.isArray(entry.path) && entry.path.length > 0) {
            flags.add(pathKey(entry.path))
          }
        }
      } catch {
        // A missing or reshaped mirror must not break the page.
      }
      return flags
    }

    /**
     * Live secret flags for one namespace.
     *
     * Subscribes rather than reading once: the describe answer may arrive after
     * this page renders, and a write from another surface changes it.
     * @param {{ ns: string }} props - the namespace of the row being edited.
     * @returns {Set<string>} secret paths reported as set.
     */
    function useNamespaceSecrets(ns) {
      const [flags, setFlags] = React.useState(() => namespaceSecrets(ns))
      React.useEffect(() => {
        const read = () => { setFlags(new Set(namespaceSecrets(ns))) }
        read()
        const face = describeFace
        if (face === undefined) return undefined
        let stop = () => {}
        try { stop = face.subscribe(read) ?? (() => {}) } catch { stop = () => {} }
        try { Promise.resolve(face.ensure?.()).then(read, () => {}) } catch { /* best effort */ }
        return stop
      }, [ns])
      return flags
    }

    /** Explicit-zone RFC3339 only. Date.parse alone normalizes invalid dates. */
    function validExpiry(raw) {
      if (raw === '') return true
      const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/.exec(raw)
      if (!match) return false
      const [, y, m, d, h, minute, second, sign, offsetHour, offsetMinute] = match
      const year = Number(y), month = Number(m), day = Number(d)
      const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
      const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
      return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
        && Number(h) <= 23 && Number(minute) <= 59 && Number(second) <= 59
        && (sign === undefined || (Number(offsetHour) <= 23 && Number(offsetMinute) <= 59
          && !(sign === '-' && offsetHour === '00' && offsetMinute === '00')))
        && Number.isFinite(Date.parse(raw))
    }
    function validAllowedOps(value) {
      return Array.isArray(value) && value.length <= 64
        && value.every(op => op.length <= 64 && /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/.test(op))
    }
    function validReadRoots(value) {
      return Array.isArray(value) && value.length <= 32
        && value.every(root => root.length >= 1 && root.length <= 4096 && !/[\x00-\x1f\x7f]/.test(root)
          && (/^[A-Za-z]:[\\/]/.test(root) || root.startsWith('/') || /^\\\\[^\\]+\\[^\\]+/.test(root)))
    }

    /** Coerce one control's raw value into the JSON shape the field declares. */
    function coerce(spec, raw) {
      if (spec.type === 'boolean') return raw === true
      if (spec.type === 'number' || spec.type === 'permission') {
        if (String(raw).trim() === '') return undefined
        const parsed = Number(raw)
        return Number.isFinite(parsed) && Number.isInteger(parsed)
          && (spec.min === undefined || parsed >= spec.min) && (spec.max === undefined || parsed <= spec.max)
          ? parsed : undefined
      }
      if (spec.type === 'list') {
        const lines = String(raw).split(/\r?\n/)
        return spec.pathRoots || spec.relayNodes ? lines.filter(part => part !== '') : lines.map(part => part.trim()).filter(Boolean)
      }
      return String(raw)
    }

    /** The staging state behind one page: drafts, pending state, and the write. */
    function useDraft(form) {
      const [draft, setDraft] = React.useState([])
      const [busy, setBusy] = React.useState(false)
      const [error, setError] = React.useState('')
      const [savedAt, setSavedAt] = React.useState(0)
      const revision = form?.state?.revision
      // A new Host revision invalidates every staged value, including secrets.
      React.useEffect(() => { setDraft([]); setError('') }, [revision])
      const save = React.useCallback(async () => {
        if (busy || draft.length === 0 || draft.some(op => op.invalid)) return
        const ops = draft.map(({ op, path, value }) => op === 'unset' ? { op, path } : { op, path, value })
        setBusy(true)
        setError('')
        try {
          const accepted = await form.mutate(ops, form.state.revision)
          if (accepted) { setDraft([]); setSavedAt(Date.now()) } else setError('refused')
        } catch (failure) {
          setError(failure instanceof Error ? failure.message : String(failure))
        } finally {
          setBusy(false)
        }
      }, [draft, form, busy])
      const discard = () => { setDraft([]); setError(''); setSavedAt(0) }
      return { draft, setDraft, busy, error, savedAt, save, discard }
    }

    /** A routed target never advertises an unused direct endpoint as fallback. */
    function endpointText(value, t) {
      if (typeof value.relayTarget === 'string' && value.relayTarget !== '') return `${t('relayRoute')} ${value.relayTarget}`
      const host = value.host === undefined || value.host === '' ? undefined : String(value.host)
      const port = typeof value.port === 'number' && value.port > 0 ? String(value.port) : undefined
      if (host === undefined && port === undefined) return t('unset')
      return `${host ?? '?'}:${port ?? '?'}`
    }

    /**
     * Build one row's component over its own field table.
     * @param {{ fields: ReadonlyArray<object>, note: string, ns: string, summary: Function }} spec
     * @returns the component the Plugins page renders for that row.
     */
    function makeComponent(spec) {
      const { fields, note, ns, summary } = spec
      const server = ns === 'dsh-remote-server'
      const mesh = ns === 'dsh-remote-mesh'
      const root = server ? 'authorizedPeers' : 'peers'
      const field = name => fields.find(entry => entry.name === name)

      function Summary(props) {
        const t = translate(props.t ?? props.lookup)
        const flags = useNamespaceSecrets(ns)
        if (props.form?.state?.status === 'loading') return h('span', null, t('loading'))
        return h('span', null, summary(props.form?.state?.value ?? {}, props.form, t, flags))
      }

      function Page(props) {
        const t = translate(props.t ?? props.lookup)
        const form = props.form
        const { draft, setDraft, busy, error, savedAt, save, discard } = useDraft(form)
        const secretFlags = useNamespaceSecrets(ns)
        const [selected, setSelected] = React.useState(null)
        const [newName, setNewName] = React.useState('')
        const [nameError, setNameError] = React.useState('')
        const [removeTarget, setRemoveTarget] = React.useState('')
        React.useEffect(() => { setRemoveTarget(''); setNameError('') }, [form?.state?.revision])
        if (form?.state === undefined) return h('p', { className: 'fsf-status' }, t('noForm'))
        const state = form.state
        if (state.status === 'loading') return h('p', { className: 'fsf-status' }, t('loading'))
        if (state.status === 'unavailable') return h('p', { className: 'fsf-error' }, t('unavailable'))
        const value = state.value ?? {}
        const writable = state.writable === true && state.mode === 'host'
        const disabled = !writable || busy
        const pending = draft.length > 0
        const names = recordNames(value, draft, root)
        const get = path => stagedAt(value, draft, path)
        const legacyName = String(get(['peerName']) || 'default')
        const legacyConfigured = String(get(['host']) ?? '').trim() !== '' || Number(get(['port'])) > 0 || String(get(['relayTarget']) ?? '') !== ''
        const selectedName = selected === '' || names.includes(selected) ? selected
          : ((server || !legacyConfigured) ? names[0] ?? '' : '')
        const prefix = selectedName === '' ? [] : [root, selectedName]
        const effectiveNames = [...names]
        if (!server && legacyConfigured && !effectiveNames.includes(legacyName)) effectiveNames.push(legacyName)
        const configuredDefault = String(get(['defaultPeer']) ?? '')
        const missingDefault = !server && !mesh && configuredDefault !== '' && !effectiveNames.includes(configuredDefault)

        function edit(entry, path, raw) {
          const converted = coerce(entry, raw)
          const invalid = (entry.type === 'number' || entry.type === 'permission') && converted === undefined
            ? 'invalidNumber' : entry.type === 'timestamp' && !validExpiry(converted) ? 'invalidExpiry'
              : entry.exactOps && !validAllowedOps(converted) ? 'invalidAllowedOps'
                : entry.pathRoots && !validReadRoots(converted) ? 'invalidReadRoots'
                  : entry.relayNodes && !validRelayTargets(converted) ? 'invalidRelayTargets'
                    : entry.relayNode && converted !== '' && !validRelayName(converted) ? 'invalidRelayTarget'
                      : entry.name === 'peerName' && (!validPeerName(String(converted))
                      || names.some(name => name !== converted && name.toLowerCase() === String(converted).toLowerCase())) ? 'invalidName' : ''
          setDraft(current => {
            const stored = atPath(value, path)
            if (!invalid && entry.type !== 'list' && JSON.stringify(converted) === JSON.stringify(stored)) {
              return current.filter(op => pathKey(op.path) !== pathKey(path))
            }
            // Keep an invalid numeric draft visible, but never send it to Host.
            const next = stage(current, path, invalid ? raw : converted, invalid)
            if (entry.type === 'list') next[next.length - 1].text = String(raw)
            return next
          })
        }

        function renderRow(entry, parent = []) {
          const path = [...parent, entry.name]
          const key = pathKey(path)
          const staged = get(path)
          const op = draft.find(candidate => pathKey(candidate.path) === key)
          const labelText = t(`${entry.localeKey}.label`)
          const overridden = isOverridden(state.user, path)
          const hint = entry.hintZh || entry.hintEn ? t(`${entry.localeKey}.hint`)
            : entry.type === 'list' ? t('listHint') : ''
          const inputId = `fsf-input-${ns}-${encodeURIComponent(key)}`
          const hintId = hint ? `fsf-hint-${ns}-${encodeURIComponent(key)}` : undefined
          const errorId = op?.invalid ? `${inputId}-error` : undefined
          const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined
          const common = {
            id: inputId, 'aria-label': labelText, 'aria-describedby': describedBy,
            'aria-invalid': op?.invalid ? true : undefined,
            disabled: disabled || entry.readOnly === true,
          }
          let control
          let extra = null
          if (entry.secret) {
            const isSet = secretIsSet(form, path, secretFlags)
            control = h('input', {
              ...common, type: 'password', className: 'fsf-input',
              // Never hydrate a password from the redacted value, even if a
              // future Host accidentally includes a similarly named property.
              value: op?.op === 'set' ? String(op.value) : '',
              spellCheck: false, autoComplete: 'new-password', placeholder: t('keepSecret'),
              onChange: event => {
                const text = event.target.value
                setDraft(current => text === '' ? current.filter(candidate => pathKey(candidate.path) !== key)
                  : stage(current, path, text))
              },
            })
            extra = h('div', { className: 'fsf-key-status' },
              h('span', { className: 'fsf-status', style: { color: isSet === true ? tokens.ok : tokens.muted } },
                t(isSet === undefined ? 'secretUnknown' : isSet ? 'secretSet' : 'secretUnset')),
              writable && isSet === true ? h('button', {
                type: 'button', className: 'fsf-btn fsf-btn-sm', disabled: busy,
                // Empty explicit inline value masks an inherited secret too;
                // unset would restore that secret from the base layer.
                onClick: () => setDraft(current => stage(current, path, '')),
              }, t('clear')) : null)
          } else if (entry.type === 'boolean') {
            control = h('input', {
              ...common, type: 'checkbox', className: 'fsf-check',
              checked: (staged ?? entry.default) === true,
              onChange: event => edit(entry, path, event.target.checked),
            })
          } else if (entry.type === 'permission') {
            control = h('select', {
              ...common, className: 'fsf-input', value: String(staged ?? entry.default ?? 1),
              onChange: event => edit(entry, path, event.target.value),
            }, [1, 2, 3].map(level => h('option', { key: level, value: String(level) }, t(`permission${level}`))))
          } else {
            const list = entry.type === 'list'
            control = h(list ? 'textarea' : 'input', {
              ...common, className: 'fsf-input', ...(list ? { rows: 3 } : { type: entry.type === 'number' ? 'number' : 'text' }),
              ...(entry.type === 'number' ? { min: entry.min, max: entry.max, step: 1 } : {}),
              value: list ? (op?.text ?? (Array.isArray(staged) ? staged.join('\n') : '')) : String(staged ?? entry.default ?? ''),
              spellCheck: false, onChange: event => edit(entry, path, event.target.value),
            })
          }
          return h('div', { key, className: 'fsf-row', 'data-path': key },
            h('label', { className: 'fsf-label', htmlFor: inputId }, labelText,
              overridden ? h('span', { className: 'fsf-badge' }, t('overridden')) : null),
            control, extra,
            writable && overridden && !entry.readOnly && !entry.secret ? h('button', {
              type: 'button', className: 'fsf-btn fsf-btn-sm', disabled: busy,
              onClick: () => setDraft(current => stage(current, path, undefined, '', true)),
            }, t('revert')) : null,
            hintId ? h('div', { id: hintId, className: 'fsf-hint' }, hint) : null,
            errorId ? h('div', { id: errorId, className: 'fsf-error fsf-hint' }, t(op.invalid)) : null,
            entry.type === 'timestamp' && staged && validExpiry(staged) && Date.parse(staged) <= Date.now()
              ? h('div', { className: 'fsf-hint' }, t('expiryState')) : null)
        }
        const rows = (entries, parent = []) => h('div', { className: 'fsf-grid' }, entries.filter(Boolean).map(entry => renderRow(entry, parent)))
        const details = (key, title, children) => h('details', { key, className: 'fsf-details' }, h('summary', null, t(title)), children)

        const addHost = () => {
          if (!validPeerName(newName)) { setNameError('invalidName'); return }
          const folded = newName.toLowerCase()
          const storedNames = Object.keys(isRecord(value[root]) ? value[root] : {})
          if ([...names, ...storedNames].some(name => name.toLowerCase() === folded)
            || (!server && legacyConfigured && legacyName !== newName && legacyName.toLowerCase() === folded)) {
            setNameError('duplicateName'); return
          }
          // New records start read-only and empty. Never copy redacted legacy
          // data or replace a map containing existing secrets/unknown fields.
          setDraft(current => stage(current, [root, newName, 'maxPermission'], 1))
          setSelected(newName); setNewName(''); setNameError(''); setRemoveTarget('')
        }
        const inherited = selectedName !== '' && atPath(state.base, [root, selectedName]) !== undefined
        const removeHost = () => {
          if (inherited || removeTarget !== selectedName || selectedName === '') return
          setDraft(current => {
            const clean = current.filter(op => !containsPath([root, selectedName], op.path))
            const removed = atPath(value, [root, selectedName]) === undefined ? clean
              : stage(clean, [root, selectedName], undefined, '', true)
            return !server && configuredDefault === selectedName ? stage(removed, ['defaultPeer'], '') : removed
          })
          setSelected(null); setRemoveTarget('')
        }
        const hostToolbar = h('div', { className: 'fsf-toolbar' },
          h('div', { className: 'fsf-row' },
            h('label', { className: 'fsf-label', htmlFor: `fsf-select-${ns}` }, t(server ? 'editingController' : 'editingHost')),
            h('select', { id: `fsf-select-${ns}`, className: 'fsf-input', 'aria-label': t(server ? 'editingController' : 'editingHost'), value: selectedName,
              disabled: busy, onChange: event => { setSelected(event.target.value); setRemoveTarget('') } },
            h('option', { value: '' }, t('legacy')), names.map(name => h('option', { key: name, value: name }, name)))),
          h('div', { className: 'fsf-row' },
            h('label', { className: 'fsf-label', htmlFor: `fsf-new-${ns}` }, t('newHostName')),
            h('input', { id: `fsf-new-${ns}`, className: 'fsf-input', value: newName, 'aria-label': t('newHostName'),
              'aria-describedby': `fsf-name-help-${ns}`, 'aria-invalid': nameError ? true : undefined,
              disabled, autoComplete: 'off', spellCheck: false,
              onChange: event => { setNewName(event.target.value); setNameError('') } })),
          h('button', { type: 'button', className: 'fsf-btn', disabled: disabled || newName === '', onClick: addHost }, t('addHost')))
        const defaultSelector = server ? null : h('div', { className: 'fsf-row' },
          h('label', { className: 'fsf-label', htmlFor: `fsf-default-${ns}` }, t('defaultHost')),
          h('select', { id: `fsf-default-${ns}`, className: 'fsf-input', 'aria-label': t('defaultHost'),
            'aria-describedby': `fsf-default-help-${ns}`, value: configuredDefault, disabled,
            onChange: event => setDraft(current => stage(current, ['defaultPeer'], event.target.value)) },
          h('option', { value: '' }, t('automaticDefault')),
          missingDefault ? h('option', { value: configuredDefault }, configuredDefault) : null,
          effectiveNames.map(name => h('option', { key: name, value: name }, name))),
          h('div', { className: 'fsf-hint', id: `fsf-default-help-${ns}` }, t('defaultHint')),
          missingDefault ? h('div', { className: 'fsf-error' }, t('missingDefault')) : null)
        const selectedFields = server
          ? [field('peerPublicKey'), field('peerPublicKeyFile'), ...(selectedName === '' ? [field('readRoots')] : [PERMISSION_FIELD, ROOT_FIELD, READ_ROOTS_FIELD, ...AUTHORIZATION_FIELDS, RELAY_TARGETS_FIELD])]
          : [field('host'), field('port'), ...(selectedName === '' ? [field('peerName')] : [PERMISSION_FIELD, ROOT_FIELD]),
            field('relayTarget'), field('peerPublicKey'), field('privateKey')]
        const hostEditor = h('section', { key: 'hosts', className: 'fsf-section' },
          h('h3', { className: 'fsf-heading' }, t(server ? 'inbound' : 'outbound')),
          defaultSelector, hostToolbar,
          h('p', { className: 'fsf-note', id: `fsf-name-help-${ns}` }, t('invalidName')),
          nameError ? h('p', { className: 'fsf-error fsf-inline-error', role: 'alert' }, t(nameError)) : null,
          h('p', { className: 'fsf-note' }, t(server ? 'authorizationNote' : 'legacyNote')),
          rows(selectedFields, prefix),
          !server ? details(`identity-${selectedName}`, 'identityFiles', rows([
            field('privateKeyFile'), field('autoGenerateKey'), field('peerPublicKeyFile'), field('timeoutMs'),
            field('allowLegacyHandshake'), field('maxSessionMs'),
          ], prefix)) : null,
          !server && selectedName === '' ? h('p', { className: 'fsf-note' }, t('legacyPermission')) : null,
          selectedName !== '' ? h('div', { className: 'fsf-confirm' },
            h('button', { type: 'button', className: 'fsf-btn fsf-btn-sm', disabled: disabled || inherited,
              onClick: () => setRemoveTarget(selectedName) }, t('removeHost')),
            inherited ? h('p', { className: 'fsf-note' }, t('inheritedHost')) : null,
            removeTarget === selectedName ? [h('p', { key: 'note', className: 'fsf-note' }, t(server ? 'removeAuthNote' : 'removeNote')),
              h('button', { key: 'confirm', type: 'button', className: 'fsf-btn fsf-btn-sm', disabled, onClick: removeHost }, t('confirmRemove')),
              h('button', { key: 'cancel', type: 'button', className: 'fsf-btn fsf-btn-sm', disabled: busy, onClick: () => setRemoveTarget('') }, t('cancel'))] : null) : null)
        const basicNames = new Set(server ? ['host', 'port', 'relayEnabled', 'maxPermission', 'privateKey', 'privateKeyFile', 'autoGenerateKey', 'peerPublicKey', 'peerPublicKeyFile', 'readRoots']
          : fields.filter(entry => entry.group === 'endpoint' || entry.group === 'key' || entry.group === 'network').map(entry => entry.name))
        const capabilityFields = fields.filter(entry => !basicNames.has(entry.name) && entry.group !== 'network' && (entry.type === 'boolean' || entry.group === 'capability'))
        const advancedFields = fields.filter(entry => !basicNames.has(entry.name) && !capabilityFields.includes(entry))
        const advancedGroups = [...new Set(advancedFields.map(entry => entry.group))]
        const invalid = missingDefault || draft.some(op => op.invalid)
        return h('div', { className: 'fsf-root', 'aria-busy': busy ? 'true' : undefined },
          h('p', { className: 'fsf-note' }, t(note)),
          !mesh ? h('p', { className: 'fsf-note' }, t('bidirectional')) : null,
          h('p', { className: 'fsf-note' }, t('legacyHandshakeWarning')),
          h('p', { className: 'fsf-note' }, t('meshTopology')),
          mesh ? h('p', { className: 'fsf-note' }, t('meshTrust')) : null,
          mesh ? h('p', { className: 'fsf-note' }, t('meshKeys')) : null,
          mesh ? h('p', { className: 'fsf-note' }, t('relayPolicy')) : null,
          server ? h('section', { className: 'fsf-section' },
            h('h3', { className: 'fsf-heading' }, t('gListen')), rows([field('host'), field('port'), field('relayEnabled'), SERVER_PERMISSION]),
            details('listener-identity', 'listenerIdentity', rows([field('privateKey'), field('privateKeyFile'), field('autoGenerateKey')]))
          ) : null,
          mesh ? [
            h('section', { key: 'endpoint', className: 'fsf-section' }, h('h3', { className: 'fsf-heading' }, t('gEndpoint')), rows(fields.filter(entry => entry.group === 'endpoint'))),
            h('section', { key: 'key', className: 'fsf-section' }, h('h3', { className: 'fsf-heading' }, t('gKey')), rows(fields.filter(entry => entry.group === 'key'))),
            h('section', { key: 'listen', className: 'fsf-section' }, h('h3', { className: 'fsf-heading' }, t('gListen')), rows(fields.filter(entry => entry.group === 'listen'))),
            details('mesh-advanced', 'advanced', ['network', 'reconnect'].map(group => h('section', { key: group },
              h('h4', { className: 'fsf-group' }, t(`group.${group}`)), rows(fields.filter(entry => entry.group === group))))),
          ] : [
            hostEditor,
            !server ? h('p', { key: 'references', className: 'fsf-note' }, t('references')) : null,
            details('capabilities', 'capabilities', [rows(capabilityFields), h('p', { key: 'restart', className: 'fsf-note' }, t('restartHint'))]),
            details('advanced', 'advanced', [h('p', { key: 'hint', className: 'fsf-note' }, t('advancedHint')),
              ...advancedGroups.map(group => h('section', { key: group },
                h('h4', { className: 'fsf-group' }, t(`group.${group}`)), rows(advancedFields.filter(entry => entry.group === group))))]),
          ],
          h('div', { className: 'fsf-footer' },
            h('button', { type: 'button', className: 'fsf-btn fsf-save', disabled: disabled || !pending || invalid,
              onClick: () => { if (!invalid) return save() } }, busy ? t('saving') : t('save')),
            pending ? h('button', { type: 'button', className: 'fsf-btn', disabled: busy,
              onClick: () => { discard(); setRemoveTarget(''); setNameError('') } }, t('discard')) : null,
            !writable ? h('span', { className: 'fsf-status' }, t('readOnly')) : null,
            pending ? h('span', { className: 'fsf-status' }, t('dirty')) : null,
            !pending && savedAt > 0 && error === '' ? h('span', { className: 'fsf-status', role: 'status' }, t('saved')) : null,
            error !== '' ? h('span', { className: 'fsf-error', role: 'alert' }, error === 'refused' ? t('refused') : error) : null))
      }
      return function DshRemoteRowConfig(props) {
        return props?.view === 'summary' ? h(Summary, props) : h(Page, props)
      }
    }

    const ClientConfig = makeComponent({
      ns: 'dsh-remote-client',
      fields: CLIENT_FIELDS,
      note: 'clientNote',
      summary: (value, form, t, flags) => {
        const names = Object.keys(isRecord(value.peers) ? value.peers : {})
        const legacyName = String(value.peerName || 'default')
        if ((String(value.host ?? '').trim() !== '' || Number(value.port) > 0 || String(value.relayTarget ?? '') !== '') && !names.includes(legacyName)) names.push(legacyName)
        const selectedName = names.includes(value.defaultPeer) ? value.defaultPeer : names[0]
        const selected = selectedName && Object.hasOwn(value.peers ?? {}, selectedName) ? value.peers[selectedName] : value
        const secret = secretIsSet(form, selected === value ? ['privateKey'] : ['peers', selectedName, 'privateKey'], flags)
        return `${names.length > 0 ? `${names.length} ${t('hosts')} · ${selectedName} · ` : ''}${endpointText(selected, t)} · ${t(secret === undefined ? 'secretUnknown' : secret ? 'secretSet' : 'secretUnset')}`
      },
    })

    const ServerConfig = makeComponent({
      ns: 'dsh-remote-server',
      fields: SERVER_FIELDS,
      note: 'serverNote',
      summary: (value, form, t, flags) => {
        const secret = secretIsSet(form, 'privateKey', flags)
        const count = Object.keys(isRecord(value.authorizedPeers) ? value.authorizedPeers : {}).length
        return `${endpointText(value, t)} · ${t(secret === undefined ? 'secretUnknown' : secret ? 'secretSet' : 'secretUnset')}${count > 0 ? ` · ${t('authorized')} ${count} ${t('hosts')}` : ''}`
      },
    })

    const MeshConfig = makeComponent({
      ns: 'dsh-remote-mesh',
      fields: MESH_FIELDS,
      note: 'meshNote',
      summary: (value, form, t, flags) => {
        const secret = secretIsSet(form, 'privateKey', flags)
        return `${endpointText(value, t)} · ${t(secret === undefined ? 'secretUnknown' : secret ? 'secretSet' : 'secretUnset')}`
      },
    })

    return {
      inject: ['slots', 'locale'],
      /**
       * Contribute direct and mesh configuration pages.
       * @param ctx - the browser plugin context.
       */
      apply(ctx) {
        // The page's stylesheet lives exactly as long as this half does.
        ctx.effect(() => { injectStyles(); return dropStyles }, 'dsh-remote: config styles')
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-remote: dictionaries')
        // Secret "set / not set / clear" comes from here: the per-entry form
        // snapshot does not carry the flag in this build. Looked up optionally —
        // `inject` deliberately does NOT list configForms, because a hard
        // dependency would stop this half from applying at all on a host that
        // does not expose it.
        try { describeFace = ctx.configForms?.describe?.() } catch { describeFace = undefined }
        const lookup = ctx.locale.bind(NS)
        const injectFace = () => ({ lookup, locale: ctx.locale.getSnapshot().active })
        ctx.slots.inject('plugins.row.config', () => ctx.slots.register({
          name: 'plugins.row.config', key: CLIENT_KEY, locale: NS, inject: injectFace,
        }, ClientConfig))
        ctx.slots.inject('plugins.row.config', () => ctx.slots.register({
          name: 'plugins.row.config', key: SERVER_KEY, locale: NS, inject: injectFace,
        }, ServerConfig))
        ctx.slots.inject('plugins.row.config', () => ctx.slots.register({
          name: 'plugins.row.config', key: MESH_KEY, locale: NS, inject: injectFace,
        }, MeshConfig))
      },
    }
  },
})
