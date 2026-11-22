本 ADR 评审钉钉 Stream 渠道在通用层需要的四项边界变更(WebSocket 出站、流式入站契约、连接已认证的密封证据、共享准入管线)以及监督器、token 交换位置和威胁模型,批准后才能开始 Task 2。

# ADR:钉钉 Stream 渠道的通用层设计评审

日期:2026-11-18
状态:待批准(见末尾"批准"一节,尚未填写)
关联计划:`docs/internal/2026-11-18-dingtalk-channel-plan.md`(Task 1)
基线提交:`b0b999d96`

## 0. 范围与已定事项

以下事项已由用户决定,本 ADR 只记录,不重新讨论:

- 机器人类型为企业内部应用机器人,接入方式为 Stream 模式。
- WebSocket 传输扩展 `ironclaw_network`,不做 Telegram MTProto 式的豁免。
- 接受新增一种"连接已认证的流式入站"密封证据,仍只由 `ironclaw_extension_host` 里唯一的 `ChannelIngressVerifier` 实现铸造。
- 交付顺序:里程碑一(通用流式入站)、里程碑 1b(token 交换)、里程碑二(钉钉包)。

本 ADR 需要决定的是上述决策**如何落地**。每一项都按"决定 / 备选方案 / 取舍理由 / 影响的文件或 crate"书写。

**事实来源的限制。** 钉钉官方文档站(`open.dingtalk.com`)对本次抓取只返回空正文,`opensource.dingtalk.com` 无法连接。因此第 8 节的"已验证"只表示"已对照官方 SDK 源码确认 SDK 的行为",不表示钉钉服务端的承诺。其余一律标"未验证",并写出由哪个后续任务验证。

**度量说明。** 本机没有 `rg`,附录里的计数用等价的 `grep -E` 在 `git ls-files -co --exclude-standard '*.rs'` 的 2333 个文件上得到。附录第 0 节给出命令,可以用 `rg` 复现,但 `rg` 的结果我没有实际运行过。

## 1. WebSocket 出站

### 1.1 `wss` 的表达方式

**决定。** 在 `NetworkScheme` 里新增 `Wss` 变体(序列化为 `"wss"`),不另建独立类型。`ironclaw_network` 内新增一个 WebSocket 连接器,复用同一个 `StaticNetworkPolicyEnforcer`、`NetworkResolver` 和 `url_target`。

**备选方案。**

- B:`NetworkScheme` 保持不变,在 `ironclaw_network` 内新建 `WebSocketTarget` / `WebSocketPolicy` 类型,策略执行器和解析器同时接受两种目标。
- C:把 WebSocket 当成 `Https` 目标,连接时再做协议升级(不改任何类型)。

**取舍理由。**

- 实测(附录第 2 节与清单 B)引用 `NetworkScheme` 的 Rust 文件有 68 个(`crates/` 59 个,`tests/` 9 个),不是计划原文的 59 个。但编译器强制处理新增变体的穷尽 `match` 只有 2 处:`crates/contracts/ironclaw_product_contracts/src/approval_prompt.rs:173-176`(审批提示文本)和 `crates/substrates/ironclaw_network/src/url_target.rs:91-94`(`default_port`,`Wss => 443`)。其余约 50 个文件只构造 `NetworkScheme::Https` 字面量,不受影响。
- 另有 3 处"字符串转 scheme"的解析点会默认拒绝 `wss`,需要主动修改:`url_target.rs:73-77`(`network_target_for_url`,所有经 `ironclaw_network` 的目标都经过它)、`ironclaw_extension_host/src/egress.rs:146-149`(渠道出站只接受 `"https"`,**保持不变**,因为 REST 调用仍是 https)、`ironclaw_network/src/egress.rs:211-214`(重定向只允许 http/https,**保持不变**,WebSocket 不跟随重定向)。真正要改的只有 `url_target.rs` 一处。
- 约 15 处"把 `Https` 当作唯一允许的安全 scheme"的比较点(附录第 2.4 节,例如 `mcp.rs:118`、`ironclaw_auth/src/engine/http.rs:145`、`v2.rs:1460`)新增 `Wss` 后继续拒绝 `wss`。这对 MCP、OAuth、skills 是期望行为(fail-closed),不需要改。
- 方案 A 的实际改动面是:`action.rs` 枚举 + 2 个穷尽 `match` + `url_target.rs` 解析 + `policy.rs:260-262`(`target_matches_pattern` 要求 `pattern.scheme` 与目标相等)+ `channel.rs`(`[[channel.egress]]` 的 `scheme` 字段,`#[serde(default = "default_https")]`)+ `docs/internal/reborn/contracts/host-api.md`(第 914、920、936 行提到 `NetworkScheme`),约 7 到 8 个生产文件。
- 方案 B 避免改动 `ironclaw_host_api` 的序列化枚举,但要让 `policy.rs`、`resolver.rs` 同时处理两类目标,策略语义会出现两份(私网拒绝、主机匹配、端口匹配各写两遍)。仓库规则要求"一个出站策略所有者"(`crates/substrates/AGENTS.md` 的 `ironclaw_network` 定位),两份策略逻辑违背这一点。
- 方案 C 把协议升级藏在 `https` 里,审批提示和审计里看不出这是长连接,而且 `reqwest` 本身不处理 WebSocket 升级(附录第 2.6 节),不可行。
- 代价:`ironclaw_host_api` 是最底层契约 crate,变更其序列化枚举会触发 `host_api_contract.rs` 一类契约测试(`NetworkScheme` 在该测试里出现)。这是 A 的主要成本,在 Task 2 的 PR 里要列出。

**影响的文件或 crate。** `ironclaw_host_api`(`action.rs`)、`ironclaw_product_contracts`(`approval_prompt.rs`)、`ironclaw_network`(`url_target.rs`、`policy.rs`、新增连接器模块)、`ironclaw_extension_contracts`(`channel.rs`)、`docs/internal/reborn/contracts/host-api.md` 与 `network.md`。

### 1.2 主机白名单

**决定。** 不放宽 egress 通配符。流式声明里逐个列出 WebSocket 主机(显式主机列表),监督器在建连调用返回 `endpoint` 后,先检查其主机精确出现在声明列表内,再交给 `ironclaw_network`。`ChannelDescriptor::validate` 对通配符的拒绝(`channel.rs:421`、错误 `WildcardOrEmptyEgressHost`,`channel.rs:849-850`)保持不变。

**当前状态:阻塞。** 钉钉网关返回的主机是否固定、是否轮换**未验证**(第 8 节条目 5)。SDK 原样使用 `endpoint`,不校验主机,也没有主机清单。因此本 ADR 只能决定"机制",不能决定"具体主机名"。

- **批准的附带条件(建议)。** 具体主机名在 Task 12 之前,由官方文档或一次真实建连得到的 `endpoint` 补齐。拿不到之前,里程碑一用 `acme` 夹具的回环假网关,不受影响。
- 如果钉钉的主机确实轮换,唯一可接受的放宽方式是第二个独立决定:仅对"流式声明的 WebSocket 主机"支持一个受限的后缀模式(例如固定二级域名下的子域),不放开 `[[channel.egress]]` 的通配符,并且需要重新批准。本 ADR 不批准任何通配符。

**备选方案。**

- 放宽 `[[channel.egress]]` 的通配符:风险是一个渠道声明 `*.example.com` 后,管理员无法在审批和审计里看到实际会连接的主机,也让 SSRF 防护只依赖私网拒绝;同时所有渠道(slack、telegram 等)共享同一个校验函数,放宽影响面是整个渠道体系。
- 不做主机检查,只依赖 `ironclaw_network` 的私网拒绝:见第 7.1 节,公网上的任意主机也是攻击目标(网关响应被篡改或钉钉被入侵时),不可接受。

**取舍理由。** 主机清单进入 manifest digest 和升级差异分类(新增 WebSocket 主机属于权限扩大,Task 3),让每一次扩大都需要管理员重新同意。代价是钉钉若更换网关域名,包必须发新版本。这是有意的 fail-closed。

**影响的文件或 crate。** `ironclaw_extension_contracts`(`channel.rs`:流式声明的主机字段、校验)、`ironclaw_extension_registry`(`v3.rs`、digest、升级差异)、`ironclaw_extension_host`(监督器的主机检查)。

### 1.3 TLS 与 `reqwest` 保持一致

**决定。** WebSocket 客户端使用 `tokio-tungstenite`,`default-features = false`,启用 `rustls-tls-native-roots`(及必要的 `connect`),与 `reqwest = { features = ["rustls-tls-native-roots"] }`(根 `Cargo.toml:101`、`crates/substrates/ironclaw_network/Cargo.toml:24`)使用同一类 rustls 与系统原生根证书。依赖只放在 `ironclaw_network`,不放进其他生产 crate。

**备选方案。** 使用 `webpki-roots`(内置根证书,与系统信任库脱节);自己用 `tokio-rustls` 握手后交给 `tungstenite`(多一层自维护的 TLS 代码)。

**取舍理由。** 第二套证书信任会让管理员在系统里加的企业根证书只对 REST 生效、对 WebSocket 无效(或相反),这是安全与可运维性的双重问题。

**未验证项(Task 2 验证)。**

- `Cargo.lock` 已有 `tokio-tungstenite` 0.23 与 0.29 两个版本;当前只作为 composition 和 webui 的 dev 依赖,特性为 `connect`,没有 TLS(计划背景一节)。选哪个版本、其 `rustls` 版本是否与 `reqwest 0.12` 的 `rustls` 一致、两者的加密后端(`ring` 或 `aws-lc-rs`)是否一致,我没有用 `cargo tree` 核对,**未验证**。Task 2 必须用 `cargo tree -i rustls -e features` 给出结论,不一致则回到本 ADR 修订。
- `cargo deny check` 对新增传递依赖的许可证结果(`deny.toml` 允许 MIT 与 Apache-2.0)**未验证**,由 Task 2 执行。

**影响的文件或 crate。** `ironclaw_network/Cargo.toml`、`Cargo.lock`、`deny.toml`(若需要新增例外)、单一出站边界扫描测试(`reborn_runtime_http_egress_has_single_network_boundary` 一类,需扩展为拒绝其他生产 crate 直接使用 WebSocket 客户端)。

### 1.4 修订记录(2026-11-20):WebSocket 握手由 `ironclaw_network` 手写

**修订内容。** 里程碑一收尾评审的第 7 项指出,`ticket` 在 URL 查询参数里,而 `tokio-tungstenite` 的客户端握手会把完整 URL 解析成 `http::Uri`(内部是不可变的 `Bytes`,不能清零),并把请求行渲染进普通 `Vec<u8>`,所以"`ticket` 只存在于清零缓冲"的承诺做不到。用户(本 ADR 的批准人)于 2026-11-20 决定:**不收窄承诺,改为握手由 `ironclaw_network` 手写**。

**变化。**
- 连接器在第一个 `?` 处把 URL 拆成不带查询的 endpoint 和查询;策略评估、DNS、URL 解析只接触 endpoint。`#` 一律拒绝。
- 升级请求由 `ironclaw_network` 构造进一个按精确容量分配的 `Zeroizing<Vec<u8>>`,发送后立即覆写,所有退出路径再覆写一次。响应按 RFC 6455 第 4.2.2 节逐条校验(状态必须是 101、`Upgrade`、`Connection`、常量时间比较 `Sec-WebSocket-Accept`),未请求的 `Sec-WebSocket-Extensions` 与 `Sec-WebSocket-Protocol`、任何 3xx 重定向一律拒绝;非 101 状态仍映射为 `HandshakeRejected{status}`,所以第 5.5 节的 401/403 分类不变。响应头上限 8 KiB,整个握手受 `connect_timeout` 约束。
- TLS 改为 `ironclaw_network` 直接使用 `tokio-rustls`(与 `reqwest` 相同的 `ring` 提供者和系统原生根证书)。这是第 1.3 节备选方案里"自己用 `tokio-rustls` 握手"的做法,但只用于 WebSocket 出站,信任来源不变,第 1.3 节"不引入第二套证书信任"的决定没有改变。`tokio-tungstenite` 仍是唯一的 WebSocket 帧层,握手后收到的残留字节原样交给它。
- 新增 `ironclaw_network` 的直接依赖(都已在 `Cargo.lock` 的依赖图里):`httparse`、`subtle`、`rustls`、`tokio-rustls`、`rustls-native-certs`、`rustls-pki-types`。

**残留副本(如实记录,2026-11-20 复核后重写)。** 此前的说法"本 crate 内没有未清零副本、调用方不在范围内"不准确,已撤回。握手路径(`ironclaw_network::websocket`)之外,`ticket` 还经过以下位置,其中前两处无法在不改动共享 HTTP 栈的前提下清零:
- `ironclaw_network` 的通用 HTTP 响应路径(`transport.rs`):建连响应体(含 `ticket`)由 `reqwest`/`hyper` 缓冲,再累积进普通 `Vec<u8>`,增长时会留下未清零的旧缓冲。主机侧一拿到响应体就移入 `Zeroizing`,但此前的副本不受控。
- 主机侧把响应体解析为 `serde_json::Value`:`ticket` 在解析树里是普通 `String`,取出后才移入 `Zeroizing`,解析树随后释放但不清零。
- `rustls` 内部加密前的明文写缓冲,以及内核 socket 缓冲。
已修复的副本:主机 `build_url` 以最坏情况容量一次分配 `Zeroizing<String>`,不再增长(评审 #7);契约要求 `{ticket}` 位于 `url_template` 第一个 `?` 之后(评审 N2),所以 `ticket` 不会进入路径、`url::Url` 解析或策略评估。
**已接受的残留。** 上面前两处(HTTP 响应体累积用的普通 `Vec<u8>`,以及 `serde_json::Value` 里 `ticket` 被移出之前的普通 `String`)由批准人(用户)于 2026-11-20 明确接受,不是编码者自行划定的范围。接受的同时不改动共享 HTTP 响应类型,也不收窄其他承诺。
即使将来改了共享响应类型,`reqwest`、`hyper`、`rustls` 的内部缓冲和内核 socket 缓冲仍会保留副本,所以建连响应路径本来就无法做到全程清零;握手路径的清零承诺(上文"变化"各条)不受影响。
**后续可选任务(未启动,不在里程碑一范围)。** 给 HTTP 响应体增加敏感标记,让 `ironclaw_network` 自己持有的那部分(`transport.rs` 的响应体累积)改用可清零缓冲。该任务会改共享响应类型,需要单独立项和评审。
**未改变。** 第 1 节到第 7 节的其余决定,包括主机白名单、`wss` 唯一、禁止重定向、私网拒绝、帧与速率上限。

## 2. 入站契约

### 2.1 传输方式改为带标签枚举

**决定。** `ChannelIngressDescriptor` 的传输方式改为带标签枚举:`Webhook`(持有 `route_suffix`、`verification`、方法集)、`Stream`(持有流式声明)、`AuthenticatedSession`(现有 `kind = "authenticated_session"`,规则不变)。manifest 向前兼容:旧写法解析为 `Webhook`。`ChannelDescriptor::validate` 里"非 `authenticated_session` 入站必须有 `route_suffix`"改为"只有 `Webhook` 必须有"(对应现有错误 `WebhookIngressWithoutRouteSuffix`);`connection` 对流式入站同样允许。

**备选方案。**

- B:保留现有结构,把 `route_suffix` 变成 `Option`,`verification` 新增 `Stream` 变体(`IngressVerificationRecipe::Stream`)。改动文件最少,但"流式入站的验证方式是什么"这个说法不成立:流式入站没有请求级验证配方,验证发生在连接建立时。把它塞进 `IngressVerificationRecipe` 会让 `verify_recipe`(`ingress/verifier.rs:127-152`)出现一个永远不该被调用的分支,并且 `route_suffix: Option` 会让"webhook 缺 route_suffix"从类型错误退化为运行时校验。
- C:流式入站作为独立描述符(`[channel.stream]`),与 `[channel.ingress]` 并列。改动面最小,但"一个渠道最多有一种入站"这个不变量需要新增互斥校验,且 `connection`、`presentation` 等依赖 `ingress` 存在的校验要逐个改。

**取舍理由。** 带标签枚举让"流式入站没有 `route_suffix`、没有 `verification`"成为类型事实,编译器会逼着每个使用点显式处理。代价是使用点多(见下)。

**影响的使用点(实测,附录第 1 节与清单 A)。**

- 引用 `route_suffix` 或 `.verification`(精确写法,排除 `.verification_uri`)的 Rust 文件为 30 个(`route_suffix` 23、`.verification` 20,并集 30)。其中 1 个无关:`crates/domains/ironclaw_trace_commons/src/contribution/envelope.rs`(它自己的字段)。另有 1 个只在注释里提到:`crates/app/ironclaw_architecture_tests/tests/reborn_dependency_boundaries.rs:714`。所以真正受影响的渠道入站使用点是 29 个,其中另含注释一处需要同步文字。宽松写法 `\.verification` 会得到 33 个,多出的 3 个是 OAuth 设备码的 `verification_uri`(`ironclaw_llm/src/auth.rs`、`openai_codex_session.rs`、`llm_config_service.rs`)。
- 生产代码文件(附录清单 A,按路径判断):`ironclaw_cli/src/commands/serve.rs`(路由挂载)、`ironclaw_extension_contracts/src/{channel,recipe}.rs`、`ironclaw_extension_host/src/{active,channel_config,channel_connection,channel_host,channel_identity_binding,deployment_channels,entrypoint,extension_ingress,lifecycle,session_ingress}.rs`、`ingress/{mod,router,verifier}.rs`、`ironclaw_extension_registry/src/v3.rs`、`ironclaw_assistant/src/reborn_services/extensions.rs`。其余为测试与测试支撑。
- 额外同步:WebUI 的渠道投影和前端类型(Task 3 要先枚举,本 ADR **未枚举**前端文件,**未验证**,由 Task 3 执行)。

**影响的文件或 crate。** `ironclaw_extension_contracts`、`ironclaw_extension_registry`、`ironclaw_extension_host`、`ironclaw_cli`(`serve.rs`)、`ironclaw_assistant`,以及契约 crate 大小上限门禁(`reborn_contracts_crates_carry_a_checked_size_ceiling`,需要在 PR 里写明提高上限的理由)。

### 2.2 流式声明字段

**决定。** `Stream` 变体携带:

| 字段 | 说明 |
|---|---|
| `connect` | 建连调用:复用 `ChannelVendorCallRecipe`(method、path、body)加 `body_credentials`,由此 `clientSecret` 只经 host 注入请求体 |
| `response` | 响应映射:`endpoint` 与 `ticket` 的 JSON 指针;`ticket` 标记为秘密 |
| `subscriptions` | 订阅主题模板(钉钉为 `type=CALLBACK`、`topic=/v1.0/im/bot/messages/get`) |
| `url_template` | WebSocket 地址模板,只允许 `{endpoint}` 与 `{ticket}` 两个占位符各一次;必须以 `{endpoint}` 开头(评审 #9),`{ticket}` 必须位于第一个 `?` 之后(评审 N2);`ticket` 进入查询参数,按秘密处理 |
| `hosts` | 显式主机列表(见 1.2) |
| `keepalive` | ping 间隔与 pong 超时 |
| `max_frame_bytes` | 单帧大小上限 |
| `max_frames_per_second`(每连接) | 速率上限 |
| ~~`body_limit_bytes`~~ | 修订(2026-11-20):stream 声明不再携带此字段,出现即被安装校验拒绝(评审 #8)。帧上限由 `max_frame_bytes` 表达;webhook 与 session 的 `body_limit_bytes` 不变 |

具体数值(默认值与上限)不在 ADR 里定,Task 3 写进声明校验,Task 6、7 测试。

**备选方案。** 把建连调用做成 manifest 里的自由 HTTP 调用(不限制路径和字段);把 `ticket` 放进路径而不是查询参数。

**取舍理由。** 复用 `ChannelVendorCallRecipe` 与 `body_credentials`(`egress.rs:60-61`,`BodyJsonPointer` 注入)意味着凭证注入走已有的、已测试的路径。响应映射是新增,因为现有配方没有响应映射(计划背景:只有 method、path、body、`body_credentials`)。`ticket` 在查询参数里是钉钉协议的要求(SDK 拼 `{endpoint}?ticket={quote_plus(ticket)}`,已验证 SDK 行为),所以 WebSocket 连接器不能沿用 egress 路径"禁止 `?`"的约束(见 7.3)。

**影响的文件或 crate。** `ironclaw_extension_contracts`(`channel.rs`、`recipe.rs`)、`ironclaw_extension_registry`(`v3.rs`、`resolved.rs`、digest)。

### 2.3 帧控制 trait 的形状

**决定。** 新增一个纯函数 trait(暂名 `ChannelStreamControl`),位于 `ironclaw_extension_contracts`,没有 I/O、不接触密钥、不接触证据:

- `fn decode(&self, frame: &[u8]) -> Result<StreamFrameDecision, StreamFrameError>`,返回:`Ack(AckFrame)`、`AckAndReconnect(AckFrame)`、`Deliver { data: Vec<u8>, ack_on_commit: AckTemplate }`、`Drop { ack: Option<AckFrame> }`。
- `fn session_key(&self, data: &[u8]) -> Option<String>`:从回调 `data` 里取只用于**排序**的键(例如钉钉的 `conversationId`),返回有界字符串。它不授予任何权限,见 5.2。

**备选方案。** 帧控制与 `ChannelIngress` 合并成一个 trait(接口少,但 `receive` 是 `async` 且带 egress,帧控制必须是同步纯函数才能在监督器里无条件安全调用);让适配器自己读写 WebSocket(违背"适配器不做 I/O"和"不能自己开 socket")。

**取舍理由。** 把"哪些帧要回什么 ACK、`disconnect` 是否重连"这类协议细节留在包里,把"何时 ACK、何时重连、何时丢弃"这类策略留在 host。`Deliver` 的 `ack_on_commit` 只是模板,监督器在共享管线返回后才发送。

**影响的文件或 crate。** `ironclaw_extension_contracts`(trait、`ChannelSurfaces` 新槽位、绑定一致性检查:声明流式入站必须同时绑定 ingress 与帧控制)、`ironclaw_extension_host`(`channel_host.rs`)、`ironclaw_composition`(`RebornHostBindings::with_channel_extension_bindings` 的槽位,只装配不点名包)、`ironclaw_cli`(二进制绑定)。

### 2.4 复用 `ChannelIngress::receive`

**决定。** 帧的 `data` 作为 `VerifiedInbound.body`,交给现有 `ChannelIngress::receive(VerifiedInbound)`。`VerifiedInbound` 的 `headers` 为空,`config` 为非秘密配置,`can_reply_in_threads` 来自 presentation。

**备选方案。** 为流式入站另设 `receive_frame`(要重写一致性套件和附件补全)。

**取舍理由。** 一致性套件(`test_support/conformance.rs`)和附件补全已经围绕 `receive` 建立,复用后只需增加流式部分。`receive` 返回的 `InboundOutcome::{Messages, BatchFragment, Respond, Ignore}` 也原样进入共享管线(第 4 节)。

**影响的文件或 crate。** `ironclaw_extension_contracts`(conformance 增加流式部分)。

## 3. 密封证据

### 3.1 新增 `AuthRequirement` 变体

**决定。** 在 `crates/contracts/ironclaw_host_api/src/product_adapter/auth.rs:116-128` 的 `AuthRequirement` 新增一个变体,暂名 `AuthenticatedStream { connection_recipe: String }`,序列化为 `authenticated_stream`。字段只记录"连接是经哪一个声明的建连配方认证的"(配方名或固定标签,经 `validate_http_token` 风格校验,有长度上限),不含任何秘密、`ticket`、连接 ID 或帧内容。证据的 `subject` 与现有两种渠道证据一致,来自 host 侧的安装归属。

**全部触点(实测,附录第 3 节与清单 C)。**

| # | 位置 | 改动 |
|---|---|---|
| 1 | `ironclaw_host_api/src/product_adapter/auth.rs` | 新变体;`validate_metadata`(130-150)的穷尽 `match` 增加分支;`ProtocolAuthEvidence` 的内联测试 |
| 2 | `ironclaw_extension_contracts/src/product_adapter_section.rs` | 两处穷尽 `match`:校验(294-313)与 manifest 原始类型转换 `into_auth_requirement`(378-391)。产品适配器 manifest **不应**能声明 `authenticated_stream`(它只属于渠道),所以转换处返回校验错误,不新增 manifest 写法 |
| 3 | `ironclaw_extension_contracts/src/verified_inbound.rs` | 新增第三个铸造函数 `mark_authenticated_stream_verified(grant, connection_recipe, subject)`,仍消耗 `VerifiedInboundGrant`,结构与 `mark_request_signature_verified`(69)、`mark_shared_secret_header_verified`(86)相同 |
| 4 | `ironclaw_extension_host/src/extension_ingress.rs` | `VerifiedEvidenceMint`(79-88)新增 `AuthenticatedStream` 变体;`mint()`(101-122)增加分支。`impl ChannelIngressVerifier for VerifiedEvidenceMint {}`(99)不变 |
| 5 | `ironclaw_extension_host/src/channel_host.rs` | `evidence_mint_for_verification`(162-182)现在按 `IngressVerificationRecipe` 推出证据。传输方式改为带标签枚举后,改为按传输方式推出:`Webhook` 沿用现有映射,`Stream` 返回 `VerifiedEvidenceMint::AuthenticatedStream`,`AuthenticatedSession` 仍返回 `None`。调用点:`channel_host.rs:674` 与测试 1285、1308、1322、1477 |
| 6 | `ironclaw_extension_host/src/ingress/verifier.rs` | `verify_recipe`(127-152)只服务 webhook。若采用 2.1 的带标签枚举,流式入站根本不会到达这里,不需要新分支;若 Task 3 改选备选方案 B,则必须返回与 `AuthenticatedSession` 相同的 `NotWebhookVerifiable` |
| 7 | `ironclaw_architecture_tests/tests/reborn_sealed_evidence_mint_ratchet.rs` | 实现者清单不变;如棘轮按铸造函数名清点,新增函数要加入允许清单,并在注释(64、68 行附近)说明 |
| 8 | `ironclaw_host_api/tests/protocol_auth_evidence_seal.rs`、`ironclaw_extension_contracts/tests/verified_inbound_seal.rs` | 现有两个测试替身(在 `tests/` 下,不被棘轮清点)增加新铸造函数的用例,不新增替身 |
| 9 | 其余约 20 个测试文件(附录第 3 节与清单 C) | 只构造现有变体,不需修改;若有对 `AuthRequirement` 的穷尽 `match`,编译器会指出 |
| 10 | `docs/internal/reborn/contracts/host-api.md` | 补充新变体的语义 |

**为什么不新增实现者。** `crates/contracts/ironclaw_host_api/AGENTS.md` 的"Sealed evidence — do not widen"写明:`ChannelIngressVerifier` 只有一个生产实现者(`ironclaw_extension_host`,信任阶段 T2),由 `reborn_sealed_evidence_mint_ratchet` 固定,因为第二个实现者能为无人认证的请求伪造已验证声明。流式监督器放在 `ironclaw_extension_host` 内,铸造仍经 `VerifiedEvidenceMint` 这一个实现,所以不需要第二个实现者。包(`packages/dingtalk`)不持有 grant,无法调用新铸造函数。

**为什么不新增 grant。** 同一文件要求"do not add a third grant"。新证据描述的仍是"渠道入站已被 host 验证",与 `VerifiedInboundGrant` 的语义完全一致,区别只在验证方式(连接级而非请求级),这由 `AuthRequirement` 变体表达。grant 保持非 `Clone`/`Default`/`Deserialize`。

**这确实是对密封证据词汇的拓宽。** 新增 `AuthRequirement` 变体意味着下游任何按 `requirement()`(`auth.rs:227`)做决策的代码都会看到一个新值。本 ADR 请求所有者(用户本人)对此书面批准,这是批准一节需要明确回答的第一项。

**取舍理由。** 流式连接的认证发生在建连时,而不是每一帧上。证据必须如实描述"连接级认证",这需要一个新的 `AuthRequirement` 取值。铸造权仍只在 `ironclaw_extension_host` 内唯一的 `ChannelIngressVerifier` 实现处,所以信任边界不变,只是词汇多一个值。代价是所有读取 `requirement()` 的下游代码要面对新值,由上表的触点清单和编译器的穷尽匹配兜住。

**备选方案。**

- 复用 `SharedSecretHeader`,把 `header_name` 填成虚构值:证据内容与实际发生的验证不符,违背 `verified_inbound.rs` 注释"the claim describes the verification that actually happened",否决。
- 新建独立的流式证据类型和 grant:违背"do not add a third grant",否决。
- HTTP 回调模式(计划"备选方案"):不需要新证据,但签名不覆盖消息体,可伪造(计划已记录),仅在本 ADR 未获批准时启用。

**铸造时机(Task 4、6 遵守)。** 证据只在监督器完成"建连调用返回成功且 WebSocket 握手成功"之后,对该连接上的帧铸造。安装标识来自连接所有权(监督器为哪个安装建的连接),**不**来自帧内容(例如帧头里的 `appId`、回调里的 `robotCode`)。连接断开后,对该连接上尚未处理的帧不再铸造。

**影响的文件或 crate。** `ironclaw_host_api`、`ironclaw_extension_contracts`、`ironclaw_extension_host`、`ironclaw_architecture_tests`,以及上表所列测试与契约文档。

## 4. 共享准入管线

**决定。** 从 `crates/extensions/ironclaw_extension_host/src/ingress/router.rs` 抽出"`receive` 返回之后"的流程,成为与传输无关的函数(暂名 `admit_inbound_outcome`),webhook 路由器与流式监督器都调用它。

**抽取边界(以当前代码行号为准)。**

| 留在 webhook 路由器(传输相关) | 进入共享管线(传输无关) |
|---|---|
| 第 1 步:按 `route_suffix` 匹配绑定(`handle`,306-330) | `InboundOutcome` 的分派(`verify_and_dispatch` 第 7 步,约 520-575) |
| 第 2、3 步:方法、体积上限、整体超时(333-358) | `admit_messages`(623-700):`message.validate()`、`reply_context` 写入、`sink.admit` 的 durable 去重 `(installation, event_id)`、可重试与永久错误分类 |
| 第 4 步:`verify_recipe` 与验证密钥(361-410) | `BatchFragment` 的暂存与合并:`InboundBatchProcessor::stage_and_schedule`(706 起)与 `binding.fingerprint()` |
| 验证后按安装限流(414-422) | `Respond` 的边界检查(`response.validate()`、2xx 范围) |
| 第 5 步:非秘密配置读取 | |
| 第 6 步:剥离已消费的验证头(440 附近)、构造 `VerifiedInbound`、`channel_egress` | |
| `receive` 的调用、`catch_unwind`、`channel_error_is_transient` 分类(611-621) | (见下) |

`receive` 调用本身和适配器错误分类有两种放法。**决定**:把"调用 `receive` 加 panic 隔离加适配器错误分类"也放进共享管线(传入已构造的 `VerifiedInbound` 与 egress),因为这三步与传输无关,而且两种传输对适配器错误的处理必须一致。HTTP 头剥离与 `VerifiedInbound` 的构造留在各自传输里。

**输出。** 共享管线返回传输无关的结果枚举(暂名 `AdmissionDisposition`):`Admitted`(含"全部为重复"的情况,与现在 `Accepted | Duplicate` 合并处理一致)、`Ignored`、`Respond(ImmediateResponse)`、`BatchStaged`、`Transient`、`DeterministicDiscard`、`HostBoundViolation`。webhook 路由器把它映射回现在的 HTTP 响应:

| 结果 | webhook 现状(必须不变) | 流式监督器 |
|---|---|---|
| `Admitted` / `Ignored` / `BatchStaged` | `IngressResponse::ok()` | 发 ACK |
| `Respond` | 适配器给出的 2xx | 发 ACK(响应体丢弃,流式没有同步响应) |
| `Transient` | 503 `temporarily_unavailable` | 不发 ACK,等钉钉重投 |
| `DeterministicDiscard` | `acknowledged_discarded()` | 发 ACK 并记审计 |
| `HostBoundViolation` | 500 `adapter` | 发 ACK 并记审计(与 webhook 不同:流式没有 5xx,重投同样的字节只会重复失败) |

**"行为不变"的保证。**

- Task 5 是单独的纯重构 PR:只移动代码和抽取接口,不改日志级别、错误码、HTTP 状态和顺序。
- 现有日志语句的级别与字段(`tracing::debug!` / `warn!`)原样移动。
- 门禁:`cargo test -p ironclaw_extension_host --no-fail-fast` 全量,`crates/extensions/ironclaw_extension_host/tests/ingress_router_contract.rs` 与 `tests/integration/extension_ingress.rs` 的 ING-1 到 ING-12(含 libSQL/PostgreSQL 矩阵)全部通过,输出不经过滤。任何失败先报告,不改断言。
- 重构前后比较 `ingress_router_contract.rs` 的通过用例名单,写进 PR。

**取舍理由。** 两种传输共用一份"`receive` 之后"的流程,可以保证去重、`reply_context`、边界校验、错误分类和批合并只有一份实现,不会随时间漂移。代价是 Task 5 要动现有 webhook 热路径,所以它必须是纯重构 PR,并以上面的门禁证明行为不变。

**备选方案。** 监督器直接调用 `sink.admit`(计划审查 H1 已否决:会漏掉 `reply_context`、边界校验、错误分类和批合并);复制一份流程给监督器(两份实现会漂移)。

**影响的文件或 crate。** `ironclaw_extension_host`(`ingress/router.rs`、新增共享模块,可能是 `ingress/admission.rs`)、`ingress_router_contract.rs`。

## 5. 监督器

监督器是 `ironclaw_extension_host` 内的新模块,每个活跃的流式安装对应一个连接任务,只依赖 Task 2 的 WebSocket 端口和现有 egress。

### 5.1 每连接速率上限

**决定。** 每帧先过 `max_frame_bytes`,再过每连接令牌桶(`max_frames_per_second`,带突发上限),然后才调用帧控制 `decode`。超速时**停止读帧**而不是丢帧(TCP 背压会让钉钉侧放缓);持续超速超过阈值时断开并按退避重连,记审计事件。全局另有所有流式连接共享的准入并发上限。速率按安装计,与 webhook 路由器"验证后按安装限流"(`router.rs:414-422`)同一语义。

**备选方案。** 超速直接丢帧(会导致消息丢失或依赖重投,而重投窗口未验证);沿用 webhook 的 429(流式没有对应返回)。

**取舍理由。** 连接已认证,对端是钉钉,"读慢一点"比"丢掉已认证用户的消息"更安全。

### 5.2 同会话顺序

**决定。** 帧控制的 `session_key` 给出排序键;监督器按键分成串行队列,同一键按到达顺序进入共享管线,不同键并发,并发总数有上限。`session_key` 返回 `None` 的帧进入一个默认串行队列。排序键只用于排序,不参与身份、作用域或去重(去重仍是 `(installation, event_id)`)。

**备选方案。** 整条连接完全串行(最简单,但一个慢会话阻塞全部);完全并发(SDK 的做法,会乱序,第 8 节补充说明)。

### 5.3 背压

**决定。** 每个会话队列和全局待处理帧数都有上限。任一上限满时停止从 WebSocket 读帧;未读的帧不 ACK,由钉钉重投或在连接层排队。不在内存里无限堆积。

**备选方案。** 无界队列(慢会话会耗尽内存);队列满时丢帧(丢掉已认证用户的消息)。

**取舍理由。** 停止读帧把压力交给 TCP 和钉钉侧,内存有界且不丢消息。代价是一个慢会话占满全局上限时会拖慢其他会话,所以会话队列上限小于全局上限。

### 5.4 ACK 时延与重投窗口

**决定。** ACK 只在共享管线返回结果之后发出,映射见第 4 节表格。监督器测量"收到帧到发出 ACK"的时延,超过配置阈值时记告警。

**备选方案。** 收到帧立即 ACK(先 ACK 后处理,处理失败就丢消息);沿用 SDK 的内存 ACK 缓存。

**取舍理由。** 先处理后 ACK 让"已 ACK"等于"已 durable 准入",失败时由钉钉重投,durable 去重保证不重复准入。代价是 ACK 时延变长,阈值依赖未验证的钉钉限制(见下)。

**未验证,阻塞 Task 7。** 钉钉的 ACK 时延上限和未 ACK 帧的重投时机、次数都**未验证**(第 8 节条目 2、3)。SDK 没有 ACK 超时设置,只对同一 `messageId` 缓存处理结果 300 秒(最多 10000 条)并重发缓存的 ACK,由此只能推断服务端会重投。因此:

- 告警阈值不在本 ADR 定值,Task 7 开工前必须从官方文档补到 ACK 时延上限;补不到则以 Task 20 实测为准,并在此之前用保守值(远小于 SDK 的 HTTP 超时 10 秒),并在代码注释里标明出处待补。
- 重复投递由 durable 去重挡住,所以"ACK 太慢导致重投"的后果是重复帧而不是重复准入。代价是 agent 侧不会重复执行,但钉钉侧可能计为失败,具体后果未验证。
- 与 SDK 不同,host 不在内存里缓存"已处理 ACK";重复帧会再走一次共享管线,得到 `Admitted`(重复),然后 ACK。这依赖 durable 去重,跨重启也成立。

### 5.5 重连与退避

**决定。** `disconnect` 帧(帧控制返回 `AckAndReconnect`)、服务端关闭、ping/pong 超时都触发重连:重新调用建连接口拿新的 `endpoint` 与 `ticket`,不复用旧 `ticket`。退避为指数加抖动,起点 1 秒、上限 60 秒(与 SDK 相同,第 8 节补充,已验证 SDK 行为),**收到一个通过帧控制的健康帧后**重置(SDK 是收到任意服务端帧即重置,host 更严格,防止"连上即断"的风暴)。建连调用连续明确被拒(401/403 一类)达到阈值后停止重试,进入"需要管理员处理"状态,管理员凭证变化后才重新尝试。

**备选方案。** 无限固定间隔重试(会形成重连风暴并被限流);收到任意服务端帧就重置退避(SDK 做法,允许"连上即断"循环)。

**取舍理由。** 指数退避加抖动加"健康帧后重置"限制建连接口压力;认证类失败不重试,避免用错误凭证反复冲击钉钉。代价是凭证修复后需要管理员动作才恢复。

### 5.6 审计事件

**决定。** 发出与 webhook 路径同等的事件:连接建立、连接断开(带原因分类)、建连认证失败、帧被拒(超大、超速、解码失败)、确定性丢弃、进入"需要管理员处理"。事件里不带 `endpoint` 的查询部分、`ticket`、`clientSecret`、帧正文;`endpoint` 只记主机名。

**备选方案。** 只写日志、不发审计事件;在事件里记完整 `endpoint`。

**取舍理由。** 流式没有 HTTP 响应码可供事后核对,审计事件是唯一的运行证据,所以要与 webhook 同等。含查询部分的 `endpoint` 带有 `ticket`,不能记录。

### 5.7 生命周期

**决定。** 激活时启动;停用和删除时停止读帧、等待已在共享管线中的帧完成(复用 `ChannelIngressDrain`),然后关闭连接;管理员凭证变化时重启连接。进程启动时经现有 boot hydration 恢复已激活的安装。每个安装在本进程内最多一条连接,全局连接数有上限。composition 只负责装配和后台任务的启停,不放领域逻辑。复用 `channel_host.rs` 的 `build_generic_graph` 产出的 `ChannelIngressRegistration`(sink 加 drain)。

**备选方案。** 监督器独立于安装生命周期自行管理连接(与 webhook 的停用语义分叉);在 composition 里写启停逻辑(违反"composition 不拥有领域策略")。

**取舍理由。** 复用现有 drain 与 boot hydration,停用语义与 webhook 渠道一致。代价是监督器必须适配 `ChannelIngressRegistration` 的现有形状。

### 5.8 状态落点

**决定。** 连接状态(已连接、重连中、需要管理员处理、最近一次脱敏错误及时间)写进扩展生命周期投影,WebUI 只渲染投影。就绪诊断为流式渠道增加单独检查,不改变其他渠道当前"渠道级就绪探针尚未接入"(`Unsupported`)的输出;是否替换全局 `Unsupported` 留给 Task 9 决定。状态是内存缓存加投影,不新增 durable 表。

**备选方案。** 新增 durable 连接状态表(多一套迁移与双后端一致性负担,且连接状态本身是进程内事实);只写日志(用户看不到状态)。

**取舍理由。** 连接状态随进程重启重建,没有持久化价值;投影让 WebUI 不自行推导状态。代价是进程重启后状态短暂为空,直到重连完成。

### 5.9 多副本结论

见第 9 节:**只承诺单副本部署**。监督器"每安装一条连接"只在单进程内成立。

**影响的文件或 crate(第 5 节整体)。** `ironclaw_extension_host`(新增监督器模块、`channel_host.rs`、生命周期)、`ironclaw_composition`(后台任务装配、就绪诊断)、事件词汇所在 crate(审计事件,由 Task 6 确认具体位置,**未验证**)、`ironclaw_webui`(只渲染投影)。

## 6. token 交换的位置(里程碑 1b)

钉钉发送接口要求请求头 `x-acs-dingtalk-access-token`,令牌由 `POST /v1.0/oauth2/accessToken`(JSON 体 `{appKey, appSecret}`)换取,响应读取 `accessToken` 与 `expireIn`(已验证 SDK 行为,第 8 节条目 11)。流式建连本身不需要令牌。

### 6.1 读代码得到的事实

- **`ironclaw_auth` 的引擎**(`crates/domains/ironclaw_auth/src/engine/mod.rs` 模块说明):实现 `oauth2_code`(含 PKCE)、`api_key` 加探测、RFC 7591 动态注册、换取与刷新、keepalive 刷新扫描,以及 `AuthAccountState` 账户状态机。厂商差异只能是配方数据,不允许厂商条件分支。
- **配方枚举**(`crates/contracts/ironclaw_extension_contracts/src/recipe.rs:195`):`VendorAuthRecipe` 只有 `Oauth2Code`、`ApiKey`、`DeviceLink`,没有 `client_credentials`。对它的 `match` 至少有 `display_name`、`scope_ceiling`、`validate`、`keepalive_idle_threshold`、`compatible_for_shared_vendor`;按词边界引用 `VendorAuthRecipe` 的 Rust 文件有 26 个(`git ls-files -co --exclude-standard '*.rs' | xargs grep -lw VendorAuthRecipe`),路径不含 `test` 的 16 个;Task 11 若改选 A,必须逐个枚举其中的 `match`。
- **令牌持久化方式**:`engine/exchange.rs` 的换取发送表单编码的 `grant_type=authorization_code` / `refresh_token`(74、156 行),令牌存到 secret store,句柄按账户生成(`refresh_token_handle(vendor, account_id, kind)`,582-589 行)。即引擎面向"某个用户的凭证账户",不是部署级应用凭证。钉钉的接口是 JSON 体、字段名 `appKey`/`appSecret`/`accessToken`/`expireIn`,不是标准 OAuth 表单。
- **渠道出站的注入路径**:`ironclaw_extension_host/src/egress.rs` 的 `PolicyEnforcedChannelEgress` 先做策略(主机、方法、声明的凭证句柄),产出 `ApprovedChannelEgress`;`ironclaw_extension_host/src/channel_egress.rs` 的 `HostRuntimeChannelEgressTransport::execute` 对每个声明的句柄调用 `ChannelEgressCredentialsPort::channel_secret`(生产实现 `ChannelConfigEgressCredentials`,读 `[admin_configuration]` / `[channel.config]` 的秘密),得到 `HostRuntimeCredentialMaterial`,再交给 `HostRuntimeHttpEgressPort`(`RuntimeHttpEgressRequest`,`ironclaw_host_api/src/http.rs`)注入头、查询、路径或 JSON 体。适配器从未看到秘密字节(`channel_egress.rs` 模块说明)。网络策略在这里固定为 `NetworkScheme::Https` 加批准的主机。
- **`ProtocolHttpEgress`**(`ironclaw_extension_contracts/src/egress.rs:382`):适配器面向的受限发送 trait,生产里渠道走的是 `RestrictedEgress` / `PolicyEnforcedChannelEgress`;`ProtocolHttpEgress` 在本仓库只有测试替身实现(`test_support/fakes.rs:124`)。所以 token 注入不应该挂在 `ProtocolHttpEgress` 上。
- `RuntimeCredentialSource`(`http.rs:119`)有 `SecretStoreLease` 与 `StagedObligation` 两种,渠道出站不用它(`credential_injections: Vec::new()`,`channel_egress.rs:323`),而是直接传 `credentials`。

### 6.2 决定

**选 B:egress 凭证来源加内存缓存。** 新增一个"交换型"声明凭证:`[[channel.egress]]` 的凭证句柄可以声明为"由 host 用另外两个声明秘密(`dingtalk_client_id`、`dingtalk_client_secret`)向已声明的令牌端点换取",实现为 `ChannelEgressCredentialsPort` 的装饰器(包在 `ChannelConfigEgressCredentials` 外面)。装饰器:

- 换取请求本身经 `HostRuntimeHttpEgressPort` 发出,端点必须在该渠道已声明的 egress 主机和路径内,两个秘密用 `BodyJsonPointer` 注入,响应体有上限,只用 JSON 指针取令牌与有效期(指针由 manifest 声明,不在 host 里写死钉钉字段名,满足"通用代码无厂商名")。
- 令牌只在内存缓存,按 `(extension, installation, handle)` 为键;类型为可清零的秘密(`SecretMaterial` 一类),不实现会泄露内容的 `Debug`。
- 过期前提前刷新;并发请求单飞;发送接口明确被拒(401 或令牌失效)时作废缓存并最多重试一次;5xx 和超时不重试。
- 注入仍走现有 `credentials` → `HostRuntimeCredentialMaterial` → `Header { name: "x-acs-dingtalk-access-token" }` 这一条路径,不新增注入通道。

**否决 C:适配器自己换取。** 令牌和 `appSecret` 会进入适配器作用域,违背"适配器从不看到秘密字节"和 `crates/extensions/AGENTS.md` 的"A package never … stores or reads a raw credential"。

**备选 A:auth 配方并持久化到 secret store。** 新增 `VendorAuthRecipe::ClientCredentials` 一类方法,由引擎换取并持久化,keepalive 扫描负责刷新。

### 6.3 取舍理由

| 维度 | A(auth 配方) | B(egress 凭证来源) |
|---|---|---|
| 凭证归属 | 引擎面向用户凭证账户(`AuthAccountState`、按 `account_id` 的句柄),钉钉令牌属于部署级应用,需要虚构一个"账户" | 与 `[admin_configuration]` 的部署级秘密同一层,不需要账户 |
| 协议适配 | 现有换取是表单编码 OAuth;钉钉是 JSON 体与非标准字段名,需要在引擎里新增一种请求形态 | 换取请求复用渠道 egress 的 `BodyJsonPointer` 注入与 JSON 指针响应映射,与第 2.2 节的建连响应映射是同一机制 |
| 改动面 | `VendorAuthRecipe` 至少 5 个穷尽 `match`、registry 的 v2/v3/resolved、引擎、keepalive、产品侧凭证视图 | `ironclaw_extension_contracts`(凭证声明)、`ironclaw_extension_registry`(解析与 digest)、`ironclaw_extension_host/src/channel_egress.rs`(装饰器)、composition 装配 |
| 持久化 | 短期令牌写入 secret store,重启后可复用,多副本可共享 | 不持久化,重启后重新换取;每个副本各自换取 |
| 多副本 | 共享令牌 | 若钉钉对重复换取返回不同令牌并使旧令牌失效(**未验证**,第 8 节条目 11),多副本会互相作废;但本 ADR 已只承诺单副本 |

B 的主要风险是"重复换取的语义未知"。单副本下每次重启最多一次额外换取,单飞保证同一进程不会并发换取。若 Task 20 实测发现重复换取会使旧令牌失效且影响已在途请求,401 后单次重试可以覆盖。A 的成本在于把一个部署级、无用户交互的应用令牌塞进为用户 OAuth 设计的账户状态机,改动面大且语义不合。

**未决。** 重复请求 `accessToken` 是否返回同一令牌,**未验证**,由 Task 11 前补查官方文档、Task 20 实测。B 的设计不依赖该语义。

**影响的文件或 crate。** `ironclaw_extension_contracts`(`channel.rs` 的 egress 凭证声明、可能的 `egress.rs`)、`ironclaw_extension_registry`(`v3.rs`、`resolved.rs`、digest、升级差异分类)、`ironclaw_extension_host`(`channel_egress.rs` 装饰器、`egress.rs` 的声明校验)、`ironclaw_composition`(装配)。`ironclaw_auth` 不改。

### 6.4 修订记录(2026-11-19):实现确定的细节
本小节只记录实现阶段确定的细节,不改动 6.1 到 6.3 的决定,也不改动"批准"和"修订批准"两节。实现仍是方案 B,否决 C 不变。
- **manifest 形状。** `[[channel.egress]]` 上新增可选的 `[channel.egress.credential_source]`:`handle`(逻辑令牌名,不是 `[admin_configuration]` 字段,不落盘)、`exchange_host`、`[...exchange]`(`method` 只允许 `post`,`path`,静态 JSON `body`,`body_credentials` 句柄列表)、`token_pointer`、`expires_in_pointer`(单位秒,必填)、`[...header]`(`name` 为小写 RFC 7230 token,可选 `prefix`)。与同一目标上的 `credential_handle`、`injection`、`body_credentials` 互斥。换取端点必须恰好匹配另一个已声明的 https egress 目标(主机、POST、路径),且该目标为每个换取句柄声明了 `body_credentials` 指针;该目标自己不能再带 `credential_source`。声明里没有任何厂商字段名,指针完全来自 manifest。
- **装饰器的字面实现。** 没有改 `ironclaw_host_api` 或 `ironclaw_network` 的共享类型。`ChannelEgressCredentialsPort`(host crate 内)新增带默认实现的 `exchanged_token`,默认返回 `TokenSourceUnavailable`(失败即关闭);`TokenExchangeEgressCredentials` 包在 `ChannelConfigEgressCredentials`(测试时再包 `Bridged`)外面,是最外层,`channel_secret` 直接转发,`BridgedChannelEgressCredentials` 转发 `exchanged_token`。策略层 `egress.rs` 在请求按令牌句柄选择时批准一个声明的 `Header` 目标并附带不含秘密的 `ApprovedCredentialSource`;声明的令牌头名在该目标上成为 host 独占头。
- **常量。** 有效期取响应里 `expires_in_pointer` 指向的正整数(JSON 数字或纯数字字符串),缺失、零、负数或无法解析时取 300 秒;再夹到 60 秒到 24 小时之间;提前刷新余量为 `min(300秒, 有效期/5)`,即在 `有效期 - 余量` 后重新换取。令牌响应体上限 16 KiB(取它与换取目标声明上限的较小值);缓存按 `(extension, installation, handle, 换取 URL)` 为键,LRU 容量 256。
- **单飞与重试。** 每个键一把 `tokio` 互斥锁,持锁期间执行换取,等待者拿到新令牌;该锁只保护进程内缓存,不涉及后端读改写,不适用 CAS 规则。发送被 401 拒绝时,只作废本次请求所用的那一代令牌(并发的多个 401 只换取一次),换取后重发一次,第二次响应原样返回。5xx、429、超时、传输错误一律不重试。除 401 之外,契约里没有声明"令牌失效"信号,本次也没有发明。
- **错误映射。** 换取返回 401/403 或应用凭证未配置:`AuthRequired`,`required_secrets` 为换取句柄;408、429、5xx、网络与超时、响应不是 JSON、缺令牌、令牌含非可见 ASCII 或超过 4096 字节:`Transport`,原因固定为 `token exchange unavailable`;3xx、404 等其他状态、策略拒绝、响应超限、缺少声明:`PolicyDenied`。所有原因都是静态字符串,不含状态体、令牌、密钥或 URL 查询。失败不做负缓存,下一次发送重新尝试。
- **服务端语义未验证。** 重复换取是否返回同一令牌、`expireIn` 的精确含义,仍是未验证项(第 8 节条目 11,Task 20 实测)。实现不依赖它们:令牌只用到刷新时间点,换取之后绝不假设旧令牌仍有效,401 后总是重新换取。
- **残留副本(按"修订批准"中的 X 处理)。** 令牌响应与建连响应走同一条共享 HTTP 响应路径,没有改共享响应类型。`ironclaw_network` 的 `transport.rs` 以 `Vec<u8>` 累积响应体,`RuntimeHttpEgressResponse.body` 持有一份,reqwest、hyper、rustls 的内部缓冲与内核套接字缓冲也会留下副本,这些都不由本实现清零。host 自己持有的副本已清零:响应体用 `Zeroizing` 包裹,令牌从解析树中 `take` 出来后无拷贝地移入缓存的 `SecretString`,注入请求头的材料随请求释放;解析树 `serde_json::Value` 是多出来的一份中间副本(令牌已被取走,其余字段仍在)。
- **改动面确认。** `ironclaw_extension_contracts`(新模块 `channel_credential_source`)、`ironclaw_extension_registry`(v3 检查与 `classify_channel_egress_change`)、`ironclaw_extension_host`(`egress.rs`、`channel_egress.rs`、`channel_egress/token_exchange.rs`,以及三处构造声明出站的位置改用 `from_descriptors`)、`ironclaw_composition`(最外层装饰器装配)。`ironclaw_auth` 与共享网络、host_api 类型未改。
- **继承的重定向行为(独立复核发现,批准人 2026-11-20 决定记为后续项)。** 换取请求走共享的 `ironclaw_network` HTTP 出站,它最多跟随 3 次经策略放行的同主机重定向,307/308 会保留方法和请求体。换取请求体里此时已经注入了应用密钥,所以同一已声明主机上的另一个路径会再收到一次带密钥的 POST。影响限于已声明的换取主机,不是外泄路径,但"换取不跟随重定向"这个说法不是字面成立的。本实现没有改共享网络层。后续项:换取请求拒绝任何 3xx(见实施计划"后续项")。
## 7. 威胁模型

**决定。** 采用下表列出的六项威胁及其控制,每项控制都落到具体 Task 并由测试断言。其中 7.1 的主机检查与 7.6 的"身份只来自连接所有权"是硬性前提,不得因进度放宽。

**备选方案。** (a) 信任网关返回的 `endpoint`,只靠 `ironclaw_network` 的私网拒绝(主机可以是任意公网地址,不可接受);(b) 把 `ticket` 当普通字符串处理(日志与错误会泄露连接凭证);(c) 信任帧内 `appId`、`robotCode` 来确定安装(帧内字段可被伪造,不可接受)。

**取舍理由。** 每个备选方案都把一个信任判断交给了对端数据。表内控制把判断放在 host 持有的事实上:声明的主机列表、连接所有权、秘密类型。代价是主机列表需要随钉钉域名变化发新包(1.2),以及更多的脱敏测试。

**影响的文件或 crate。** `ironclaw_network`(连接器、错误脱敏)、`ironclaw_extension_contracts`(流式声明、秘密标记的响应映射)、`ironclaw_extension_host`(监督器、主机检查、铸造时机)、`ironclaw_extension_registry`(声明与 digest)。

| # | 威胁 | 场景 | 控制 | 落在 |
|---|---|---|---|---|
| 7.1 | 网关返回的 `endpoint` 带来 SSRF | 建连响应被篡改或钉钉侧异常,返回内网地址、云元数据地址或任意公网主机 | 监督器先检查主机精确在声明列表内(1.2);`ironclaw_network` 再做 DNS 解析、私网与保留地址拒绝、连接时复查已解析地址(防 DNS 重绑定);只允许 `wss`;禁止重定向;端口固定 443 或声明值 | Task 2、6 |
| 7.2 | `clientSecret` 出现在建连请求体 | 请求体或错误信息被写进日志、审计、状态或 trace | 只经 `body_credentials`(`BodyJsonPointer`)由 host 注入;适配器构造的请求体里只有占位;请求体不进日志;注入后的请求体有上限(`post_injection_body_limit_bytes`);测试断言日志与错误中没有秘密 | Task 3、6 |
| 7.3 | `ticket` 被当作普通字符串 | `ticket` 在 URL 查询参数里,而 URL 常被记录 | 响应映射把 `ticket` 标记为秘密并用秘密类型持有;WebSocket 地址只在连接器内部拼接,策略评估与 DNS 只见不带查询的 endpoint,`ticket` 只在握手边界进入 `Zeroizing` 缓冲,残留副本见 1.4(2026-11-20 重写;前两项由批准人于 2026-11-20 明确接受):HTTP 响应路径、响应解析树、`rustls` 内部明文写缓冲与内核 socket 缓冲;错误、日志、状态、审计只带主机名;`ironclaw_network` 的错误输出去掉查询部分(Task 2 测试);每次重连重新换取,不缓存 | Task 2、3、6 |
| 7.4 | 重连风暴 | 钉钉频繁 `disconnect`、网络抖动、或凭证错误导致快速重连,打爆建连接口或被钉钉限流 | 指数退避加抖动(1 到 60 秒);健康帧后才重置;认证类失败达阈值进入"需要管理员处理";全局连接数上限;每安装最多一条连接 | Task 7、8 |
| 7.5 | 帧洪泛 | 大量帧或超大帧耗尽内存和准入容量 | `max_frame_bytes` 与 `ironclaw_network` 的帧/消息大小上限;每连接速率上限;会话队列与全局待处理上限,满则停止读帧(5.1 到 5.3) | Task 2、6、7 |
| 7.6 | 帧内身份字段 | 帧里的 `senderStaffId`、`conversationId`、`chatbotCorpId`、`robotCode`、头里的 `appId` 被伪造 | 这些字段只有在帧来自本 host 为该安装建立并认证的连接时才可信;安装标识只取自连接所有权,不取自帧(第 3 节铸造时机);帧内字段只作为已认证渠道内的 actor 与会话数据,经现有配对与 `ProviderIdentityActorResolver` 解析;`chatbotCorpId` 的校验依赖其含义,**未验证**(第 8 节条目 9),Task 12 前补查 | Task 4、12、17 |

补充残余风险:

- 钉钉服务端本身被入侵或网关响应被篡改时,7.6 的信任前提失效;这与 webhook 渠道信任厂商签名的残余风险同级。
- 多副本下消息可能被另一个副本收走(第 9 节),这是可用性问题,不是认证问题。
- 群成员文本按不可信文本处理,与 Slack、Telegram 一致(Task 17)。

## 8. 钉钉事实核对表

来源说明:SDK 指 `https://github.com/open-dingtalk/dingtalk-stream-sdk-python`(main 分支)。官方文档页(例如 `https://open.dingtalk.com/document/orgapp/introduction-to-stream-mode`、`https://open.dingtalk.com/document/orgapp/receive-message`、`https://open.dingtalk.com/document/orgapp/robots-send-single-chat-messages`、`https://open.dingtalk.com/document/development/obtain-orgapp-token`)在 Task 1 执行时只返回空正文,没有任何一条结论取自官方文档。"已验证"只指 SDK 源码直接支持该结论。

| # | 条目 | 结论 | 来源 | 标记 | 由谁补验 |
|---|---|---|---|---|---|
| 1 | 多连接分发语义 | SDK 无任何多连接逻辑或说明,无法下结论 | `https://github.com/open-dingtalk/dingtalk-stream-sdk-python/blob/main/dingtalk_stream/stream.py`(全文无相关内容) | 未验证 | Task 20 双进程实测;在此之前按第 9 节只承诺单副本 |
| 2a | SDK 的重复帧处理 | 按 `messageId` 缓存处理结果,最多 10000 条,TTL 300 秒;重复帧重发缓存的 ACK;`code != 200` 不缓存 | `.../dingtalk_stream/stream.py`(`MAX_CACHED_MESSAGE_RESULTS`、`MESSAGE_RESULT_TTL_SECONDS`、`_background_task`) | 已验证(SDK 行为) | — |
| 2b | 未 ACK 帧的重投时机与次数 | 无出处 | 无 | 未验证 | Task 7 开工前查官方文档;Task 20 实测 |
| 3 | ACK 时延上限 | SDK 无 ACK 超时设置 | 无 | 未验证 | Task 7 开工前;Task 20 |
| 4a | `disconnect` 的客户端处理 | `type=SYSTEM`、`headers.topic="disconnect"`;SDK 先 ACK 再关闭 WebSocket,按退避重新建连 | `.../dingtalk_stream/frames.py`(`SystemMessage.TOPIC_DISCONNECT`)、`stream.py`(`_dispatch_message`、`start`) | 已验证(SDK 行为) | — |
| 4b | 服务端何时发 `disconnect`;每应用连接数上限 | 无出处 | 无 | 未验证 | Task 8 开工前 |
| 5 | WebSocket 网关主机集合 | 建连响应给出 `endpoint` 与 `ticket`,SDK 拼 `{endpoint}?ticket={quote_plus(ticket)}`,不校验主机;主机是否固定或轮换无出处 | `.../dingtalk_stream/stream.py`(`start`、`open_connection`) | 未验证 | **阻塞 1.2 的具体主机名**;Task 12 前由官方文档或一次真实建连(脱敏主机名)补齐 |
| 6 | 限流与单条消息长度上限 | SDK 只有本地选择(`MAX_PENDING_TASKS = 100`、HTTP 超时 10 秒),无服务端限制 | `.../dingtalk_stream/stream.py` | 未验证 | Task 13 前;Task 20 记录实测 |
| 7a | 回调字段名与帧头 | `ChatbotMessage.from_dict` 解析 `msgId`、`conversationId`、`conversationType`("1" 单聊、"2" 群聊)、`senderStaffId`、`senderId`、`senderNick`、`senderCorpId`、`chatbotCorpId`、`chatbotUserId`、`robotCode`、`isInAtList`、`atUsers`、`sessionWebhook`、`sessionWebhookExpiredTime`、`createAt`、`isAdmin`、`conversationTitle`、`msgtype`、`text.content` 等;话题 `/v1.0/im/bot/messages/get`;帧头 `appId`、`connectionId`、`contentType`、`messageId`、`topic`、`time`;`data` 为 JSON 字符串 | `.../dingtalk_stream/chatbot.py`、`.../dingtalk_stream/frames.py` | 已验证(字段名与用法) | — |
| 7b | 字段必填性、长度、取值约束、完整字段表 | 无出处 | 无 | 未验证 | Task 12 前;`payload.rs` 先按"可缺失"解析 |
| 8a | 发送侧 `robotCode` | SDK 调用发送类 OpenAPI 时 `robotCode` 取 `credential.client_id` | `.../dingtalk_stream/chatbot.py`(`get_image_download_url`、`reply_card`、`set_off_duty_prompt`) | 已验证(SDK 行为) | — |
| 8b | 回调 `robotCode` 是否恒等于 `clientId` | 无出处 | 无 | 未验证 | Task 12 默认不另设 RobotCode 配置,入站记录二者是否一致;Task 20 |
| 9 | `chatbotCorpId` / `senderCorpId` 含义 | SDK 只解析不解释;"机器人所属企业 / 发送者所属企业"是按字段名的推断 | `.../dingtalk_stream/chatbot.py` | 未验证 | Task 12、17 前 |
| 10 | `oToMessages/batchSend`、`groupMessages/send` 的请求与响应;是否有回读接口 | SDK 无这两个调用;只能确认 OpenAPI 通用形态:主机 `https://api.dingtalk.com`、头 `x-acs-dingtalk-access-token`、JSON 体 | `.../dingtalk_stream/chatbot.py`、`.../dingtalk_stream/utils.py` | 未验证 | Task 13、15、17、18 前;Task 13 按"歧义即未验证、不重发"设计 |
| 11a | `accessToken` 请求与响应字段 | `POST /v1.0/oauth2/accessToken`,体 `{appKey, appSecret}`,读 `accessToken`、`expireIn`;SDK 本地缓存,过期前 5 分钟视为失效 | `.../dingtalk_stream/stream.py`(`get_access_token`、`reset_access_token`) | 已验证(SDK 行为) | — |
| 11b | 重复请求是否返回同一令牌 | 无出处 | 无 | 未验证 | Task 11 前;Task 20 |
| 12 | 建连请求体与保活 | 体键 `clientId`、`clientSecret`、`subscriptions`(`{type, topic}`)、`ua`、`localIp`;SDK 每 60 秒发 WebSocket ping;Node SDK 注释要求 `Accept: application/json` | `.../dingtalk_stream/stream.py`;`https://github.com/open-dingtalk/dingtalk-stream-sdk-nodejs/blob/main/src/client.ts` | 已验证(SDK 行为) | — |
| 13 | ACK 帧格式 | `{code, headers{messageId, contentType}, message, data}`,`data` 为 JSON 字符串;SYSTEM 帧默认回 `code=200, message="OK"` | `.../dingtalk_stream/frames.py`(`AckMessage.to_dict`)、`stream.py` | 已验证(SDK 行为) | — |
| 14 | 名为 `ping` 的 SYSTEM 主题 | SDK 源码中不存在该主题名 | `.../dingtalk_stream/frames.py` | 未验证 | Task 6、12 写帧控制前 |

## 9. 多副本门槛结论

**钉钉是否保证一条消息只投给一条连接:无法验证**(第 8 节条目 1)。按计划 Task 1 的门槛,**本计划只承诺单副本部署**。

- 监督器"每安装一条连接"只在单进程内成立,不能阻止第二个副本或第二个环境开第二条连接。
- Task 9 的就绪诊断对流式渠道固定提示:该渠道仅支持单副本部署;多副本下同一条消息可能被多条连接收到,或被分到未持有该安装状态的副本。诊断不得表述为"已保证唯一"。帧头 `connectionId` 只作为日志线索,不作为单连接证明。
- Task 19 的用户文档写明:只支持一个 IronClaw 实例连接同一个钉钉应用;不要在多个副本或多个环境(例如测试与生产)使用同一组 `ClientID`/`ClientSecret`。
- `(installation, event_id)` 的 durable 去重保留;它挡住重复,挡不住"消息被另一个副本收走"。
- 解除条件:官方文档或 Task 20 双进程实测证明"单消息单连接"后,修订本节。

## 10. 用户必须在钉钉开放平台手动完成的步骤

本任务没有执行以下任何步骤。页面与菜单名称来自 SDK README 指引和计划描述,未对照官方界面核对(未验证),以钉钉开放平台当前界面为准。

1. 用有开发者权限的企业管理员账号登录钉钉开放平台。
2. 创建一个**企业内部应用**(不要选第三方企业应用或自定义群机器人)。
3. 在该应用里添加"机器人"能力,填写机器人基本信息。
4. 把机器人的消息接收模式设为 **Stream 模式**(不是 HTTP 回调模式),保存并发布使其生效。
5. 在应用凭证页面取得 `ClientID`(AppKey)和 `ClientSecret`(AppSecret)。这两个值只填在 IronClaw 的管理员配置里(`dingtalk_client_id`、`dingtalk_client_secret`),不要写进仓库、文档、聊天记录或夹具。
6. 为应用申请发送机器人消息所需的接口权限(单聊批量发送、群发送),并把应用可用范围设置为包含测试用户和测试群。具体权限点名称未验证,Task 13 前对照官方文档。
7. 把机器人加入一个测试群,并准备一个测试账号与机器人单聊,供 Task 20 联调。
8. 为解除第 1.2 节的阻塞:第一次真实建连后,只提供 `endpoint` 的**主机名**和帧的字段结构;不要提供 `ticket`、`accessToken`、`ClientSecret`。

## 11. 测试夹具

- 目录:`tests/fixtures/extensions/dingtalk-stream/`,包含 `README.md`、`open_connection_response.json`、`access_token_response.json`、`system_disconnect.json`、`system_ping.json`、`callback_single_chat_text.json`、`callback_group_at_text.json`。
- **这些夹具是按 SDK 源码字段构造的,不是从真实钉钉系统抓取的。** 所有标识、密钥、`ticket`、`accessToken` 都是 `REDACTED_*` 占位;时间戳、`specVersion`、`expireIn` 等是占位值。每个文件的来源写在该目录的 `README.md`。
- `system_ping.json` 的主题名 `ping` 在 SDK 中不存在,是构造的(第 8 节条目 14)。
- 计划 Task 1 的 Demo 要求"一个不进入仓库的小脚本连上网关并收到一条真实回调",以及"把脱敏的真实帧样例存为夹具"。本次**没有完成**:没有钉钉应用和凭证(第 10 节)。由 Task 20(或在 Task 12 前用户完成第 10 节后)补充真实脱敏样例并替换构造值。

## 12. 与计划审查记录的对照

| 审查编号 | 本 ADR 的对应 |
|---|---|
| H1 | 第 4 节共享准入管线;2.4 复用 `receive` |
| H2 | 2.1 带标签枚举与 30 个使用点(29 个相关) |
| H3 | 1.1 `Wss` 变体与实测 68 个文件、2 个穷尽 `match`;1.2 主机白名单 |
| H4 | 1.3 TLS 一致性(版本一致性未验证,Task 2) |
| H5 | 第 3 节全部触点;批准一节 |
| H6 | 不在本 ADR 范围(Task 3、10、16) |
| M1 | 5.1、5.2、5.6 |
| M2 | 2.2 响应映射;7.3 |
| M3 | 第 6 节(里程碑 1b) |
| M4 | 5.8 |
| M5 | 第 9 节 |
| M6 | 2.1 影响段落(契约 crate 大小上限) |

## 13. 回滚

- 里程碑一的契约变化对旧 manifest 向前兼容(2.1),回退 PR 不需要迁移数据。
- `NetworkScheme::Wss` 与 `AuthRequirement::AuthenticatedStream` 是新增序列化值。一旦有持久化记录或事件带上这两个值,回退代码会让这些记录无法反序列化。因此在里程碑二上线前,回退应连同停用所有流式渠道一起进行;Task 2、4 的 PR 需要说明哪些持久化位置可能出现这两个值(本 ADR **未枚举**,未验证)。
- token 交换(B)不持久化,回退无数据残留。

## 14. 修订记录(2026-11-20):钉钉包(里程碑二)的决定

本节只追加,不改动第 1 节到第 7 节的已批准决定,也不改动"批准"和"修订批准"两节。决定人是批准人(用户),由编排者在用户授权的范围内转达。

### 14.1 网关主机:未验证,Task 20 核实

用户选择不做开发期探测。manifest 只声明一个精确主机 `wss-open-connection.dingtalk.com`(不用通配符,遵守 1.2)。**这个主机名没有官方来源,也没有真实建连核对**(第 8 节条目 5 仍为未验证)。如果主机错误,监督器会因"返回主机不在声明列表内"或策略拒绝而失败,连接进入"需要管理员处理",这是可接受的明确失败。Task 20 用一次真实建连核实,核实后更正 manifest 注释、本节和运营者文档。manifest、`manifest.toml` 的注释和运营者文档都必须带"未验证"标记。

### 14.2 组织 ID 规则:无状态等值,fail closed

- **规则。** 一条回调只有在 `chatbotCorpId` 与 `senderCorpId` 都存在、非空且相等时才视为本组织成员并继续(配对、准入);否则一律不准入、不能配对。缺字段视为不满足。实现在 `packages/dingtalk/src/payload.rs`,单聊和群聊共用同一条规则。
- **被拒消息。** 适配器返回 `InboundOutcome::Ignore`。契约里的 `Ignore` 不带原因码,所以固定原因码(`corp_id_missing`、`sender_outside_bot_org`、`sender_staff_id_missing` 等)写进一条 `tracing` 警告;日志里没有任何 ID、昵称或消息正文。没有改通用层。
- **理由。** 企业内部应用的机器人只属于一个组织,所以 `chatbotCorpId` 就是本组织;帧来自经连接认证的会话,字段由钉钉提供。外部组织成员(例如跨组织群)的 `senderCorpId` 不同,会被这条规则挡住。
- **为什么不做"首次见到的组织"进程内 pin,也不加 `dingtalk_corp_id` 管理员字段。** 进程内 pin 重启即失效,对企业内部应用几乎不增加保护,还会让人误以为已持久绑定。管理员字段会多一个运营者步骤。两者都暂不做。这替换了实施计划里"与首次见到的组织一致"的措辞。
- **未验证。** 第 8 节条目 9(两个字段的含义)仍未验证。如果同组织用户的帧里实际没有 `senderCorpId`,这条规则会把所有消息都拒掉,这是明确可见的失败。
- **Task 20 核实方法。** 用同组织账号单聊机器人,确认被准入;用外部组织账号(跨组织群或外部联系人)发消息,确认日志里出现 `sender_outside_bot_org` 且不进入配对。
- **后续。** 如果核实后发现字段语义不同,再决定是否改为管理员显式配置组织 ID(`dingtalk_corp_id`)。已记入实施计划"后续项"。

### 14.3 ClientID 当作秘密保存;robotCode 的观察方式

- 建连请求体和 token 交换请求体里的 `clientId`、`appKey` 只能经 `body_credentials`(秘密句柄)注入。所以 `dingtalk_client_id` 在 `[admin_configuration]` 里声明为 **secret**。ClientID 本身不敏感,这样做的原因是注入路径只接受秘密句柄。运营者只需填写一次 ClientID 和一次 ClientSecret。
- (2026-11-20 更正)此前曾写"发送侧的 `robotCode` 也由 host 从 `dingtalk_client_id` 注入",这一点做不到,已撤回,见 14.5。
- 适配器的 `receive` 只能读到非秘密配置,看不到 `clientId`,所以不能在入站时比较 `robotCode == clientId`。**改写第 8 节条目 8b 的核实方式:** 入站只记录 `robotCode` 是否存在,以及同一安装内是否发生变化(只记布尔值,不记取值;日志字段 `robot_code_present`、`robot_code_changed`)。二者是否相等留到 Task 20 核实。
- 没有采用"再加一个非秘密 ClientID 字段"(运营者要填两次)和"改通用层让 `receive` 看到 `clientId`"。

### 14.4 发送接口与令牌接口:已核对(官方 Go SDK)

来源:`https://github.com/alibabacloud-go/dingtalk`(master 分支),文件 `robot_1_0/client.go` 与 `oauth2_1_0/client.go`。这是阿里云为钉钉 OpenAPI 生成的官方 SDK。"已核对"只表示字段名、路径和方法与该 SDK 一致,不表示钉钉服务端的其他承诺(限流、长度上限、错误码仍未验证)。本节是对第 8 节条目 10 与 11a 的修订记录,第 8 节表格本身不改。

| 接口 | SDK 结构 | 路径与方法 | 请求体字段 | 响应体字段 |
|---|---|---|---|---|
| 单聊批量发送 | `BatchSendOTO` | `POST /v1.0/robot/oToMessages/batchSend` | `msgKey`(必填)、`msgParam`(必填,JSON 字符串)、`robotCode`(必填)、`userIds`(必填,数组) | `processQueryKey`、`invalidStaffIdList`、`filteredStaffIdList`、`flowControlledStaffIdList` |
| 群发送 | `OrgGroupSend` | `POST /v1.0/robot/groupMessages/send` | `msgKey`(必填)、`msgParam`(必填)、`openConversationId`、`robotCode`、`coolAppCode`、`token` | `processQueryKey`(标为必填) |
| 企业内部应用令牌 | `GetAccessToken` | `POST /v1.0/oauth2/accessToken` | `appKey`(必填)、`appSecret` | `accessToken`、`expireIn`(int64) |

- 两个发送接口都通过请求头 `x-acs-dingtalk-access-token` 携带令牌(SDK 的 `BatchSendOTOHeaders`、`OrgGroupSendHeaders`)。令牌接口本身不带令牌(`AuthType: Anonymous`)。
- `msgParam` 的形状只来自 SDK 注释里的示例:`sampleText` 为 `{"content"}`,`sampleMarkdown` 为 `{"title","text"}`。完整的消息类型表未核对。
- 单条消息长度上限、限流、错误码含义仍**未验证**。实现按 3000 个字符分片(按字符边界);429 可重试;5xx 标为 `sent_unverified`,不重发(2026-11-20 复核后修订:5xx 时钉钉可能已经送达,重试会重复发送);401 在 host 的单次令牌刷新之后仍失败时视为未授权;其他 4xx 为永久失败;单聊响应里的 `invalidStaffIdList`/`filteredStaffIdList` 包含收件人时为永久失败,`flowControlledStaffIdList` 包含收件人时可重试。
- 成功证据是 `processQueryKey`。2xx 但缺少它、2xx 但不是 JSON、或请求可能已发出但没读到响应,一律标为 `sent_unverified`(`PartDeliveryOutcome::Ambiguous`),适配器不重发。是否有可用 `processQueryKey` 回读的查询接口,本次没有核对,未做回读。
- 与 ADR 和计划的假设没有冲突。

### 14.5 发送侧 robotCode 取自回调(2026-11-20)

- **决定。** 发送请求里的 `robotCode` 取自原始回调的 `robotCode`。入站时把它写进 `reply_context`,回复和系统通知(配对反馈、"请先连接")都从 `reply_context` 读取。`reply_context` 缺失、无法解析、属于另一个会话,或其中没有 `robotCode` 时,发送在发出任何请求之前按 `Permanent` 失败。`robotCode` 不是秘密,但不写进日志、审计或错误原因。
- **原因。** 发送目标必须声明 `[channel.egress.credential_source]` 才能拿到令牌头,而 `ChannelDescriptor` 的校验(`CredentialSourceWithStaticCredential`)不允许同一目标再声明 `body_credentials`、`credential_handle` 或 `injection`。所以 host 无法把 `dingtalk_client_id` 注入发送请求体的 `/robotCode`,适配器又看不到 `clientId`。没有改通用层。
- **与第 8 节条目 8a 的关系。** SDK 在发送接口里把 `robotCode` 取为 `clientId`。回调里的 `robotCode` 按定义就是该机器人的编码,所以两者在企业内部应用下预期相同;是否相等仍在 Task 20 核实(14.3 的存在性与稳定性观察保留)。
- **对 Task 18(主动推送)的影响。** 主动推送没有入站上下文。允许的推送目标本来就只来自先前的入站会话(调用者本人的单聊、机器人已在场的群),所以计划在 `outbound_target_provider` 列出目标和 `PreferenceTargetCodec` 编码目标时,把该会话 `reply_context` 里的 `robotCode` 一起带上,解码时严格校验格式。如果这样做需要改通用层(契约、registry、host egress)或新增 test-support 字段,Task 18 开工时停下来报告。


### 14.6 群聊 @机器人(Task 17,2026-11-21)

- **准入。** 群消息只有在 `isInAtList` 为 JSON `true` 时才继续(其余形态,包括缺失、`null`、字符串,都视为未 @,返回已认证的 no-op,固定原因码 `group_message_not_addressed`)。组织 ID 规则与单聊共用(14.2)。触发原因为 `BotMention`,所以配对拦截器不会处理群里的验证码(配对只在单聊),未配对者由通用层发"请先连接"提示,并按会话限频。
- **去掉 @ 前缀。** `atUsers` 只有 ID 没有显示名。只有当 `atUsers` 恰好一项(被 @ 的只能是机器人)时,才去掉文本开头的 `@名字` 词;多于一项时开头的 `@名字` 可能是别人,保持原文。钉钉是否把 @ 文本放进 `text.content`(夹具里 `content` 以空格开头,看起来没有)**未验证,Task 20 核实**。
- **外部成员(批准人已接受,2026-11-21)。** 外部组织成员的消息被组织 ID 规则挡住(固定原因码,无任何 ID),既不进入准入也不能配对,**不会收到任何提示**。这与计划原先"外部成员只收到提示"不同:适配器没有发给外部成员的安全通道,向外部组织发消息本身也不合适。运营者文档如实写明。
- **临时可见通知。** 钉钉没有群内仅某人可见的发送。通用层把未配对者的"请先连接"以 `EphemeralTo(发送者)` 要求投递;适配器把它改成发给该成员本人的单聊(`oToMessages/batchSend`,`userIds=[该成员]`),不发到群里。`EphemeralTo` 的 actor 类型不是本渠道的 actor 时,不发送,按 `Permanent` 失败。批准人已接受:外部成员已被前置规则挡住,所以收到私信的只会是本组织成员。限频沿用通用层现有机制,**按会话**(同一个群在窗口内最多一条),不是按成员;按成员限频需要通用层改动或持久状态,记入计划后续项 13。发送失败只让这次通知失败,不影响群消息的准入。
### 14.7 主动推送:只做本人单聊(Task 18,2026-11-21)

- **策略。** 批准人选择:只能推送到调用者本人的单聊,经现有通用 outbound-target provider(它只列出调用者自己已配对、已预置的单聊目标)实现。不新增包内 provider,不依赖 `ironclaw_outbound`,不新增持久状态,不改通用层。
- **群聊推送暂不可用。** 原计划还允许"机器人已在场且调用者是成员的群"。通用 provider 有意不提供共享会话目标(`channel_outbound_targets.rs` 头部:这类目标的每用户归属来自已退役的订阅绑定,重新引入需要"调用者在该会话里有绑定"的参与关系规则),而判断成员关系需要入站时写入的成员记录。这是通用层变更,需要单独设计和评审,记入计划后续项 12。包内的 `group:<conversationId>` 编解码已写好并有测试,但没有任何路径产出或解析群目标。
- **DM 编码改为 `dm:<staffId>:<conversationId>`(原计划 `dm:<staffId>`)。** 投递协调器按会话指纹读取入站时存下的 `reply_context`,发送所需的 `robotCode` 就在其中(14.5)。只有 staffId 的编码解出的会话没有对应上下文,推送会在发出任何请求之前失败。通用 provider 调用 `encode_personal_direct_message_target` 时本来就传入单聊会话和 staffId,所以不改通用层。
- **严格解码。** 前缀(`dm`/`group`)、分段数(`dm` 三段,`group` 两段)、staffId(ASCII 字母数字与 `_-.`,至多 64 字节)、conversationId(ASCII 字母数字与 `+/=_-.`,至多 160 字节,不含 `:`)逐段校验;多余分段、空段、空白、控制字符、非 ASCII 一律解码为空。
- **失败关闭。** `reply_context` 缺失、无法解析、属于另一个会话或没有 `robotCode` 时,推送在发出请求前按 `Permanent` 失败。
- **未验证。** staffId 与 conversationId 的真实字符集和长度没有官方来源(第 8 节);上面的限制是保守的包内规则,Task 20 若发现真实 ID 被拒再放宽。

### 14.8 加固与文档(Task 19,2026-11-21)
- 不改动第 1 到 7 节的决定。实现复核:包内生产代码没有 `.unwrap()`/`.expect()`、字节切片或丢失原因的 `map_err(|_| …)`;分片按字符边界(`render.rs`);回调文本上限 `MAX_TEXT_BYTES`;帧大小和速率由 manifest 的 `max_frame_bytes`、`max_frames_per_second` 与监督器约束(未验证的保守值,第 8 节条目 6)。
- `msgId` 重复投递:事件 ID 取自 `msgId`,重复回调得到同一事件 ID,由通用准入账本结算(`acme` 流式夹具的重复帧集成测试覆盖通用路径,包内测试 `a_redelivered_callback_keeps_one_event_id_and_a_new_msg_id_gets_another` 覆盖映射)。
- 运营者文档(公开页 `docs/channels/dingtalk.mdx`、中文页 `docs/zh/channels/dingtalk.mdx`)已写。网关主机名、权限点名称和 @ 文本形态仍标"未验证,Task 20 核实"。文档如实写明:外部成员不收提示(14.6)、主动推送只到本人单聊(14.7,群推送为后续项 12)。
## 附录:实测命令与完整清单

以下内容来自 Task 1 的实测记录(工作区临时文件,不进入仓库,此处为全文转录)。写 ADR 时我在同一文件集合上重跑了关键计数:Rust 文件 2333 个;`route_suffix` 或 `.verification`(精确)30 个;`NetworkScheme` 68 个;`AuthRequirement`(词边界)106 行、**30** 个文件(原记录第 3.2 节写的"29 个文件"有误,清单 C 实际列出 30 个,本附录已更正);`VendorAuthRecipe`(词边界)26 个。


基线提交:`b0b999d96`(工作区另有未跟踪文件 `docs/internal/2026-11-18-dingtalk-channel-plan.md`、`tests/fixtures/extensions/dingtalk-stream/`,均不含 .rs,不影响计数)。

### 0. 方法与命令

本机没有安装 `rg`(`command not found`),因此用等价的 `grep -E` 在 git 已知文件集合上测量。文件集合是 `git ls-files -co --exclude-standard '*.rs'`,共 2333 个 Rust 文件(含未跟踪但未被忽略的文件,不含 `target/`)。

```bash
cd /Users/jinkui/myclaw
git ls-files -co --exclude-standard '*.rs' > /tmp/rsfiles.txt          # 2333 个

# (a) route_suffix 或 .verification(宽松写法,计划原文的写法)
xargs grep -lE 'route_suffix|\.verification' < /tmp/rsfiles.txt | sort            # 33
# (a) 精确写法:`.verification` 后面不能接 `_` 或字母数字(排除 .verification_uri 等)
xargs grep -lE 'route_suffix|\.verification([^_[:alnum:]]|$)' < /tmp/rsfiles.txt | sort   # 30
xargs grep -l  'route_suffix' < /tmp/rsfiles.txt | sort                             # 23
xargs grep -lE '\.verification([^_[:alnum:]]|$)' < /tmp/rsfiles.txt | sort          # 20

# (b) NetworkScheme
xargs grep -l 'NetworkScheme' < /tmp/rsfiles.txt | sort                             # 68
xargs grep -lw 'NetworkScheme' < /tmp/rsfiles.txt | wc -l                           # 68(加词边界结果相同)
# match 点
xargs grep -nE 'NetworkScheme::Http\b' < /tmp/rsfiles.txt
xargs grep -nE 'match .*scheme|NetworkScheme::Https *=>' < /tmp/b.txt

# AuthRequirement(词边界,避免命中 RuntimeCredentialAuthRequirement / DispatchAuthRequirement)
xargs grep -nwE 'AuthRequirement' < /tmp/rsfiles.txt                                # 106 行,30 个文件
```

若要用 `rg` 复现,等价命令是 `rg -l --type rust -e 'route_suffix' -e '\.verification\b'` 与 `rg -l --type rust NetworkScheme`。`rg` 默认遵守 `.gitignore`,结果应与上面一致,但我没有在本机实际运行过 `rg`。

### 1. (a) `route_suffix` 与 `.verification`:实测 30 个文件

| 写法 | 文件数 |
|---|---|
| `route_suffix` | 23 |
| `.verification`(精确) | 20 |
| 二者并集(精确) | **30** |
| 宽松写法 `\.verification`(命中 `.verification_uri`) | 33 |

宽松写法多出的 3 个文件是误报:`crates/domains/ironclaw_llm/src/auth.rs`、`crates/domains/ironclaw_llm/src/openai_codex_session.rs`、`crates/product/ironclaw_operator/src/llm_admin/llm_config_service.rs`。它们只涉及 OAuth 设备码的 `verification_uri`。

并集 30 个文件里,还有 1 个与渠道入站无关:`crates/domains/ironclaw_trace_commons/src/contribution/envelope.rs`(`self.verification = Some(..)`,是 trace 贡献信封自己的字段)。因此**真正与渠道入站声明相关的是 29 个**。

另有 1 个文件只是在注释里提到 `route_suffix`:`crates/app/ironclaw_architecture_tests/tests/reborn_dependency_boundaries.rs:714`。它不是代码依赖,但属于"改动后需要同步更新"的集合。

#### 1.1 30 个文件清单(并集,精确写法)

见本附录末尾"清单 A"。分类如下(按路径判断,`test`/`tests` 目录和 `test_support` 记为测试):

- 生产代码(src,非 test_support):`serve.rs`、`ironclaw_extension_contracts/src/{channel,recipe}.rs`、`ironclaw_extension_host/src/{active,channel_config,channel_connection,channel_host,channel_identity_binding,deployment_channels,entrypoint,extension_ingress,lifecycle,session_ingress}.rs`、`ingress/{mod,router,verifier}.rs`、`ironclaw_extension_registry/src/v3.rs`、`ironclaw_assistant/src/reborn_services/extensions.rs`、`ironclaw_trace_commons/.../envelope.rs`(无关)。
- 测试与测试支撑:其余文件(`e2e_tests.rs`、`test_support.rs`、`test_support/session_channel.rs`、`test_support/lifecycle.rs`、`tests/*.rs`、`web-app/tests/manifest_lockstep.rs`、`tests/integration/auth/oauth_popup_journeys.rs`、架构测试)。

注意:`channel_host.rs` 在宽松和精确写法下都命中 `.verification`(`evidence_mint_for_verification(&ingress.verification)`,第 674 行),但不含 `route_suffix`;`active.rs`、`deployment_channels.rs`、`lifecycle.rs`、`ingress/mod.rs` 等只含 `route_suffix`。

### 2. (b) `NetworkScheme`:实测 68 个文件

| 维度 | 文件数 |
|---|---|
| 全部 | **68** |
| `crates/` 下 | 59 |
| `crates/` 之外(`tests/`) | 9 |
| 路径含 `/src/` | 34 |
| 路径不含 `/src/`(多为 `tests/`) | 34 |

计划写的 59 恰好等于 `crates/` 下的文件数,漏掉了根 `tests/` 下的 9 个文件(`tests/integration/` 下 5 个、`tests/reborn_*_parity.rs` 3 个、`tests/support/reborn_parity_qa/network.rs` 1 个)。非 Rust 文件中只有 `docs/internal/reborn/contracts/host-api.md` 提到 `NetworkScheme`(第 914、920、936 行),改枚举时需要同步该契约文档。

完整清单见"清单 B"。

#### 2.1 枚举定义与序列化

`crates/contracts/ironclaw_host_api/src/action.rs:41-44`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScheme { Http, Https }
```

新增 `Wss`(或 `Ws`)会改变 serde 线上格式(`"wss"`),`ironclaw_host_api` 是最底层契约 crate,变更会触发 `host_api_contract.rs`、`reborn_dependency_boundaries.rs` 一类契约测试和 `docs/internal/reborn/contracts/host-api.md`。

#### 2.2 必须处理 wss 的 `match` 点(穷尽匹配,无通配分支)

只有两处是对 `NetworkScheme` 值的穷尽 `match`,新增变体会直接编译失败:

| 位置 | 作用 | 对 wss 的影响 |
|---|---|---|
| `crates/contracts/ironclaw_product_contracts/src/approval_prompt.rs:173-176` | `match scheme { Http => "http", Https => "https" }`,为审批提示生成目的地 URL 文本 | 必须新增 `"wss"` 分支,否则编译失败 |
| `crates/substrates/ironclaw_network/src/url_target.rs:91-94`(`default_port`) | `Http => 80`,`Https => 443` | 新增 `Wss => 443`;被 `resolver.rs:42` 用于解析默认端口 |

#### 2.3 由字符串到 `NetworkScheme` 的解析点(`match url.scheme()`,会拒绝 `wss`)

这些 `match` 的被匹配值是 URL 字符串,不是枚举,新增枚举变体不会触发编译错误,但**默认会拒绝 `wss`**,是需要主动修改的位置:

| 位置 | 作用 |
|---|---|
| `crates/substrates/ironclaw_network/src/url_target.rs:73-77` | `"http"`→Http,`"https"`→Https,其余返回 `UnsupportedScheme`。这是 `network_target_for_url` 的核心,所有经 `ironclaw_network` 的出站目标都过它 |
| `crates/extensions/ironclaw_extension_host/src/egress.rs:146-149` | 渠道出站 `ApprovedChannelEgress` 的解析,只接受 `"https"`,其余返回 `PolicyDenied`;第 416 行测试构造 `scheme: NetworkScheme::Https` |
| `crates/substrates/ironclaw_network/src/egress.rs:211-214`(`resolve_redirect_url`) | 重定向 `Location` 只允许 `"http" \| "https"`,wss 在 HTTP 升级场景不涉及重定向,通常无需改,但应在 ADR 中明确 |

#### 2.4 比较/过滤点(非 `match`,但语义与 scheme 绑定)

| 位置 | 作用 |
|---|---|
| `crates/substrates/ironclaw_network/src/policy.rs:260-262` | `target_matches_pattern`:`pattern.scheme` 为 `Some` 时必须与 `target.scheme` 相等。wss 目标需要对应的 `Some(Wss)` 模式或 `None` 通配 |
| `crates/contracts/ironclaw_extension_contracts/src/channel.rs:695, 780-781` | `[[channel.egress]]` 描述符的 `scheme` 字段,`#[serde(default = "default_https")]`;声明 `wss` 需要这里接受并校验 |
| `crates/extensions/ironclaw_extension_registry/src/v3.rs:217, 461` | v3 manifest 的 `RawAudienceV3.scheme` 与 MCP 凭证受众,固定 `Https` |
| `crates/extensions/ironclaw_extension_registry/src/v2.rs:1460` | v2 受众校验 `audience.scheme != Some(Https)` 即拒绝 |
| `crates/extensions/ironclaw_extension_registry/src/v2.rs:1647` | `matches!(parsed.scheme(), "http" \| "https")` |
| `crates/kernel/ironclaw_host_runtime/src/process_port.rs:285` | 沙箱进程凭证受众要求 `Some(Https)` |
| `crates/extensions/ironclaw_extension_host/src/mcp.rs:118, 134` | 托管 MCP 仅允许 https |
| `crates/extensions/ironclaw_extension_host/src/hosted_mcp_manifest.rs:164` | 同上 |
| `crates/extensions/ironclaw_extension_manager/src/ironhub/artifact_hosts.rs:63` | `target.scheme == Some(Https) && port.is_none()` |
| `crates/app/ironclaw_composition/src/builtin_capability_policy.rs:893` | `target.scheme == Some(Https)` |
| `crates/extensions/ironclaw_extension_support/src/web_access.rs:1116` | `matches!(scheme, "https" \| "http")` |
| `crates/domains/ironclaw_auth/src/engine/http.rs:145` | OAuth 引擎要求 `https` |
| `crates/extensions/ironclaw_extension_manager/src/ironhub/catalog.rs:438, 500, 523` | 目录 URL 要求 https |
| `crates/extensions/ironclaw_extension_support/src/skills/url_install.rs:199` | 技能安装 URL 要求 https |
| `crates/extensions/ironclaw_extension_registry/src/hosted_mcp_discovery.rs:108` | 发现 URL 要求 https |

这些比较点把 `Https` 当作"唯一允许的安全 scheme"。新增 `Wss` 后,它们不需要改动就会继续拒绝 wss,这对 MCP、OAuth、skills 等无关场景是期望行为(fail-closed)。只有 2.2、2.3 前两行和 `policy.rs`/`channel.rs` 是 wss 支持的必改点。

#### 2.5 其余引用(构造值,不需修改)

其余约 50 个文件只是构造 `NetworkScheme::Https` 字面量(`scheme: Some(NetworkScheme::Https)`)或在测试里断言它,新增变体不影响它们。显式使用 `NetworkScheme::Http` 的位置有:`approval_prompt.rs:174`、`url_target.rs:74, 92`、`ironclaw_network/tests/network_policy_contract.rs`(136、166、212、221、237、246、258、265)、`ironclaw_host_runtime/tests/runtime_http_egress_contract.rs:5278`、`tests/integration/support/harness_mcp.rs:235`、`tests/reborn_trace_core_builtin_tools_parity.rs:289`、`tests/support/reborn_parity_qa/network.rs:221`。

#### 2.6 对 ADR 的含义

- 编译器会强制处理的穷尽 `match` 只有 2 处(`approval_prompt.rs`、`url_target.rs::default_port`),不是 59 个文件。
- 方案 A(扩展 `NetworkScheme`)的实际改动面:枚举定义 + 2 个穷尽 match + `url_target.rs` 解析 + `egress.rs` 渠道出站解析 + `channel.rs` 描述符校验 + `policy.rs` 比较 + `host-api.md` 契约文档;约 7 到 8 个生产文件,外加按需新增测试。
- 方案 B(网络层独立类型)避免动 `ironclaw_host_api` 的序列化枚举,但需要在 `ironclaw_network` 内另建策略类型,并让 `StaticNetworkPolicyEnforcer`、`NetworkResolver` 同时接受两种目标。ADR 需要对比这两者。
- `reqwest` 本身不处理 WebSocket 升级,wss 连接需要在 `ironclaw_network`(唯一 TLS 所在地)内新增连接器,这一点不由 `NetworkScheme` 解决,属于另一项设计。

### 3. `AuthRequirement` 触点

#### 3.1 router.rs 本身

`crates/extensions/ironclaw_extension_host/src/ingress/router.rs` **不引用 `AuthRequirement`**(`grep -nw AuthRequirement` 无结果)。路由器直接使用 `IngressVerificationRecipe`(`ingress.verification`):

| 位置 | 内容 |
|---|---|
| `router.rs:55-70` | `IngressSecretsPort::verification_candidates`(取校验密钥候选) |
| `router.rs:333-345` | 第 2、3 步:方法/体积上限、整体超时 |
| `router.rs:361-410` | `verify_and_dispatch`:取 `ingress.verification.secret_handle()`,调用 `verify_recipe(&ingress.verification, ...)`,失败返回 401,密钥取不到返回 503 |
| `router.rs:414-422` | 验证通过后才按已验证安装做限流 |
| `router.rs:440` | adapter.inbound 前剥离验证头 |

即:现有证据链是 `IngressVerificationRecipe`(清单数据)→ `verify_recipe`(执行)→ `VerifiedEvidenceMint`(铸造)→ `AuthRequirement`(密封证据内容)。计划中"新增一种密封证据"会同时触及后三层,并要扩展第一层。

#### 3.2 `AuthRequirement` 定义与全部引用

定义:`crates/contracts/ironclaw_host_api/src/product_adapter/auth.rs:116-128`,变体 `RequestSignature { header_name, timestamp_header_name }`、`SharedSecretHeader { header_name }`、`SessionCookie { name }`、`BearerToken`,`#[serde(rename_all = "snake_case")]`。

词边界匹配共 106 行,分布在 30 个文件(生产代码约 6 个,其余为测试):

| 文件 | 行数 | 角色 |
|---|---|---|
| `ironclaw_host_api/src/product_adapter/auth.rs` | 24 | 定义;`validate_metadata`(130-150)对 4 个变体穷尽 `match`;`ProtocolAuthEvidence` 字段与构造(196-402);`requirement()` 访问器(227);`BearerToken` 用于会话证据(457);内联测试(469-572) |
| `ironclaw_host_api/src/product_adapter/mod.rs:27` | 1 | `pub use auth::AuthRequirement` |
| `ironclaw_extension_contracts/src/product_adapter_section.rs` | 13 | `auth_requirement` 字段(148、164);校验 `match`(294-313,4 个变体穷尽);manifest 原始类型转换 `into_auth_requirement`(378-391,4 个变体穷尽) |
| `ironclaw_extension_contracts/src/verified_inbound.rs` | 3 | `mark_request_signature_verified`(69)、`mark_shared_secret_header_verified`(86):调用 `seal_verified_inbound` 的两个铸造函数,**新增证据变体要在此新增第三个铸造函数** |
| `ironclaw_architecture_tests/tests/reborn_sealed_evidence_mint_ratchet.rs` | 3 | 棘轮测试,注释(64、68)说明 `AuthRequirement` 的渠道一半不另建枚举;1816 行是测试用例字符串 |
| `ironclaw_product_contracts/src/command.rs` | 2 | 测试 |
| `ironclaw_product_contracts/src/inbound/tests.rs` | 3 | 测试 |
| `ironclaw_extension_host/src/channel_command_roles.rs` | 2 | 测试模块内构造 `SharedSecretHeader` |
| `ironclaw_extension_host/src/channel_host/e2e_tests.rs` | 2 | 测试 |
| `ironclaw_extension_manager/src/lifecycle_product_service.rs` | 2 | 测试模块 |
| `ironclaw_assistant/src/workflow.rs` | 3 | 测试模块 |
| 其余(`verified_inbound_seal.rs`、`protocol_auth_evidence_seal.rs`、`ironclaw_assistant/tests/*`、`ironclaw_openai_compat/tests/*`、`tests/integration/*`、`product_adapter_manifest_ingestion.rs`) | 约 48 | 测试 |

#### 3.3 `ChannelIngressVerifier` 实现与铸造

- trait 定义:`ironclaw_host_api/src/product_adapter/auth.rs:103`。
- 生产实现只有 1 个:`crates/extensions/ironclaw_extension_host/src/extension_ingress.rs:99`,`impl ChannelIngressVerifier for VerifiedEvidenceMint {}`。
- 测试实现 2 个:`ironclaw_extension_contracts/tests/verified_inbound_seal.rs:21`、`ironclaw_host_api/tests/protocol_auth_evidence_seal.rs:26`。
- `VerifiedEvidenceMint` 枚举(`extension_ingress.rs:79-88`)有 `RequestSignature`、`SharedSecretHeader` 两个变体;`mint()`(101-122)对二者穷尽 `match`。
- `evidence_mint_for_verification`(`channel_host.rs:162-182`):`HmacSha256`→`RequestSignature`,`SharedSecretHeader`→`SharedSecretHeader`,`AuthenticatedSession | None`→`None`(路由不挂载,fail-closed)。调用点:`channel_host.rs:674`、测试 1285、1308、1322、1477。
- `IngressVerificationRecipe`(`ironclaw_extension_contracts/src/recipe.rs:723-734`):`HmacSha256`、`SharedSecretHeader`、`AuthenticatedSession`、`None`。对其穷尽匹配的生产点:`channel_host.rs:165-181`(上条)与 `ingress/verifier.rs:127-152`(`verify_recipe`;`AuthenticatedSession` 返回 `NotWebhookVerifiable`)。

#### 3.4 新增"流式入站"证据时的必改点(清单)

1. `recipe.rs`:`IngressVerificationRecipe` 或其替代(传输方式带标签枚举)。
2. `auth.rs`:`AuthRequirement` 新变体 + `validate_metadata` 的穷尽 `match`。
3. `product_adapter_section.rs`:两处穷尽 `match`(校验、manifest 转换)。
4. `verified_inbound.rs`:新增第三个 `mark_*_verified` 铸造函数。
5. `extension_ingress.rs`:`VerifiedEvidenceMint` 新变体与 `mint()` 的 `match`。
6. `channel_host.rs::evidence_mint_for_verification`:新增对应分支。
7. `ingress/verifier.rs::verify_recipe`:流式入站不走请求签名校验,需明确分支。
8. `reborn_sealed_evidence_mint_ratchet.rs` 及 `host_api` 的 AGENTS.md("do not widen")要求,以及上述两个测试实现的 `ChannelIngressVerifier` 不增加。

### 4. 与计划估算的对比

| 项目 | 计划估算 | 实测 | 说明 |
|---|---|---|---|
| 引用 `route_suffix` 或 `.verification` 的 Rust 文件 | 30 | **30**(精确写法);33(宽松写法) | 数量吻合。其中 1 个无关(`trace_commons` 信封),3 个宽松误报是 `verification_uri`。真正相关 29 个。计划原文使用的正则若是宽松写法,则 33 才是它会得到的数字,30 应为人工剔除误报后的结果 |
| 引用 `NetworkScheme` 的文件 | 59 | **68** | 59 只覆盖 `crates/`,漏了根 `tests/` 的 9 个文件。应修正为 68(`crates/` 59 + `tests/` 9) |
| 需要处理 wss 的 `match` | "需枚举 59 个引用文件里的 match" | 穷尽 `match` 仅 **2** 处;字符串解析点 3 处;scheme 比较点约 15 处 | 绝大多数文件只是构造 `Https` 字面量,不需要改。计划应把 Task 4/6 的"逐个检查所有 match"改为引用 2.2 到 2.4 的清单 |
| `AuthRequirement` 触点 | 未估算 | 4 个变体,定义 1 处,生产用法约 6 个文件,生产 `ChannelIngressVerifier` 实现 1 个 | `router.rs` 不直接引用 `AuthRequirement`,而是通过 `IngressVerificationRecipe` |

建议:计划里"59 个文件"改为"68 个文件(其中需要改动的穷尽 match 为 2 处)","30 个文件"保留,并注明其中 1 个无关。

### 清单 A:引用 route_suffix 或 .verification 的 30 个文件

```
crates/app/ironclaw_architecture_tests/tests/reborn_dependency_boundaries.rs
crates/app/ironclaw_cli/src/commands/serve.rs
crates/app/ironclaw_composition/src/test_support/session_channel.rs
crates/contracts/ironclaw_extension_contracts/src/channel.rs
crates/contracts/ironclaw_extension_contracts/src/recipe.rs
crates/contracts/ironclaw_extension_contracts/tests/reply_contract.rs
crates/domains/ironclaw_trace_commons/src/contribution/envelope.rs
crates/extensions/ironclaw_extension_host/src/active.rs
crates/extensions/ironclaw_extension_host/src/channel_config.rs
crates/extensions/ironclaw_extension_host/src/channel_connection.rs
crates/extensions/ironclaw_extension_host/src/channel_host.rs
crates/extensions/ironclaw_extension_host/src/channel_host/e2e_tests.rs
crates/extensions/ironclaw_extension_host/src/channel_identity_binding.rs
crates/extensions/ironclaw_extension_host/src/deployment_channels.rs
crates/extensions/ironclaw_extension_host/src/entrypoint.rs
crates/extensions/ironclaw_extension_host/src/extension_ingress.rs
crates/extensions/ironclaw_extension_host/src/ingress/mod.rs
crates/extensions/ironclaw_extension_host/src/ingress/router.rs
crates/extensions/ironclaw_extension_host/src/ingress/verifier.rs
crates/extensions/ironclaw_extension_host/src/lifecycle.rs
crates/extensions/ironclaw_extension_host/src/session_ingress.rs
crates/extensions/ironclaw_extension_host/src/test_support.rs
crates/extensions/ironclaw_extension_host/tests/ingress_router_contract.rs
crates/extensions/ironclaw_extension_host/tests/lifecycle_contract.rs
crates/extensions/ironclaw_extension_manager/src/test_support/lifecycle.rs
crates/extensions/ironclaw_extension_registry/src/v3.rs
crates/extensions/ironclaw_extension_registry/tests/manifest_v3_contract.rs
crates/extensions/packages/web-app/tests/manifest_lockstep.rs
crates/product/ironclaw_assistant/src/reborn_services/extensions.rs
tests/integration/auth/oauth_popup_journeys.rs
```

### 清单 B:引用 NetworkScheme 的 68 个文件

```
crates/app/ironclaw_cli/src/first_party/gsuite.rs
crates/app/ironclaw_composition/src/builtin_capability_policy.rs
crates/app/ironclaw_composition/src/factory/tests.rs
crates/app/ironclaw_composition/src/product_capability.rs
crates/app/ironclaw_composition/src/runtime/approval/tests.rs
crates/app/ironclaw_composition/tests/gsuite.rs
crates/app/ironclaw_composition/tests/refreshing_capability_port_test_support.rs
crates/contracts/ironclaw_extension_contracts/src/channel.rs
crates/contracts/ironclaw_host_api/src/action.rs
crates/contracts/ironclaw_host_api/tests/host_api_contract.rs
crates/contracts/ironclaw_product_contracts/src/approval_prompt.rs
crates/domains/ironclaw_auth/src/engine/http.rs
crates/extensions/ironclaw_extension_host/src/capability_surface.rs
crates/extensions/ironclaw_extension_host/src/channel_egress.rs
crates/extensions/ironclaw_extension_host/src/egress.rs
crates/extensions/ironclaw_extension_host/src/hosted_mcp_manifest.rs
crates/extensions/ironclaw_extension_host/src/mcp.rs
crates/extensions/ironclaw_extension_host/src/test_support/first_party_registrars.rs
crates/extensions/ironclaw_extension_manager/src/ironhub/artifact_hosts.rs
crates/extensions/ironclaw_extension_manager/src/ironhub/catalog.rs
crates/extensions/ironclaw_extension_registry/src/hosted_mcp_discovery.rs
crates/extensions/ironclaw_extension_registry/src/v2.rs
crates/extensions/ironclaw_extension_registry/src/v3.rs
crates/extensions/ironclaw_extension_registry/tests/extension_contract.rs
crates/extensions/ironclaw_extension_registry/tests/manifest_v2_contract.rs
crates/extensions/ironclaw_extension_registry/tests/manifest_v3_contract.rs
crates/extensions/ironclaw_extension_support/src/gsuite/network.rs
crates/extensions/ironclaw_extension_support/src/skills/url_install.rs
crates/extensions/ironclaw_extension_support/src/web_access.rs
crates/extensions/ironclaw_extension_support/tests/gsuite_core.rs
crates/kernel/ironclaw_approvals/tests/approval_resolution_contract.rs
crates/kernel/ironclaw_authorization/tests/capability_access_contract.rs
crates/kernel/ironclaw_authorization/tests/runtime_credentials_contract.rs
crates/kernel/ironclaw_host_runtime/src/egress/host_port.rs
crates/kernel/ironclaw_host_runtime/src/first_party_tools/shell.rs
crates/kernel/ironclaw_host_runtime/src/obligations/tests.rs
crates/kernel/ironclaw_host_runtime/src/process_port.rs
crates/kernel/ironclaw_host_runtime/src/services/tests.rs
crates/kernel/ironclaw_host_runtime/src/wasm_credentials.rs
crates/kernel/ironclaw_host_runtime/tests/builtin_obligation_handler_contract.rs
crates/kernel/ironclaw_host_runtime/tests/extension_v2_lifecycle_e2e.rs
crates/kernel/ironclaw_host_runtime/tests/first_party_builtin_tools.rs
crates/kernel/ironclaw_host_runtime/tests/first_party_runtime_contract.rs
crates/kernel/ironclaw_host_runtime/tests/github_wasm_runtime_contract.rs
crates/kernel/ironclaw_host_runtime/tests/host_runtime_services_contract.rs
crates/kernel/ironclaw_host_runtime/tests/obligation_services_composition_contract.rs
crates/kernel/ironclaw_host_runtime/tests/reborn_e2e_gate.rs
crates/kernel/ironclaw_host_runtime/tests/runtime_http_egress_contract.rs
crates/kernel/ironclaw_host_runtime/tests/support/host_runtime_harness.rs
crates/lanes/ironclaw_mcp/tests/mcp_adapter_contract.rs
crates/lanes/ironclaw_sandbox/src/sandbox_process/managed_egress.rs
crates/lanes/ironclaw_sandbox/tests/script_http_adapter_contract.rs
crates/lanes/ironclaw_wasm/tests/wasm_dispatch_integration.rs
crates/lanes/ironclaw_wasm/tests/wasm_http_adapter_contract.rs
crates/product/ironclaw_assistant/src/projection/tests.rs
crates/product/ironclaw_assistant/src/projection/tests/turn_stream.rs
crates/substrates/ironclaw_network/src/types.rs
crates/substrates/ironclaw_network/src/url_target.rs
crates/substrates/ironclaw_network/tests/network_policy_contract.rs
tests/integration/hosted_mcp_registration.rs
tests/integration/support/github.rs
tests/integration/support/harness/assembly.rs
tests/integration/support/harness_mcp.rs
tests/integration/support/harness_web_access.rs
tests/reborn_http_network_scope_isolation_parity.rs
tests/reborn_tool_param_coercion_parity.rs
tests/reborn_trace_core_builtin_tools_parity.rs
tests/support/reborn_parity_qa/network.rs
```

### 清单 C:引用 AuthRequirement(词边界)的 30 个文件及行数

```
   3 crates/app/ironclaw_architecture_tests/tests/reborn_sealed_evidence_mint_ratchet.rs
  13 crates/contracts/ironclaw_extension_contracts/src/product_adapter_section.rs
   3 crates/contracts/ironclaw_extension_contracts/src/verified_inbound.rs
   3 crates/contracts/ironclaw_extension_contracts/tests/verified_inbound_seal.rs
  24 crates/contracts/ironclaw_host_api/src/product_adapter/auth.rs
   1 crates/contracts/ironclaw_host_api/src/product_adapter/mod.rs
   4 crates/contracts/ironclaw_host_api/tests/protocol_auth_evidence_seal.rs
   2 crates/contracts/ironclaw_product_contracts/src/command.rs
   3 crates/contracts/ironclaw_product_contracts/src/inbound/tests.rs
   2 crates/extensions/ironclaw_extension_host/src/channel_command_roles.rs
   2 crates/extensions/ironclaw_extension_host/src/channel_host/e2e_tests.rs
   2 crates/extensions/ironclaw_extension_manager/src/lifecycle_product_service.rs
   2 crates/extensions/ironclaw_extension_registry/tests/product_adapter_manifest_ingestion.rs
   2 crates/product/ironclaw_assistant/src/inbound_turn/tests/attachments.rs
   3 crates/product/ironclaw_assistant/src/workflow.rs
   2 crates/product/ironclaw_assistant/tests/inbound_turn_contract.rs
   2 crates/product/ironclaw_assistant/tests/product_command_surface_contract.rs
   3 crates/product/ironclaw_assistant/tests/product_surface_contract.rs
   2 crates/product/ironclaw_assistant/tests/run_delivery_contract.rs
   2 crates/product/ironclaw_assistant/tests/support/planned_agent_loop.rs
   5 crates/product/ironclaw_openai_compat/tests/chat_workflow_handlers_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/docs_responses_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/models_handlers_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/responses_path_prefix_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/responses_temperature_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/responses_workflow_handlers_contract.rs
   2 crates/product/ironclaw_openai_compat/tests/streaming_handlers_contract.rs
   2 tests/integration/delivery_user_journeys.rs
   5 tests/integration/extension_delivery.rs
   2 tests/integration/support/test_adapter.rs
```

## 批准

批准人:用户本人

日期:2026-11-18

结论:批准。批准范围是本 ADR 第 1 节到第 7 节的全部决定,其中第 1 节(WebSocket 出站,含新增 `NetworkScheme::Wss`)和第 3 节(新增 `AuthRequirement::AuthenticatedStream` 密封证据变体)是仓库规则明确要求所有者批准的边界。里程碑一的 Task 2 到 Task 10 可以开始。

附带条件:批准人未提出新增条件。本 ADR 正文已有的前置条件和未验证项继续有效,不因批准而解除:
- 第 1.2 节:不批准任何通配符。WebSocket 主机必须逐个声明。如果钉钉的主机确实轮换,需要第二个独立决定并重新批准。
- 第 8 节:所有标"未验证"的钉钉事实,在对应任务开工前核实,核实结果与 ADR 不一致时回到本 ADR 修订。网关主机集合阻塞 Task 12。
- 第 9 节:在"单消息单连接"被证明之前,只承诺单副本部署。
- 第 13 节:Task 2 和 Task 4 的 PR 需要说明 `Wss` 与 `AuthenticatedStream` 可能出现在哪些持久化位置。

记录说明:本节由助手按批准人在 2026-11-18 的口头指示写入,批准人可直接修改本节措辞。

### 修订批准

批准人:用户本人

日期:2026-11-20

以下决定是批准人在里程碑一收尾评审的修复阶段,对助手的提问作出的明确回复。原"批准"一节的文字未改动。

| 决定 | 批准人回复 | 内容 |
|---|---|---|
| 修复范围 | "1,同意" | 同意修复评审 #1 到 #12,暂缓 #13。这包括第 2.2 节移除 stream 声明的 `body_limit_bytes` 字段(评审 #8),以及帧上限、速率上限的收紧(评审 #2、#11) |
| #7 目标与方案 | "2#7(ticket 清零)"、"B" | `ticket` 要真正清零,做不到就停下来报告而不是收窄承诺。方案选 B:WebSocket 握手由 `ironclaw_network` 手写,放入 `Zeroizing` 缓冲(见 1.4) |
| #7 残留副本 | "X" | 接受建连响应路径上的两处残留(`transport.rs` 的响应体累积 `Vec<u8>`,主机侧 `serde_json::Value` 中 `ticket` 移出前的 `String`),如实记录,并把改共享 HTTP 响应类型记为未启动的后续可选任务 |
| Task 10 测试注入点 | "A" | 为集成测试增加一个 `cfg(test-support)` 注入点(`with_stream_connector_for_test`),并把棘轮的三个冻结计数各上调 1。这一项对应的是里程碑一更早的 Task 10 提交,不在本轮复核的差异里,这里只是补记批准 |

记录说明:本节由助手按批准人在会话中的明确回复写入,批准人可直接修改措辞。

### 修订记录(2026-11-22,评审修复)
原"批准"与"修订批准"两节的文字未改动;本节只追加。以下是批准人对双模型评审(分支 `dingtalk-channel`)的决定。

| 评审编号 | 决定 | 依据与未核实事项 |
|---|---|---|
| #2 | 429 与 `flowControlledStaffIdList` 保持 `Retryable`,不改成 `Ambiguous` | 依据:按 HTTP 惯例,429 表示服务端没有处理该请求;改成未确认会让限流期间的回复永远发不出去。**未经钉钉官方文档或实测核实。** 与 5xx 不同,5xx 没有这条惯例可依,所以仍是 `Ambiguous`。风险:如果钉钉可以在受理消息后再限流,重试会产生一条重复消息。该问题已写入计划 Task 20 的核实清单,并如实写在 `send.rs` 的模块文档里。 |
| #4 | 不再从 `text.content` 去掉开头的 `@` 标记,原文交给模型 | 钉钉是否把 @机器人 写进 `text.content` 仍未核实,当前选择是不做任何删除:多出一个可见的 `@机器人` 只是噪声,丢掉用户输入的 `@Alice` 是丢失信息。已写入 Task 20 核实清单。 |
| #1 | 建连目标不再声明 `credential_handle` | 建连凭证只通过 `body_credentials` 注入请求体;目标级凭证会让主机额外把 ClientSecret 作为 `Authorization: Bearer` 头发出。manifest 层和集成层都有断言。 |
| #3 | 不作为阻塞项 | 仓库 CI 的各测试任务统一设置 `RUST_MIN_STACK=67108864`,里程碑一的集成测试同样依赖它;测试文件头注释写明这一依赖。 |
| #14 | 本任务不处理 | 架构测试按目录名查找边界规则是通用缺陷(`docs/internal/gate-audit-2026-08.md` 已记录,slack、telegram 同样受影响);记入计划"后续项"。 |


### 修订记录(2026-11-23,真实验收发现:管理员保存凭证后流式连接不恢复)
原"批准"与"修订批准"两节以及已批准的决定未改动;本节只追加。

现象(真实环境验收):管理员已保存 ClientID 与 ClientSecret,扩展页仍显示"需要配置",状态为 `NeedsAdministrator`、原因 `connect_credentials_missing`;进程重启后才恢复。

根因:有部署绑定的流式渠道(钉钉有)的连接来源是 `StreamSource::Deployment`,其标识是进程内永不改变的 `Arc`。第 5.7 节要求的"管理员凭证变化时重启连接"只对 `Active` 来源成立:保存配置只重新发布 Active 快照,监督器看到同一个部署来源,就跳过了已结束的任务。连接在凭证尚不可读的启动时段进入 `NeedsAdministrator` 后,保存凭证不会让它重试。

不是以下原因(已逐项排除):
- 评审 #1 删除 `credential_handle`:`body_credentials` 与目标凭证分别解析,恢复它只会重新引入 `Authorization: Bearer` 头,未恢复。
- 凭证端口作用域:生产的 `ChannelConfigEgressCredentials` 读管理员配置的租户共享作用域,与保存路径一致;集成测试通过 `builtin.admin_configuration_replace` 保存后能读到值。
- 启动时的 `config_unavailable`:监督器先于渠道入站注册读取配置,属瞬时失败,按第 5.5 节退避重试,不是缺陷。`Connected` 事件按 debug 级别记录,是可观测性缺口,未改动(开放项)。

为什么测试没发现:原有流式与钉钉集成测试在安装前通过测试注入点提供秘密,绕过了管理员配置保存路径,也从未进入 `NeedsAdministrator` 后再保存;crate 层测试用的是空的部署渠道表,只覆盖 Active 来源。

修复(通用层,无厂商名,不改契约和 manifest):`ironclaw_extension_host::stream_supervisor` 新增 `StreamConfigurationChanges`(按扩展 id 的变更代次)和 `StreamRestartingReactivation`(装饰唯一的 `ChannelConfigReactivation` 端口,重新激活后无条件递增代次)。监督器在部署来源的代次变化时重启连接,Active 来源不重复重启。composition 把装饰后的端口同时交给 `ChannelConfigService` 和管理员配置 handler。代次只含扩展 id 与计数,不含秘密。回滚:revert 对应提交,无持久化变更。

同类路径排查:token 交换与建连共用同一凭证端口,webhook 渠道的 registration/activation_calls 由生命周期激活驱动且不依赖监督器来源,均不受影响。开放项:部署绑定但未安装的 webhook 渠道,保存配置时 `reactivate_if_active` 不做任何事(生命周期范畴,未改)。
