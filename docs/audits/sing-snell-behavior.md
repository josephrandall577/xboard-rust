# sing-snell 服务端行为一致性核对

审查日期：2026-10-20。执行路线：Matt Pocock `research` standalone capability，以源码及实际探针为依据。

## 结论与基线

**初次审查基线不能判定为与 Go 参考实现完全一致。** 内置 Rust `snell` 库在已运行的常规握手、TCP/UDP、复用、半关闭、混淆及 wire fixture 场景中通过验证；共享地址模型和 TLS 空记录接口仍有边界差异。Xboard 节点实际使用的转发层另有两项 P1 数据完整性问题：启用限速会丢弃 TCP 块的后缀、截断 UDP 数据报。这些问题不经过示例服务端，因此原有互操作测试不能发现。

**修复复核：F1/F2/F3/F4 已修复并验证。** 下文保留初次审查的故障证据；最终实现、输入契约、测试和双轴审查见文末“修复与复核”。C1 保留 Rust 的 EOF 适配，IPv4 UDP 出站限制仍存在。

- 上游：[SagerNet/sing-snell @ bc5a12ac736f235b2de2926ecd2791cc925e6b8c](https://github.com/SagerNet/sing-snell/tree/bc5a12ac736f235b2de2926ecd2791cc925e6b8c)。审查时 `git ls-remote … HEAD` 返回该版本。
- 本地 HEAD：`7d443cb8b999f9cf0ea432165304bf2909e1faed`；互操作模块已经锁定同一上游版本，见 [go.mod](../../snell/interop/go.mod#L7)。因此此次差异并非上游版本漂移导致。
- 比较对象：`snell/src/v5`、`snell/src/v6`、共享请求/地址/认证/加密/混淆，以及节点的 `src/server.rs`、`src/relay.rs`、限速相关的 `src/accounting.rs`。v4 是客户端，服务端兼容由 v5 提供，见 [模块说明](../../snell/src/v5/mod.rs#L1)。
- 初次审查仅新增本文及 [诊断探针](probes/)；后续修复修改了文末列出的产品实现及回归测试。开始时已存在的 `src/panel.rs` 修改保持原样。面板 API 语义不属于此次 Go Snell 服务端比较范围。

## 初次审查：已确认的产品缺陷

### F1 · P1：TCP 限速路径永久丢掉当前读取块的后缀

**触发：** 用户 `speed_limit > 0`，某次 `acquire` 返回的额度小于已读字节数。这在新建限速连接即可发生，无需高并发或耗尽一整秒额度。

[copy_metered](../../src/relay.rs#L176) 读取 `n` 字节后只写出 `buf[..allowed]`，随后进入下一次 `source.read`；`buf[allowed..n]` 没有保留或重试。上传、下载共用此函数，两个方向都受影响。[acquire](../../src/accounting.rs#L146) 明确可能只返回部分额度；额度为零时还会等待后直接返回 1，调用方不能把结果当作“整个块已经处理完毕”。

**实测：** 通过真实 Node、v6 客户端及 loopback TCP 目标发送 32,768 字节。目标读取到 EOF 后，独立发送固定 32,768 字节回复，以便分别验证上、下行。不限速时，三种模式的上游接收量和客户端回复接收量均为 32,768。设为 1 Mbps 后：

| 模式 | 客户端发送 | 上游实际收到 | 客户端回复收到 |
| --- | ---: | ---: | ---: |
| default | 32,768 | 9,312 | 1 |
| unshaped | 32,768 | 1 | 1 |
| unsafe-raw | 32,768 | 1 | 1 |

`default` 的精确损失量随分帧和调度变化；缺陷是后缀必然在部分授权时被丢弃，而不是某个固定数字。结果来自 [tcp 探针](probes/src/main.rs)。

**参考契约：** 上游 Snell 服务端将完整解码后的数据交给 Handler，见 [v6 serverConn.Read](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/server.go#L323) 与 [v6 baseReader.Read](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/record.go#L73)。本地用于 Go 参考服务端的 [Handler](../../snell/interop/snell-server/main.go#L27) 通过 sing 的 `bufio.CopyConn` 转发，不包含该丢弃逻辑。上游库本身不定义 Xboard 限速；这是节点新增的转发缺陷，不能归因于 Go 的协议实现。

**修复方向：** 对当前块维护 offset，等待后继续发送剩余字节，直至整个块完成；计量实际成功写出的字节。新增覆盖上/下行、持续传输及并发连接的“限速但字节完全相等”测试。限速等待也应重新检查并扣除实际额度，不能依靠固定返回 1 来代表等待成功。

### F2 · P1：UDP 限速把数据报改成另一个更短的数据报

**触发：** 限速用户的单个 UDP 数据报大于当前可用额度。

上传在 [relay_udp](../../src/relay.rs#L246) 执行 `socket.send_to(&bytes[..allowed], …)`；下载在 [下载任务](../../src/relay.rs#L228) 用 `buf[..allowed]` 构造回复数据报。两个方向都改变了原始消息的边界和内容。这会破坏 DNS、QUIC 等上层协议，不能视为正常的带宽限制。

**实测：** 同一套 Node 探针发送一个 4,096 字节 UDP 数据报。目标无论收到多少字节，都独立回复完整的 4,096 字节，以分别验证上、下行。三种 v6 模式在不限速时，上游和客户端均收到完整的 4,096 字节；1 Mbps 时，上游收到 1 字节，客户端收到的也是 1 字节，接口仍返回成功。见 [udp 探针](probes/src/main.rs)。

**参考契约：** 上游 [serverPacketConn.ReadPacket / WritePacket](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/packet.go#L260) 按完整 record 读取、发送完整 datagram，过大时返回错误。Go 参考包装器也 [发送完整 buffer](../../snell/interop/snell-server/main.go#L81)。Rust 库的 [包处理](../../snell/src/v6/packet.rs#L229) 保留该语义；截断发生在节点转发层。

**修复方向：** 为整个数据报等待额度，再原样发送；需要容纳比 burst 更大的合法数据报，例如累计预约或记账债务。若策略选择丢包，应丢弃整个数据报并明确计数，不可发送前缀；不要把 UDP 数据报拆成多个独立 UDP 消息。

## 初次审查：已确认的库级边界差异

### F3 · P2：非法 UTF-8 主机字节被静默替换

Rust [read_sock_string](../../snell/src/address.rs#L11) 和 [UDP 域名读取](../../snell/src/address.rs#L100) 使用 `String::from_utf8_lossy`。Go [ReadConnectAddress](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/address.go#L31) 保留 `M.ReadSockString` 的 Go string；[ReadUDPRequestAddress](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/address.go#L78) 直接执行 `string(host)`。Go string 可以保存任意原始字节。

对 CONNECT host `ff` 加端口 443 的实测：Go 返回 host 字节 `ff`，Rust 返回 `ef bf bd`（U+FFFD）；两边均未报告解析错误。见 [Go 探针](probes/go_probe.go) 和 [Rust 探针](probes/src/main.rs)。

这是目标地址在到达 Handler 前被改变的差异，也可能使不同非法输入折叠为同一字符串。正常 ASCII/有效 UTF-8 主机名不受此项影响；不能据此推断正常 DNS 域名访问失败。若要求字节级等价，需要保留原始 host 字节；若决定拒绝非法 UTF-8，需将其明确记录为与 Go 不同的输入策略，避免无声替换。

### F4 · P2：带 scope 的 IPv6 地址不能保持 Go 的地址模型

Rust [Socksaddr](../../snell/src/addr.rs#L11) 仅保存 `std::net::IpAddr`，[parse_host_port](../../snell/src/addr.rs#L53) 直接调用该类型的 parser；`fe80::1%lo0` 被识别成域名，`is_ip() == false`。Go 的 `metadata.ParseSocksaddrHostPort` 使用 `netip.ParseAddr`，保存 zone，返回 `IsIP() == true`。两边读取同一个 CONNECT host 的实测已确认这一差异。

Go 一手依据：[sing metadata/addr.go @ d096a164bc7f](https://github.com/SagerNet/sing/blob/d096a164bc7f/common/metadata/addr.go#L211)；该依赖由 [互操作 go.mod](../../snell/interop/go.mod#L6) 锁定。Rust [from_socket_addr](../../snell/src/addr.rs#L42) 也只取 `addr.ip()` 和 port，无法保留 `SocketAddrV6.scope_id`。

影响是地址类型、scope 信息和选择 IP/域名处理路径不同。操作系统的域名解析器可能仍能识别部分带 zone 的字符串，所以本项不宣称所有 scoped IPv6 CONNECT 都连接失败。若支持此类地址，需扩展地址模型并核对 scope 的输入、保存和拨号流程。

### C1 · P3 / 接口语义差异：TLS obfs 会跳过空记录

Go [tlsObfsServerConn.Read](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/obfs.go#L398) 返回单个 TLS record 的读取结果，空 record 可返回 `(0, nil)`；Rust [TlsObfsServerConn::read_inner](../../snell/src/obfs.rs#L494) 循环到 `n > 0` 才返回。客户端方向有同样的结构差异，见 [Rust](../../snell/src/obfs.rs#L383) 和 [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/obfs.go#L304)。

探针向服务端 obfs wrapper 提供长度为零的首记录、对应 trailer、随后带 `A` 的记录：Go 第一次 Read 返回 0，第二次返回 `A`；Rust 第一次直接返回 `A`。

这是已确认的调用级差异，未证明正常 Snell 会话不兼容。Rust 用 `Ok(0)` 表示 EOF，因此跳过空 TLS 记录可能是有意的语言接口适配；不建议为了模仿 Go 的 `(0, nil)` 而直接返回 Rust EOF。若要求对异常输入的阻塞时机也完全等价，需要单独定义转换契约。

## 正常路径及协议分支核对

下表中的“一致”限定为所列源码分支及已执行测试，不等同于整个输入空间的形式证明。

| 检查项 | 对照结果及依据 |
| --- | --- |
| Argon2id / AES-128-GCM / nonce | 内部协议密钥使用 Argon2id 参数 3/8/1、派生 32 字节后取前 16 字节；nonce 均按小端逐字节递增。见 [Rust](../../snell/src/crypto.rs#L12) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/crypto.go#L10)。未把两边公开 crypto API 的所有可接受参数都纳入结论。 |
| 请求头及 PING | 都要求 3 字节 prefix 和 request version 1；PING 在 prefix 后直接处理，忽略所声明的 client ID 内容。见 [Rust](../../snell/src/request.rs#L112) / [Go v6](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/server.go#L125) / [Go v5](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/server.go#L229)。PING 不经过多用户 key 验证是双方共有行为。 |
| 多用户更新与认证 | 非空用户集、数量一致、key 长度 1..255、重复 key 拒绝的顺序一致；CONNECT、CONNECT_V2、UDP 通过 key 选择用户，复用的新逻辑请求重新认证。见 [Rust 共享 auth](../../snell/src/auth.rs#L16)、[Rust 复用](../../snell/src/v6/reuse.rs#L730) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/server.go#L75)。Rust 的用户映射使用锁及快照发布，不应为了复制 Go 的裸 map 赋值而移除同步。 |
| v5 replay cache | 均在首 record 解密后检查 salt，使用两代、每代 500,000 项、误判率 1e-10 的 Bloom filter 和相同 MurmurHash2；已有 Go vector 及 replay 用例通过。见 [Rust](../../snell/src/v5/server.rs#L28) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/server.go#L24)。v6 framing 没有对应 cache，不能把 v5 保障扩大到 v6。 |
| v5 record、padding、增长 | Header 版本检查、padding 混合、零 payload EOF、首次 padding 256..511、增长和重置常量与参考匹配。见 [Rust reader/writer](../../snell/src/v5/record.rs)、[常量](../../snell/src/v5/mod.rs#L18) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/record.go)。注意 v5 reader 与 v6 default 都不拒绝两个非零 reserved 字节。 |
| v6 default shaping | 首次盐块、prefix/padding AAD、混合、seq、chunk 增长及按秒 idle reset 的对应分支一致。45 个 PSK 的 profile vector 和 wire fixture 通过。见 [Rust profile test](../../snell/src/v6/profile.rs#L745)、[shaped](../../snell/src/v6/shaped.rs) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/shaped.go)。未穷举全部 PSK。 |
| v6 unshaped / unsafe-raw | 都拒绝非零 reserved、非零 padding；最大单 record payload 为 65,535；较大流写入拆帧。见 [Rust](../../snell/src/v6/record.rs#L22)、[首帧](../../snell/src/v6/handshake.rs#L34) / [Go record](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/record.go#L20)、[首帧](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/handshake.go#L16)。raw 首帧/异常输入 289 组差分未发现不同。 |
| v6 UDP 首帧 | 都拒绝 UDP tunnel request 后同一个解密 record 还带额外数据；先发 tunnel reply，再读取首个完整数据报，缓存后交给 Handler。见 [Rust](../../snell/src/v6/server.rs#L205) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/server.go#L177)。v5 对 request record 的剩余内容直接丢弃，这是双方共有的版本差异。 |
| UDP 地址与批量发送 | IPv4/IPv6 response address、request forward opcode、单数据报完整 record 及过大报错分支对应；vector/batch 互操作通过。见 [Rust packet](../../snell/src/v6/packet.rs#L229) / [Go packet](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/packet.go#L260)。域名字节及 scope 例外见 F3/F4。 |
| 非复用关闭 | v5 在首次回复前 EOF 回 `ff / end of file`，回复后直接关 transport；v6 command 1 CloseWrite 直接关 transport，均不追加 Snell zero chunk。见 [Rust v5](../../snell/src/v5/server.rs#L482)、[Rust v6](../../snell/src/v6/server.rs#L330) / [Go v5](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/server.go#L599)、[Go v6](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/server.go#L401)。 |
| 复用与半关闭 | 回复前关闭回 `65 / Remote EOF` 并终止 transport；回复后写 zero chunk；handler 完成后 drain 到客户端 zero chunk，再读下一个 request；等待丢弃阈值为 `0x80001`。见 [Rust session](../../snell/src/v6/reuse.rs#L713)、[逻辑连接](../../snell/src/v6/reuse.rs#L952) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv6/reuse.go#L639)。常规 reuse、active read、close-before-client-EOF 用例通过；未穷举竞态调度。 |
| HTTP/TLS obfs | HTTP 首个 CRLFCRLF 前全部忽略，TLS payload framing 和普通互操作匹配；空 TLS record 接口差异见 C1。见 [Rust](../../snell/src/obfs.rs) / [Go](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/obfs.go)。 |

## 节点能力限制与证据范围

1. **节点只启动 v6 MultiService。** vendored 库支持 v5 并不意味着节点监听口也接受 v4/v5。见 [节点 listener](../../src/server.rs#L28)。这是产品范围限制。
2. **节点 UDP 出站 socket 固定为 IPv4。** [relay_udp](../../src/relay.rs#L216) 绑定 `0.0.0.0:0`。不限速、目标为 `[::1]` 的本地探针超时，上游收到 0 字节。同仓库的 [Go 参考服务端包装器](../../snell/interop/snell-server/main.go#L43) 也绑定 IPv4；所以这说明节点/包装器的出站限制，不能单独当作对上游通用 Snell 库的移植回归。
3. **上游是协议库，不是 Xboard 节点。** 用户额度、过期、设备数、封禁和限速都是额外的节点策略，见 [authorize](../../src/relay.rs#L36) / [Registry::open_connection](../../src/accounting.rs#L315)。认证后被策略拒绝属于预期扩展；F1/F2 中无声修改有效载荷则破坏转发契约。
4. **互操作目标要辨明。** Go suite 的外部服务器由 [SNELL_SERVER_BIN](../../snell/interop/suite/server_test.go#L21) 指定；此次指向 Rust 示例 binary。Rust official tests 此次指向 Go 包装器 binary，未运行 Surge 闭源官方 binary。
5. **普通 cargo test 会隐藏外部测试跳过。** 没有 `SNELL_SERVER_BIN` 且 Docker 不可用时，[启动函数](../../snell/tests/common/server.rs#L140) 返回 None，调用方提前返回；测试运行器仍显示 ok，而非 ignored。本次额外设置 Go binary 后确实运行了 28 项，因此最终互操作结论没有把最初的空跑当成证据。
6. **测试入口还有维护缺口。** 根 `cargo test` 不运行路径依赖 `snell` 的自身测试；[snell/Makefile](../../snell/Makefile#L6) 的 `XBOARD_NODE = xboard-node` 路径在当前仓库布局也不存在。本次使用下文的显式命令执行两套测试。

## 初次审查执行结果

| 验证 | 本次结果 | 结论范围 |
| --- | --- | --- |
| 根 cargo test --locked | 23 unit + 7 e2e + 4 panel + 1 ws = 35 通过 | 节点既有测试；e2e 默认不启用限速，见 [UserSpec](../../tests/e2e.rs#L61)。 |
| 库 cargo test --locked | 7 unit/vector + 23 loopback = 30 实际执行通过 | 原本显示 ok 的 28 项外部测试在未配置 server 时提前返回，不计入这一行。 |
| Go suite，设置 Rust 示例 server | 35 顶层测试通过，含 48 个子测试，无 skip/fail | 其中 28 顶层测试连接外部 Rust server；另 7 项为 Go 本地服务端回环，见 [TLS loopback](../../snell/interop/suite/tls_obfs_loopback_test.go) 与 [v6 loopback](../../snell/interop/suite/v6_test.go#L257)。 |
| Rust external suite，设置 Go server | 28 项通过 | Rust 客户端 → Go 服务端；不代表 Xboard RelayHandler 已验证。 |
| raw_differential.py | 289 输入，0 差异 | 全部 256 opcode、请求/record 版本、PING ID 长度、reserved、padding、截断及 UDP 请求/数据报边界；只覆盖 v6 unsafe-raw、单用户 Service。额外用已知 PONG 断言确认两个进程实际响应。 |
| Rust Node 探针 | 三模式不限速完整通过；三模式限速均损坏 TCP/UDP；IPv6 UDP 超时 | 确认 F1/F2 和节点 IPv4 出站限制。 |
| Go/Rust 地址及 TLS 探针 | 确认 F3/F4/C1 | 公开解析函数及 obfs wrapper 的同输入差分。 |

以下仍不在证据范围内：全 PSK 空间、所有加密 malformed-frame 组合、复用切换时的穷举并发竞态、完整多用户热更新差分、长期资源泄漏/压力测试、Linux 与 macOS 全部网络差异、Xboard 策略和 Go 外部宿主的全功能等价。源码对应与有限测试不足以宣称数学意义上的全行为等价。

## 复现命令

在仓库根运行。需要 Rust、Go、Python 3；所有探针仅使用合成测试凭据及 loopback listener，子进程通过参数数组启动。诊断探针打印实际行为，发现差异并不自动令进程失败，因此必须检查输出，不能把退出码 0 当作字节完整性通过。

```sh
cargo test --locked
cargo test --manifest-path snell/Cargo.toml --locked
cargo build --manifest-path snell/Cargo.toml --locked --example snell-server

REPO_ROOT="$PWD"
AUDIT_GO_SERVER="$(mktemp -d)/go-snell-server"
(
  cd snell/interop
  go build -o "$AUDIT_GO_SERVER" ./snell-server
  SNELL_SERVER_BIN="$REPO_ROOT/snell/target/debug/examples/snell-server" \
    go test -count=1 -timeout 10m ./...
)
SNELL_SERVER_BIN="$AUDIT_GO_SERVER" \
  cargo test --manifest-path snell/Cargo.toml --locked --test official -- --test-threads=4

CARGO_TARGET_DIR="$REPO_ROOT/target" \
  cargo run --manifest-path docs/audits/probes/Cargo.toml
(
  cd snell/interop
  go run ../../docs/audits/probes/go_probe.go
)
python3 docs/audits/probes/raw_differential.py \
  --rust-server snell/target/debug/examples/snell-server \
  --go-server "$AUDIT_GO_SERVER"
```

若当前 shell 不含 Rust 工具链，需先把实际 Cargo bin 目录加入 PATH。本次环境使用 `/Users/moshufan/.cargo/bin`；不把该机器路径写死到探针。

初次审查建议已在本次修复中执行：F1/F2 的真实 Node 内容完整性回归与 F3/F4 的地址输入契约均已落地，详见以下复核。

## 修复与复核

以下结论针对工作区修复候选，基线仍为上述本地 HEAD；不包含开始时已有的 src/panel.rs 改动。初次审查中的损坏数据是历史复现结果，不是修复后的行为。源码链接定位当前工作区，历史语句以基线版本为准。

| 项目 | 最终状态与实现 |
| --- | --- |
| F1 TCP 丢后缀 | 已修复。copy_metered 对当前块维护 offset，逐次获取额度并发送至全部完成，成功写完每个片段后才计费。Conn::write 的公开契约为写完全部输入或报错。 |
| F2 UDP 截断 | 已修复。上、下行先用 acquire_all 累计取得整个数据报所需额度，再发送完整内容；不再发送前缀或拆成多个 UDP 消息。 |
| 共享限速器 | 等待后循环重新填充、竞争并扣减真实额度，取消固定返回 1；取整只扣实际授予的字节，保留小数。单次等待最多 250 ms 以重查配置；所有连接共用用户额度，上、下行独立，不再通过跨方向 mutex 持锁等待。 |
| F3 非法 UTF-8 | 已修复协议编解码和 Handler 地址信息的丢失：raw_fqdn 保留原始字节，host_bytes() 用于 CONNECT/UDP 和 Request::len，fqdn/addr_string 仅用于显示。系统拨号通过 host() 明确拒绝不能表示为 UTF-8 的主机名，不会解析替换后的名称。 |
| F4 IPv6 scope | 已修复。zone 保存命名或数字 scope，解析后仍为 IP；CONNECT 编码保留 zone，SocketAddrV6 的数字 scope 往返保留；命名 zone 通过 host() 原样交给 OS 解析。UDP IP 地址 wire 格式没有 zone 字段，与 Go 相同。 |
| C1 TLS 空记录 | 保留。Rust 的 Ok(0) 表示 EOF；跳过空 record 后继续读取有效数据，避免误报 EOF。仍有 Go 先返回 (0,nil) 的调用语义差异，不宣称完全行为等价。 |

相关实现：[限速额度](../../src/accounting.rs)、[节点转发](../../src/relay.rs)、[地址模型](../../snell/src/addr.rs)、[地址编码](../../snell/src/address.rs)、[请求长度](../../snell/src/request.rs)、[系统拨号](../../snell/src/net.rs)、[示例解析器](../../snell/examples/snell-server.rs)。Socksaddr 新增公共字段 raw_fqdn/zone；外部代码使用结构体字面量时需补充字段或默认值，推荐使用构造函数，见 [接口说明](../../snell/README.md)。

### 回归的红绿证据

- 真实 Node 接口：[limited_tcp_preserves_concurrent_streams](../../tests/e2e.rs) 在三种模式、同一限速用户的两个并发连接中，分别验证每条流 128 KiB 上传、独立生成的 128 KiB 回复，以及各 256 KiB 计费。修复前上传 131,072 字节只收到 3,954；修复后字节内容和计费全部相等。
- 同一 Node 接口：[limited_udp_preserves_complete_datagrams](../../tests/e2e.rs) 验证 4,096 / 8,192 字节的上传和独立回复，逐字节比较、源地址和双向各 12,288 字节计费。修复前 4,096 字节回复只收到 1；修复后完整。使用 8 KiB 上限避免 macOS 默认 UDP maxdgram 对更大本地发送返回 Message too long。
- [限速回归](../../src/accounting.rs)：固定等待返回 1、小数额度丢失的测试先失败；修复后通过。补充并发请求共享总速率，以及等待中取消限速的检查。计时检查有容差和超时，不要求精确毫秒调度或严格公平性。
- [地址回归](../../snell/tests/address.rs)：CONNECT 的 ff、255 字节非法 UTF-8、有效域名，UDP 的 ff fe，命名/数字 IPv6 zone 和 SocketAddrV6 scope。修复前分别重现替换字节、IP 误分类和 scope 丢失；修复后通过，另验证 SystemDialer 明确返回 InvalidInput。

### 最终验证

| 验证 | 修复后结果 |
| --- | --- |
| 根 cargo test --locked | 27 unit + 9 e2e + 4 panel + 1 ws = 41 通过。 |
| 库 cargo test，显式设置 Go SNELL_SERVER_BIN | 7 unit/vector + 5 address + 23 loopback + 28 external = 63 实际执行通过。 |
| Go suite，显式设置 Rust 示例 server，禁用结果缓存 | 35 顶层及 48 子测试通过，0 skip/fail；与初次审查相同，其中 28 顶层连接 Rust server，7 为 Go loopback。 |
| 根与库 Clippy --all-targets -- -D warnings | 均通过。 |
| 原始 Rust Node 探针 | 三种模式，0 / 1 Mbps 下，TCP 上传和独立下载均为 32,768 字节；UDP 双向均为 4,096 字节。 |
| Go/Rust 地址及 TLS 探针 | host ff 保留 ff，fe80::1%lo0 均为 IP；TLS 空记录接口差异保留。 |
| raw_differential.py | 289 组输入，0 差异。 |

重现命令沿用上文；库全量验证时显式设置 SNELL_SERVER_BIN，避免将外部测试的提前返回当作实测。额外检查命令为 cargo clippy --locked --all-targets -- -D warnings，以及增加 --manifest-path snell/Cargo.toml 的库版本。

### 根因与预防

正确假设是：转发层把部分带宽授权误当作整次读取已完成，而限速器又把等待误当作获得额度；地址层用可损失的文本表示承载协议字节，并把 IPv6 scope 丢在模型之外。修复分别保存待发数据、重新扣减共享额度、保留原始 host 字节和 zone。

现有真实 Node seam 可以复现并锁定故障；缺口是原 e2e 用户都不限速，协议互操作套件也绕过节点 RelayHandler。新增正确 seam 的回归即可预防，不需要引入新的转发框架或架构迁移。测试和探针位于 tests 与 docs/audits/probes；产品代码未保留临时 DEBUG 日志。

保留的限制：节点 UDP 仍使用 IPv4 socket，::1 探针继续超时；命名 IPv6 zone 最终依赖 OS 接口配置，未实测真实链路本地 IPv6 路由；系统解析非法 UTF-8 的策略与 Go 的任意字节 string 接口不同，但不会静默改写目标。上述通过范围不扩展为全输入、全平台等价证明。

## 最终代码审查

基线为本次修复前的本地 HEAD 及前轮审计文件；排除 src/panel.rs 既有修改。审查采用同一执行者分别检查 Standards、Spec 两个维度，未使用独立子代理。候选为 11 个实现、测试、接口说明及 Rust 探针文件的 SHA-256 清单聚合（JSON key 排序、紧凑编码）；本报告本身作为审查元数据不包含在指纹中。

候选指纹：38e70ca4d5f329941a79591272e9f3f3e9e79dfc1db42a29ba86bd633084edfd

## Standards

**PASS，0 项未解决发现。** 依据现有 Rust 风格、README 测试要求，以及流程规定的代码异味和 AI slop 基线；仓库未提供 CONTEXT、ADR、专门编码规范或相关 docs/memory 约定。检查全部修复 diff 和新地址测试，未发现残留调试日志、未使用的限速抽象、持锁等待、无依据的错误吞并或新增绕过输入检查的解析路径。

反证尝试：保留 String 显示值可能使不同非法主机折叠并再次被解析，新增字段也可能造成重复状态。证据核查：raw_fqdn 是协议字节的优先来源，host_bytes 用于两种地址编码和请求长度；所有四个系统解析入口使用 host，非法 UTF-8 明确报错。公共字段优先级和外部结构体字面量兼容要求已写入接口说明。Clippy 两套全目标均通过；本地锁仅保护同步额度更新，等待在锁外。

## Spec

**PASS，0 项未解决发现。** 需求为修复本轮审计确认的 F1/F2/F3/F4，保持正常 Snell 互操作及已有用户改动，保留 C1 的 Rust EOF 适配。真实 Node 测试覆盖启用限速时的双向完整内容、独立回复、两个连接共用用户状态和精确计费；地址测试覆盖原始字节、255 字节长度及 scope。双向 Go/Rust 互操作和原始探针均通过，既有 panel 改动未被编辑。

反证尝试：仅修复上传、下载只是回显上传结果，或并发连接各获得完整独立预算，会造成测试假阳性。证据核查：TCP/UDP 目标都发送与上传独立生成的固定回复，分别比较两个方向；TCP 每个模式并发两连接；额外预算检查约束共享总速率，且计费断言要求精确总量。协议地址重编码与系统拨号失败类型分别验证，没有以显示字符串作为字节保留证据。

最终结论：Standards 0 项、Spec 0 项；两轴均 PASS。保留限制与验证范围见上文。
