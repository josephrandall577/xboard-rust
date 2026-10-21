# 2026-10-21 代码变动审计

初次结论：**REWORK**。今日变更确认 3 项缺陷（P1 × 1、P2 × 2）；相邻调用链另确认 1 项基线已有的 P1 计费缺陷。以下保留初次审计证据，行号对应初始候选。用户随后授权全部修复；最终结果见[修复复核](2026-10-21-fix-review.md)，四项均已修复，Standards / Spec 均 PASS。

## 范围、候选与依据

- 时区：北京时间；今天为 2026-10-21。
- 路线：Matt Pocock `code-review` standalone capability；直接执行 Standards / Spec 两轴审查。
- 提交基线：`5ee06f534ef9ef3dc38f4d952b545169a8cbc112`。
- 今日唯一提交 / 候选 HEAD：`9b08a39c8e3d1467572043a8cfdafaa2a56130ad`，20 个文件，677 行新增 / 110 行删除。
- 同时审查开始时已有的 `src/panel.rs` 未提交改动：将面板的 null 限速 / 设备限制映射为 0。该文件 SHA-256：`7e1c7f98f0ad993b85da3ffa33279c82796aa465bc657ef0382d07f8ef723ece`。
- 仓库未发现 AGENTS.md、CLAUDE.md、CONTRIBUTING.md、CODING_STANDARDS.md 或 docs/memory/；Standards 使用能力规定的 smell / AI slop 基线，不把 Clippy 已覆盖的问题重复列为人工发现。
- 未提供原始 issue / PRD；Spec 依据本次提交的 [README](../../README.md#multiple-panel-nodes)、[发布说明](../../RELEASE_NOTES_v1.1.0.md)、[多节点交付说明](sing-snell-behavior.md#v110-多节点交付补充) 中明确写出的行为承诺，不声称覆盖未记录的需求。
- 阅读完整变更，向下追踪 Config → Node → SnellServer → RelayHandler，以及管理 API、用户同步、计费和停止流程；审查重命名、打包及 Release workflow 的调用一致性。

## Standards

**PASS；发现 0 项。** 未发现需独立列出的规范违反或 smell / AI slop 判断项。该结论只针对编码规范轴，安全和运行行为见 Spec。

反证尝试：派生数据库文件名可能允许目录穿越，或在大小写不敏感的文件系统上覆盖另一节点。确认失败所需的证据是节点名可包含路径分隔符，或大小写变体同时通过检查。相反证据：[config.rs:413](../../src/config.rs#L413) 将名字限制为 ASCII 字母、数字、横线和下划线，并按 ASCII 小写去重；[config.rs:465](../../src/config.rs#L465) 用 with_file_name 派生名字。现有测试也拒绝 EDGE-A / edge-a 重名。因此这项反证被排除，Standards 保持 PASS。

## Spec

**REWORK；今日变更发现 3 项。**

### F1 · P1：IPv4-mapped IPv6 可绕过禁止通配 IP 和独立 IP 校验

位置：[src/config.rs:421](../../src/config.rs#L421)，相关出口路径 [src/relay.rs:218](../../src/relay.rs#L218)。

契约：README 要求 “a distinct, specific local IP address (not a wildcard)”；发布说明要求绑定失败时不回退默认出口。

校验直接对原始 IpAddr 调用 is_unspecified / HashSet 去重。`::ffff:0.0.0.0` 被视为非通配 IPv6；`127.0.0.1` 与 `::ffff:127.0.0.1` 也被视为不同 IP。本机真实 Node 接受前一种配置，实际 listener 为 `[::]:随机端口`，可经 IPv4 连接。请求 mapped IPv4 目标时 TCP 成功到达目标，源地址由系统选为 127.0.0.1，破坏显式绑定特定源 IP 的约束。

触发前提是部署配置使用这些 mapped 地址。建议拒绝 mapped 形式，或在监听、去重和出口建立前统一规范化；补充 mapped wildcard / 同 IP 别名回归。

### F2 · P2：管理端口冲突检测依赖节点顺序，且忽略通配监听覆盖

位置：[src/config.rs:430](../../src/config.rs#L430)。

契约：README 要求 “unique management API listen address”；交付说明承诺拒绝重复管理 socket。

检查只将当前 admin 与此前出现的 Snell listener 比较。若第一个节点的 admin 等于后续节点的 Snell listener，配置通过；颠倒节点顺序则报 DuplicateAdminListen。`0.0.0.0:P` 与 `127.0.0.1:P` 也通过精确 SocketAddr 去重，却争用实际端口。运行结果取决于绑定先后，可出现启动回滚或管理 API 退出。

相邻的既有行为会放大问题：管理 API 在后台绑定，端口占用只记日志，Node::start_many 仍返回 Ok。建议先收集全部 listener，再做与顺序无关的覆盖冲突检查，并在成功启动前确认管理端口已绑定。

### F3 · P2：绑定出口后的 TCP 拨号丢失同地址族的 DNS 备选地址重试

位置：[src/relay.rs:245](../../src/relay.rs#L245)，调用方 [src/relay.rs:218](../../src/relay.rs#L218)。

行为契约：TCP 应使用相应节点 IP 连接目标；原实现的 TcpStream::connect(host, port) 会在地址失败时继续尝试解析结果。

新增 resolve_destination 用 find 取出第一个匹配地址族的结果，之后只 connect 一次。目标域名有两个 IPv4 地址、首地址拒绝连接而第二地址可用时，旧拨号成功，真实多节点转发失败，客户端收到 Remote EOF。尝试其他同族地址仍可保持源 IP 绑定。建议遍历匹配地址，每次新建并绑定 socket，所有候选失败后再返回错误。

## 相邻调用链发现：基线已有，未计入今日 3 项

### B1 · P1：停止节点先清空 pending，导致最后一段流量漏报面板

位置：[src/node.rs:229](../../src/node.rs#L229)，相关函数 [src/node.rs:481](../../src/node.rs#L481)。

shutdown 先调用 floor_flush；后者 take_pending 将流量写入本地 SQLite 并清空。随后 collect_traffic 再取 pending，通常已为空，因此跳过最终面板报告。下次启动也没有持久化的待上报队列重试这部分流量。

实测：准备用户并记录 123 字节待上报上传量，保持周期上报间隔为 3600 秒，然后立即停止。结果是本地 upload=123、面板 report 次数=0、remaining_pending=0。由此确认正常停止也会造成面板计费少报。

已用 `git show 5ee06f5:src/node.rs` 确认相同调用顺序已存在于基线；今日将它用于多个节点，但没有引入该根因。修复时需要让本地持久化与面板投递共用同一批 delta，并保留发送失败时可重试的状态；也需验证停止与周期上报并发。

## 验证与反证边界

| 检查 | 结果与范围 |
| --- | --- |
| `cargo test --locked` | 46 项通过：unit 31、e2e 10、panel 4、WebSocket 1 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| `cargo test --manifest-path snell/Cargo.toml --locked --lib --test address --test loopback` | 35 项通过：unit 7、address 5、loopback 23 |
| 真 Node 的 mapped 地址探针 | 非法配置通过；通配 listener 和 TCP 默认选源已复现；UDP mapped 目标超时，没有把 UDP 算作已证明的出口泄漏 |
| 管理端口探针 | 前向冲突 / 反序不一致 / wildcard 重叠均复现；占用管理端口时返回 Ok 且记录绑定错误 |
| DNS 失败探针 | 控制两个 IPv4 解析结果和首地址 ECONNREFUSED；原拨号成功，多节点转发失败 |
| 未提交 null 兼容改动 | 经真实 HTTP PanelClient seam：省略 / null → 0，整数保留，非法字符串拒绝 |
| 第二节点 Snell 端口被占用 | start_many 返回 Err；第一节点 listener 随后可重新绑定，回滚探针通过 |
| 停止计费探针 | 本地 123 字节，面板报告 0 次，pending 清空 |
| `git diff --check` / 候选一致性 | 通过；产品代码未修改，panel.rs 指纹与审计起点一致 |

现有新增 e2e 只使用 127.0.0.1 / ::1 字面目标、禁用管理 API，并手动装载用户；因此它通过不能排除 F1 / F2 / F3。独立数据库、注册表以及正常 IP 出口的现有测试通过，不能扩大为全地址输入的隔离证明。

复现环境为本机 ARM64 macOS，依赖沿用根 Cargo.lock（Tokio 1.53.3）。未在此次执行 Linux / Windows 实机、六平台 Release 构建或 Go 双向互操作；没有将历史 CI 或此次未执行的路径列为通过。F1 的 OS 绑定表现只对已运行平台作证。

额外观察：不同 token 的相同面板 URL / node_id 会通过 panel_identity 去重。尚未验证实际 Xboard 部署能否同时接受这两份凭证，因此没有将它列为独立的串账漏洞。

## 复现程序

源码：[2026-10-21-probes](2026-10-21-probes/)。它是输出事实的审计探针，不是已接入 CI 的回归测试；不改产品代码，不修改系统 hosts / DNS，不联系真实面板。

在仓库根目录运行：

~~~sh
# 沿用项目锁定的依赖；首次运行仅补充探针自身的锁文件条目。
cp Cargo.lock docs/audits/2026-10-21-probes/Cargo.lock
cargo run --offline \
  --manifest-path docs/audits/2026-10-21-probes/Cargo.toml \
  --target-dir target

# macOS 专用：仅对子进程替换合成域名解析与一个地址的 connect 失败。
# audit-two.invalid → 127.0.0.2（强制拒绝）/ 127.0.0.1（真实 TCP 目标）。
audit_tmp=$(mktemp -d /tmp/xboard-snell-resolver.XXXXXX)
clang -dynamiclib -o "$audit_tmp/resolver.dylib" \
  docs/audits/2026-10-21-probes/resolver.c
DYLD_INSERT_LIBRARIES="$audit_tmp/resolver.dylib" \
  target/debug/xboard-snell-audit --dns
~~~

关键输出（省略随机端口和日志时间）：

~~~text
admin_conflicts_future_listener: Ok(())
same_config_reversed: Err(DuplicateAdminListen(...))
wildcard_admin_overlap: Ok(())
mapped_duplicate_ip: Ok(())
mapped_wildcard_ip: Ok(())
mapped_wildcard_actual_listener: [::]:...
mapped_wildcard_tcp_egress: source=127.0.0.1:... payload=[112, 105, 110, 103]
occupied_admin_start_many: returned Ok with 1 nodes
panel_limits_missing: speed=0 devices=0
panel_limits_null: speed=0 devices=0
panel_limits_numeric: speed=12 devices=3
panel_limits_invalid_type: rejected
second_node_listener_occupied: returned_error=true
first_node_listener_released: true
shutdown_pending_upload: local=123 panel_reports=0 remaining_pending=0
legacy_tcpstream_connect: success
managed_dns_target_reached: false; client_read: ... Remote EOF
~~~

两轴合计：Standards 0 项，最严重项无；Spec 3 项，最严重为 F1 / P1。另列基线已有 B1 / P1，不混入今日变更计数。最终判定 REWORK。
