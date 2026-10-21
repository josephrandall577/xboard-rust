# xboard-snell v2.0.0

正式版：单端口、每用户独立 PSK 的 Snell v6 节点，面向不发送 userkey/client_id 的 Surge 客户端。

## 不兼容变更与迁移

- 每个客户端的 `psk` 改为该用户在 XBoard 的 `uuid`，不再使用共享服务器 PSK 或单独的 userkey。PSK 必须唯一且为 12–255 字节。
- 仅支持 Snell v6 `default` shaped 模式。`unshaped` 与 `unsafe-raw` 配置会被拒绝。
- 旧配置中的 `[node].psk` / `[[nodes]].psk` 可保留但不参与认证；它们不会授予连接权限。面板的 Surge 订阅模板也必须改为输出用户 UUID 作为 PSK。
- 只支持面板管理用户。单节点必须有 `[panel]`；每个多节点定义必须配置自己的面板。移除 `[[node.users]]`；本地管理 API 只读。
- 保留已有 SQLite 数据库和待上报流量。先备份配置与数据库，再替换二进制、更新客户端/订阅并重启服务。旧版发布包仍使用旧认证方式。

Surge 配置示例：

```ini
MySnell = snell, node.example.com, 6160, psk=YOUR_PANEL_USER_UUID, version=6
```

## 认证与隔离

- 启动及用户同步时预计算 PSK 派生的 Profile 和 salt-block 指纹；未变化的凭据复用已有预计算结果。
- 首包先读 32 字节，再以 16 字节步进，最多读取 144 字节。检查新覆盖到的所有实际块长度，忽略恰好 16 个随机 salt 位置，并回灌多读的记录字节。
- 只为命中的 PSK 派生入站密钥，首记录 AEAD 验证成功后才确定用户；不逐个候选试解密。伪造 client_id 不会改变认证或计费用户。
- 增加按 PSK 隔离的有界 v6 salt 重放缓存，仅记录已验证首包；用户同步不清空缓存。缓存不持久化，重启或容量轮换后失去对应旧记录的保护。
- 凭据更新原子替换；非法用户集保留已有有效用户集；空用户集可撤销全部凭据。复用连接上的后续逻辑请求重新检查凭据是否有效。

## 其他改动

- 协议库对齐 snell-in-rust v1.1.2（55002dca55eea45b2774e19e0d8d05d1c590398c），保留本仓库的原始域名字节与 IPv6 scope 修复，合入缓冲池及 TCP/v6 热路径优化。
- 保留 XBoard V1/V2、流量计费、限速、设备数及配额限制、多节点独立出口与状态隔离。
- Linux 安装脚本、systemd 服务及公开下载站支持随正式发布包分发；安装脚本为兼容旧版仍生成 legacy PSK，v2 客户端应使用用户 UUID。

## 验证与已知限制

- 已通过 Rust 认证/回环/节点端到端测试、独立 Go 客户端 TCP/UDP 与精确分用户计费、Go/Rust 双向互操作、Clippy、安装脚本和下载站测试。
- Apple M4 / macOS arm64 的 release 单次测量：1000 用户 Profile/指纹注册 6.042 ms，完整指纹扫描 2.338 µs，单次 Argon2id 派生 23.131 µs。扫描不含网络 I/O，数值不是部署性能保证。
- **真实 Surge 抓首包与端到端验证尚未完成。** 当前兼容性证据来自 Rust 和 Go 参考客户端。上线前须用实际 Surge 版本验证首包、TCP/UDP 及分用户计费；包内附离线首包验证步骤。
- 指纹只用于选择凭据；未将 2⁻¹²⁸ 作为已经证明的真实 Profile 碰撞率保证，身份认证依赖 AEAD。
- 面板报告采用至少一次交付：面板已接收但响应丢失时重试可能重复计费。WebSocket 增量用户事件由轮询补齐；路由、自定义出站及证书配置不应用。

发布包提供 Linux、macOS、Windows 的 x86_64 与 ARM64，共六个平台及 SHA256SUMS。Linux 使用 musl，Windows 静态链接 MSVC 运行库，macOS 二进制未签名。
