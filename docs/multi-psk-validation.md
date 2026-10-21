# 单端口独立 PSK 验证

节点使用面板用户 UUID 作为该用户的 PSK，只接受 Snell v6 default shaped 模式。
指纹负责选择凭据；只有首记录 AEAD 验证成功后才能确定身份。请求中的
client_id 无法改变认证用户或计费用户。每个入站首记录只对选定 PSK 派生一次密钥。

## 首包读取与约束

- 先读 32 字节，再按 16 字节步进，最多读取 144 字节。
- 每一步检查新覆盖到的全部实际块长度。Profile 的块长度并不限定为 16 的倍数。
- 指纹保留所有固定字节，恰好忽略 16 个 salt 位置，至少比较 16 个固定字节。
- 最多多读 15 字节，通过 PrefixedConn 回灌；ShapedReader 从 salt 已消费状态开始。
- PSK 唯一且为 12–255 字节；非法更新保持原凭据集。空用户集撤销所有凭据。
- 有界重放缓存按 PSK 隔离，只写入通过 AEAD 验证的 salt；用户更新不清空缓存。
  缓存不持久化，重启或容量轮换后不再保留旧的重放记录。

不能仅凭“比较了 16 个固定字节”保证真实 Profile 之间的误匹配率为 2⁻¹²⁸：
shaped 填充并非均匀随机。误选凭据仍必须通过 AEAD 验证，失败时关闭连接，
不会回退到 client_id 认证或逐个候选 PSK 试解密。

## 已执行验证

- 1000 个 Profile 的长度、固定字节及 salt 通配位置。
- 分片首包、32+16 字节读取步进、非对齐块长度及多读字节回灌。
- 空 client_id、伪造 client_id、未知 PSK、篡改首记录和截断首包。
- 重放拒绝、无效 AEAD 不污染重放缓存、缓存按用户隔离。
- 密钥轮换、清空用户及同一 TCP 连接复用后的凭据撤销。
- 真实本地节点 TCP/UDP 转发、限速及按 PSK 所属用户计费。
- 独立 Go 参考客户端的 TCP/UDP 与精确面板流量报告。

2026-10-21，Apple M4 / macOS arm64，release 单次本机测量：

| 项目 | 结果 |
| --- | --- |
| 注册 1000 个 Profile 与指纹 | 6.042 ms |
| 1000 用户完整指纹扫描 | 2.338 µs |
| 单次 Argon2id 派生 | 23.131 µs |

扫描测量针对已缓冲字节，排除网络 I/O；数值不是部署环境的延迟保证。
可重复运行：

```sh
cargo test --manifest-path snell/Cargo.toml --locked --release --lib benchmark_1000_user_psk_selection -- --ignored --nocapture
```

## 上线前尚待完成：真实 Surge

当前环境未检测到已安装或运行的 Surge，本次没有完成真实 Surge 抓包验证。
Rust/Go 参考客户端通过不能代替这项验证。

1. 在隔离测试节点上，使用目标 Surge 版本和两个不同用户的 PSK 分别发起实际 TCP/UDP 请求。
2. 抓取并重组客户端到服务端的 TCP 字节流，从首个应用数据字节开始导出原始二进制；
   不包含 pcap、以太网、IP 或 TCP 头，不能只截取某个 TCP 分片。
3. 将对应 PSK 的原始字节存到私有文件，文件末尾不要添加换行。运行下方离线验证入口。
   它核对固定字节、提取 salt、验证首记录 AEAD，并确认请求未声明 client_id，不转发流量。
4. 验证双向载荷完整性和面板分用户计费；记录 Surge 平台、完整版本及 default 模式。

```sh
SNELL_CAPTURE_FILE=/private/path/client-stream.bin \
SNELL_PSK_FILE=/private/path/user-psk.bin \
  cargo test --manifest-path snell/Cargo.toml --locked --lib verify_external_surge_hello -- --ignored --nocapture
```

该入口默认跳过；尚无真实样本运行记录。请勿把真实 PSK 或可重放的生产抓包提交到仓库。
