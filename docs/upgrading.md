# 升级到 xboard-snell v2

v2.0.1 沿用 v2.0.0 的每用户独立 PSK 认证方式。v2.0.0 用户可保留配置和数据库升级；
若管理 API 监听非回环地址，必须设置非空白令牌，否则启动会被拒绝。

## 从 v1 或 standalone 迁移

1. 备份节点 TOML 和 SQLite 数据库，保留数据库及待上报流量。
2. 在面板订阅模板中将客户端 `psk` 改为当前用户的 `uuid` 原始字符串。
   UUID 必须唯一且为 12–255 字节；不做哈希、Base64 或额外派生，不发送 userkey/client_id。
3. 仅使用 Snell v6、`mode = "default"`；`unshaped` 和 `unsafe-raw` 不再支持。
   旧 `[node].psk` / `[[nodes]].psk` 可以保留，但不会授予连接权限。
4. 单节点必须配置 `[panel]`；每个 `[[nodes]]` 必须配置自己的面板。
   删除 `[[node.users]]`。用户、权限及配额在面板管理，本地 API 只读。
5. 替换二进制并重启，等待首次成功的完整用户同步，再刷新客户端订阅。
   数据库缓存由面板快照替换，已有流量和待报数据保留。
6. 使用两个用户分别验证 TCP/UDP 转发及面板计费。真实 Surge 验证步骤见
   [独立 PSK 验证](multi-psk-validation.md)。

```ini
MySnell = snell, node.example.com, 6160, psk=YOUR_PANEL_USER_UUID, version=6
```

旧版与 v2 不能在同一监听端口上同时接受两套凭据方案。需要并行迁移时，
使用不同节点 ID 和独立监听端点，并下发对应订阅。
面板对接字段及同步边界见 [XBoard 对接指南](xboard-v2-update-guide.md)。

## 部署注意事项

- 使用 HTTPS/WSS 连接远端面板。HTTP/WS 仅保留兼容性并告警，仍会明文传输令牌和用户 PSK。
- 握手默认限制每节点 256 个并发、每 IP 32 个并发、10 秒绝对超时。
  共享 NAT 可调整 `max_handshakes_per_ip`；详见验证文档和配置示例。
- 新用户集出现 PSK 指纹歧义时会整体拒绝，并保留旧凭据。重新生成新增或修改用户的 UUID 后重试。
- 报告采用至少一次交付；面板接收后响应丢失，重试仍可能重复计费。

历史变更保留在 [GitHub Releases](https://github.com/josephrandall577/xboard-snell/releases)。
