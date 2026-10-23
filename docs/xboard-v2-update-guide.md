# XBoard 对接指南

适用于 xboard-snell v2。本文描述节点的接口契约与面板验收要求，不表示面板改造或实际客户端联调已经完成。
从旧版升级见 [迁移指南](upgrading.md)。

## 凭据与订阅

- 同一端口支持每用户独立 PSK：`psk = user.uuid`、`version = 6`、`mode = default`。
  UUID 原样传递，唯一且为 12–255 字节；不使用共享服务器 PSK 或 userkey/client_id。
- 面板保存及订阅输出均应限制为 v6/default，并处理存量 unshaped/unsafe-raw 配置。
  面板同时服务其他后端时，按后端能力应用约束。
- 两个用户订阅可使用同一地址和端口，但必须输出各自 UUID；订阅缓存按用户隔离，UUID 轮换后失效。
- 其他客户端也遵循相同凭据规则；是否支持 Snell v6/default，须以实际客户端验证为准。

```ini
Snell = snell, node.example.com, 6160, psk=11111111-1111-4111-8111-111111111111, version=6
```

## HTTP 接口

新部署推荐 V2；V1 部署可继续使用 `api_version = 1`。
GET 通过 query、POST 通过 JSON body 传递 `token` 和 `node_id`；机器模式使用 `machine_id`。
远端连接使用 HTTPS，避免凭据明文传输。

| 方法 | V2 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/v2/server/handshake` | 握手；最小响应为 `{"websocket":{"enabled":false}}` |
| GET | `/api/v2/server/user` | 完整用户快照 |
| POST | `/api/v2/server/report` | 流量增量、存活、状态及指标 |
| GET | `/api/v2/server/config` | 客户端提供此方法；运行循环不自动拉取并应用 |

V1 使用 `/api/v1/server/UniProxy/{config,user,push,alive,status}`。
监听地址、模式、轮询周期由本地 TOML 决定，面板改配置后需同步调整节点并重启；
`sync.config` 不会热更新。路由、自定义出站及证书配置不应用。

## 用户快照

```json
{"users":[{"id":1001,"uuid":"11111111-1111-4111-8111-111111111111","speed_limit":100,"device_limit":2}]}
```

- `id` 为稳定整数，计费归属和本地流量累计均按 ID；UUID 轮换不重置累计流量。
- 同一快照内 ID 和 UUID 必须唯一；指纹歧义或非法字段导致整个快照被拒绝，旧凭据保留。
- `speed_limit` 单位 Mbps；`device_limit` 为来源 IP 数量。两者省略、null 或 0 表示不限。
- 无用户时返回 `{"users":[]}`，表示全部撤销。缺少 users、null、空响应体或错误响应表示同步失败。
  过滤集合后须重新索引，保证 users 是数组；不要包装为 `{"data":{"users":[]}}`。
- 保留面板的授权、封禁、到期及余额筛选；客户端不发送 If-None-Match，不应无条件返回 304。
- 节点另支持 `enabled`、`expired_at`、`transfer_enable`。
  `expired_at = 0` 为永不过期，`transfer_enable = 0` 为不限额。
  节点不从响应的 u/d 重建面板全局用量，增加 transfer_enable 不能实现跨节点实时统一配额。

## 流量与同步

V2 报告中的 `traffic` 示例：`{"1001":[1024,2048]}`。
数组依次为上传、下载字节增量，上传指客户端到目标，下载指目标到客户端。
V1 push 将此映射放在顶层；V2 另有 alive、online、status、metrics 字段。
空闲节点也报告状态，V1 流量请求失败不阻断存活与状态请求。

按认证 PSK 对应的用户 ID 计费，继续使用面板原有倍率与计费链路，避免额外重复入账。
删除用户后，其已产生的待报流量仍须接收。报告采用至少一次交付，无幂等 ID；
响应丢失后重试可能重复计费，不能仅按字节数相同去重。

WebSocket 使用 WSS，在本地 `[panel].ws_url` 显式配置；握手返回的 URL 不会自动启用连接。
完整事件格式为：

```json
{"event":"sync.users","data":{"users":[{"id":1001,"uuid":"11111111-1111-4111-8111-111111111111"}]}}
```

清空时发送 `data.users=[]`；HTTP 与 WebSocket 使用相同授权和凭据逻辑。
只即时应用 `sync.users`，增量事件由下一次轮询补齐。
撤销或轮换后旧 PSK 的新连接和复用连接的后续逻辑请求被拒绝；已建立的转发流不会全部立即切断。

## 验收

1. 保存和订阅输出只接受目标后端支持的 v6/default；旧配置完成迁移。
2. 两用户订阅使用各自 UUID，缓存命中、刷新及 UUID 轮换均不串用凭据。
3. HTTP/WebSocket 完整快照、空快照和非法快照行为一致；无权限用户不下发。
4. 两用户 TCP/UDP 载荷分别计费，方向和倍率正确；报告失败重试不会重置本地流量。
5. 使用实际 Surge 版本完成首包、双向转发和计费验证，记录版本与平台。
   当前项目尚未完成此项，步骤见 [独立 PSK 验证](multi-psk-validation.md)。
