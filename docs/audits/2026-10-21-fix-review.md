# 2026-10-21 修复复核

结论：**Standards PASS / Spec PASS**。F1、F2、F3 和 B1 均已修复；原始失败证据保留在[初次审计](2026-10-21-code-review.md)。

## 复核对象与需求

- 工作流：Matt Pocock hard-bug → implement → code-review；直接执行两轴复核。
- 基线：9b08a39c8e3d1467572043a8cfdafaa2a56130ad。
- 用户授权：“都修复吧”，即初次报告确认的 3 项新增缺陷和 1 项既有计费缺陷。
- 候选 SHA-256：57b9e83ef623c5432a91eb527c790f4846d9c72b831e0c20005287e9f39da511。
- [候选清单](2026-10-21-fix-candidate.json) 包含产品代码、依赖锁、README、新增测试和复现探针的逐文件指纹。已逐项校验，无需创建提交来固定候选。
- 开始时已有的 panel.rs 空值兼容改动原样保留，SHA-256 仍为 7e1c7f98f0ad993b85da3ffa33279c82796aa465bc657ef0382d07f8ef723ece。
- 未确认的面板重复凭证观察仍不作为已证明的漏洞或已修复项目。

需求和场景通过 [node_lifecycle.rs](../../tests/node_lifecycle.rs)、[traffic_store.rs](../../tests/traffic_store.rs) 的测试函数表达；DNS 原始调用链另由合成解析探针验证，不修改系统 DNS / hosts。

## 已保留的红绿证据

首次新增的 6 项 node_lifecycle 测试在修复前全部失败，分别命中 mapped 地址、端点顺序、wildcard 覆盖、管理端口错误传播、最终报告缺失、重启后待上报流量丢失。

DNS 探针在修复前以“bound TCP must try the second DNS address”断言失败；地址列表为 127.0.0.2 / 127.0.0.1，第一个 connect 被固定为 ECONNREFUSED。修复后第二地址完成 ping 的真实回传，client_read 为 Ok(Ok(4))。

追加测试发现了修复过程需要同时处理的三个生命周期条件：持久化后 live quota 仍应显示 123 字节；停止返回时 active relay 应为 0；管理端口应能立即重新绑定。这三项各自观察过预期断言失败，随后通过。周期报告与最终报告并发的测试也通过，独立批次分别为 [111,0] 和 [0,22]。

这些测试均在本机临时数据库和本地 socket 上执行；未使用真实面板或生产数据。

## 修复内容

| 项目 | 最终行为 | 主要证据 |
| --- | --- | --- |
| F1 | managed node 拒绝全部 IPv4-mapped IPv6 listen IP；通配地址和 IP 别名不再绕过去重 | mapped 三种输入的配置回归；真实 Node 启动拒绝探针 |
| F2 | 收集全部端点后检测重叠，顺序无关；识别 IPv4 wildcard、IPv6 wildcard 和 mapped admin 别名；启用的 admin 在启动成功前完成绑定 | 正反顺序、wildcard、占用端口、启动立即 health 请求与停止立即重绑定 |
| F3 | TCP 逐个尝试同族解析结果，每次新建并绑定相同本地 IP；不匹配的地址族不被使用 | 两项真实 socket 拨号测试；合成 DNS 的完整 Node / Snell 客户端回传 |
| B1 | 本地累计量与待上报 delta 在 SQLite 同一事务提交；确认成功后仅移除已交付批次，失败跨重启保留 | V1/V2 最终报告；重复 shutdown；失败重启；并发报告；事务回滚与重新打开数据库 |

停止先取消并等待 listener、handshake、TCP/UDP relay，随后串行执行最终报告；最终返回前也等待后台任务退出。UDP 两个方向位于同一受跟踪任务中，取消不会遗留独立 downlink。

Registry 持久化 pending 与更新自身的已落库用量在同一把锁内完成，持久化失败恢复 pending；因此将流量写入待上报表不会暂时清空配额检查中的用量。SQLite 新表用 CREATE TABLE IF NOT EXISTS 创建，不重写已有 users 数据。

## Standards

**PASS；发现 0 项。**

规范来源与初次审计相同：仓库没有独立规范 / pitfall memory 文件；使用工作流的 smell / AI slop 基线。新增逻辑围绕配置验证、连接生命周期、持久化和报告各自集中；没有新增 unsafe、错误抑制或内部 mock。根 Clippy 全目标 -D warnings 已通过。

最强反证：持久化队列若将未经验证的 u64 / i64 互转，会让异常值变成负数，违反账务不变量。确认失败的证据应为直接截断写入或可被过量 ack 扣成负值。相反证据：新写入和 ack 使用 i64::try_from；表约束限定非负整数；读取转换明确依赖该约束；invalid_batch 和 over-ack 测试确认整批回滚。故此反证被排除，Standards 保持 PASS。

## Spec

**PASS；发现 0 项。**

F1/F2/F3/B1 的确切触发场景和相邻生命周期场景均有通过的执行证据。没有将初次仅凭正常路径通过的测试扩大为“所有输入安全”。panel.rs 未被改写，省略 / null / 数字 / 非法类型仍分别映射到 0 / 0 / 原值 / 解码错误。

最强反证：正常停止测试可能掩盖周期请求尚在飞行、面板失败后重启，或 relay 在最终快照之后继续计量，造成漏报 / 本地重复累计。确认失败的证据应是重启后 accepted report 为空、local 总量翻倍、停止后 active 不为 0，或并发两批的总数不符。相反证据：11 项 Node 生命周期测试验证 V1/V2、重启重试、并发报告、重复停止、活跃 TCP/UDP、quota 和端口释放；3 项 Store 测试验证 ack 不删除后来新加的字节、重开数据库保留状态、错误整批回滚。原始审计探针也显示 local=123、panel_reports=1、remaining_pending=0。故此反证被排除，Spec 保持 PASS。

## 最终验证

| 命令 / 场景 | 结果 |
| --- | --- |
| cargo test --locked | 62 项通过：unit 33、e2e 10、node_lifecycle 11、panel 4、traffic_store 3、WebSocket 1 |
| cargo clippy --locked --all-targets -- -D warnings | 通过 |
| cargo test --manifest-path snell/Cargo.toml --locked --lib --test address --test loopback | 35 项通过；vendored 源码未修改 |
| 更新后的初次审计探针 | 地址 / 管理端口在启动前拒绝，失败启动回滚，null 兼容，最终报告断言均通过 |
| macOS 合成 DNS 探针 | 第二地址真实回传 ping，通过 |
| git diff --check / 候选逐文件 SHA-256 | 通过 |

共 97 项测试通过，新增 16 项回归。未在此次执行 Linux/Windows 实机、六平台 Release 构建或 Go 双向互操作。CI 将自动发现新增的两个根 integration test 文件；macOS DNS 拦截器是补充探针，根测试的拨号回归使用普通本地 socket。

## 限制与预防

面板协议没有幂等键，报告使用至少一次交付。如果面板已接收而响应丢失，或接收成功后本地 ack 写入失败，后续重试仍可能重复计费。该协议歧义与此次确认的“未发送即清空”不同；README 明确记录，测试没有声称能提供分布式 exactly-once。

根因是以原始 socket / IP 表示直接判断占用、DNS 只选一个结果，以及本地刷盘与面板发送各自 drain 同一组 pending。此前 e2e 禁用 admin、使用单个字面目标、并在停止前关闭连接，未覆盖这些生命周期。预防措施是把实际 Node 启停、故障恢复和真实 socket 结果作为 CI 的行为约束；本地累计与待交付状态在同一事务内维护。无需另建一套转发框架或扩大架构迁移。

两轴合计：Standards 0 项，最严重项无；Spec 0 项，最严重项无。最终判定 PASS。

## v1.1.1 发布准备

上述指纹固定了修复复核时的候选。随后发布准备仅调整根 Cargo.toml 与 Cargo.lock 的版本为 1.1.1，并新增 RELEASE_NOTES_v1.1.1.md；已核对其他候选文件指纹保持一致。版本调整后重新通过根 62 项测试、全目标 Clippy，以及本机 ARM64 macOS 的 Release 构建和压缩包解压后的 --version、两份配置 --check。跨平台 CI、互操作和六平台附件的发布证据以该版本的 GitHub Actions / Release 为准。
