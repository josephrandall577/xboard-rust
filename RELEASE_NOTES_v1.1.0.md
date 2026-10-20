# xboard-snell v1.1.0

首个同时支持多面板节点和多出口 IP 的正式版本。

- 一个进程可管理多个相互隔离的 Xboard 节点；每个节点独立监听 IP/端口、PSK、面板节点 ID、用户、速率/设备限制、SQLite 计费库和管理 API。
- TCP 与 UDP 出站绑定对应节点的监听 IP；绑定失败或地址族不匹配时不回退到默认出口。
- 保留旧版单节点配置格式。省略 [storage] 的旧配置会在新默认数据库不存在时继续使用已有 snell-xboard-node.db；显式数据库路径不变。新增 config.multi-node.example.toml 配置示例，并包含在所有平台压缩包中。
- 统一软件包、库、二进制、用户代理和配置命名为 `xboard-snell`。
- 修复限速 TCP 数据丢失、UDP 数据报截断、非法 UTF-8 地址替换及 IPv6 zone 丢失。
- GitHub Actions 发布 Release 时构建 Linux、macOS、Windows 的 x86_64 与 ARM64 二进制，运行解压后的启动/配置检查，并将压缩包和 `SHA256SUMS` 附加到该 Release。

Linux 二进制使用静态 musl；Windows 静态链接 MSVC 运行库。macOS 二进制未进行 Apple 签名。

升级现有节点可继续使用原单节点 TOML。多节点部署请从示例复制并配置每个节点已分配的本机 IP、唯一管理端口和各自的面板凭证；不要同时配置旧版 `[node]`/`[panel]` 与 `[[nodes]]`。

验证：节点测试、地址与互操作测试、Linux/macOS/Windows CI、六平台 Release 构建。
