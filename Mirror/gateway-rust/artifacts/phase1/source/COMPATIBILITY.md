# v3 兼容矩阵：本批未完整通过

旧 101 项与新增契约分开验收。下列计数存在重叠，不可相加为产品覆盖率。
四角色已更新为同一最终 Linux x86-64 候选；原版和旧证据不变。

| 契约/制品 | 比较量 | 一致 | 差异 |
|---|---:|---:|---:|
| core/candidate | 101 | 101 | 0 |
| core/rollback | 101 | 101 | 0 |
| headers/candidate | 86 | 86 | 0 |
| headers/candidate/audit | 85 | wire integrity | 0 |
| headers/rollback | 86 | 86 | 0 |
| headers/rollback/audit | 85 | wire integrity | 0 |
| management/candidate | 283 | 278 | 5 |
| management/candidate/audit | 47 | 32 | 15 |
| management/rollback | 283 | 283 | 0 |
| management/rollback/audit | 47 | 47 | 0 |
| proxy/candidate | 68 | 66 | 2 |
| proxy/candidate/audit | 75 | 71 | 4 |
| proxy/rollback | 68 | 68 | 0 |
| proxy/rollback/audit | 75 | 75 | 0 |
| backup/candidate | 84 | 84 | 0 |
| backup/rollback | 84 | 84 | 0 |

## 判定与边界

BASELINE 使用已记录原版结果，MODIFIED 与 ROLLBACK 使用完全相同脚本哈希、独立 QEMU 无网卡实例、合成数据和本地模拟上游。
回滚逐套实际执行 ROLLBACK.sh、验证恢复 SHA-256，再执行同输入。它只恢复程序，不处理数据库。
61 个 Rust 测试、Clippy -D warnings、locked/offline Linux musl 构建已通过。强制防御性审查见 DEFENSIVE_REVIEW.md。
响应 JSON 按结构比较，HTTP Date/随机令牌使用原有校验规则；未新增随机字段忽略规则。
Header 压缩审计绑定原始字节长度、摘要、gzip 校验和及解码正文，不要求不同编码器输出相同 DEFLATE 字节。
管理 DB 审计验证签发令牌与持久化摘要、认证解密、明示时间列；ID 偏移未归为随机性。备份另比恢复前后八表与输入。
历史子代理 contract.md 是当时的移交笔记，不代表当前实现；本文件与 STATUS.json、delivery 报告为最新判定。

## 未完成/显式差异

- 审核 provider 成功请求/校准协议未获原版 TLS 观测；5 个扩展响应用例保留显式 503 门禁差异
- 管理非空数据库 gateway_sessions 自增 ID 偏移与上游调用序列仍有差异，未忽略 ID
- auth/session 上游 accounts/check + me 刷新链未对齐
- Connection 命名头按安全要求过滤，与原版泄漏行为显式不同
- 两个未知 chat 探针路径继续 503；不为通过测试整体开放聊天路由
- login extra_cookies 字符串/缺失/错误类型的严格原版提取契约仍需完善
- 完整 SSE/WebSocket、指纹传输、MCP/Skills 请求侧与限额、会话/项目读写隔离独立门禁
- Docker 未验证；真实账号/真实上游/浏览器联调未批准，本次未运行

## 证据

- evidence/delivery-v3-runs.json：每个进程实际退出状态，比较有差异时 exit 1。
- 备份首轮端口占用失败保留在 delivery；调整监听端口后的最终三方证据为 backup-v3-original-014、backup-v3-{candidate,rollback}-delivery-2 及对应 compare-command。
- evidence/*-v3-{candidate,rollback}-delivery{-diff,-audit}.json：最终比较及差异原值。
- evidence/*-delivery/command.json、serial.log、results.json：执行、原始输出和数据库/上游记录。
- artifacts/VERIFICATION.txt：原版/候选/回滚 literal 命令与输出、退出、哈希。
- evidence/verification-before-v3.txt：上一轮 ledger 原样保留。
