# Mirror 第一批滚动并行集成门禁

本文件是协调补充，不替代 `gateway-rust/artifacts/phase1/STATUS.json`。

## 归属与稳定输入

- 唯一集成人：`01a0c9af-fab7-7780-af7f-537dde662636`；未交接。其确认记录为 `E:/M/Project/MiRebuild/Mirror/gateway-rust/artifacts/phase1/COORDINATION.json`。
- 三个独立 worktree 从提交 `b837ba2556bc3363570d247e61246e6b8f43421c` 导出候选子树，不用正在变化的源目录当快照。
- 默认 worktree HEAD `4c7b3fa6d8448b0d7410820c0679365083172b67` 是空基线，不是网关输入版本。
- 旧版 QEMU 二进制的合成协议观测、新 Rust 候选测试、真实账号验收分栏记录。历史 D 盘路径不是本轮可执行输入。

## 本轮决议

1. 既有负责人完成公共 JS/CSS 静态批次及主四角色；HTML 初始化与认证刷新仍由其负责。
2. ACL 线只提交独立 `src/resource_acl.rs` 与 `tests/coord_acl_contract.rs`。公共 lib、schema、初始化、依赖和路由仍由集成人处理；单模块测试通过不等于产品已接入 ACL。
3. 回归线只交付 `tests/coord_boundary_regression.rs`：closed-gate、任意目标覆盖、错误泄露与 session 隔离。不重复静态五项测试，不再运行旧版 QEMU，不让产品迁就测试。
4. 后台线本批只交付源码调用点、接口提案和独立失败语义测试。不实现第二份 ACL，也不将提案测试算作 Django/Vue 验收。
5. Identity v1：可信稳定 user_id 为规范十进制字符串；is_admin 来自实时核验的 staff OR superuser；authorization_version 为不透明字符串，对应现有 wire version。新增 principal_kind 明确普通用户与访客；共享 FREE_ACCOUNT user_id 不能成为访客资源归属键，新 ACL 暂拒 visitor。此限制不改变既有访客登录。
6. 服务密钥仅认证服务，管理员动作仍需真实操作者签名、当前角色及授权版本。用户、账号、资源 ID 的浏览器自报值均不能授予权限。

## 收件后依序执行

| 顺序 | 接收条件 | 执行与证据 | 不允许的结论 |
|---|---|---|---|
| 1 | 负责人静态批次稳定包、hash、检查点 | 固定副本重放独立边界回归；记录候选身份 | 不将旧配置测试当静态验收 |
| 2 | 回归差异、literal stdout/stderr、退出码及出口追踪 | 主代理抽查边界断言；交唯一负责人集成 | 不能只统计几个分支各自通过 |
| 3 | ACL 模块/API和测试、后台身份契约一致 | 抽查账号绑定、共享继承、撤权、访客与管理员边界；先独立集成不开放业务 | 不将模块存在当统一鉴权完成 |
| 4 | 已审查的集成文件清单 | 集成人在同一候选跑全体 Rust、Clippy、配置及边界回归，更新原四角色并追加证据 | 不整体覆盖文件解决冲突 |

## 仍未达到的发布条件

页面初始化数据隔离、刷新闭环、可信 Django 身份接线、全路径 ACL、后台页面、聊天/文件/图片/项目/研究/语音/连接器、版本化完整备份与三身份浏览器验收仍需按依赖推进。真实账号、外部写、生产切换、删除旧资源和重置 Django 用户未授权；这些暂停不阻塞离线开发。

历史配置同输入事务保持：BASELINE 退出1并拒绝 configured；MODIFIED 退出0并接受分离源；ROLLBACK 退出1并恢复拒绝，恢复包 SHA256 `bc0b14a57a4e1106ebf0fb5500831f8e659879cd3a6f8a2db466a7f28c8cb6c2`。新测试应追加，不覆盖或伪装为该历史。
