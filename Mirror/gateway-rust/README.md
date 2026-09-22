# Mirror Rust gateway — offline candidate, NOT a completed replacement

独立 Rust 工程，当前交付是可编译、可运行、可回滚的开发候选，**不是原版行为等价验收通过的网关**。
原版及已有 Mirror 工程未改动。不可部署到真实账号环境；真实上游传输被数字回环地址白名单明确阻止。

## 已实现与边界

- Axum/Tokio 服务、管理密钥认证、原版八表存储、AES-256-GCM 原版密文格式。
- 完整 v2 备份导出，HTTP legacy/v2 兼容恢复及提交前配置校验；迁移仍严格拒绝错误密钥、损坏记录和未知字段，只读源库到新库、重加密、旧会话失效。
- 独立 Mirror 签名授权适配：调用 Django 校验、每次认证请求重新核对版本和有效期、版本匹配撤销、重新登录保护。
- 登录交接、Cookie 轮换和退出清理；配置持久化、Django 回环代理（含查询串/响应流）。
- 纯模型与能力允许清单策略及回归测试；**MCP/Skills 请求侧协议、完整配额执行未接线**。
- 已开放 GET `/backend-api/me` 和 GET `/backend-api/conversations`，后者按共享账号内用户归属过滤并保留分页语义；其它聊天路径仍有明确门禁。完整隔离、SSE、WebSocket、指纹客户端尚未实现，不能宣称可正常聊天。
- 已接线六个管理端点，支持真实令牌轮换、访问计数、会话清理、审核配置持久化。审核 provider 成功协议尚未验证，明确返回未完成门禁。
- 响应头、多值 Vary、真实逐帧 gzip 压缩、代理 CSP/缓存及 HTML 客户端模板已对照原版；见 COMPATIBILITY.md 的响应、数据库、上游三个维度，不以旧 101 项通过替代完整验收。

## 开发与验证

Rust 工具链实测 1.97.1，依赖固定在 Cargo.lock。构建依赖下载与离线运行测试分离。

```powershell
cd D:\Project\Mirror\gateway-rust
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
```

Linux x86-64 musl 制品使用本工程 `.build/zig/ziglang` 中的 Zig 0.13.0 和 `.build/cargo-tools/bin` 中的 cargo-zigbuild 0.23.4 编译；这些是一次性构建环境，不纳入源码。
`artifacts/MODIFIED_FILE` 是静态 Linux ELF，不是 Windows exe。Dockerfile/compose.offline.yml 是断网候选打包配置；本机未执行 Docker 构建。

`tools/prepare_guest.py` 在新工程下复制并扩展已有 initramfs，绝不改原文件。`tools/oracle.py` 用 **QEMU -nic none** 建立独立 VM，通过串口传入观察脚本，数据与模拟上游全部位于 guest 回环网络。结束时只停止自己创建的 QEMU。

`tools/compare.py` 校验响应状态、正文、Header；时间戳作类型校验，密文实际解密比较，令牌摘要与签发 token 对应核验。`tools/audit_v3.py` 补充已记录的数据库投影、上游序列及 gzip 完整性审计，`tools/compare_backup_v3.py` 校验恢复前后状态。尚非全产品全量比较，所有未解释差异保留为失败。

## 配置

`GATEWAY_ADMIN_SECRET` 至少 16 字节；`CREDENTIAL_ENCRYPTION_KEY` 去除两端空白后至少 32 字节。
`DJANGO_UPSTREAM`、`CHATGPT_BASE_URL`、可选 `CF_BYPASS_URL` 只接受 `http://127.x.x.x` 或 `http://[::1]`，不接受域名、HTTPS 或外网地址。
`GATEWAY_COMPAT_PROFILE=mirror` 是默认值，必须传 Django 授权与策略字段；`original` 只用于原版契约观测，不自动降级到该模式。
`COOKIE_SECURE` 默认 true。局部合成 HTTP 测试可设 false；这不是公网部署配置。

## 迁移与回滚

仅操作停写后得到的原库一致性副本，目标文件必须不存在：

```text
SOURCE_CREDENTIAL_ENCRYPTION_KEY=<source-key>
CREDENTIAL_ENCRYPTION_KEY=<new-key>
mirror-gateway migrate SOURCE_COPY NEW_DATABASE
```

未知字段、错误密钥、损坏密文停止迁移；不会覆盖原文件或现有目标。源库需要包含原版已知列；不自动导入 Python 参考网关数据库。
实际生产迁移/切换未执行。成功切换需重新登录；切换后新增写入不自动回灌原库。

`artifacts/ROLLBACK.sh TARGET_COPY` 从同目录 `baseline.gateway` 恢复原版程序。它只回滚程序，不回滚数据库；生产数据回滚必须使用维护窗口前的一致性快照。
`artifacts/DIFF_FILE.patch` 是原版 `gateway` 到候选 `gateway` 的 Git binary patch，已在独立副本用 `git apply` 验证重建哈希。

## 下一工作项

旧 45 项响应差异已消除；下一步处理扩展审核协议、管理自增 ID 与上游序列差异、严格输入提取契约，再补齐按用户归属的聊天读写与 SSE/WebSocket、指纹传输及 MCP/Skills 实际请求协议。准确当前结果与证据入口见 STATUS.json、COMPATIBILITY.md；本批仍未完整通过。
每一步都要扩充原版观测再实现；禁止将缺口改为固定成功或移除共享账号保护来提高表面通过率。
