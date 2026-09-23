# Mirror Rust gateway — offline candidate, NOT a completed replacement

独立 Rust 工程，当前交付是可编译、可运行、可回滚的开发候选，**不是原版行为等价验收通过的网关**。
原版及已有 Mirror 工程未改动。本副本推进新替换计划第一阶段，仍不可作为完整替换部署。
默认只允许离线回环上游；显式 configured 模式支持服务名及 HTTPS，但不代表真实环境验收通过。
本批契约、实现和下一步见 [PHASE1_CONTRACT.md](PHASE1_CONTRACT.md)。

## 已实现与边界

- Axum/Tokio 服务、管理密钥认证、原版八表存储、AES-256-GCM 原版密文格式。
- 完整 v2 备份导出，HTTP legacy/v2 兼容恢复及提交前配置校验；迁移仍严格拒绝错误密钥、损坏记录和未知字段，只读源库到新库、重加密、旧会话失效。
- 独立 Mirror 签名授权适配：调用 Django 校验、每次认证请求重新核对版本和有效期、版本匹配撤销、重新登录保护。
- 登录交接、Cookie 轮换和退出清理；配置持久化、Django 回环代理（含查询串/响应流）。
- 纯模型与能力允许清单策略及回归测试；**MCP/Skills 请求侧协议、完整配额执行未接线**。
- 匿名上游前端已接通（2026-09-23 真实上游实测）：页面 `/`、`/c/*`，匿名通道 `/backend-anon/*`，公共接口 `/public-api/`、`/ces/`、`/cdn-cgi/`、`/sentinel/`，以及 `/assets/`、`/cdn/` 与 `/internal-upstream/https/<host>/...` 媒体代理；页面 HTML 在 `</head>` 之前注入客户端模板，匿名对话（SSE）、匿名上传（签名 blob PUT）与媒体加载均在真实上游通过。
- 已开放 GET `/backend-api/me` 和 GET `/backend-api/conversations`，后者按共享账号内用户归属过滤并保留分页语义；其它 `/backend-api/*` 与 `/external/*`、WS/realtime 仍有明确门禁，完整隔离与 WebSocket 桥接尚未实现。
- 全局共享匿名上游身份：`server/anonymous.rs` 从 cfbypass 取 Cloudflare cookies（整组下发），持久化到 `gateway_settings['anonymous_upstream']`（整值加密）；只有实测的 Cloudflare 挑战（403 + `cf-mitigated: challenge`）才触发缓存处理：幂等 GET 刷新一次并重放一次，生成/上传类请求只失效缓存、由下一次请求重新获取。匿名链路以 cookies 为唯一凭据、不发 `Authorization`：`accessToken` 只属于真实账号登录（实测匿名 `/api/auth/session` 返回 200 `{}`），匿名对话与上传均不需要它。
- 已接线六个管理端点，支持真实令牌轮换、访问计数、会话清理、审核配置持久化。审核 provider 成功协议尚未验证，明确返回未完成门禁。
- 凭据类上游调用（`session_token` 换取、`/api/get-user-info`、`/api/diagnose-chatgpt-auth`、会话刷新）已统一注入 CF 白名单 cookies：命中实测挑战刷新一次并重放一次（只限幂等 GET，生成/SSE/上传不重放）；持续拦截返回 `502` + `code=upstream_blocked`，不回传上游 HTML，配套 Django 健康检测不再据此判失效或清空 token。这是相对原版的有意加固，见 COMPATIBILITY.md。
- 显式非目标（产品决定：个人小团体内部共享账号，不对外收费分发）：请求计量、配额执行、限流、审核 provider 与 PoW/降智风险面**不在替代实现范围内**。`daily_quota`/`monthly_quota`/`limit_per_minute` 等字段保留仅为载荷兼容（`Policy::from_login` 要求下发），网关不写 `visit_logs` 的 `proxy` 行，因此管理端“今日请求/配额已用”恒为 0；`/api/political-moderation-config/test` 保持 503 门禁；注入模板已删除写死的“降智风险/PoW 难度”横幅。详见 COMPATIBILITY.md 的显式非目标一节。
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
`GATEWAY_UPSTREAM_MODE` 默认 `offline`：`DJANGO_UPSTREAM`、`CHATGPT_BASE_URL`、可选 `CHATGPT_CDN_BASE_URL` / `CF_BYPASS_URL` 只接受数字 HTTP 回环服务源。
显式设为 `configured` 时接受 HTTP/HTTPS 服务名和端口，Django、聊天、CDN 三个源必须各自配置，CF 源可选。拒绝凭据、路径前缀、查询串和片段；不提供默认公网地址。配置模板见 `.env.configured.example`。
CDN 已接入公共静态的 `/assets/` 与 `/cdn/` 路径（脚本、样式、图片、字体、音视频扩展名白名单）；不转发凭据或上游 Cookie，拒绝路径穿越、错误 MIME、HTML 正文与重定向。TLS 校验保持启用，请求无法改写配置目标。
`/internal-upstream/https/<host>/<path>` 是注入脚本内置主机表（`src/assets/gateway-client-hosts.json`）的媒体代理：GET/HEAD 读取，PUT 用于匿名上传返回的签名 blob 地址；主机不在表内、非 https、缺少路径分隔符或其它方法都在接触上游前拒绝。
`GATEWAY_ALLOW_ANONYMOUS_SESSION` 默认 `false`（只接受字面量 `true`/`false`）：打开后 `/api/login` 允许无上游凭据的镜像会话，该会话绑定全局共享匿名上游身份。关闭时与原版一致，空凭据登录仍然 400。镜像自身的登录门禁不变：无 `mirror_token` 的页面/匿名请求仍是 401。
`/api/auth/session` 已接入 accounts/check → me 的逐次刷新，网络等待不持数据库锁，并在返回前重新校验撤权；初次登录的accounts检查仍未对齐。独立ACL模块只暂存和运行契约测试，没有产品权限接线。
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

## 旧候选的兼容差异（保留记录）

旧 45 项响应差异已消除；下一步处理扩展审核协议、管理自增 ID 与上游序列差异、严格输入提取契约，再补齐按用户归属的聊天读写与 SSE/WebSocket、指纹传输及 MCP/Skills 实际请求协议。准确当前结果与证据入口见 STATUS.json、COMPATIBILITY.md；本批仍未完整通过。
每一步都要扩充原版观测再实现；禁止将缺口改为固定成功或移除共享账号保护来提高表面通过率。

## 下一批优先工作

2026-09-23 用户决定：优先推进**缺口 1（已登录业务面）、缺口 2（改写前缀与服务端不匹配）、
缺口 3（归属登记与 ACL 接线）、缺口 5（传输身份与出口策略）**；缺口 4（计量/配额/限流/审核/PoW）
列为显式非目标。范围、现状证据、依赖顺序与验收要点见 [NEXT_WORK.md](NEXT_WORK.md)。
