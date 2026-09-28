# 原镜像与替换重建边界

## 证据

`image-metadata.json` 来自本地 `../image.tar` 的 Docker manifest/config，未运行镜像。
`original-entrypoint.sh` 是镜像最终层中的 `/usr/local/bin/chatgpt-mirror-all-in-one` 原始字节，仅供参考，不能作为 Rust 替换镜像的已验收启动脚本。

原镜像为 linux/amd64，入口管理三个进程：Django、CF 辅助服务、闭源 `/app/chatgpt-mirror-gateway`。旧启动逻辑在网关进程中加载 `/opt/curl-impersonate/libcurl-impersonate.so`；这不是当前 Rust 候选已支持的能力，不能直接照搬。

原离线包说明将公开源码快照标为 `74f7ffae73f10c62d9b8b2ec929a04e5a3aac297`。本仓库的 `Mirror/chatgpt-mirror-build/` 是当前工作源码，不能声称与原镜像逐字节对应。原始公开快照 `MirrorNiXiang/source/` 留作本地参考，避免同时维护两套不明确的构建源。

## 交付步骤进度（2026-09-28 复核）

1. **已完成**：`Mirror/gateway-rust/artifacts/phase1/source/Dockerfile` 改成 `debian:trixie-slim`
   两阶段源码构建（原 `FROM scratch` + 复制 `artifacts/MODIFIED_FILE` 已删除）。BoringSSL 需要
   构建期 cmake/clang/libclang，运行期需要 libstdc++/libgcc_s；TLS 根证书由 wreq 的
   `webpki-roots` 内联，运行镜像另装 ca-certificates 供排障。
2. **已完成（管理面）**：Vue 已编译，管理静态资源与同源路由按「nginx 侧车服务 `/admin/`、
   转发 `/0x/` 到网关」落地；镜像内置的 `frontend/nginx.conf` 只面向 route-a 的 8000 端口，
   Rust 编配改用 `frontend/nginx.rust.conf` 覆盖。聊天入口仍直连网关端口，不经过这个 nginx
   （SSE/WS 少一跳）。
3. **部分完成**：四服务编配 `Mirror/chatgpt-mirror-build/docker-compose.rust-gateway.yml`
   （gateway/django/cfbypass/frontend）已构建并起栈验证，含健康检查与重启策略；**未做**的是
   原版那种 All-in-One 单镜像与进程监管（入口脚本同时管 Django、cfbypass、网关三个进程）。
4. **已完成**：网关使用独立数据库 `/app/data/gateway-rust.db`（卷 `gateway-data`），
   Django 数据沿用 `backend/db`，不挂载旧网关库、不重置用户。
5. **未完成**：功能验收与权限隔离仍在推进（资源 ACL、身份、打包各自有批次证据），真实上游
   写入验收需另行批准；验收前不替换线上服务。
6. **未完成**：`docker image save --output image-rust.tar <新镜像标签>`、校验值、离线包、
   回滚说明都还没做。

回滚只回到保留的旧部署/数据备份，不承诺撤销已发生的上游修改。本批已在 WSL dockerd 内构建
四个镜像并运行容器验证（未接触真实账号；真实上游只读冒烟见 `artifacts/phase1/` 与
`source/COMPATIBILITY.md`）。
