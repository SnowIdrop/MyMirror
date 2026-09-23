# 原镜像与替换重建边界

## 证据

`image-metadata.json` 来自本地 `../image.tar` 的 Docker manifest/config，未运行镜像。
`original-entrypoint.sh` 是镜像最终层中的 `/usr/local/bin/chatgpt-mirror-all-in-one` 原始字节，仅供参考，不能作为 Rust 替换镜像的已验收启动脚本。

原镜像为 linux/amd64，入口管理三个进程：Django、CF 辅助服务、闭源 `/app/chatgpt-mirror-gateway`。旧启动逻辑在网关进程中加载 `/opt/curl-impersonate/libcurl-impersonate.so`；这不是当前 Rust 候选已支持的能力，不能直接照搬。

原离线包说明将公开源码快照标为 `74f7ffae73f10c62d9b8b2ec929a04e5a3aac297`。本仓库的 `Mirror/chatgpt-mirror-build/` 是当前工作源码，不能声称与原镜像逐字节对应。原始公开快照 `MirrorNiXiang/source/` 留作本地参考，避免同时维护两套不明确的构建源。

## 仍缺少的交付步骤（未执行）

1. 用 `Mirror/gateway-rust/artifacts/phase1/source/` 完成 Linux 源码构建配方。其现有 Dockerfile 使用 `FROM scratch` 并复制预编译 `artifacts/MODIFIED_FILE`，不是端到端源码构建；HTTPS 还需确认 CA 和运行依赖。
2. 编译 Vue，并明确管理静态资源挂载与同源路由。现有 `frontend/nginx.conf` 仅配置 `/admin/` 和 `/0x/`，不能当成完整聊天入口。
3. 整合 Django、前端资源、Rust 与辅助服务的 All-in-One Dockerfile 和进程监管；验证健康检查、终止信号与日志。原 Compose 使用上游预构建镜像；route-a 使用 Python 网关，均不是 Rust 替换部署文件。
4. 为新 Rust 网关使用独立数据库路径；保留 Django 数据，不重置用户、不删除上游资源。不得简单覆盖原 `/app/data` 或把旧网关数据库挂载给新实现。
5. 完成既定权限隔离与完整功能验收，再构建独立的新镜像标签；验收前不替换线上服务。原镜像中的其他二进制/系统依赖尚未证明可以从这些源码重建。
6. 验收后才能用 `docker image save --output image-rust.tar <已验收的新镜像标签>` 导出离线包。新包同时提供校验值、Compose、空凭据模板、备份恢复与切换回滚说明；不要覆盖原 `image.tar`。

回滚只回到保留的旧部署/数据备份，不承诺撤销已发生的上游修改。此轮没有构建镜像、运行容器或接触真实账号。
