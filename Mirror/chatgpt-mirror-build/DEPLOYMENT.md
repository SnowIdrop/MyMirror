# 生产部署记录：替换闭源 all-in-one（2026-09-30）

把 `54.95.51.66`（AWS Lightsail ap-northeast-1）上的闭源
`lisa666520/chatgpt-mirror-django:all-in-one` 换成候选四容器栈，对外仍走同一台
Caddy 的 `https://mirror.linuxsnowdrop.ccwu.cc`。本文记录**实际做过的动作**与回滚路径，
不是计划。

## 目标机上的目录

| 路径 | 内容 |
|---|---|
| `/home/ubuntu/mirror/chatgpt-mirror-build/` | 本目录（Django + cfbypass + frontend + 编排 + `.env`） |
| `/home/ubuntu/mirror/gateway-rust/artifacts/phase1/source/` | 候选 Rust 网关源码（compose 的构建上下文） |
| `/home/ubuntu/mirror/source-gateway.db` | 替换前那个闭源网关库的只读副本 |
| `/home/ubuntu/mirror-backups/20260930-pre-switch/` | 切换前备份（Django 库、原 `.env`、Caddyfile、`docker inspect`） |

源码用 `git archive` 打包上传（只含已提交内容，自动排除构建产物与本地状态）。

## 编排：必须叠加生产覆盖

```bash
cd /home/ubuntu/mirror/chatgpt-mirror-build
docker compose -p mirror-build --env-file .env \
  -f docker-compose.rust-gateway.yml -f docker-compose.prod.yml up -d
```

`docker-compose.prod.yml` 用 `!override` 把 `gateway` 与 `frontend` 的宿主端口改绑
`127.0.0.1`。不叠加它就会绑 `0.0.0.0`，把网关与管理界面直接暴露到公网、绕过 Caddy 与
TLS——比替换前的部署更糟。目标机实测：只有 Caddy（80/443）与 sshd（22）对外监听，
四个应用端口全部在回环上。

## 数据承接

**Django 库直接沿用**（含 5 个镜像用户、1 个上游账号与其加密凭据）：

```bash
cp -a <旧数据目录>/data/backend-db/db.sqlite3  ./backend/db/db.sqlite3
```

必须逐字继承原 `.env` 的 `DJANGO_SECRET_KEY` / `CREDENTIAL_ENCRYPTION_KEY` /
`GATEWAY_ADMIN_SECRET` / `ADMIN_PASSWORD`：库里既有账号的凭据是加密存储的，换密钥即
不可解密；换 `DJANGO_SECRET_KEY` 则所有会话失效。启动时 Django 会自动补齐比线上多出来的
5 个迁移（`accounts` 0009–0012、`chatgpt` 0011），逐个核对过全是 `CreateModel`/`AddField`，
没有删除或重命名。

**网关库走 `migrate` 子命令**（不是「全新库」）：

```bash
export SOURCE_CREDENTIAL_ENCRYPTION_KEY="$(sed -n 's/^CREDENTIAL_ENCRYPTION_KEY=//p' .env | head -1)"
export CREDENTIAL_ENCRYPTION_KEY="$SOURCE_CREDENTIAL_ENCRYPTION_KEY"
docker run --rm -v mirror-build_gateway-data:/app/data -v /home/ubuntu/mirror:/src:ro \
  -e SOURCE_CREDENTIAL_ENCRYPTION_KEY -e CREDENTIAL_ENCRYPTION_KEY \
  --entrypoint /app/chatgpt-mirror-gateway mirror-gateway:phase1 \
  migrate /src/source-gateway.db /app/data/gateway-rust.db
```

源库只读打开，迁移前后 sha256 一致。实测承接：`conversation_owners` 11、`project_owners` 1、
`visit_logs` 163、`conversation_statistics` 11 全部保留，`gateway_sessions` 归零
（旧会话按设计失效，所有人需重新登录）。网关启动时的旧归属回填随后把 12 条归属
（11 会话 + 1 项目）写进 `acl_resources`——**不做这一步，既有会话会全部变成未登记、
用户在列表里看不见**。

## 对外形态：管理面与镜像面同源

Caddy 的 `mirror.linuxsnowdrop.ccwu.cc` 由单条 `reverse_proxy` 改为路径分流：

```caddyfile
mirror.linuxsnowdrop.ccwu.cc {
	@admin_bare path /admin
	redir @admin_bare /admin/ 308

	@admin_app path /admin/* /0x/*
	reverse_proxy @admin_app 127.0.0.1:40003   # nginx 侧车：Vue 产物 + /0x/ 转发
	reverse_proxy 127.0.0.1:40002              # 候选网关：镜像面
}
```

保持原版「单域名同源」的形态，因此 `.env` 里 `MIRROR_PUBLIC_URL` **留空**——
登录交接的相对地址 `/api/not-login` 天然落在镜像面上。`ADMIN_PUBLIC_URL` 指向
`https://mirror.linuxsnowdrop.ccwu.cc/admin/`，供注入脚本的「返回后台」使用。

Django 判定 HTTPS 靠 `SECURE_PROXY_SSL_HEADER`，链路是
`Caddy（设 X-Forwarded-Proto: https）→ 侧车 nginx（原样透传）→ 网关（/0x/* 透传，
只在出网跳剥该头）→ Django`。

## 切换后实测

| 检查 | 结果 |
|---|---|
| 四个镜像在目标机现编 | gateway 179MB / django 324MB / cfbypass 1.4GB / frontend 76.3MB，均构建成功 |
| 容器健康 | gateway / django healthy，cfbypass / frontend Up，重启策略均为 `unless-stopped` |
| 端口暴露 | 仅 Caddy 80/443 与 sshd 22 对外；应用端口全在 127.0.0.1（公网 IP 上 HTTP 无响应） |
| 公网路由 | `/` 401、`/admin` 308→`/admin/`、`/admin/` 200（Vue 产物）、`/0x/user/version-cfg` 200、`/backend-api/me` 401 |
| Django | 5 个用户、1 个上游账号保留，加密凭据可读 |
| 网关 | 旧归属回填 `claimed=12`；0 条身份不一致告警、0 次 prewarm 失败 |
| cfbypass | 身份逐字段对齐（chromium 146.0.7680.177、arch x86、platformVersion 空），对 chatgpt.com 取到 5 个 Cookie |

## 回滚

闭源栈的**镜像与数据都还在**，回滚不需要重建：

```bash
docker compose -p mirror-build \
  --env-file .env -f docker-compose.rust-gateway.yml -f docker-compose.prod.yml down
sudo mkdir -p /home/ubuntu/restore && cd /home/ubuntu/restore
sudo tar -xzf /home/ubuntu/chatgpt-mirror-share-20260922.tar.gz   # 或直接用下面已保留的镜像
# 用 /home/ubuntu/mirror-backups/20260930-pre-switch/ 里的 original-compose.yml + original.env
# 在还原出的数据目录上 docker compose up -d，再把 Caddyfile 换回 Caddyfile.before-switch 并 reload
```

保留物：`lisa666520/chatgpt-mirror-django:all-in-one`（2.32GB 镜像）、
`/home/ubuntu/chatgpt-mirror-share-20260922.tar.gz`（408MB）、以及
`mirror-backups/20260930-pre-switch/`（Django 库 + 原 `.env` + 两份 Caddyfile）。

## 尚未覆盖

- 出口 IP 仍是 AWS 机房段，指纹统一不解决按 IP 段的风控。
- All-in-One 单镜像打包仍未做：现在是四容器 + 宿主 Caddy，不是单镜像交付形态。
- 目标机上没有 `tests/` 与 `evidence/`，因此那台机器只能构建、不能跑 Rust 回归；
  需要时单独同步。
