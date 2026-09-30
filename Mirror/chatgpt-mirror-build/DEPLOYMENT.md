# 生产部署记录：替换闭源 all-in-one（2026-09-30）

把 `54.95.51.66`（AWS Lightsail ap-northeast-1）上的闭源
`lisa666520/chatgpt-mirror-django:all-in-one` 换成候选四容器栈，对外仍走同一台
Caddy 的 `https://mirror.linuxsnowdrop.ccwu.cc`。本文记录**实际做过的动作**与回滚路径，
不是计划。

## 上线前检查（每次切换前先跑这条）

```bash
cd Mirror/chatgpt-mirror-build
py -3 tools/preflight_cutover.py            # 人读；加 --json 给流水线
```

它对目标机只做只读探测（一次 SSH、不落任何文件、不重启服务），逐条核对：磁盘与内存余量、
docker / compose 是否可用、40002/40003 是否被**别人**占着、网关源码树与两份编排是否齐、
`.env` 的五个必要键是否非空、Django 库与旧网关库副本是否还在、**回滚四件套**
（旧镜像 / `original-compose.yml` + `original.env` / `Caddyfile.before-switch` / `SHA256SUMS`
与那份 `db.sqlite3`）、Caddy 是否 active 与是否已分流。

退出码：`0` = 可以开始（可能有 WARN），`1` = 有 FAIL 必须补齐后再开始，`2` = 连不上或参数错。
它**不打印任何密钥值**，只打印键名与「已设置/空」。

## 目标机上的目录

| 路径 | 内容 |
|---|---|
| `/home/ubuntu/mirror/chatgpt-mirror-build/` | 本目录（Django + cfbypass + frontend + 编排 + `.env`） |
| `/home/ubuntu/mirror/gateway-rust/artifacts/phase1/source/` | 候选 Rust 网关源码（compose 的构建上下文） |
| `/home/ubuntu/mirror/source-gateway.db` | 替换前那个闭源网关库的只读副本 |
| `/home/ubuntu/mirror-backups/20260930-pre-switch/` | 切换前备份（Django 库、原 `.env`、Caddyfile、`docker inspect`） |

源码用 `git archive` 打包上传（只含已提交内容，自动排除构建产物与本地状态）。

## 迁移运行手册（照着做）

前提：`preflight_cutover.py` 结论为 GO。下面命令都在目标机上执行，`$` 开头的是变量。

1. **切换前备份**（做完立即 `sha256sum -c` 验证）

   ```bash
   STAMP=$(date +%Y%m%d%H%M)
   B=/home/ubuntu/mirror-backups/${STAMP}-pre-switch
   mkdir -p "$B/data/backend-db"
   cp -a /home/ubuntu/mirror/chatgpt-mirror-build/backend/db/db.sqlite3 "$B/data/backend-db/db.sqlite3"
   cp -a /home/ubuntu/mirror/chatgpt-mirror-build/.env "$B/original.env" && chmod 600 "$B/original.env"
   sudo -n cp /etc/caddy/Caddyfile "$B/Caddyfile.before-switch"
   # 旧栈容器名先用 docker ps 确认，别照抄名字
   CONTAINER=$(docker ps --format '{{.Names}}' | grep -i chatgpt-mirror | head -1)
   docker cp "$CONTAINER:/app/data/chatgpt_mirror.db" "$B/data/chatgpt_mirror.db"
   docker ps -a > "$B/containers-before.txt"; docker images > "$B/images-before.txt"
   docker inspect "$CONTAINER" > "$B/inspect-all-in-one.json"
   # 旧栈的 compose 定义从它自己的运行目录取（切换后旧目录会被删，这是唯一的来源之一）
   OLD_DIR=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CONTAINER")
   cp -a "$OLD_DIR/docker-compose.yml" "$B/original-compose.yml"
   (cd "$B" && sha256sum data/backend-db/db.sqlite3 data/chatgpt_mirror.db original.env Caddyfile.before-switch > SHA256SUMS)
   (cd "$B" && sha256sum -c SHA256SUMS)
   ```

   备份**必须含旧栈的 compose 定义与 `.env`**：切换后旧目录会被删，只有这两份能重建旧栈。

2. **上传源码**：本机 `git archive --format=tar.gz -o mirror-src.tar.gz <ref>` → `scp` →
   目标机解包到 `/home/ubuntu/mirror/`（覆盖 `chatgpt-mirror-build/` 与 `gateway-rust/`）。

3. **构建四个镜像**（依赖层命中缓存约 2–3 分钟；全冷要编 BoringSSL，2 核机上约 9 分钟）

   ```bash
   cd /home/ubuntu/mirror/chatgpt-mirror-build
   docker compose -p mirror-build --env-file .env \
     -f docker-compose.rust-gateway.yml -f docker-compose.prod.yml build
   ```

4. **承接 Django 库**（必须在第一次 `up` 之前做，见「上次不顺的两处」）

   ```bash
   cp -a "$B/data/backend-db/db.sqlite3" /home/ubuntu/mirror/chatgpt-mirror-build/backend/db/db.sqlite3
   ```

5. **承接网关库**（用 `migrate` 子命令，源库只读）

   ```bash
   export SOURCE_CREDENTIAL_ENCRYPTION_KEY="$(sed -n 's/^CREDENTIAL_ENCRYPTION_KEY=//p' .env | head -1)"
   export CREDENTIAL_ENCRYPTION_KEY="$SOURCE_CREDENTIAL_ENCRYPTION_KEY"
   docker run --rm -v mirror-build_gateway-data:/app/data -v /home/ubuntu/mirror:/src:ro \
     -e SOURCE_CREDENTIAL_ENCRYPTION_KEY -e CREDENTIAL_ENCRYPTION_KEY \
     --entrypoint /app/chatgpt-mirror-gateway mirror-gateway:phase1 \
     migrate /src/source-gateway.db /app/data/gateway-rust.db
   ```

   数据卷必须先存在：卷由第 6 步的 `up` 或 `docker volume create mirror-build_gateway-data` 建。

6. **起栈**（必须叠加 `docker-compose.prod.yml`，否则端口绑到 `0.0.0.0`）

   ```bash
   docker compose -p mirror-build --env-file .env \
     -f docker-compose.rust-gateway.yml -f docker-compose.prod.yml up -d
   ```

7. **Caddy 分流**（第 1 步已经存好 `Caddyfile.before-switch`）

   ```bash
   sudo -n cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.before-manual-edit
   sudo -n cp "$B/Caddyfile.before-switch" /etc/caddy/Caddyfile   # 先确认这是「切换前」那份
   # 按「对外形态」小节把 mirror 站点改成 /admin/* 与 /0x/* 分流，然后：
   sudo -n caddy validate --config /etc/caddy/Caddyfile && sudo -n systemctl reload caddy
   ```

8. **切换后验证**（全绿才算切换完成）

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' https://mirror.linuxsnowdrop.ccwu.cc/            # 401
   curl -s -o /dev/null -w '%{http_code}\n' https://mirror.linuxsnowdrop.ccwu.cc/admin         # 308
   curl -s -o /dev/null -w '%{http_code}\n' https://mirror.linuxsnowdrop.ccwu.cc/admin/        # 200
   curl -s -o /dev/null -w '%{http_code}\n' https://mirror.linuxsnowdrop.ccwu.cc/0x/user/version-cfg
   docker ps --format '{{.Names}}|{{.Status}}'
   docker logs mirror-build-gateway-1 2>&1 | tail -20   # 只应有 listening 与旧归属回填
   ss -ltn | awk 'NR>1{print $4}'                        # 对外只应剩 80/443/22
   ```

   再用一次性镜像用户走一遍登录 → 会话列表 → 发一条消息 → 删除（用完即删该用户）。

9. **清理**：只有第 8 步全绿、且开始前那份备份已 `sha256sum -c` 通过，才删旧的
   all-in-one 目录。旧镜像与 `chatgpt-mirror-share-*.tar.gz` **不要删**——它们是回滚本体。

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

闭源栈的**镜像与数据都还在**，回滚不需要重建。**顺序不能颠倒**：先 `down` 新栈
（否则 40002/40003 被占着，旧栈起不来），再起旧栈，最后换 Caddy 配置。

```bash
# 1) 停新栈（保留数据卷与 backend/db，回滚后还要用）
docker compose -p mirror-build \
  --env-file .env -f docker-compose.rust-gateway.yml -f docker-compose.prod.yml down

# 2) 备好旧栈工作目录：优先用已保留的镜像 + 备份目录里的两件套，不必解 tar.gz
B=/home/ubuntu/mirror-backups/20260930-pre-switch
sudo mkdir -p /home/ubuntu/rollback && sudo chown ubuntu:ubuntu /home/ubuntu/rollback
cd /home/ubuntu/rollback
cp "$B/original-compose.yml" ./docker-compose.yml
cp "$B/original.env" ./.env && chmod 600 ./.env
cp -a "$B/data" ./data            # 注意备份里是 data/data/... 双层，见下一节
(cd "$B" && sha256sum -c SHA256SUMS)   # 先验哈希，再启栈
docker compose up -d

# 3) Caddy 换回切换前那份并 reload
sudo -n cp "$B/Caddyfile.before-switch" /etc/caddy/Caddyfile
sudo -n caddy validate --config /etc/caddy/Caddyfile && sudo -n systemctl reload caddy

# 4) 复验：四条探针应回到「闭源栈在跑」时的形态
curl -s -o /dev/null -w '%{http_code}\n' https://mirror.linuxsnowdrop.ccwu.cc/
```

保留物：`lisa666520/chatgpt-mirror-django:all-in-one`（2.32GB 镜像）、
`/home/ubuntu/chatgpt-mirror-share-20260922.tar.gz`（408MB）、以及
`mirror-backups/20260930-pre-switch/`（Django 库 + 原 `.env` + 两份 Caddyfile）。

**这套回滚未演练过**：材料齐全（`preflight_cutover.py` 会逐件核对），但截至 2026-09-30
只验证到「材料在」，没有真正切回去过。要演练请单独安排窗口，并先确认 Django 库与
网关库的一致性——回滚会丢掉切换之后新产生的数据。

## 上次不顺的两处

这两处是切换当天真正花时间的地方，写成明确步骤，下次按上面手册做就不会再卡。

**一、备份与恢复**

- 备份目录里出现 `data/data/backend-db/db.sqlite3` 这样的**双层 `data`**：当时是 `cp -a`
  整个 `data/` 拷进去的。恢复时按内层路径取文件，别照抄外层目录名。
- 恢复**必须发生在第一次 `up` 之前**。Django 容器一起来就会在空库上跑迁移，
  之后再覆盖 `db.sqlite3` 等于把迁移结果丢掉；`backend/db/` 是宿主绑定目录，
  不存在「先起来再补」的安全窗口。
- `SHA256SUMS` 覆盖 `db.sqlite3` / `chatgpt_mirror.db` / `original.env` /
  `Caddyfile.before-switch` 四件，恢复前先 `sha256sum -c`；哈希不符就先停下来查传输。
- 网关库是「**只读源库 → 新卷**」的一次迁移：`source-gateway.db` 迁移前后 sha256 不变，
  旧栈的 `chatgpt_mirror.db` 始终没被写过。任何情况下都不要把新库写回旧文件，
  否则回滚时旧栈会读到被新版本改过 schema 的库。
- `CREDENTIAL_ENCRYPTION_KEY` 必须与旧栈 `.env` 里的**同一份**：库里既有账号的凭据是
  加密存储的，换密钥就解不出来（表现为账号页能打开但凭据全是空）。

**二、回滚开关**

- 回滚是**四件套**：旧镜像 `lisa666520/chatgpt-mirror-django:all-in-one`、
  `original-compose.yml` + `original.env`、`Caddyfile.before-switch`、
  以及备份里的那份 `db.sqlite3`。少任何一件都回不去，所以 `preflight_cutover.py`
  把它们做成硬 FAIL 项。
- `/etc/caddy/` 里只有 `Caddyfile.before-gpt-load-*` 与 `Caddyfile.before-mirror-*`
  两代历史备份；**切换前那份不在 `/etc/caddy/`**，它躺在备份目录里
  （`Caddyfile.before-switch`）。改 Caddy 前先 `sudo -n cp` 一份到 `/etc/caddy/`
  作为就地回退点，别只依赖备份目录。
- Caddy 改完必须 `caddy validate` 再 `systemctl reload`；`reload` 是热加载，
  失败会保留旧配置，但**端口分流写错会让整站 404**，所以第 8 步的四条探针是必须的。
- 端口冲突是回滚最常见的一次性失败：新栈不停，旧栈起不来，`docker compose up -d`
  只会报 bind 失败而不会自动退让。

## 尚未覆盖

- 出口 IP 仍是 AWS 机房段，指纹统一不解决按 IP 段的风控。
- All-in-One 单镜像打包仍未做：现在是四容器 + 宿主 Caddy，不是单镜像交付形态。
- 目标机上没有 `tests/` 与 `evidence/`，因此那台机器只能构建、不能跑 Rust 回归；
  需要时单独同步。
