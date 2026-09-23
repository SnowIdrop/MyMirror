# MiRebuild

目标：保留 Mirror 聊天界面、Django 身份和 Vue 管理后台，以 Rust 替代闭源网关，最终交付可重新构建的 All-in-One 镜像及离线 `image.tar`。不是仅发布一个独立网关。

## 已纳入的材料

- `Mirror/chatgpt-mirror-build/backend/`：Django 源码、迁移、依赖、启动脚本与 Dockerfile。
- `Mirror/chatgpt-mirror-build/frontend/`：Vue/TypeScript 源码、npm 锁文件、Nginx 配置与 Dockerfile。
- `Mirror/chatgpt-mirror-build/cfbypass/`：辅助服务源码、依赖与 Dockerfile。
- `Mirror/chatgpt-mirror-build/gateway/`：既有 Python 兼容实验，保留供参考；不是目标 Rust 网关。
- `Mirror/chatgpt-mirror-build/` 下的 Compose 与 `.env.example`：既有部署/实验模板，不代表替换已完成。
- `Mirror/gateway-rust/artifacts/phase1/source/`：当前已验证的 Rust 开发候选；`Mirror/gateway-rust/src/` 保留原基线。
- `MirrorNiXiang/`：原离线包部署模板、校验清单及使用说明；原 `image.tar` 留在本地，不纳入 Git。
- `MirrorNiXiang/rebuild-reference/`：从原镜像只读取得的身份元数据、启动脚本及重建缺口说明。

## 交付状态

本仓库保存完整项目的现有源码与重建参考，不表示替换网关或 All-in-One 重建已经完成。当前只补齐版本管理范围，不恢复此前暂停的功能开发，不启动真实账号验证或生产切换。

后续必须补齐可从源码构建的 Rust Linux 镜像、管理静态资源与聊天入口、All-in-One 进程/数据目录布局，并完成权限和完整功能验收。详见 `MirrorNiXiang/rebuild-reference/README.md`。

真实 `.env`、数据库、日志、原镜像、截图和本地缓存不随源码上传。Django 用户数据仍须单独备份并保留；新网关使用全新数据库，不导入旧网关数据库。
