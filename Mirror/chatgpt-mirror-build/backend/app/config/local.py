import os
from pathlib import Path


def env_bool(key: str, default: bool) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


DEBUG = env_bool("DJANGO_DEBUG", True)
SHOW_GITHUB = env_bool("SHOW_GITHUB", True)
FREE_ACCOUNT_USERNAME = os.environ.get("FREE_ACCOUNT_USERNAME", "free_account")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
GATEWAY_ADMIN_SECRET = os.environ.get("GATEWAY_ADMIN_SECRET", "")
ALLOW_REGISTER = env_bool("ALLOW_REGISTER", True)
CHATGPT_GATEWAY_URL = os.environ.get("CHATGPT_GATEWAY_URL", "http://chatgpt-mirror:40002")
# 镜像面对外基址（浏览器可达）。候选编排把管理界面与镜像面拆成两个端口
# （40003 / 40002）后，网关返回的 `login_url` 是相对路径，浏览器会在管理端源上
# 打开它并拿到 nginx 404；配置该变量后由管理端改成绝对地址。原版单端口部署
# 两者同源，留空即保持原语义。
MIRROR_PUBLIC_URL = os.environ.get("MIRROR_PUBLIC_URL", "").strip().rstrip("/")

TURNSTILE_MODE = os.environ.get("CLOUDFLARE_TURNSTILE", "disable").strip().lower()
if TURNSTILE_MODE not in {"enable", "disable"}:
    raise RuntimeError("CLOUDFLARE_TURNSTILE must be enable or disable")
TURNSTILE_ENABLED = TURNSTILE_MODE == "enable"
TURNSTILE_SITE_KEY = os.environ.get("CLOUDFLARE_TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("CLOUDFLARE_TURNSTILE_SECRET_KEY", "").strip()
if TURNSTILE_ENABLED and (not TURNSTILE_SITE_KEY or not TURNSTILE_SECRET_KEY):
    raise RuntimeError(
        "CLOUDFLARE_TURNSTILE_SITE_KEY and CLOUDFLARE_TURNSTILE_SECRET_KEY "
        "must be set when CLOUDFLARE_TURNSTILE=enable"
    )

BASE_DIR = Path(__file__).resolve().parent.parent
log_file_path = os.path.join(BASE_DIR, os.pardir, 'logs/cron.log')

CRONJOBS = [
    ('*/1 * * * *', 'app.cron.check_access_token', f'>> {log_file_path}'),
    ('*/1 * * * *', 'app.cron.update_access_token', f'>> {log_file_path}'),

]
