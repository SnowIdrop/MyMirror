#!/usr/bin/env bash
set -Eeuo pipefail

PIDS=()

shutdown() {
    local status=$?
    trap - EXIT INT TERM

    if ((${#PIDS[@]})); then
        kill -TERM "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi

    exit "$status"
}

trap shutdown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

required_variables=(
    ADMIN_PASSWORD
    CREDENTIAL_ENCRYPTION_KEY
    DJANGO_SECRET_KEY
    GATEWAY_ADMIN_SECRET
)

for variable_name in "${required_variables[@]}"; do
    if [[ -z "${!variable_name:-}" ]]; then
        echo "缺少必需环境变量: ${variable_name}" >&2
        exit 64
    fi
done

export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export PORT="${PORT:-40002}"
export DJANGO_INTERNAL_PORT="${DJANGO_INTERNAL_PORT:-8000}"
export CF_BYPASS_INTERNAL_PORT="${CF_BYPASS_INTERNAL_PORT:-8001}"
export DJANGO_UPSTREAM="${DJANGO_UPSTREAM:-http://127.0.0.1:${DJANGO_INTERNAL_PORT}}"
export CHATGPT_GATEWAY_URL="${CHATGPT_GATEWAY_URL:-http://127.0.0.1:${PORT}}"
export CF_BYPASS_URL="${CF_BYPASS_URL:-http://127.0.0.1:${CF_BYPASS_INTERNAL_PORT}}"
export CF_BYPASS_SECRET="${CF_BYPASS_SECRET:-${GATEWAY_ADMIN_SECRET}}"

mkdir -p /app/data/backend-db /app/data/backend-logs

cd /app/backend
python manage.py migrate --noinput
python cli/create_init_user.py

wait_for_port() {
    local service_name=$1
    local port=$2
    local process_id=$3
    local timeout=${STARTUP_TIMEOUT_SECONDS:-60}
    local attempt

    for ((attempt = 1; attempt <= timeout; attempt++)); do
        if ! kill -0 "$process_id" 2>/dev/null; then
            echo "${service_name} 启动失败" >&2
            return 1
        fi

        if python -c "import socket; s=socket.create_connection(('127.0.0.1', ${port}), 1); s.close()" 2>/dev/null; then
            echo "${service_name} 已就绪"
            return 0
        fi

        sleep 1
    done

    echo "等待 ${service_name} 启动超时（${timeout} 秒）" >&2
    return 1
}

(
    cd /app/cfbypass
    exec python -m uvicorn app:app \
        --host 127.0.0.1 \
        --port "$CF_BYPASS_INTERNAL_PORT"
) &
cf_bypass_pid=$!
PIDS+=("$cf_bypass_pid")

(
    cd /app/backend
    exec python manage.py runserver \
        "127.0.0.1:${DJANGO_INTERNAL_PORT}" \
        --noreload
) &
django_pid=$!
PIDS+=("$django_pid")

wait_for_port "管理服务" "$DJANGO_INTERNAL_PORT" "$django_pid"
wait_for_port "兼容性辅助服务" "$CF_BYPASS_INTERNAL_PORT" "$cf_bypass_pid"

(
    cd /app
    export LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so
    export CURL_IMPERSONATE="${CURL_IMPERSONATE_PROFILE:-chrome146}"
    export CURL_IMPERSONATE_HEADERS=no
    exec ./chatgpt-mirror-gateway
) &
gateway_pid=$!
PIDS+=("$gateway_pid")

wait_for_port "主服务" "$PORT" "$gateway_pid"
echo "三合一服务已启动，监听端口 ${PORT}"

set +e
wait -n "${PIDS[@]}"
exit_status=$?
set -e

echo "检测到子服务退出，正在停止容器" >&2
exit "$exit_status"
