#!/usr/bin/env bash
# =============================================================================
#  install_agent.sh — Установка AI Agent v3 (WebSocket-чат + веб-интерфейс)
#  Запускать на сервере мониторинга ПОСЛЕ install_monitoring.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config.env"
[[ -f "$CONFIG" ]] || { log_error "config.env не найден — запустите ./configure.sh"; exit 1; }
source "$CONFIG"
[[ $EUID -ne 0 ]] && { log_error "Нужен root (sudo)"; exit 1; }

AGENT_DIR="/opt/ai-alert-agent"

# =============================================================================
log_section "Python"
# =============================================================================
dnf install -y python3 python3-pip 2>/dev/null || yum install -y python3 python3-pip
python3 --version

# =============================================================================
log_section "Файлы агента"
# =============================================================================
mkdir -p "${AGENT_DIR}/web"

cp "${SCRIPT_DIR}/../agent/agent.py"      "${AGENT_DIR}/agent.py"
cp "${SCRIPT_DIR}/../clusters.json"       "${AGENT_DIR}/clusters.json"
cp "${SCRIPT_DIR}/../web/index.html"      "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/style.css"       "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/app.js"          "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/login.html"      "${AGENT_DIR}/web/"

log_info "Файлы скопированы в ${AGENT_DIR}"

# =============================================================================
log_section "Python-зависимости (venv)"
# =============================================================================
python3 -m venv "${AGENT_DIR}/venv"

# ── pip-репозиторий из config.env (пусто = публичный PyPI) ────────────────────
PIP_ARGS=()
if [[ -n "${PIP_INDEX_URL:-}" ]]; then
    PIP_ARGS+=(--index-url "${PIP_INDEX_URL}")
    [[ -n "${PIP_EXTRA_INDEX_URL:-}" ]] && PIP_ARGS+=(--extra-index-url "${PIP_EXTRA_INDEX_URL}")
    [[ -n "${PIP_TRUSTED_HOST:-}"    ]] && PIP_ARGS+=(--trusted-host "${PIP_TRUSTED_HOST}")
    [[ -n "${PIP_CERT:-}"            ]] && PIP_ARGS+=(--cert "${PIP_CERT}")

    if [[ -n "${PIP_CERT:-}" && ! -f "${PIP_CERT}" ]]; then
        log_error "CA-сертификат для pip не найден: ${PIP_CERT}"
        exit 1
    fi

    # Закрепляем репозиторий в самом venv, чтобы последующие ручные
    # pip install в нём тоже шли во внутренний репозиторий.
    {
        echo "[global]"
        echo "index-url = ${PIP_INDEX_URL}"
        [[ -n "${PIP_EXTRA_INDEX_URL:-}" ]] && echo "extra-index-url = ${PIP_EXTRA_INDEX_URL}"
        [[ -n "${PIP_TRUSTED_HOST:-}"    ]] && echo "trusted-host = ${PIP_TRUSTED_HOST}"
        [[ -n "${PIP_CERT:-}"            ]] && echo "cert = ${PIP_CERT}"
    } > "${AGENT_DIR}/venv/pip.conf"
    chmod 600 "${AGENT_DIR}/venv/pip.conf"

    # URL может содержать логин:пароль — не печатаем его целиком
    log_info "pip-репозиторий: $(printf '%s' "${PIP_INDEX_URL}" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#')"
else
    log_info "pip-репозиторий: публичный PyPI"
fi

"${AGENT_DIR}/venv/bin/pip" install --upgrade pip -q "${PIP_ARGS[@]}"
"${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" \
    "fastapi==0.111.0" \
    "uvicorn[standard]==0.29.0" \
    "httpx==0.27.0" \
    "pydantic==2.7.1" \
    "websockets==12.0"

if [[ "${LDAP_ENABLED:-false}" == "true" ]]; then
    if "${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" "ldap3==2.9.1"; then
        log_info "ldap3 установлен (LDAP-аутентификация)"
    else
        log_error "Не удалось поставить ldap3 — вход по LDAP работать не будет"
        log_warn  "Проверьте доступность пакета в вашем pip-репозитории"
    fi
fi

log_info "Зависимости установлены"

# =============================================================================
log_section "Конфигурация агента (.env)"
# =============================================================================
cat > "${AGENT_DIR}/.env" << EOF
LLM_BASE_URL=${LLM_BASE_URL}
LLM_API_KEY=${LLM_API_KEY}
LLM_MODEL=${LLM_MODEL}
LLM_MAX_TOKENS=${LLM_MAX_TOKENS}
LLM_TEMPERATURE=${LLM_TEMPERATURE}
PROMETHEUS_URL=http://localhost:9090${PROMETHEUS_ROOT_PATH:-}
AGENT_PORT=${AGENT_PORT}
ROOT_PATH=${ROOT_PATH:-}
REGISTRY_PATH=${AGENT_DIR}/clusters.json
WEB_DIR=${AGENT_DIR}/web
ALERTS_DB_PATH=${AGENT_DIR}/alerts.db
ALERTS_RETENTION_DAYS=${ALERTS_RETENTION_DAYS:-30}
CHATS_RETENTION_DAYS=${CHATS_RETENTION_DAYS:-30}
AUTH_ENABLED=${AUTH_ENABLED:-true}
AUTH_ADMIN_USER=${AUTH_ADMIN_USER:-admin}
AUTH_ADMIN_PASSWORD_HASH=${AUTH_ADMIN_PASSWORD_HASH:-}
AUTH_SECRET=${AUTH_SECRET:-}
AUTH_SESSION_TTL_HOURS=${AUTH_SESSION_TTL_HOURS:-12}
LDAP_ENABLED=${LDAP_ENABLED:-false}
LDAP_URL=${LDAP_URL:-}
LDAP_BIND_TEMPLATE=${LDAP_BIND_TEMPLATE:-}
LDAP_BASE_DN=${LDAP_BASE_DN:-}
LDAP_USER_FILTER=${LDAP_USER_FILTER:-}
LDAP_REQUIRED_GROUP=${LDAP_REQUIRED_GROUP:-}
LDAP_TLS_VERIFY=${LDAP_TLS_VERIFY:-true}
LDAP_SEARCH_USER=${LDAP_SEARCH_USER:-}
LDAP_SEARCH_PASSWORD=${LDAP_SEARCH_PASSWORD:-}
OIDC_ENABLED=${OIDC_ENABLED:-false}
OIDC_ISSUER=${OIDC_ISSUER:-}
OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-}
OIDC_REDIRECT_URL=${OIDC_REDIRECT_URL:-}
OIDC_SCOPES=${OIDC_SCOPES:-openid profile email}
OIDC_USERNAME_CLAIM=${OIDC_USERNAME_CLAIM:-preferred_username}
OIDC_BUTTON_TEXT=${OIDC_BUTTON_TEXT:-Войти через SSO}
OIDC_TLS_VERIFY=${OIDC_TLS_VERIFY:-true}
SSO_ENABLED=${SSO_ENABLED:-false}
SSO_HEADER=${SSO_HEADER:-X-Remote-User}
SSO_TRUSTED_PROXIES=${SSO_TRUSTED_PROXIES:-127.0.0.1,::1}
SSO_LOGOUT_URL=${SSO_LOGOUT_URL:-}
EOF
chmod 600 "${AGENT_DIR}/.env"

if [[ "${AUTH_ENABLED:-true}" == "true" ]] && [[ -z "${AUTH_ADMIN_PASSWORD_HASH:-}" ]] && [[ "${LDAP_ENABLED:-false}" != "true" ]] && [[ "${SSO_ENABLED:-false}" != "true" ]] && [[ "${OIDC_ENABLED:-false}" != "true" ]]; then
    log_error "Аутентификация включена, но не задан ни пароль админа, ни LDAP, ни SSO."
    log_error "Войти в интерфейс будет невозможно. Запустите ./configure.sh"
    exit 1
fi

touch /var/log/ai-alert-agent.log
chmod 666 /var/log/ai-alert-agent.log

id aiagent &>/dev/null || useradd -r -s /sbin/nologin aiagent
chown -R aiagent:aiagent "${AGENT_DIR}"

# =============================================================================
log_section "Systemd-сервис"
# =============================================================================
cat > /etc/systemd/system/ai-alert-agent.service << EOF
[Unit]
Description=MySQL AI Alert Agent v3 (WebSocket chat)
After=network.target prometheus.service

[Service]
User=aiagent
Group=aiagent
WorkingDirectory=${AGENT_DIR}
EnvironmentFile=${AGENT_DIR}/.env
ExecStart=${AGENT_DIR}/venv/bin/python agent.py
Restart=always
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ai-alert-agent 2>/dev/null || true
# на уже работающем сервисе --now ничего не делает, а .env изменился
systemctl restart ai-alert-agent
sleep 4

# =============================================================================
log_section "Проверка"
# =============================================================================
if curl -sf "http://localhost:${AGENT_PORT}/health" >/dev/null; then
    log_info "AI Agent запущен ✓"
    curl -s "http://localhost:${AGENT_PORT}/health" | python3 -m json.tool
else
    log_error "Агент не отвечает на :${AGENT_PORT}"
    journalctl -u ai-alert-agent --no-pager -n 25
    exit 1
fi

echo ""
log_info "Веб-интерфейс (чат): http://${MONITORING_IP}:${AGENT_PORT}/"
echo ""
log_info "Дальше:"
echo "  1. Добавьте кластеры:          ./manage_cluster.sh add"
echo "  2. Установите экспортёры:      ./manage_cluster.sh install-exporters <name>"
echo "  3. Примените конфигурацию:     sudo ./manage_cluster.sh apply"
echo "  4. Проверьте стек:             ./scripts/verify.sh"
