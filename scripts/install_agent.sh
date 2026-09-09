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
source "${SCRIPT_DIR}/lib_secrets.sh"
load_config "$CONFIG"
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

# Агент теперь пакет, а не один файл. Старую копию убираем целиком:
# оставшийся рядом agent.py прошлой версии сбил бы импорт.
rm -rf "${AGENT_DIR}/agent" "${AGENT_DIR}/agent.py"
cp -r "${SCRIPT_DIR}/../agent"            "${AGENT_DIR}/agent"
find "${AGENT_DIR}/agent" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
# Парсер nslcd.conf: агент дозаполняет им пустые настройки LDAP на старте
cp "${SCRIPT_DIR}/import_nslcd.py"        "${AGENT_DIR}/agent/import_nslcd.py"
cp "${SCRIPT_DIR}/../clusters.json"       "${AGENT_DIR}/clusters.json"
cp "${SCRIPT_DIR}/../web/index.html"      "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/style.css"       "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/app.js"          "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/login.html"      "${AGENT_DIR}/web/"
cp "${SCRIPT_DIR}/../web/report.html"     "${AGENT_DIR}/web/"

log_info "Файлы скопированы в ${AGENT_DIR}"

# =============================================================================
log_section "Python-зависимости (venv)"
# =============================================================================
python3 -m venv "${AGENT_DIR}/venv"

# ── pip-репозиторий из config.env (пусто = публичный PyPI) ────────────────────
# Хост из URL — чтобы добавить его в trusted-host: за корпоративным TLS-прокси
# сертификат подменяется, и pip иначе падает на проверке.
pip_host() { printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#[:/].*$##'; }

# Проверку сертификатов не делаем никогда: в закрытом контуре её всё равно
# ломает MITM-прокси. Трафик остаётся внутри периметра.
PIP_TRUSTED=(pypi.org files.pythonhosted.org)
[[ -n "${PIP_INDEX_URL:-}" ]]       && PIP_TRUSTED+=("$(pip_host "${PIP_INDEX_URL}")")
[[ -n "${PIP_EXTRA_INDEX_URL:-}" ]] && PIP_TRUSTED+=("$(pip_host "${PIP_EXTRA_INDEX_URL}")")
[[ -n "${PIP_TRUSTED_HOST:-}" ]]    && PIP_TRUSTED+=("${PIP_TRUSTED_HOST}")
# убрать дубли и пустые
mapfile -t PIP_TRUSTED < <(printf '%s\n' "${PIP_TRUSTED[@]}" | awk 'NF && !seen[$0]++')

PIP_ARGS=()
for h in "${PIP_TRUSTED[@]}"; do PIP_ARGS+=(--trusted-host "$h"); done

if [[ -n "${PIP_INDEX_URL:-}" ]]; then
    PIP_ARGS+=(--index-url "${PIP_INDEX_URL}")
    [[ -n "${PIP_EXTRA_INDEX_URL:-}" ]] && PIP_ARGS+=(--extra-index-url "${PIP_EXTRA_INDEX_URL}")
    [[ -n "${PIP_CERT:-}"            ]] && PIP_ARGS+=(--cert "${PIP_CERT}")

    if [[ -n "${PIP_CERT:-}" && ! -f "${PIP_CERT}" ]]; then
        log_error "CA-сертификат для pip не найден: ${PIP_CERT}"
        exit 1
    fi
    # URL может содержать логин:пароль — не печатаем его целиком
    log_info "pip-репозиторий: $(printf '%s' "${PIP_INDEX_URL}" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#')"
else
    log_info "pip-репозиторий: публичный PyPI"
fi

# Закрепляем настройки в самом venv, чтобы последующие ручные pip install
# в нём шли туда же и тоже не спотыкались о сертификаты.
{
    echo "[global]"
    [[ -n "${PIP_INDEX_URL:-}" ]]       && echo "index-url = ${PIP_INDEX_URL}"
    [[ -n "${PIP_EXTRA_INDEX_URL:-}" ]] && echo "extra-index-url = ${PIP_EXTRA_INDEX_URL}"
    [[ -n "${PIP_CERT:-}" ]]            && echo "cert = ${PIP_CERT}"
    echo "trusted-host = ${PIP_TRUSTED[*]}"
} > "${AGENT_DIR}/venv/pip.conf"
chmod 600 "${AGENT_DIR}/venv/pip.conf"
log_info "trusted-host: ${PIP_TRUSTED[*]}"

"${AGENT_DIR}/venv/bin/pip" install --upgrade pip -q "${PIP_ARGS[@]}"
"${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" \
    "fastapi==0.111.0" \
    "uvicorn[standard]==0.29.0" \
    "httpx==0.27.0" \
    "pydantic==2.7.1" \
    "websockets==12.0" \
    "sqlalchemy==2.0.30" \
    "aiosqlite==0.20.0"

# cryptography нужен драйверам MySQL для плагина caching_sha2_password —
# он включён по умолчанию с MySQL 8.0. Без пакета подключение обрывается
# на «Authentication plugin 'caching_sha2_password' requires cryptography».
# Ставим один раз, независимо от того, кто попросил первым: драйвер хранилища
# агента или драйвер запросов к кластерам.
CRYPTO_DONE=""
install_cryptography() {
    local why="$1"
    [[ -n "${CRYPTO_DONE}" ]] && return 0
    # Пин — для повторяемости, но у пакета есть бинарные колёса, и на старом
    # Python нужного просто нет. В таком случае берём то, что подходит
    # интерпретатору, вместо того чтобы падать.
    if "${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" "cryptography==42.0.8"        || "${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" "cryptography"; then
        CRYPTO_DONE="yes"
        log_info "cryptography установлен (${why}, MySQL 8 caching_sha2_password)"
        return 0
    fi
    log_error "Не удалось поставить cryptography (${why})."
    log_error "С MySQL 8.0 подключение упадёт на caching_sha2_password."
    log_warn  "Положите пакет во внутренний индекс pip либо переведите учётку"
    log_warn  "агента на mysql_native_password:"
    log_warn  "  ALTER USER ... IDENTIFIED WITH mysql_native_password BY '...';"
    return 1
}

# Драйвер MySQL для хранилища агента ставим, только если на него перешли.
# По умолчанию хранилище в SQLite, и тянуть лишнее в закрытый контур незачем.
if [[ "${DB_URL:-}" == mysql* ]]; then
    if "${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" "asyncmy==0.2.9"; then
        log_info "Хранилище агента: MySQL (asyncmy)"
        install_cryptography "хранилище агента" || true
    else
        log_error "Не удалось поставить asyncmy — хранилище MySQL не заработает."
        log_error "Положите пакет во внутренний индекс pip или уберите DB_URL."
        exit 1
    fi
else
    log_info "Хранилище агента: SQLite"
fi

# pymysql — только если хоть у одного кластера заполнен db_user.
# Чистый Python, без системных библиотек: в закрытый pip-репозиторий ложится.
NEED_MYSQL=$(python3 -c "
import json
d = json.load(open('${SCRIPT_DIR}/../clusters.json', encoding='utf-8'))
print('yes' if any((c.get('db_user') or '').strip() for c in d['clusters']) else 'no')
" 2>/dev/null || echo "no")

if [[ "$NEED_MYSQL" == "yes" ]]; then
    if "${AGENT_DIR}/venv/bin/pip" install -q "${PIP_ARGS[@]}" "pymysql==1.1.0"; then
        log_info "pymysql установлен (SQL-запросы к кластерам)"
        install_cryptography "запросы к кластерам" || true
    else
        log_error "Не удалось поставить pymysql — SQL-запросы работать не будут"
    fi
fi

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
# Подпуть задан -> агент ходит в Prometheus через nginx, без порта
if [[ -n "${PROMETHEUS_ROOT_PATH:-}" ]]; then
    PROM_URL_FOR_AGENT="${INTERNAL_BASE_URL:-http://localhost}${PROMETHEUS_ROOT_PATH}"
else
    PROM_URL_FOR_AGENT="http://localhost:9090"
fi

cat > "${AGENT_DIR}/.env" << EOF
LLM_BASE_URL=${LLM_BASE_URL}
LLM_API_KEY=${LLM_API_KEY}
LLM_MODEL=${LLM_MODEL}
LLM_MAX_TOKENS=${LLM_MAX_TOKENS}
LLM_TEMPERATURE=${LLM_TEMPERATURE}
PROMETHEUS_URL=${PROM_URL_FOR_AGENT}
AGENT_PORT=${AGENT_PORT}
ROOT_PATH=${ROOT_PATH:-}
REGISTRY_PATH=${AGENT_DIR}/clusters.json
WEB_DIR=${AGENT_DIR}/web
ALERTS_DB_PATH=${AGENT_DIR}/alerts.db
# Хранилище агента. Пусто — SQLite по пути ALERTS_DB_PATH.
# MySQL: mysql+asyncmy://user:pass@host:3306/agent
DB_URL=${DB_URL:-}
ALERTS_RETENTION_DAYS=${ALERTS_RETENTION_DAYS:-30}
CHATS_RETENTION_DAYS=${CHATS_RETENTION_DAYS:-30}
INGEST_TOKENS=${INGEST_TOKENS:-}
# Событий в минуту от одного отправителя. 0 — не ограничивать.
# Защита не от расходов, а от зациклившегося скрипта на той стороне
INGEST_RATE_PER_MIN=${INGEST_RATE_PER_MIN:-120}
# Чтение логов на серверах БД идёт по SSH под той же учёткой,
# что и установка экспортёров
SSH_USER=${SSH_USER:-}
SSH_PORT=${SSH_PORT:-22}
SSH_KEY=${SSH_KEY:-}
# Дедупликация повторных алертов и глубина контекста чата
ALERT_DEDUP_MINUTES=${ALERT_DEDUP_MINUTES:-30}
CHAT_CONTEXT_MESSAGES=${CHAT_CONTEXT_MESSAGES:-10}
# Окно профиля нагрузки: два среза performance_schema с этим интервалом.
# На столько же задерживается ответ при разборе «почему медленно»
WORKLOAD_WINDOW_S=${WORKLOAD_WINDOW_S:-10}
# Через сколько минут после записи решения проверить, не повторилось ли
FOLLOWUP_MINUTES=${FOLLOWUP_MINUTES:-15}
# Сверка с обычным состоянием: ловит поломки, на которые нет порога
ANOMALY_ENABLED=${ANOMALY_ENABLED:-true}
ANOMALY_INTERVAL_MIN=${ANOMALY_INTERVAL_MIN:-30}
# Самопроверка: Prometheus, модель, SSH, учётки баз, каталог
SELFCHECK_ENABLED=${SELFCHECK_ENABLED:-true}
SELFCHECK_INTERVAL_MIN=${SELFCHECK_INTERVAL_MIN:-60}
# Сводка по расписанию: во сколько, за какой период и кому
DIGEST_ENABLED=${DIGEST_ENABLED:-false}
DIGEST_AT=${DIGEST_AT:-09:00}
DIGEST_HOURS=${DIGEST_HOURS:-24}
DIGEST_TO=${DIGEST_TO:-}
DIGEST_WEBHOOK=${DIGEST_WEBHOOK:-}
# Почта берётся из тех же настроек, что и у Alertmanager
ALERT_EMAIL_FROM=${ALERT_EMAIL_FROM:-}
ALERT_SMTP_HOST=${ALERT_SMTP_HOST:-}
ALERT_SMTP_USER=${ALERT_SMTP_USER:-}
ALERT_SMTP_PASSWORD=${ALERT_SMTP_PASSWORD:-}
BASELINE_WEEKS=${BASELINE_WEEKS:-4}
LOG_MAX_LINES=${LOG_MAX_LINES:-400}
LOG_SSH_TIMEOUT=${LOG_SSH_TIMEOUT:-25}
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
LDAP_ALLOWED_GROUPS=${LDAP_ALLOWED_GROUPS:-}
LDAP_NESTED_GROUPS=${LDAP_NESTED_GROUPS:-true}
LDAP_ALLOWED_NETGROUPS=${LDAP_ALLOWED_NETGROUPS:-}
LDAP_NETGROUP_BASE=${LDAP_NETGROUP_BASE:-}
LDAP_NETGROUP_FILTER=${LDAP_NETGROUP_FILTER:-(objectClass=nisNetgroup)}
LDAP_TLS_VERIFY=${LDAP_TLS_VERIFY:-true}
LDAP_SEARCH_USER=${LDAP_SEARCH_USER:-}
LDAP_SEARCH_PASSWORD=${LDAP_SEARCH_PASSWORD:-}
LDAP_SEARCH_FILTER=${LDAP_SEARCH_FILTER:-}
LDAP_USER_BASE=${LDAP_USER_BASE:-}
# prefix — по началу строки (использует индекс), contains — по вхождению
LDAP_SEARCH_MODE=${LDAP_SEARCH_MODE:-prefix}
# Откуда дозаполнять пустые настройки LDAP. Пусто в NSLCD_CONF — не читать
NSLCD_CONF=${NSLCD_CONF:-/etc/nslcd.conf}
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
log_section "Доступ по SSH"
# =============================================================================
# Агент работает под учёткой aiagent, а ключ обычно лежит в домашнем каталоге
# администратора с правами 600. Прочитать его агент не сможет, и всё, что
# ходит по SSH — логи, туннель к базе, проверка копий — молча перестанет
# работать: в интерфейсе будет «сервер не отвечает», а причина невидима.
if [[ -n "${SSH_USER:-}" ]]; then
    log_info "Учётная запись для серверов БД: ${SSH_USER}, порт ${SSH_PORT:-22}"

    if [[ -n "${SSH_KEY:-}" ]]; then
        if [[ ! -f "$SSH_KEY" ]]; then
            log_error "SSH-ключ не найден: ${SSH_KEY}"
            log_error "Поправьте SSH_KEY в config.env либо оставьте его пустым"
            exit 1
        fi

        AGENT_KEY="${AGENT_DIR}/.ssh/id_agent"
        if sudo -u aiagent test -r "$SSH_KEY" 2>/dev/null; then
            log_info "Ключ ${SSH_KEY} читается учёткой aiagent — оставляю как есть"
        else
            # Копия, а не chmod на оригинал: раздавать права на ключ
            # администратора всем — плохая идея, а своя копия у агента
            # закрыта и живёт вместе с ним
            log_warn "Ключ ${SSH_KEY} недоступен учётке aiagent — делаю копию"
            install -d -m 700 -o aiagent -g aiagent "${AGENT_DIR}/.ssh"
            install -m 600 -o aiagent -g aiagent "$SSH_KEY" "$AGENT_KEY"
            log_info "Копия ключа: ${AGENT_KEY} (только для aiagent)"
            # В окружении агента подменяем путь на копию
            sed -i "s|^SSH_KEY=.*|SSH_KEY=${AGENT_KEY}|" "${AGENT_DIR}/.env"
        fi
    else
        log_info "Путь к ключу не задан — используется ключ по умолчанию"
        log_warn "Учётка aiagent служебная и своего ~/.ssh не имеет."
        log_warn "Если по SSH ничего не работает, укажите SSH_KEY в config.env"
    fi
else
    log_warn "SSH_USER не задан: чтение логов, туннель к базе и проверка"
    log_warn "резервных копий работать не будут. Заполните ./configure.sh"
fi

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
# ssh ищет настройки в домашнем каталоге, а у служебной учётки его нет:
# без HOME он ругается на "No such file or directory" ещё до подключения
Environment=HOME=${AGENT_DIR}
ExecStart=${AGENT_DIR}/venv/bin/python -m agent.main
Restart=always
RestartSec=3s
# Без этого systemd ждёт остановки 90 секунд по умолчанию
TimeoutStopSec=15
KillMode=mixed
KillSignal=SIGTERM
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
