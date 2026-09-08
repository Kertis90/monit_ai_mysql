#!/usr/bin/env bash
# =============================================================================
#  configure.sh — Интерактивная настройка всего стека
#  ЗАПУСКАТЬ ПЕРВЫМ. Создаёт config.env со всеми параметрами.
#
#  Использование:
#    chmod +x configure.sh
#    ./configure.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.env"
source "${SCRIPT_DIR}/scripts/lib_secrets.sh"

echo ""
echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║   MySQL AI Monitoring — Мастер настройки           ║${NC}"
echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# Загрузить существующие значения если конфиг уже есть
if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "${YELLOW}Найден существующий config.env — значения будут предложены как defaults${NC}"
    load_config "$CONFIG_FILE"
    echo ""
fi

ask() { # prompt varname default [secret]
    local prompt="$1" var="$2" default="${3:-}" secret="${4:-}"
    local current="${!var:-$default}"
    local display="$current"
    [[ -n "$secret" && -n "$current" ]] && display="${current:0:6}***"

    if [[ -n "$secret" ]]; then
        read -rsp "  ${prompt} [${display}]: " input
        echo ""
    else
        read -rp "  ${prompt} [${display}]: " input
    fi
    if [[ -n "$input" ]]; then
        eval "$var=\"\$input\""
    else
        eval "$var=\"\$current\""
    fi
}

echo -e "${CYAN}── 1. Сервер мониторинга ─────────────────────────────${NC}"
DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "10.0.0.100")
ask "IP этого сервера (Prometheus/Grafana/Agent)" MONITORING_IP "$DETECTED_IP"

echo ""
echo -e "${CYAN}── 2. Удалённая LLM (OpenAI-совместимый API) ─────────${NC}"
echo -e "  ${YELLOW}Пример: https://llm.mycompany.ru/v1${NC}"
ask "LLM Base URL" LLM_BASE_URL "https://your-llm-server.com/v1"
ask "LLM API токен (Bearer)" LLM_API_KEY "" secret
ask "Название модели" LLM_MODEL "gpt-4o-mini"
ask "Max tokens" LLM_MAX_TOKENS "2048"
ask "Temperature" LLM_TEMPERATURE "0.3"

echo ""
echo -e "${CYAN}── 3. Grafana ────────────────────────────────────────${NC}"
ask "Пароль admin для Grafana" GRAFANA_ADMIN_PASSWORD "ChangeMe123!" secret

echo ""
echo -e "${CYAN}── 4. Email-уведомления (Alertmanager) ───────────────${NC}"
echo -e "  ${YELLOW}Enter — пропустить (алерты пойдут только в AI-агент)${NC}"
ask "Email получателя алертов" ALERT_EMAIL_TO ""
if [[ -n "${ALERT_EMAIL_TO}" ]]; then
    ask "Email отправителя" ALERT_EMAIL_FROM "alertmanager@$(hostname -d 2>/dev/null || echo 'company.com')"
    ask "SMTP сервер (host:port)" ALERT_SMTP_HOST "smtp.company.com:587"
    ask "SMTP логин" ALERT_SMTP_USER "$ALERT_EMAIL_FROM"
    ask "SMTP пароль" ALERT_SMTP_PASSWORD "" secret
else
    ALERT_EMAIL_FROM=""; ALERT_SMTP_HOST=""; ALERT_SMTP_USER=""; ALERT_SMTP_PASSWORD=""
fi

echo ""
echo -e "${CYAN}── 5. SSH-доступ к MySQL-серверам ────────────────────${NC}"
echo -e "  ${YELLOW}Учётная запись, под которой ставятся экспортёры.${NC}"
echo -e "  ${YELLOW}Команды выполняются через sudo, поэтому на MySQL-серверах нужно:${NC}"
echo -e "  ${YELLOW}  echo '<user> ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mysql_monit${NC}"
ask "SSH-пользователь" SSH_USER "${USER:-$(id -un)}"
ask "SSH-порт" SSH_PORT "22"
ask "Путь к SSH-ключу (Enter — ключ по умолчанию/агент)" SSH_KEY ""

echo ""
echo -e "${CYAN}── 6. Python-репозиторий (pip) ───────────────────────${NC}"
echo -e "  ${YELLOW}Enter — публичный PyPI. Для внутреннего Nexus/Artifactory${NC}"
echo -e "  ${YELLOW}укажите URL вида https://nexus.company.ru/repository/pypi/simple${NC}"
ask "pip index-url" PIP_INDEX_URL ""
if [[ -n "${PIP_INDEX_URL}" ]]; then
    PIP_HOST_GUESS=$(printf '%s' "$PIP_INDEX_URL" | sed -E 's#^[a-z]+://##; s#^[^@]*@##; s#[:/].*$##')
    echo -e "  ${YELLOW}extra-index-url — если во внутреннем репо есть не все пакеты${NC}"
    ask "pip extra-index-url (Enter — не нужен)" PIP_EXTRA_INDEX_URL ""
    echo -e "  ${YELLOW}trusted-host — для http или самоподписанного сертификата${NC}"
    ask "pip trusted-host (Enter — не нужен)" PIP_TRUSTED_HOST "$PIP_HOST_GUESS"
    echo -e "  ${YELLOW}CA-сертификат — если репозиторий за корпоративным TLS${NC}"
    ask "Путь к CA-бандлу (Enter — системный)" PIP_CERT ""
else
    PIP_EXTRA_INDEX_URL=""; PIP_TRUSTED_HOST=""; PIP_CERT=""
fi

echo ""
echo -e "${CYAN}── 7. Зеркала для скачивания ─────────────────────────${NC}"
echo -e "  ${YELLOW}Подменяется только домен, путь достраивается как на оригинале:${NC}"
echo -e "  ${YELLOW}  https://my.ru/proxy  →  https://my.ru/proxy/prometheus/node_exporter/...${NC}"
ask "Зеркало GitHub (бинари экспортёров/Prometheus)" GITHUB_BASE_URL "https://github.com"
echo -e "  ${YELLOW}  https://my.ru/graf   →  https://my.ru/graf/api/dashboards/1860/...${NC}"
ask "Зеркало grafana.com (дашборды)" GRAFANA_COM_URL "https://grafana.com"

# Убрать хвостовой слэш — пути везде добавляются со своим
GITHUB_BASE_URL="${GITHUB_BASE_URL%/}"
GRAFANA_COM_URL="${GRAFANA_COM_URL%/}"

echo ""
echo -e "${CYAN}── 8. Обратный прокси (nginx) ────────────────────────${NC}"
echo -e "  ${YELLOW}Подпути, на которых сервисы видны снаружи. Enter — сервис${NC}"
echo -e "  ${YELLOW}не проксируется (доступен напрямую по своему порту).${NC}"

# Привести подпуть к виду /path: без хвостового слэша, пусто = не проксируется
norm_path() { # имя переменной
    local v="${!1}"
    v="/${v#/}"; v="${v%/}"
    [[ "$v" == "/" ]] && v=""
    eval "$1=\"\$v\""
}

ask "Подпуть AI-агента (напр. /ai-agent)"      ROOT_PATH              ""
ask "Подпуть Prometheus (напр. /prometheus)"   PROMETHEUS_ROOT_PATH   ""
ask "Подпуть Alertmanager (напр. /alertmanager)" ALERTMANAGER_ROOT_PATH ""
norm_path ROOT_PATH
norm_path PROMETHEUS_ROOT_PATH
norm_path ALERTMANAGER_ROOT_PATH

# Подпути хватает самого по себе: Prometheus и Alertmanager начнут отдаваться
# под ним. Внешний адрес — необязательное дополнение: он нужен только чтобы
# ссылки В АЛЕРТАХ (generatorURL, silence) вели наружу, а не на localhost.
if [[ -n "$PROMETHEUS_ROOT_PATH" || -n "$ALERTMANAGER_ROOT_PATH" ]]; then
    echo ""
    echo -e "  ${YELLOW}Необязательно: внешний адрес сервера. Нужен только для${NC}"
    echo -e "  ${YELLOW}ссылок в алертах. Enter — пропустить, подпути и так будут${NC}"
    echo -e "  ${YELLOW}работать.${NC}"
    ask "Внешний адрес сервера (Enter — пропустить)" EXTERNAL_BASE_URL ""
    EXTERNAL_BASE_URL="${EXTERNAL_BASE_URL%/}"
    if [[ -n "$EXTERNAL_BASE_URL" ]]; then
        PROMETHEUS_EXTERNAL_URL="${EXTERNAL_BASE_URL}${PROMETHEUS_ROOT_PATH}"
        ALERTMANAGER_EXTERNAL_URL="${EXTERNAL_BASE_URL}${ALERTMANAGER_ROOT_PATH}"
    else
        PROMETHEUS_EXTERNAL_URL=""
        ALERTMANAGER_EXTERNAL_URL=""
    fi
else
    EXTERNAL_BASE_URL=""
    PROMETHEUS_EXTERNAL_URL=""
    ALERTMANAGER_EXTERNAL_URL=""
fi

echo ""
echo -e "${CYAN}── 9. Порты и версии (Enter — по умолчанию) ──────────${NC}"
ask "Порт AI-агента" AGENT_PORT "5001"
ask "Prometheus retention" PROMETHEUS_RETENTION "30d"
echo -e "  ${YELLOW}История алертов хранится в SQLite рядом с агентом${NC}"
ask "Хранить алерты, дней" ALERTS_RETENTION_DAYS "30"
ask "Хранить историю чатов, дней" CHATS_RETENTION_DAYS "30"

echo -e "  ${YELLOW}Токен для приёма алертов из внешних систем (Zabbix и т.п.)${NC}"
echo -e "  ${YELLOW}Enter — сгенерировать новый, минус (-) — выключить приём${NC}"
ask "Токен приёма алертов" INGEST_TOKENS ""
if [[ "${INGEST_TOKENS}" == "-" ]]; then
    INGEST_TOKENS=""
elif [[ -z "${INGEST_TOKENS}" ]]; then
    INGEST_TOKENS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    echo -e "  ${GREEN}✓ Токен сгенерирован (будет в config.env)${NC}"
fi

echo ""
echo -e "${CYAN}── 10. Аутентификация ────────────────────────────────${NC}"
echo -e "  ${YELLOW}Веб-интерфейс закрывается формой входа.${NC}"
ask "Включить аутентификацию (true/false)" AUTH_ENABLED "true"

if [[ "${AUTH_ENABLED}" == "true" ]]; then
    # ── Локальный админ ──────────────────────────────────────────────────────
    ask "Логин локального администратора" AUTH_ADMIN_USER "admin"
    echo -e "  ${YELLOW}Пароль хранится только в виде PBKDF2-хеша${NC}"
    if [[ -n "${AUTH_ADMIN_PASSWORD_HASH:-}" ]]; then
        echo -e "  ${YELLOW}Хеш уже задан — Enter, чтобы оставить прежний пароль${NC}"
    fi
    read -rsp "  Пароль администратора: " ADMIN_PW1; echo ""
    if [[ -n "$ADMIN_PW1" ]]; then
        read -rsp "  Повторите пароль: " ADMIN_PW2; echo ""
        if [[ "$ADMIN_PW1" != "$ADMIN_PW2" ]]; then
            echo -e "  ${YELLOW}! Пароли не совпадают — прежний хеш оставлен${NC}"
        elif [[ ${#ADMIN_PW1} -lt 8 ]]; then
            echo -e "  ${YELLOW}! Пароль короче 8 символов — прежний хеш оставлен${NC}"
        else
            AUTH_ADMIN_PASSWORD_HASH=$(ADMIN_PW="$ADMIN_PW1" python3 -c '
import hashlib, os, secrets
pw   = os.environ["ADMIN_PW"]
salt = secrets.token_hex(16)
it   = 200000
dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), it)
print(f"pbkdf2_sha256${it}${salt}${dk.hex()}")
')
            echo -e "  ${GREEN}✓ Хеш пароля обновлён${NC}"
        fi
    fi
    unset ADMIN_PW1 ADMIN_PW2

    # Секрет подписи сессий: генерируем один раз и сохраняем, иначе после
    # каждого рестарта агента все пользователи вылетают из сессии
    if [[ -z "${AUTH_SECRET:-}" ]]; then
        AUTH_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
        echo -e "  ${GREEN}✓ Сгенерирован секрет подписи сессий${NC}"
    fi
    ask "Время жизни сессии, часов" AUTH_SESSION_TTL_HOURS "12"

    # ── LDAP / Active Directory ──────────────────────────────────────────────
    echo ""
    echo -e "  ${CYAN}LDAP / Active Directory${NC}"
    echo -e "  ${YELLOW}Enter в первом вопросе — не использовать${NC}"
    ask "Включить LDAP (true/false)" LDAP_ENABLED "false"
    if [[ "${LDAP_ENABLED}" == "true" ]]; then
        ask "URL контроллера домена" LDAP_URL "ldaps://dc.company.ru:636"
        echo -e "  ${YELLOW}Шаблон bind: {username} подставляется. Для AD обычно UPN${NC}"
        ask "Шаблон bind-DN" LDAP_BIND_TEMPLATE '{username}@company.ru'
        echo -e "  ${YELLOW}Ниже — только если нужно ограничить доступ группой${NC}"
        ask "Base DN (Enter — без проверки группы)" LDAP_BASE_DN ""
        if [[ -n "${LDAP_BASE_DN}" ]]; then
            ask "Фильтр поиска пользователя" LDAP_USER_FILTER '(sAMAccountName={username})'
            echo -e "  ${YELLOW}Группы, членам которых разрешён вход.${NC}"
            echo -e "  ${YELLOW}Несколько — через точку с запятой (в DN есть запятые).${NC}"
            echo -e "  ${YELLOW}Enter — вход только по явно выданным доступам.${NC}"
            ask "Группы доступа (DN через ;)" LDAP_ALLOWED_GROUPS ""
            echo -e "  ${YELLOW}Учитывать вложенные группы AD (обычно да)${NC}"
            ask "Вложенные группы (true/false)" LDAP_NESTED_GROUPS "true"
            echo -e "  ${YELLOW}Netgroup (nisNetgroup) — если состав описан ими,${NC}"
            echo -e "  ${YELLOW}как в nslcd. Имена (cn) через точку с запятой.${NC}"
            ask "Netgroup доступа (cn через ;)" LDAP_ALLOWED_NETGROUPS ""
            if [[ -n "${LDAP_ALLOWED_NETGROUPS:-}" ]]; then
                echo -e "  ${YELLOW}Ветка netgroup. Enter — искать от общего Base DN${NC}"
                ask "Base DN для netgroup" LDAP_NETGROUP_BASE ""
            fi
        fi
        ask "Проверять TLS-сертификат (true/false)" LDAP_TLS_VERIFY "true"
        echo -e "  ${YELLOW}Сервисная учётка нужна, чтобы выдавать доступ выбором${NC}"
        echo -e "  ${YELLOW}из каталога, а не вводом логина руками${NC}"
        ask "Сервисная учётка для поиска (Enter — без поиска)" LDAP_SEARCH_USER ""
        if [[ -n "${LDAP_SEARCH_USER}" ]]; then
            ask "Пароль сервисной учётки" LDAP_SEARCH_PASSWORD "" secret
            [[ -z "${LDAP_BASE_DN}" ]] && ask "Base DN (нужен для поиска)" LDAP_BASE_DN ""
        else
            LDAP_SEARCH_PASSWORD=""
        fi
        echo -e "  ${YELLOW}Нужен пакет ldap3 — install_agent.sh поставит его сам${NC}"
    else
        LDAP_URL=""; LDAP_BIND_TEMPLATE=""; LDAP_BASE_DN=""
        LDAP_USER_FILTER=""; LDAP_ALLOWED_GROUPS=""; LDAP_NESTED_GROUPS="true"
        LDAP_ALLOWED_NETGROUPS=""; LDAP_NETGROUP_BASE=""
        LDAP_TLS_VERIFY="true"
        LDAP_SEARCH_USER=""; LDAP_SEARCH_PASSWORD=""
    fi

    # ── OIDC (встроенный) ────────────────────────────────────────────────────
    echo ""
    echo -e "  ${CYAN}OIDC / OAuth2${NC}"
    echo -e "  ${YELLOW}Keycloak, Entra ID, Authentik и т.п.${NC}"
    ask "Включить OIDC (true/false)" OIDC_ENABLED "false"
    if [[ "${OIDC_ENABLED}" == "true" ]]; then
        ask "Issuer URL" OIDC_ISSUER "https://sso.company.ru/realms/main"
        ask "Client ID" OIDC_CLIENT_ID "mysql-ai-agent"
        ask "Client secret (Enter — публичный клиент с PKCE)" OIDC_CLIENT_SECRET "" secret
        echo -e "  ${YELLOW}Должен совпадать с зарегистрированным у провайдера${NC}"
        DEFAULT_REDIRECT="${EXTERNAL_BASE_URL:-http://${MONITORING_IP}:${AGENT_PORT}}${ROOT_PATH}/auth/oidc/callback"
        ask "Redirect URI" OIDC_REDIRECT_URL "$DEFAULT_REDIRECT"
        ask "Scopes" OIDC_SCOPES "openid profile email"
        echo -e "  ${YELLOW}Поле userinfo с логином. Entra/AD — preferred_username${NC}"
        ask "Claim с именем пользователя" OIDC_USERNAME_CLAIM "preferred_username"
        ask "Надпись на кнопке входа" OIDC_BUTTON_TEXT "Войти через SSO"
        ask "Проверять TLS провайдера (true/false)" OIDC_TLS_VERIFY "true"
    else
        OIDC_ISSUER=""; OIDC_CLIENT_ID=""; OIDC_CLIENT_SECRET=""
        OIDC_REDIRECT_URL=""; OIDC_SCOPES="openid profile email"
        OIDC_USERNAME_CLAIM="preferred_username"
        OIDC_BUTTON_TEXT="Войти через SSO"; OIDC_TLS_VERIFY="true"
    fi

    # ── SSO через доверенный прокси ──────────────────────────────────────────
    echo ""
    echo -e "  ${CYAN}SSO через обратный прокси${NC}"
    echo -e "  ${YELLOW}nginx (Kerberos/SAML/oauth2-proxy) аутентифицирует${NC}"
    echo -e "  ${YELLOW}пользователя и передаёт имя заголовком${NC}"
    ask "Включить SSO (true/false)" SSO_ENABLED "false"
    if [[ "${SSO_ENABLED}" == "true" ]]; then
        ask "Заголовок с именем пользователя" SSO_HEADER "X-Remote-User"
        echo -e "  ${YELLOW}ВАЖНО: заголовку верим только с этих адресов,${NC}"
        echo -e "  ${YELLOW}иначе кто угодно подставит себе чужое имя${NC}"
        ask "Доверенные адреса прокси (через запятую)" SSO_TRUSTED_PROXIES "127.0.0.1,::1"
        ask "URL выхода из SSO (Enter — нет)" SSO_LOGOUT_URL ""
    else
        SSO_HEADER="X-Remote-User"; SSO_TRUSTED_PROXIES="127.0.0.1,::1"; SSO_LOGOUT_URL=""
    fi
else
    AUTH_ADMIN_USER="admin"; AUTH_ADMIN_PASSWORD_HASH=""; AUTH_SECRET=""
    AUTH_SESSION_TTL_HOURS="12"
    LDAP_ENABLED="false"; LDAP_URL=""; LDAP_BIND_TEMPLATE=""; LDAP_BASE_DN=""
    LDAP_USER_FILTER=""; LDAP_REQUIRED_GROUP=""; LDAP_TLS_VERIFY="true"
    LDAP_ALLOWED_NETGROUPS=""; LDAP_NETGROUP_BASE=""
    SSO_ENABLED="false"; SSO_HEADER="X-Remote-User"
    SSO_TRUSTED_PROXIES="127.0.0.1,::1"; SSO_LOGOUT_URL=""
    LDAP_SEARCH_USER=""; LDAP_SEARCH_PASSWORD=""
    OIDC_ENABLED="false"; OIDC_ISSUER=""; OIDC_CLIENT_ID=""; OIDC_CLIENT_SECRET=""
    OIDC_REDIRECT_URL=""; OIDC_SCOPES="openid profile email"
    OIDC_USERNAME_CLAIM="preferred_username"
    OIDC_BUTTON_TEXT="Войти через SSO"; OIDC_TLS_VERIFY="true"
    echo -e "  ${YELLOW}! Интерфейс будет открыт всем, у кого есть сетевой доступ${NC}"
fi

# Версии — фиксированные, но настраиваемые
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-2.52.0}"
NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION:-1.8.2}"
MYSQLD_EXPORTER_VERSION="${MYSQLD_EXPORTER_VERSION:-0.15.1}"
ALERTMANAGER_VERSION="${ALERTMANAGER_VERSION:-0.27.0}"

# ── Запись конфига ────────────────────────────────────────────────────────────
cat > "$CONFIG_FILE" << EOF
# =============================================================================
#  MySQL AI Monitoring — конфигурация
#  Сгенерировано configure.sh $(date '+%Y-%m-%d %H:%M:%S')
#  Для изменения: ./configure.sh (повторный запуск) или правьте вручную
# =============================================================================

# Сервер мониторинга
MONITORING_IP="${MONITORING_IP}"

# Удалённая LLM (OpenAI-совместимый API: /chat/completions)
LLM_BASE_URL="${LLM_BASE_URL}"
LLM_API_KEY=$(sq "${LLM_API_KEY}")
LLM_MODEL="${LLM_MODEL}"
LLM_MAX_TOKENS=${LLM_MAX_TOKENS}
LLM_TEMPERATURE=${LLM_TEMPERATURE}

# Grafana
GRAFANA_ADMIN_PASSWORD=$(sq "${GRAFANA_ADMIN_PASSWORD}")

# Alertmanager email (пусто = отключено)
ALERT_EMAIL_TO="${ALERT_EMAIL_TO}"
ALERT_EMAIL_FROM="${ALERT_EMAIL_FROM}"
ALERT_SMTP_HOST="${ALERT_SMTP_HOST}"
ALERT_SMTP_USER="${ALERT_SMTP_USER}"
ALERT_SMTP_PASSWORD=$(sq "${ALERT_SMTP_PASSWORD}")

# SSH-доступ к MySQL-серверам (установка экспортёров)
# Команды на удалённых серверах выполняются как: sudo -n <команда>
# Требуется NOPASSWD-правило в /etc/sudoers.d/ на каждом MySQL-сервере.
SSH_USER="${SSH_USER}"
SSH_PORT=${SSH_PORT}
SSH_KEY="${SSH_KEY}"

# Python-репозиторий для установки зависимостей агента
# Пусто = публичный PyPI. Может содержать логин:пароль в URL,
# поэтому config.env создаётся с правами 600.
PIP_INDEX_URL="${PIP_INDEX_URL}"
PIP_EXTRA_INDEX_URL="${PIP_EXTRA_INDEX_URL}"
PIP_TRUSTED_HOST="${PIP_TRUSTED_HOST}"
PIP_CERT="${PIP_CERT}"

# Зеркала для скачивания. Подменяют только схему+домен(+префикс пути),
# остальной путь скрипты достраивают сами.
#   ${GITHUB_BASE_URL}/prometheus/node_exporter/releases/download/v<ver>/<file>
#   ${GRAFANA_COM_URL}/api/dashboards/<id>/revisions/latest/download
GITHUB_BASE_URL="${GITHUB_BASE_URL}"
GRAFANA_COM_URL="${GRAFANA_COM_URL}"

# ── Аутентификация ───────────────────────────────────────────────────────────
# Пароль администратора хранится ТОЛЬКО хешем (PBKDF2-SHA256, 200k итераций).
# AUTH_SECRET подписывает сессионные cookie — при его смене все сессии слетают.
AUTH_ENABLED="${AUTH_ENABLED}"
AUTH_ADMIN_USER="${AUTH_ADMIN_USER}"
AUTH_ADMIN_PASSWORD_HASH=$(sq "${AUTH_ADMIN_PASSWORD_HASH}")
AUTH_SECRET=$(sq "${AUTH_SECRET}")
AUTH_SESSION_TTL_HOURS=${AUTH_SESSION_TTL_HOURS}

# LDAP / Active Directory
LDAP_ENABLED="${LDAP_ENABLED}"
LDAP_URL="${LDAP_URL}"
LDAP_BIND_TEMPLATE="${LDAP_BIND_TEMPLATE}"
LDAP_BASE_DN="${LDAP_BASE_DN}"
LDAP_USER_FILTER="${LDAP_USER_FILTER}"
# Группы, членам которых разрешён вход. Несколько — через «;».
# Пусто = вход только по явно выданным доступам.
LDAP_ALLOWED_GROUPS="${LDAP_ALLOWED_GROUPS}"
LDAP_NESTED_GROUPS="${LDAP_NESTED_GROUPS}"
# Netgroup (nisNetgroup): имена через «;». Членство лежит в самой netgroup,
# в триплетах (хост,пользователь,домен), а не в memberOf у пользователя.
LDAP_ALLOWED_NETGROUPS="${LDAP_ALLOWED_NETGROUPS:-}"
# Своя ветка netgroup (в nslcd — строка "base netgroup ...").
# Пусто — искать от LDAP_BASE_DN.
LDAP_NETGROUP_BASE="${LDAP_NETGROUP_BASE:-}"
LDAP_NETGROUP_FILTER="${LDAP_NETGROUP_FILTER:-(objectClass=nisNetgroup)}"
LDAP_TLS_VERIFY="${LDAP_TLS_VERIFY}"
# Сервисная учётка — только для поиска по каталогу при выдаче доступов
# Фильтр поиска людей во вкладке «Доступы». Пусто — агент соберёт его сам
# из атрибутов, которые есть в схеме каталога. Подстановка: {query}
LDAP_SEARCH_FILTER="${LDAP_SEARCH_FILTER:-}"
# Откуда дозаполнять пустые настройки LDAP. Пусто — не читать
NSLCD_CONF="${NSLCD_CONF:-/etc/nslcd.conf}"
LDAP_SEARCH_USER="${LDAP_SEARCH_USER}"
LDAP_SEARCH_PASSWORD=$(sq "${LDAP_SEARCH_PASSWORD}")

# OIDC (встроенный, Authorization Code + PKCE)
OIDC_ENABLED="${OIDC_ENABLED}"
OIDC_ISSUER="${OIDC_ISSUER}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID}"
OIDC_CLIENT_SECRET=$(sq "${OIDC_CLIENT_SECRET}")
OIDC_REDIRECT_URL="${OIDC_REDIRECT_URL}"
OIDC_SCOPES="${OIDC_SCOPES}"
OIDC_USERNAME_CLAIM="${OIDC_USERNAME_CLAIM}"
OIDC_BUTTON_TEXT="${OIDC_BUTTON_TEXT}"
OIDC_TLS_VERIFY="${OIDC_TLS_VERIFY}"

# SSO через доверенный обратный прокси
SSO_ENABLED="${SSO_ENABLED}"
SSO_HEADER="${SSO_HEADER}"
SSO_TRUSTED_PROXIES="${SSO_TRUSTED_PROXIES}"
SSO_LOGOUT_URL="${SSO_LOGOUT_URL}"

# Порты
AGENT_PORT=${AGENT_PORT}

# ── Обратный прокси ──────────────────────────────────────────────────────────
# Подпути, на которых сервисы видны снаружи. Пусто = сервис не проксируется.
# Во всех трёх случаях префикс срезает nginx (proxy_pass со слэшем на конце),
# а сами сервисы продолжают отвечать в корне — эти значения нужны им только
# чтобы правильно строить собственные ссылки.
ROOT_PATH="${ROOT_PATH}"
PROMETHEUS_ROOT_PATH="${PROMETHEUS_ROOT_PATH}"
ALERTMANAGER_ROOT_PATH="${ALERTMANAGER_ROOT_PATH}"

# Полные внешние адреса (--web.external-url) — считаются из адреса сервера
EXTERNAL_BASE_URL="${EXTERNAL_BASE_URL}"
PROMETHEUS_EXTERNAL_URL="${PROMETHEUS_EXTERNAL_URL}"
ALERTMANAGER_EXTERNAL_URL="${ALERTMANAGER_EXTERNAL_URL}"

# Prometheus
PROMETHEUS_VERSION="${PROMETHEUS_VERSION}"
PROMETHEUS_RETENTION="${PROMETHEUS_RETENTION}"

# История алертов агента (SQLite). Записи старше окна удаляются автоматически.
ALERTS_RETENTION_DAYS=${ALERTS_RETENTION_DAYS}

# История чатов (та же БД). Пользователь опознаётся по client_id браузера.
CHATS_RETENTION_DAYS=${CHATS_RETENTION_DAYS}

# Токены для POST /api/alerts/ingest (несколько — через запятую).
# Пусто = приём алертов из внешних систем выключен.
INGEST_TOKENS=$(sq "${INGEST_TOKENS}")

# Версии экспортёров
NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION}"
MYSQLD_EXPORTER_VERSION="${MYSQLD_EXPORTER_VERSION}"
ALERTMANAGER_VERSION="${ALERTMANAGER_VERSION}"
EOF

chmod 600 "$CONFIG_FILE"

echo ""
echo -e "${GREEN}✓ Конфигурация сохранена: ${CONFIG_FILE}${NC}"
echo ""

# ── Тест LLM соединения ───────────────────────────────────────────────────────
echo -e "${CYAN}── Проверка соединения с LLM ─────────────────────────${NC}"
AUTH="${LLM_API_KEY}"
[[ "$AUTH" != Bearer\ * ]] && AUTH="Bearer ${AUTH}"

HTTP_CODE=$(curl -s -o /tmp/llm_test.json -w "%{http_code}" \
    -X POST "${LLM_BASE_URL}/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: ${AUTH}" \
    -d "{\"model\":\"${LLM_MODEL}\",\"max_tokens\":20,\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}" \
    --max-time 20 2>/dev/null || true)

if [[ "$HTTP_CODE" == "200" ]]; then
    echo -e "  ${GREEN}✓ LLM отвечает (HTTP 200)${NC}"
elif [[ "$HTTP_CODE" == "000" ]]; then
    echo -e "  ${YELLOW}! Не удалось подключиться к ${LLM_BASE_URL}${NC}"
    echo -e "  ${YELLOW}  Проверьте URL и сетевую доступность. Установку можно продолжить.${NC}"
else
    echo -e "  ${YELLOW}! LLM вернул HTTP ${HTTP_CODE}${NC}"
    head -c 300 /tmp/llm_test.json 2>/dev/null && echo ""
    echo -e "  ${YELLOW}  Проверьте токен и название модели. Установку можно продолжить.${NC}"
fi
rm -f /tmp/llm_test.json

# ── Тест pip-репозитория ──────────────────────────────────────────────────────
if [[ -n "${PIP_INDEX_URL}" ]]; then
    echo ""
    echo -e "${CYAN}── Проверка pip-репозитория ──────────────────────────${NC}"
    # Скрыть логин:пароль в выводе
    PIP_SHOWN=$(printf '%s' "$PIP_INDEX_URL" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#')

    PIP_CURL=(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -L)
    if [[ -n "${PIP_CERT}" ]]; then
        PIP_CURL+=(--cacert "${PIP_CERT}")
    elif [[ -n "${PIP_TRUSTED_HOST}" ]]; then
        PIP_CURL+=(-k)   # самоподписанный сертификат — как trusted-host у pip
    fi

    # curl сам печатает 000 при сбое соединения; без `|| true` ненулевой
    # код возврата добавил бы вторую строку и сломал сравнение.
    PIP_CODE=$("${PIP_CURL[@]}" "${PIP_INDEX_URL%/}/pip/" 2>/dev/null || true)

    case "$PIP_CODE" in
        200|301|302)
            echo -e "  ${GREEN}✓ Репозиторий отвечает: ${PIP_SHOWN}${NC}" ;;
        000)
            echo -e "  ${YELLOW}! Нет соединения с ${PIP_SHOWN}${NC}"
            echo -e "  ${YELLOW}  Проверьте URL, сеть и TLS. Установку можно продолжить.${NC}" ;;
        401|403)
            echo -e "  ${YELLOW}! HTTP ${PIP_CODE} — репозиторий доступен, но отклонил доступ${NC}"
            echo -e "  ${YELLOW}  Укажите логин:пароль в URL: https://user:token@host/...${NC}" ;;
        *)
            echo -e "  ${YELLOW}! Репозиторий вернул HTTP ${PIP_CODE}${NC}"
            echo -e "  ${YELLOW}  Убедитесь, что URL заканчивается на /simple${NC}" ;;
    esac
fi

echo ""
echo -e "${BOLD}Следующие шаги:${NC}"
echo ""
echo "  1. Добавьте кластеры:            ./manage_cluster.sh add"
echo "  2. Установите мониторинг:        sudo ./scripts/install_monitoring.sh"
echo "  3. Установите AI-агента:         sudo ./scripts/install_agent.sh"
echo "  4. Установите экспортёры:        ./manage_cluster.sh install-exporters <name>"
echo "     (SSH под '${SSH_USER}', команды через sudo — проверьте NOPASSWD на MySQL-серверах)"
echo "  5. Примените конфигурацию:       sudo ./manage_cluster.sh apply"
echo "  6. Проверьте:                    ./scripts/verify.sh"
echo ""
echo "  Или всё сразу (кроме экспортёров): sudo ./scripts/install_all.sh"
echo ""
