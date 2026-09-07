#!/usr/bin/env bash
# =============================================================================
#  manage_cluster.sh — Управление реестром MySQL-кластеров
#
#  Команды:
#    list                          — показать все кластеры
#    add                           — добавить новый кластер (интерактивно)
#    remove  <name>                — удалить кластер
#    enable  <name>                — включить мониторинг кластера
#    disable <name>                — отключить мониторинг кластера
#    show    <name>                — показать детали кластера
#    apply                         — применить реестр → пересоздать конфиги Prometheus
#    install-exporters <name>      — установить экспортёры на серверах кластера
#                                    [--user U] [--port N] [--key PATH]
#
#  Установка экспортёров идёт по SSH под учётной записью SSH_USER из config.env
#  (переопределяется флагом --user), команды на удалённом сервере выполняются
#  через sudo -n. На каждом MySQL-сервере нужно NOPASSWD-правило:
#    echo 'SSH_USER ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mysql_monit
#
#  Примеры:
#    ./manage_cluster.sh list
#    ./manage_cluster.sh add
#    ./manage_cluster.sh remove kemerovo
#    ./manage_cluster.sh apply
#    ./manage_cluster.sh install-exporters novosibirsk
#    ./manage_cluster.sh install-exporters novosibirsk --user dbadmin --port 2222
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}── $1 ──────────────────────────────────${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="${SCRIPT_DIR}/clusters.json"
CONFIG="${SCRIPT_DIR}/config.env"

[[ -f "$CONFIG" ]] && source "$CONFIG"

# Проверить наличие jq и python3
need_python() {
    command -v python3 &>/dev/null || { log_error "python3 не найден"; exit 1; }
}
need_python

# ── Вспомогательные функции ───────────────────────────────────────────────────

# Получить значение поля кластера
cluster_field() { # name field
    python3 -c "
import json, sys
d = json.load(open('$REGISTRY'))
for c in d['clusters']:
    if c['name'] == '$1':
        print(c.get('$2', ''))
        sys.exit(0)
sys.exit(1)
"
}

# Проверить существование кластера
cluster_exists() {
    python3 -c "
import json, sys
d = json.load(open('$REGISTRY'))
sys.exit(0 if any(c['name']=='$1' for c in d['clusters']) else 1)
" 2>/dev/null
}

# ── КОМАНДА: list ─────────────────────────────────────────────────────────────
cmd_list() {
    echo ""
    echo -e "${BOLD}  Реестр MySQL-кластеров${NC}"
    echo ""
    printf "  %-16s %-18s %-16s %-16s %-8s %s\n" \
        "NAME" "LABEL" "PRIMARY" "REPLICA" "STATUS" "TAGS"
    printf "  %s\n" "$(printf '%.0s─' {1..90})"

    python3 - "$REGISTRY" << 'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
for c in d['clusters']:
    status = "✓ enabled" if c.get('enabled', True) else "✗ disabled"
    tags   = ",".join(c.get('tags', []))
    print(f"  {c['name']:<16} {c['label']:<18} {c['primary_ip']:<16} "
          f"{c.get('replica_ip','—'):<16} {status:<10} {tags}")
EOF
    echo ""
    TOTAL=$(python3 -c "import json;d=json.load(open('$REGISTRY'));print(len(d['clusters']))")
    ENABLED=$(python3 -c "import json;d=json.load(open('$REGISTRY'));print(sum(1 for c in d['clusters'] if c.get('enabled',True)))")
    echo -e "  Итого: ${BOLD}${TOTAL}${NC} кластеров, ${GREEN}${ENABLED}${NC} активных"
    echo ""
}

# ── КОМАНДА: add ──────────────────────────────────────────────────────────────
cmd_add() {
    echo ""
    echo -e "${BOLD}  Добавить новый MySQL-кластер${NC}"
    echo ""

    read -rp "  Машинное имя (латиница, без пробелов, напр. kemerovo): " NAME
    NAME="${NAME// /_}"
    NAME="${NAME,,}"

    if cluster_exists "$NAME"; then
        log_error "Кластер '$NAME' уже существует"
        exit 1
    fi

    read -rp "  Отображаемое название (напр. Кемерово): "          LABEL
    read -rp "  Описание (кратко): "                               DESCRIPTION
    read -rp "  IP primary-сервера MySQL: "                        PRIMARY_IP_C
    read -rp "  IP replica-сервера (Enter — пропустить): "         REPLICA_IP_C
    DELAY_C=0
    if [[ -n "$REPLICA_IP_C" ]]; then
        echo "  Запланированное отставание реплики (MASTER_DELAY), сек."
        echo "  0 — реплика идёт в реальном времени, 7200 — отстаёт на 2 часа"
        read -rp "  Задержка реплики, сек [7200]: "                   DELAY_C
        DELAY_C="${DELAY_C:-7200}"
        [[ "$DELAY_C" =~ ^[0-9]+$ ]] || { log_error "Задержка должна быть целым числом секунд"; exit 1; }
    fi
    echo "  Учётка для SQL-запросов агента (только SELECT)."
    echo "  Одна на все серверы кластера. Enter — запросы к БД отключить."
    read -rp  "  Логин для SQL-запросов (Enter — пропустить): "      DB_USER_C
    DB_PASS_C=""
    if [[ -n "$DB_USER_C" ]]; then
        read -rsp "  Пароль этой учётки: "                            DB_PASS_C
        echo ""
    fi
    read -rsp "  Пароль пользователя exporter в MySQL: "           EXPORTER_PASS
    echo ""
    read -rp "  Теги через запятую (напр. siberia,production): "   TAGS_STR

    IFS=',' read -ra TAGS_ARR <<< "$TAGS_STR"
    TAGS_JSON=$(python3 -c "
import json, sys
tags = [t.strip() for t in sys.argv[1].split(',') if t.strip()]
print(json.dumps(tags))
" "$TAGS_STR")

    python3 - "$REGISTRY" << EOF
import json

with open('$REGISTRY', 'r') as f:
    d = json.load(f)

new_cluster = {
    "name":                    "$NAME",
    "label":                   "$LABEL",
    "description":             "$DESCRIPTION",
    "primary_ip":              "$PRIMARY_IP_C",
    "replica_ip":              "$REPLICA_IP_C",
    "replica_delay_seconds":   $DELAY_C,
    "mysql_exporter_password": "$EXPORTER_PASS",
    "db_user":                 "$DB_USER_C",
    "db_password":             "$DB_PASS_C",
    "enabled":                 True,
    "tags":                    $TAGS_JSON,
}
d['clusters'].append(new_cluster)

with open('$REGISTRY', 'w') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
print("OK")
EOF

    log_info "Кластер '${LABEL}' (${NAME}) добавлен ✓"
    echo ""
    log_warn "Следующие шаги:"
    echo "  1. Установить экспортёры:  ./manage_cluster.sh install-exporters ${NAME}"
    echo "  2. Применить конфиги:      ./manage_cluster.sh apply"
    echo "  3. Перезапустить агент:    sudo systemctl restart ai-alert-agent"
}

# ── КОМАНДА: remove ───────────────────────────────────────────────────────────
cmd_remove() {
    local NAME="$1"
    cluster_exists "$NAME" || { log_error "Кластер '$NAME' не найден"; exit 1; }

    LABEL=$(cluster_field "$NAME" "label")
    read -rp "Удалить кластер '${LABEL}' (${NAME})? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { log_warn "Отменено"; exit 0; }

    python3 - "$REGISTRY" "$NAME" << 'EOF'
import json, sys
with open(sys.argv[1], 'r') as f:
    d = json.load(f)
d['clusters'] = [c for c in d['clusters'] if c['name'] != sys.argv[2]]
with open(sys.argv[1], 'w') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
EOF
    log_info "Кластер '${LABEL}' удалён"
    log_warn "Запустите ./manage_cluster.sh apply для обновления конфигов"
}

# ── КОМАНДА: enable / disable ─────────────────────────────────────────────────
cmd_set_enabled() {
    local NAME="$1"; local VALUE="$2"
    cluster_exists "$NAME" || { log_error "Кластер '$NAME' не найден"; exit 1; }

    python3 - "$REGISTRY" "$NAME" "$VALUE" << 'EOF'
import json, sys
with open(sys.argv[1], 'r') as f:
    d = json.load(f)
for c in d['clusters']:
    if c['name'] == sys.argv[2]:
        c['enabled'] = (sys.argv[3] == 'true')
with open(sys.argv[1], 'w') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
EOF
    local ACTION; [[ "$VALUE" == "true" ]] && ACTION="включён" || ACTION="отключён"
    log_info "Кластер '${NAME}' ${ACTION}"
    log_warn "Запустите ./manage_cluster.sh apply"
}

# ── КОМАНДА: show ─────────────────────────────────────────────────────────────
cmd_show() {
    local NAME="$1"
    cluster_exists "$NAME" || { log_error "Кластер '$NAME' не найден"; exit 1; }

    python3 - "$REGISTRY" "$NAME" << 'EOF'
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
for c in d['clusters']:
    if c['name'] == sys.argv[2]:
        print(f"\n  Кластер: {c['label']} ({c['name']})")
        print(f"  Описание:  {c.get('description','')}")
        print(f"  Primary:   {c['primary_ip']}:9104")
        print(f"  Replica:   {c.get('replica_ip','—')}")
        if c.get('replica_ip'):
            d_s = int(c.get('replica_delay_seconds', 0) or 0)
            human = f"{d_s // 3600} ч {d_s % 3600 // 60} мин" if d_s else "нет (реальное время)"
            print(f"  Задержка:  {human}" + (f" ({d_s} с)" if d_s else ""))
        print(f"  Статус:    {'✓ enabled' if c.get('enabled',True) else '✗ disabled'}")
        print(f"  Теги:      {', '.join(c.get('tags',[]))}")
        break
EOF
}

# ── КОМАНДА: apply — пересоздать конфиги Prometheus ──────────────────────────
cmd_apply() {
    log_section "Генерация конфигов из реестра"

    PROM_CFG="/etc/prometheus/prometheus.yml"
    RULES_DIR="/etc/prometheus/rules"

    if [[ ! -f "$PROM_CFG" ]]; then
        log_warn "Prometheus не установлен ($PROM_CFG не найден)"
        log_warn "Запустите сначала: sudo ./scripts/02_install_monitoring.sh"
        exit 1
    fi

    # Генерируем scrape_configs из реестра
    # Если Prometheus/Alertmanager отдают себя под своим путём, это влияет
    # на собственный scrape-таргет и на адрес Alertmanager в конфиге.
    python3 - "$REGISTRY" "$PROM_CFG" \
             "${PROMETHEUS_ROOT_PATH:-}" "${ALERTMANAGER_ROOT_PATH:-}" << 'EOF'
import json, sys

with open(sys.argv[1], encoding='utf-8') as f:
    data = json.load(f)

prom_prefix = (sys.argv[3] if len(sys.argv) > 3 else "").rstrip("/")
am_prefix   = (sys.argv[4] if len(sys.argv) > 4 else "").rstrip("/")

# При заданном подпуте ходим через nginx — без порта; иначе прямо в порт.
prom_target = "localhost" if prom_prefix else "localhost:9090"
am_target   = "localhost" if am_prefix   else "localhost:9093"

clusters = [c for c in data['clusters'] if c.get('enabled', True)]

scrape_configs = []
for c in clusters:
    name     = c['name']
    label    = c['label']
    prim_ip  = c['primary_ip']
    repl_ip  = c.get('replica_ip', '')

    mysql_targets = [f"{prim_ip}:9104"]
    node_targets  = [f"{prim_ip}:9100"]
    if repl_ip:
        mysql_targets.append(f"{repl_ip}:9104")
        node_targets.append(f"{repl_ip}:9100")

    scrape_configs.append(f"""
  # ── {label} ──
  - job_name: 'mysql_{name}'
    static_configs:
      - targets: ['{prim_ip}:9104']
        labels:
          cluster: '{name}'
          cluster_label: '{label}'
          role: primary
          env: production""")
    if repl_ip:
        scrape_configs.append(f"""      - targets: ['{repl_ip}:9104']
        labels:
          cluster: '{name}'
          cluster_label: '{label}'
          role: replica
          env: production""")

    scrape_configs.append(f"""
  - job_name: 'node_{name}'
    static_configs:
      - targets: ['{prim_ip}:9100']
        labels:
          cluster: '{name}'
          cluster_label: '{label}'
          role: primary""")
    if repl_ip:
        scrape_configs.append(f"""      - targets: ['{repl_ip}:9100']
        labels:
          cluster: '{name}'
          cluster_label: '{label}'
          role: replica""")

scrape_block = "\n".join(scrape_configs)

# Prometheus под своим путём отдаёт метрики на <префикс>/metrics
prom_path_line = (f"\n    metrics_path: '{prom_prefix}/metrics'"
                  if prom_prefix else "")
# и Alertmanager тогда доступен по <префикс>, а не в корне
am_path_line   = (f"\n      path_prefix: '{am_prefix}/'"
                  if am_prefix else "")

config = f"""global:
  scrape_interval:     15s
  evaluation_interval: 15s
  external_labels:
    env: production

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['{am_target}']{am_path_line}

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:

  - job_name: 'prometheus'{prom_path_line}
    static_configs:
      - targets: ['{prom_target}']
{scrape_block}
"""
# encoding явно: при locale C запись кириллицы в метках иначе падает
with open(sys.argv[2], 'w', encoding='utf-8') as f:
    f.write(config)
print(f"Сгенерировано {len(clusters)} кластеров")
EOF

    # ── Recording rules: эффективный лаг реплик ───────────────────────────────
    # Реплики могут работать с намеренной задержкой (replica_delay_seconds).
    # Генератор считает отставание СВЕРХ запланированного — по нему алертим.
    GEN="${SCRIPT_DIR}/scripts/gen_replication_rules.py"
    if [[ -f "$GEN" ]]; then
        python3 "$GEN" "$REGISTRY" "${RULES_DIR}/replication_delay.yml"
    else
        log_warn "gen_replication_rules.py не найден — правила лага реплик не обновлены"
    fi

    # Перезагрузить Prometheus без рестарта
    if systemctl is-active prometheus &>/dev/null; then
        PROM_RELOAD="http://localhost:9090"
        [[ -n "${PROMETHEUS_ROOT_PATH:-}" ]] && PROM_RELOAD="${INTERNAL_BASE_URL:-http://localhost}${PROMETHEUS_ROOT_PATH}"
        curl -sf -X POST "${PROM_RELOAD}/-/reload" \
             || systemctl reload prometheus || true
        log_info "Prometheus конфиг перезагружен ✓"
    else
        log_warn "Prometheus не запущен"
    fi

    # Синхронизировать реестр с агентом и перезапустить его
    if [[ -d /opt/ai-alert-agent ]]; then
        cp "$REGISTRY" /opt/ai-alert-agent/clusters.json
        log_info "Реестр скопирован в /opt/ai-alert-agent/clusters.json"
    fi
    if systemctl is-active ai-alert-agent &>/dev/null; then
        systemctl restart ai-alert-agent
        log_info "AI Agent перезапущен ✓"
    fi

    log_info "Готово. Активных кластеров: $(python3 -c "
import json; d=json.load(open('$REGISTRY'))
print(sum(1 for c in d['clusters'] if c.get('enabled',True)))
")"
}

# ── КОМАНДА: install-exporters ────────────────────────────────────────────────

# Безопасно закавычить значение для передачи в удалённый shell.
# Одинарные кавычки внутри значения заменяются на '\'' — пароли экспортёра
# из clusters.json могут содержать пробелы, $, ` и кавычки.
shquote() {
    local s=$1 out="'"
    while [[ $s == *"'"* ]]; do
        out+="${s%%\'*}'\\''"
        s=${s#*\'}
    done
    printf "%s%s'" "$out" "$s"
}

# Подсказка по настройке sudo на удалённом сервере
_sudo_hint() { # user host
    echo ""
    log_warn "На сервере $2 выполните под root:"
    echo "    echo '$1 ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mysql_monit"
    echo "    chmod 440 /etc/sudoers.d/mysql_monit"
    echo "    visudo -c        # проверка синтаксиса"
    echo ""
    echo "  Если в sudoers включён requiretty, добавьте туда же:"
    echo "    Defaults:$1 !requiretty"
    echo ""
}

cmd_install_exporters() {
    local NAME="$1"; shift || true

    # Разовые переопределения из командной строки (приоритет над config.env)
    local OPT_USER="" OPT_PORT="" OPT_KEY=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user|-u) OPT_USER="${2:?'--user требует значение'}"; shift 2 ;;
            --port|-p) OPT_PORT="${2:?'--port требует значение'}"; shift 2 ;;
            --key|-i)  OPT_KEY="${2:?'--key требует значение'}";  shift 2 ;;
            *) log_error "Неизвестный параметр: $1"; exit 1 ;;
        esac
    done

    cluster_exists "$NAME" || { log_error "Кластер '$NAME' не найден"; exit 1; }

    LABEL=$(cluster_field "$NAME" "label")
    PRIM=$(cluster_field "$NAME" "primary_ip")
    REPL=$(cluster_field "$NAME" "replica_ip")
    PASS=$(cluster_field "$NAME" "mysql_exporter_password")

    # Учётная запись: --user > config.env SSH_USER > текущий пользователь
    local R_USER="${OPT_USER:-${SSH_USER:-$(id -un)}}"
    local R_PORT="${OPT_PORT:-${SSH_PORT:-22}}"
    local R_KEY="${OPT_KEY:-${SSH_KEY:-}}"

    if [[ "$R_USER" == "root" ]]; then
        log_warn "SSH_USER=root — обычно нужна непривилегированная учётка с sudo"
    fi
    if [[ -n "$R_KEY" && ! -f "$R_KEY" ]]; then
        log_error "SSH-ключ не найден: ${R_KEY}"
        exit 1
    fi

    local SSH_OPTS=(-o StrictHostKeyChecking=no -o BatchMode=yes
                    -o ConnectTimeout=10 -p "$R_PORT")
    [[ -n "$R_KEY" ]] && SSH_OPTS+=(-i "$R_KEY")

    log_section "Установка экспортёров для '${LABEL}'"
    log_info "Учётная запись: ${R_USER}@<host>:${R_PORT}${R_KEY:+ (ключ: ${R_KEY})}"
    log_info "Команды на серверах выполняются через sudo"
    if [[ -n "${GITHUB_BASE_URL:-}" && "${GITHUB_BASE_URL}" != "https://github.com" ]]; then
        log_info "Зеркало GitHub: ${GITHUB_BASE_URL} (должно быть доступно с MySQL-серверов)"
    fi

    EXPORTER_SCRIPT="${SCRIPT_DIR}/scripts/install_exporters.sh"
    [[ -f "$EXPORTER_SCRIPT" ]] || { log_error "install_exporters.sh не найден"; exit 1; }

    # Проверка: SSH доступен и sudo работает без пароля
    _check_host() { # host role
        local HOST="$1" ROLE="$2"
        log_info "Проверка доступа ${R_USER}@${HOST} (${ROLE})..."

        if ! ssh "${SSH_OPTS[@]}" "${R_USER}@${HOST}" true 2>/dev/null; then
            log_error "SSH-подключение к ${R_USER}@${HOST}:${R_PORT} не удалось"
            echo "  Проверьте: доступность хоста, порт, и что ключ добавлен в"
            echo "  ~${R_USER}/.ssh/authorized_keys (ssh-copy-id ${R_USER}@${HOST})"
            exit 1
        fi

        if ! ssh "${SSH_OPTS[@]}" "${R_USER}@${HOST}" 'sudo -n true' 2>/dev/null; then
            log_error "sudo без пароля недоступен для '${R_USER}' на ${HOST}"
            _sudo_hint "$R_USER" "$HOST"
            exit 1
        fi
        log_info "  ✓ SSH + sudo -n доступны"
    }

    _install_on_host() { # host role
        local HOST="$1" ROLE="$2"
        log_info "Установка на ${HOST} (${ROLE})..."

        # env вместо VAR=... перед sudo: не требует setenv в sudoers.
        # Скрипт передаётся в stdin, поэтому bash -s читает его как обычно.
        ssh "${SSH_OPTS[@]}" "${R_USER}@${HOST}" \
            "sudo -n env \
               PRIMARY_IP=$(shquote "$PRIM") \
               REPLICA_IP=$(shquote "$REPL") \
               MYSQL_EXPORTER_PASSWORD=$(shquote "$PASS") \
               MONITORING_IP=$(shquote "${MONITORING_IP:-10.0.0.100}") \
               NODE_EXPORTER_VERSION=$(shquote "${NODE_EXPORTER_VERSION:-1.8.2}") \
               MYSQLD_EXPORTER_VERSION=$(shquote "${MYSQLD_EXPORTER_VERSION:-0.15.1}") \
               GITHUB_BASE_URL=$(shquote "${GITHUB_BASE_URL:-https://github.com}") \
               bash -s" < "$EXPORTER_SCRIPT"
    }

    # Сначала проверяем все хосты, потом ставим — чтобы не оставить
    # кластер в полусобранном состоянии из-за забытого sudo на replica.
    _check_host "$PRIM" "primary"
    [[ -n "$REPL" ]] && _check_host "$REPL" "replica"

    _install_on_host "$PRIM" "primary"
    [[ -n "$REPL" ]] && _install_on_host "$REPL" "replica"

    log_info "Экспортёры установлены на кластере '${LABEL}' ✓"
    log_warn "Теперь запустите: ./manage_cluster.sh apply"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
CMD="${1:-help}"
shift || true

case "$CMD" in
    list)               cmd_list ;;
    add)                cmd_add ;;
    remove)             cmd_remove "${1:?'Укажите name кластера'}" ;;
    enable)             cmd_set_enabled "${1:?'Укажите name'}" "true" ;;
    disable)            cmd_set_enabled "${1:?'Укажите name'}" "false" ;;
    show)               cmd_show "${1:?'Укажите name'}" ;;
    apply)              cmd_apply ;;
    install-exporters)  cmd_install_exporters "${1:?'Укажите name'}" "${@:2}" ;;
    *)
        echo ""
        echo -e "${BOLD}  manage_cluster.sh — управление MySQL-кластерами${NC}"
        echo ""
        echo "  Команды:"
        echo "    list                        — список всех кластеров"
        echo "    add                         — добавить кластер (интерактивно)"
        echo "    remove  <name>              — удалить кластер"
        echo "    enable  <name>              — включить мониторинг"
        echo "    disable <name>              — отключить мониторинг"
        echo "    show    <name>              — детали кластера"
        echo "    apply                       — применить реестр в Prometheus"
        echo "    install-exporters <name> [--user U] [--port N] [--key PATH]"
        echo "                                — установить экспортёры по SSH (через sudo)"
        echo ""
        echo "  Примеры:"
        echo "    ./manage_cluster.sh list"
        echo "    ./manage_cluster.sh add"
        echo "    ./manage_cluster.sh install-exporters kemerovo"
        echo "    ./manage_cluster.sh install-exporters kemerovo --user dbadmin"
        echo "    ./manage_cluster.sh apply"
        echo ""
        echo "  SSH-учётка по умолчанию берётся из config.env (SSH_USER/SSH_PORT/SSH_KEY),"
        echo "  команды на MySQL-серверах выполняются через sudo -n (нужен NOPASSWD)."
        echo ""
        ;;
esac
