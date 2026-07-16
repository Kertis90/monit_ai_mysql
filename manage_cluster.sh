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
#
#  Примеры:
#    ./manage_cluster.sh list
#    ./manage_cluster.sh add
#    ./manage_cluster.sh remove kemerovo
#    ./manage_cluster.sh apply
#    ./manage_cluster.sh install-exporters novosibirsk
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
    "mysql_exporter_password": "$EXPORTER_PASS",
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
    python3 - "$REGISTRY" "$PROM_CFG" << 'EOF'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

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

config = f"""global:
  scrape_interval:     15s
  evaluation_interval: 15s
  external_labels:
    env: production

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
{scrape_block}
"""
with open(sys.argv[2], 'w') as f:
    f.write(config)
print(f"Сгенерировано {len(clusters)} кластеров")
EOF

    # Перезагрузить Prometheus без рестарта
    if systemctl is-active prometheus &>/dev/null; then
        curl -sf -X POST http://localhost:9090/-/reload || systemctl reload prometheus || true
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
cmd_install_exporters() {
    local NAME="$1"
    cluster_exists "$NAME" || { log_error "Кластер '$NAME' не найден"; exit 1; }

    LABEL=$(cluster_field "$NAME" "label")
    PRIM=$(cluster_field "$NAME" "primary_ip")
    REPL=$(cluster_field "$NAME" "replica_ip")
    PASS=$(cluster_field "$NAME" "mysql_exporter_password")

    log_section "Установка экспортёров для '${LABEL}'"

    EXPORTER_SCRIPT="${SCRIPT_DIR}/scripts/install_exporters.sh"
    [[ -f "$EXPORTER_SCRIPT" ]] || { log_error "01_install_exporters.sh не найден"; exit 1; }

    _install_on_host() {
        local HOST="$1"
        local ROLE="$2"
        log_info "Подключаюсь к ${HOST} (${ROLE})..."
        ssh -o StrictHostKeyChecking=no root@"$HOST" \
            "PRIMARY_IP=$PRIM REPLICA_IP=$REPL MYSQL_EXPORTER_PASSWORD=$PASS \
             MONITORING_IP=${MONITORING_IP:-10.0.0.100} \
             NODE_EXPORTER_VERSION=${NODE_EXPORTER_VERSION:-1.8.2} \
             MYSQLD_EXPORTER_VERSION=${MYSQLD_EXPORTER_VERSION:-0.15.1} \
             bash -s" < "$EXPORTER_SCRIPT"
    }

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
    install-exporters)  cmd_install_exporters "${1:?'Укажите name'}" ;;
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
        echo "    install-exporters <name>    — установить экспортёры по SSH"
        echo ""
        echo "  Примеры:"
        echo "    ./manage_cluster.sh list"
        echo "    ./manage_cluster.sh add"
        echo "    ./manage_cluster.sh install-exporters kemerovo"
        echo "    ./manage_cluster.sh apply"
        echo ""
        ;;
esac
