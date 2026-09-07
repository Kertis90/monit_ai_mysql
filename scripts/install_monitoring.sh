#!/usr/bin/env bash
# =============================================================================
#  install_monitoring.sh — Prometheus + Alertmanager + Grafana
#  Запускать на сервере мониторинга ПОСЛЕ ./configure.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }

CLEAN_MODE=false
for arg in "$@"; do
    case "$arg" in
        --clean|--reset) CLEAN_MODE=true ;;
        -h|--help)
            echo "Использование: $0 [--clean]"
            echo "  --clean   удалить сгенерированные конфиги и создать заново"
            echo ""
            echo "Удаляются ТОЛЬКО файлы, которые создаёт этот скрипт."
            echo "Не трогаются: /var/lib/prometheus (метрики),"
            echo "              /var/lib/grafana/grafana.db (пользователи Grafana),"
            echo "              /opt/ai-alert-agent/alerts.db (алерты, чаты, доступы)."
            exit 0 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config.env"
[[ -f "$CONFIG" ]] || { log_error "config.env не найден — запустите сначала ./configure.sh"; exit 1; }
source "$CONFIG"
[[ $EUID -ne 0 ]] && { log_error "Нужен root (sudo)"; exit 1; }


# ── Режим --clean: снести сгенерированные конфиги и создать заново ───────────
# Нужен, когда конфиг «разъехался» и сервис не стартует: чинить по кусочкам
# дольше, чем переложить всё из config.env и clusters.json с нуля.

if [[ "$CLEAN_MODE" == "true" ]]; then
    log_section "Очистка конфигов (--clean)"

    # Останавливаем, чтобы сервисы не держали старые файлы и не писали в них
    for svc in prometheus alertmanager grafana-server; do
        systemctl stop "$svc" 2>/dev/null || true
    done

    rm -f /etc/prometheus/prometheus.yml
    rm -f /etc/prometheus/rules/*.yml
    rm -f /etc/alertmanager/alertmanager.yml
    rm -f /etc/systemd/system/prometheus.service
    rm -f /etc/systemd/system/alertmanager.service

    # Grafana: только НАШ провижининг. grafana.db с пользователями и вручную
    # созданными дашбордами не трогаем.
    rm -f /etc/grafana/provisioning/datasources/prometheus.yml
    rm -f /etc/grafana/provisioning/dashboards/mysql_monit.yml
    rm -f /var/lib/grafana/dashboards/*.json

    systemctl daemon-reload
    log_info "Сгенерированные конфиги удалены — будут созданы заново"
    log_warn "Метрики, grafana.db и alerts.db сохранены"
fi
# Зеркала: подменяется только домен, путь достраивается как на оригинале
GITHUB_BASE_URL="${GITHUB_BASE_URL:-https://github.com}"; GITHUB_BASE_URL="${GITHUB_BASE_URL%/}"
GRAFANA_COM_URL="${GRAFANA_COM_URL:-https://grafana.com}"; GRAFANA_COM_URL="${GRAFANA_COM_URL%/}"
[[ "$GITHUB_BASE_URL" != "https://github.com" ]] && log_info "Зеркало GitHub: ${GITHUB_BASE_URL}"
[[ "$GRAFANA_COM_URL" != "https://grafana.com" ]] && log_info "Зеркало grafana.com: ${GRAFANA_COM_URL}"

# ── Работа за обратным прокси ────────────────────────────────────────────────
# Сервисы отдают себя ПОД своим путём (route-prefix = подпуть), поэтому nginx
# префикс не срезает, а все внутренние адреса включают его.
PROM_PREFIX="${PROMETHEUS_ROOT_PATH:-}"
AM_PREFIX="${ALERTMANAGER_ROOT_PATH:-}"
# Когда задан подпуть, снаружи и изнутри ходим через nginx — без порта.
# Без подпутей nginx маршрутизировать не по чему, поэтому идём прямо в порт.
INTERNAL_BASE_URL="${INTERNAL_BASE_URL:-http://localhost}"
if [[ -n "$PROM_PREFIX" ]]; then
    PROM_LOCAL="${INTERNAL_BASE_URL}${PROM_PREFIX}"
else
    PROM_LOCAL="http://localhost:9090"
fi
if [[ -n "$AM_PREFIX" ]]; then
    AM_LOCAL="${INTERNAL_BASE_URL}${AM_PREFIX}"
else
    AM_LOCAL="http://localhost:9093"
fi

# Цели скрейпа: с подпутём идём через nginx (без порта), иначе прямо в порт
[[ -n "$PROM_PREFIX" ]] && PROM_TARGET="localhost" || PROM_TARGET="localhost:9090"
[[ -n "$AM_PREFIX"   ]] && AM_TARGET="localhost"   || AM_TARGET="localhost:9093"

# Подпути достаточно самого по себе — как у агента. Внешний адрес нужен
# только чтобы ссылки в алертах вели наружу, а не на localhost; без него
# сервис всё равно корректно отдаётся под своим префиксом.
PROM_WEB_FLAGS=""
if [[ -n "${PROM_PREFIX}" ]]; then
    PROM_WEB_FLAGS="--web.route-prefix=${PROM_PREFIX}/"
    log_info "Prometheus под путём ${PROM_PREFIX} (локально ${PROM_LOCAL})"
fi
if [[ -n "${PROMETHEUS_EXTERNAL_URL:-}" ]]; then
    PROM_WEB_FLAGS="--web.external-url=${PROMETHEUS_EXTERNAL_URL} ${PROM_WEB_FLAGS}"
    log_info "Prometheus снаружи: ${PROMETHEUS_EXTERNAL_URL}"
fi

AM_WEB_FLAGS=""
if [[ -n "${AM_PREFIX}" ]]; then
    AM_WEB_FLAGS="--web.route-prefix=${AM_PREFIX}/"
    log_info "Alertmanager под путём ${AM_PREFIX} (локально ${AM_LOCAL})"
fi
if [[ -n "${ALERTMANAGER_EXTERNAL_URL:-}" ]]; then
    AM_WEB_FLAGS="--web.external-url=${ALERTMANAGER_EXTERNAL_URL} ${AM_WEB_FLAGS}"
    log_info "Alertmanager снаружи: ${ALERTMANAGER_EXTERNAL_URL}"
fi

# =============================================================================
log_section "1/4 Firewall"
# =============================================================================
for p in 9090 9093 3000 "${AGENT_PORT}"; do
    firewall-cmd --permanent --add-port="${p}/tcp" 2>/dev/null || true
done
firewall-cmd --reload 2>/dev/null || true
log_info "Порты 9090 9093 3000 ${AGENT_PORT} открыты"

# =============================================================================
log_section "2/4 Prometheus v${PROMETHEUS_VERSION}"
# =============================================================================
id prometheus &>/dev/null || useradd -r -s /sbin/nologin prometheus
mkdir -p /etc/prometheus/rules /var/lib/prometheus
chown prometheus:prometheus /var/lib/prometheus

if ! command -v prometheus &>/dev/null; then
    cd /tmp
    F="prometheus-${PROMETHEUS_VERSION}.linux-amd64"
    curl -fsSL -o "${F}.tar.gz" \
        "${GITHUB_BASE_URL}/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${F}.tar.gz"
    tar xzf "${F}.tar.gz"
    mv "${F}/prometheus" "${F}/promtool" /usr/local/bin/
    cp -r "${F}/consoles" "${F}/console_libraries" /etc/prometheus/ 2>/dev/null || true
    rm -rf "${F}" "${F}.tar.gz"
    log_info "Prometheus установлен"
else
    log_warn "Prometheus уже установлен — пропускаем скачивание"
fi

# Базовый конфиг (кластеры добавит manage_cluster.sh apply)
if [[ ! -f /etc/prometheus/prometheus.yml ]]; then
cat > /etc/prometheus/prometheus.yml << EOF
global:
  scrape_interval:     15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['${AM_TARGET}']${AM_PREFIX:+
      path_prefix: '${AM_PREFIX}/'}

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:
  - job_name: 'prometheus'${PROM_PREFIX:+
    metrics_path: '${PROM_PREFIX}/metrics'}
    static_configs:
      - targets: ['${PROM_TARGET}']
EOF
fi

# Правила алертов (используют метки cluster / cluster_label / role)
cat > /etc/prometheus/rules/mysql_alerts.yml << 'EOF'
groups:
  - name: mysql_availability
    rules:
      - alert: MySQLDown
        expr: mysql_up == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "MySQL DOWN — {{ $labels.cluster_label }} ({{ $labels.role }})"

      - alert: MySQLRestartDetected
        expr: mysql_global_status_uptime < 300
        for: 0m
        labels: { severity: warning }
        annotations:
          summary: "MySQL перезапустился — {{ $labels.cluster_label }}"

  - name: mysql_performance
    rules:
      - alert: MySQLHighConnections
        expr: mysql_global_status_threads_connected / mysql_global_variables_max_connections * 100 > 80
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Соединения {{ $value | printf \"%.0f\" }}% — {{ $labels.cluster_label }}"

      - alert: MySQLConnectionsCritical
        expr: mysql_global_status_threads_connected / mysql_global_variables_max_connections * 100 > 95
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "КРИТИЧНО соединения {{ $value | printf \"%.0f\" }}% — {{ $labels.cluster_label }}"

      - alert: MySQLSlowQueriesHigh
        expr: rate(mysql_global_status_slow_queries[5m]) > 5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Slow queries {{ $value | printf \"%.1f\" }}/s — {{ $labels.cluster_label }}"

      - alert: MySQLInnoDBBufferPoolLowHitRate
        expr: rate(mysql_global_status_innodb_buffer_pool_reads[5m]) / rate(mysql_global_status_innodb_buffer_pool_read_requests[5m]) * 100 > 5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "InnoDB hit rate < 95% — {{ $labels.cluster_label }}"

      - alert: MySQLHighRowLockWaits
        expr: rate(mysql_global_status_innodb_row_lock_waits[5m]) > 10
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Row lock waits {{ $value | printf \"%.1f\" }}/s — {{ $labels.cluster_label }}"

      - alert: MySQLQPSDropped
        expr: rate(mysql_global_status_queries[5m]) < rate(mysql_global_status_queries[5m] offset 10m) * 0.5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "QPS упал >50% — {{ $labels.cluster_label }}"

  - name: mysql_replication
    rules:
      - alert: ReplicationIOThreadDown
        expr: mysql_slave_status_slave_io_running == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "IO thread упал — {{ $labels.cluster_label }}"

      - alert: ReplicationSQLThreadDown
        expr: mysql_slave_status_slave_sql_running == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "SQL thread упал — {{ $labels.cluster_label }}"

      # ВНИМАНИЕ: считаем отставание СВЕРХ запланированного MASTER_DELAY.
      # mysql:replica_effective_lag_seconds генерирует manage_cluster.sh apply
      # из поля replica_delay_seconds в clusters.json. Алертить по сырому
      # mysql_slave_status_seconds_behind_master нельзя: у отложенной реплики
      # он всегда равен задержке, и алерт горел бы непрерывно.
      - alert: ReplicationLagWarning
        expr: mysql:replica_effective_lag_seconds > 10
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "Реплика отстала на {{ $value | printf \"%.0f\" }}s сверх плана — {{ $labels.cluster_label }}"

      - alert: ReplicationLagCritical
        expr: mysql:replica_effective_lag_seconds > 60
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "КРИТИЧНО: реплика отстала на {{ $value | printf \"%.0f\" }}s сверх плана — {{ $labels.cluster_label }}"

      - alert: ReplicaNotReadOnly
        expr: mysql_global_variables_read_only{role="replica"} == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Реплика принимает запись! — {{ $labels.cluster_label }}"

  - name: node_resources
    rules:
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance,cluster,cluster_label)(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 85
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "CPU {{ $value | printf \"%.0f\" }}% — {{ $labels.cluster_label }}"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "RAM {{ $value | printf \"%.0f\" }}% — {{ $labels.cluster_label }}"

      - alert: DiskSpaceLow
        expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100 < 15
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Диск < 15% — {{ $labels.cluster_label }}"

      - alert: DiskSpaceCritical
        expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100 < 5
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "КРИТИЧНО диск < 5% — {{ $labels.cluster_label }}"

      - alert: HighDiskIOWait
        expr: avg by(instance,cluster,cluster_label)(rate(node_cpu_seconds_total{mode="iowait"}[5m])) * 100 > 20
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "IO wait {{ $value | printf \"%.0f\" }}% — {{ $labels.cluster_label }}"
EOF

promtool check rules /etc/prometheus/rules/mysql_alerts.yml
chown -R prometheus:prometheus /etc/prometheus

cat > /etc/systemd/system/prometheus.service << EOF
[Unit]
Description=Prometheus
After=network.target
[Service]
User=prometheus
Group=prometheus
ExecStart=/usr/local/bin/prometheus \\
  --config.file=/etc/prometheus/prometheus.yml \\
  --storage.tsdb.path=/var/lib/prometheus \\
  --storage.tsdb.retention.time=${PROMETHEUS_RETENTION} \\
  --web.listen-address=:9090 \\
  --web.enable-lifecycle ${PROM_WEB_FLAGS}
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prometheus 2>/dev/null || true
systemctl restart prometheus      # подхватить изменившийся ExecStart
sleep 3
curl -sf "${PROM_LOCAL}/-/healthy" >/dev/null && log_info "Prometheus ✓" || log_error "Prometheus не отвечает"

# =============================================================================
log_section "3/4 Alertmanager v${ALERTMANAGER_VERSION}"
# =============================================================================
# Группа сервиса задаётся отдельно: в нашем контуре это reguser, а не
# одноимённая группа, которую создал бы useradd по умолчанию.
AM_GROUP="${ALERTMANAGER_GROUP:-reguser}"
getent group "$AM_GROUP" >/dev/null || {
    groupadd -r "$AM_GROUP"
    log_info "Создана группа ${AM_GROUP}"
}
id alertmanager &>/dev/null || useradd -r -s /sbin/nologin -g "$AM_GROUP" alertmanager
# Учётка могла существовать с прежней группой — приводим к нужной
usermod -g "$AM_GROUP" alertmanager 2>/dev/null || true
mkdir -p /etc/alertmanager /var/lib/alertmanager

if ! command -v alertmanager &>/dev/null; then
    cd /tmp
    F="alertmanager-${ALERTMANAGER_VERSION}.linux-amd64"
    curl -fsSL -o "${F}.tar.gz" \
        "${GITHUB_BASE_URL}/prometheus/alertmanager/releases/download/v${ALERTMANAGER_VERSION}/${F}.tar.gz"
    tar xzf "${F}.tar.gz" && mv "${F}/alertmanager" /usr/local/bin/
    rm -rf "${F}" "${F}.tar.gz"
    log_info "Alertmanager установлен"
fi

# Конфиг: email опционален
if [[ -n "${ALERT_EMAIL_TO}" ]]; then
cat > /etc/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m
  smtp_smarthost:     '${ALERT_SMTP_HOST}'
  smtp_from:          '${ALERT_EMAIL_FROM}'
  smtp_auth_username: '${ALERT_SMTP_USER}'
  smtp_auth_password: '${ALERT_SMTP_PASSWORD}'

route:
  group_by: ['alertname', 'cluster']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'ai-and-email'
  routes:
    - match: { severity: warning }
      receiver: 'ai-only'

receivers:
  - name: 'ai-and-email'
    webhook_configs:
      - url: 'http://localhost:${AGENT_PORT}/webhook'
        send_resolved: false
    email_configs:
      - to: '${ALERT_EMAIL_TO}'
  - name: 'ai-only'
    webhook_configs:
      - url: 'http://localhost:${AGENT_PORT}/webhook'
        send_resolved: false

inhibit_rules:
  - source_match: { severity: critical }
    target_match: { severity: warning }
    equal: ['cluster']
EOF
else
cat > /etc/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'ai-agent'

receivers:
  - name: 'ai-agent'
    webhook_configs:
      - url: 'http://localhost:${AGENT_PORT}/webhook'
        send_resolved: false

inhibit_rules:
  - source_match: { severity: critical }
    target_match: { severity: warning }
    equal: ['cluster']
EOF
log_warn "Email не настроен — алерты идут только в AI-агента"
fi

chown -R "alertmanager:${AM_GROUP}" /etc/alertmanager /var/lib/alertmanager

# heredoc без кавычек — нужен для ${AM_WEB_FLAGS}; поэтому \\ вместо \
cat > /etc/systemd/system/alertmanager.service << EOF
[Unit]
Description=Alertmanager
After=network.target
[Service]
User=alertmanager
Group=${AM_GROUP}
ExecStart=/usr/local/bin/alertmanager \\
  --config.file=/etc/alertmanager/alertmanager.yml \\
  --storage.path=/var/lib/alertmanager \\
  --web.listen-address=:9093 ${AM_WEB_FLAGS}
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now alertmanager 2>/dev/null || true
systemctl restart alertmanager      # подхватить изменившийся ExecStart
sleep 2
curl -sf "${AM_LOCAL}/-/healthy" >/dev/null && log_info "Alertmanager ✓" || log_error "Alertmanager не отвечает"

# =============================================================================
log_section "4/4 Grafana"
# =============================================================================
if ! command -v grafana-server &>/dev/null; then
    cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=grafana
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
    dnf install -y grafana
    log_info "Grafana установлена"
fi

mkdir -p /etc/grafana/provisioning/datasources
cat > /etc/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

# Сначала удаляем запись по ИМЕНИ, потом создаём с фиксированным uid.
# Без этого Grafana НЕ СТАРТУЕТ: если в grafana.db уже есть "Prometheus"
# со случайным uid (её создал провижининг прошлых версий, без uid), то
# сопоставление по uid не находит запись и модуль провижининга падает с
# "Datasource provisioning error: data source not found".
deleteDatasources:
  - name: Prometheus
    orgId: 1

datasources:
  - name: Prometheus
    type: prometheus
    uid: prometheus          # фиксированный uid — на него ссылаются наши дашборды
    access: proxy
    url: ${PROM_LOCAL}
    isDefault: true
    jsonData:
      timeInterval: "15s"
EOF

# ── Свои дашборды (провижининг из файлов) ─────────────────────────────────────
# Community-дашборды ниже фильтруют по job="node"/"mysql", а этот проект
# генерирует job вида node_<кластер>, поэтому нужен дашборд под свои метки.
#
# Важно: Grafana НЕ СТАРТУЕТ, если провижининг ссылается на несуществующий
# каталог или там лежит битый JSON. Поэтому провайдер создаётся только после
# того, как в каталог реально лёг хотя бы один проверенный дашборд.
DASH_SRC="${SCRIPT_DIR}/../grafana/dashboards"
DASH_DST="/var/lib/grafana/dashboards"
DASH_PROVIDER="/etc/grafana/provisioning/dashboards/mysql_monit.yml"

mkdir -p /etc/grafana/provisioning/dashboards "$DASH_DST"

DASH_OK=0
if compgen -G "${DASH_SRC}/*.json" > /dev/null; then
    for f in "${DASH_SRC}"/*.json; do
        if python3 -c "
import json, sys
d = json.load(open(sys.argv[1], encoding='utf-8'))
sys.exit(0 if d.get('title') and isinstance(d.get('panels'), list) else 1)
" "$f" 2>/dev/null; then
            cp "$f" "${DASH_DST}/"
            DASH_OK=$((DASH_OK + 1))
        else
            log_warn "Дашборд $(basename "$f") невалиден — пропущен"
        fi
    done
fi

if [[ $DASH_OK -gt 0 ]]; then
    chown -R grafana:grafana "$DASH_DST" 2>/dev/null || true
    chmod 755 "$DASH_DST"
    cat > "$DASH_PROVIDER" << 'EOF'
apiVersion: 1
providers:
  - name: mysql-ai-monitoring
    orgId: 1
    folder: MySQL AI Monitoring
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
EOF
    log_info "Свои дашборды: ${DASH_OK} шт. → папка «MySQL AI Monitoring»"
else
    # Провайдер, указывающий в пустоту, роняет старт Grafana — убираем
    rm -f "$DASH_PROVIDER"
    log_warn "Валидных дашбордов не найдено — провижининг не настраивается"
fi

systemctl enable --now grafana-server 2>/dev/null || true
systemctl restart grafana-server 2>/dev/null || true
sleep 4

if ! systemctl is-active --quiet grafana-server; then
    log_error "Grafana не запустилась. Причина из журнала:"
    journalctl -u grafana-server -n 20 --no-pager \
        | grep -iE "init failed|provisioning|error|level=eror" | tail -8 || true
    echo ""
    log_warn "Чаще всего это провижининг. Снять его и поднять Grafana:"
    echo "    mv ${DASH_PROVIDER} /tmp/ && systemctl restart grafana-server"
    exit 1
fi

grafana-cli admin reset-admin-password "${GRAFANA_ADMIN_PASSWORD}" 2>/dev/null || true
curl -sf http://localhost:3000/api/health >/dev/null && log_info "Grafana ✓" || log_error "Grafana не отвечает на :3000"

# ── Импорт дашбордов ──────────────────────────────────────────────────────────
# JSON скачивается с ${GRAFANA_COM_URL} и отправляется в Grafana целиком.
# Передать один "dashboardId" нельзя: /api/dashboards/import ничего не качает
# сам, а без блока inputs панели ссылаются на несуществующий ${DS_PROMETHEUS}.
sleep 3
for ID in 1860 7362 11323 7371; do
    DASH_JSON="/tmp/grafana_dash_${ID}.json"
    DASH_URL="${GRAFANA_COM_URL}/api/dashboards/${ID}/revisions/latest/download"

    if ! curl -fsSL --max-time 30 -o "$DASH_JSON" "$DASH_URL"; then
        log_warn "Дашборд ${ID}: не скачался с ${GRAFANA_COM_URL}"
        log_warn "  Импортируйте вручную: Dashboards → Import → ${ID}"
        rm -f "$DASH_JSON"
        continue
    fi

    if ! python3 - "$DASH_JSON" > "${DASH_JSON}.payload" << 'PY'
import json, sys
dashboard = json.load(open(sys.argv[1], encoding='utf-8'))
# Datasource-плейсхолдеры дашборда привязываем к провижененному Prometheus
inputs = [
    {"name": i["name"], "type": i["type"],
     "pluginId": i.get("pluginId", "prometheus"), "value": "Prometheus"}
    for i in dashboard.get("__inputs", [])
    if i.get("type") == "datasource"
]
json.dump({"dashboard": dashboard, "overwrite": True,
           "folderId": 0, "inputs": inputs},
          sys.stdout, ensure_ascii=False)
PY
    then
        log_warn "Дашборд ${ID}: некорректный JSON — пропускаем"
        rm -f "$DASH_JSON" "${DASH_JSON}.payload"
        continue
    fi

    if curl -sf -u "admin:${GRAFANA_ADMIN_PASSWORD}" \
            -H "Content-Type: application/json" \
            -d "@${DASH_JSON}.payload" \
            "http://localhost:3000/api/dashboards/import" >/dev/null; then
        log_info "Дашборд ${ID} импортирован"
    else
        log_warn "Дашборд ${ID} — импортируйте вручную (Dashboards → Import → ${ID})"
    fi
    rm -f "$DASH_JSON" "${DASH_JSON}.payload"
done

echo ""
log_info "Мониторинг установлен:"
echo "  Prometheus  : http://${MONITORING_IP}:9090"
echo "  Grafana     : http://${MONITORING_IP}:3000"
echo "  Alertmanager: http://${MONITORING_IP}:9093"
echo ""
log_info "Следующий шаг: sudo ./scripts/install_agent.sh"
