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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config.env"
[[ -f "$CONFIG" ]] || { log_error "config.env не найден — запустите сначала ./configure.sh"; exit 1; }
source "$CONFIG"
[[ $EUID -ne 0 ]] && { log_error "Нужен root (sudo)"; exit 1; }

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
        "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${F}.tar.gz"
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
cat > /etc/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval:     15s
  evaluation_interval: 15s

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

      - alert: ReplicationLagWarning
        expr: mysql_slave_status_seconds_behind_master > 10
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "Лаг {{ $value | printf \"%.0f\" }}s — {{ $labels.cluster_label }}"

      - alert: ReplicationLagCritical
        expr: mysql_slave_status_seconds_behind_master > 60
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "КРИТИЧНО лаг {{ $value | printf \"%.0f\" }}s — {{ $labels.cluster_label }}"

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
  --web.enable-lifecycle
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now prometheus
sleep 3
curl -sf http://localhost:9090/-/healthy >/dev/null && log_info "Prometheus ✓" || log_error "Prometheus не отвечает"

# =============================================================================
log_section "3/4 Alertmanager v${ALERTMANAGER_VERSION}"
# =============================================================================
id alertmanager &>/dev/null || useradd -r -s /sbin/nologin alertmanager
mkdir -p /etc/alertmanager /var/lib/alertmanager

if ! command -v alertmanager &>/dev/null; then
    cd /tmp
    F="alertmanager-${ALERTMANAGER_VERSION}.linux-amd64"
    curl -fsSL -o "${F}.tar.gz" \
        "https://github.com/prometheus/alertmanager/releases/download/v${ALERTMANAGER_VERSION}/${F}.tar.gz"
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

chown -R alertmanager:alertmanager /etc/alertmanager /var/lib/alertmanager

cat > /etc/systemd/system/alertmanager.service << 'EOF'
[Unit]
Description=Alertmanager
After=network.target
[Service]
User=alertmanager
Group=alertmanager
ExecStart=/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager \
  --web.listen-address=:9093
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now alertmanager
sleep 2
curl -sf http://localhost:9093/-/healthy >/dev/null && log_info "Alertmanager ✓" || log_error "Alertmanager не отвечает"

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
cat > /etc/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
    jsonData:
      timeInterval: "15s"
EOF

systemctl enable --now grafana-server
sleep 4
grafana-cli admin reset-admin-password "${GRAFANA_ADMIN_PASSWORD}" 2>/dev/null || true
curl -sf http://localhost:3000/api/health >/dev/null && log_info "Grafana ✓" || log_error "Grafana не отвечает"

# Импорт дашбордов
sleep 3
for ID in 1860 7362 11323 7371; do
    curl -sf -u "admin:${GRAFANA_ADMIN_PASSWORD}" \
        -H "Content-Type: application/json" \
        -d "{\"dashboardId\":${ID},\"folderId\":0,\"overwrite\":true}" \
        "http://localhost:3000/api/dashboards/import" >/dev/null 2>&1 && \
        log_info "Дашборд ${ID} импортирован" || \
        log_warn "Дашборд ${ID} — импортируйте вручную (Dashboards → Import → ${ID})"
done

echo ""
log_info "Мониторинг установлен:"
echo "  Prometheus  : http://${MONITORING_IP}:9090"
echo "  Grafana     : http://${MONITORING_IP}:3000"
echo "  Alertmanager: http://${MONITORING_IP}:9093"
echo ""
log_info "Следующий шаг: sudo ./scripts/install_agent.sh"
