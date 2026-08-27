#!/usr/bin/env bash
# =============================================================================
#  install_exporters.sh — Установка экспортёров на MySQL-сервере
#  Требует root. Способы запуска:
#    с сервера мониторинга: ./manage_cluster.sh install-exporters <name>
#      (подключается по SSH под SSH_USER и выполняет этот скрипт через sudo)
#    локально на MySQL-сервере: sudo -E bash install_exporters.sh
#
#  Переменные окружения (устанавливаются manage_cluster.sh автоматически):
#    MYSQL_EXPORTER_PASSWORD — пароль пользователя exporter
#    NODE_EXPORTER_VERSION   — версия node_exporter
#    MYSQLD_EXPORTER_VERSION — версия mysqld_exporter
#    MYSQL_ROOT_PASSWORD     — (необязательно) для авто-создания пользователя
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BLUE}══ $1 ══${NC}"; }

# Попытаться загрузить config.env если запускается напрямую
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${SCRIPT_DIR}/../config.env" ]] && source "${SCRIPT_DIR}/../config.env"

NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION:-1.8.2}"
MYSQLD_EXPORTER_VERSION="${MYSQLD_EXPORTER_VERSION:-0.15.1}"
MYSQL_EXPORTER_PASSWORD="${MYSQL_EXPORTER_PASSWORD:-ExporterPass123!}"

if [[ $EUID -ne 0 ]]; then
    log_error "Нужны права root. Запустите через sudo:"
    echo "    sudo -E bash ${BASH_SOURCE[0]}"
    echo "  или с сервера мониторинга: ./manage_cluster.sh install-exporters <name>"
    exit 1
fi

CURRENT_IP=$(hostname -I | awk '{print $1}')
log_info "Сервер: ${CURRENT_IP}"

# =============================================================================
log_section "Firewall"
# =============================================================================
firewall-cmd --permanent --add-port=9100/tcp 2>/dev/null || true
firewall-cmd --permanent --add-port=9104/tcp 2>/dev/null || true
firewall-cmd --reload
log_info "Порты 9100, 9104 открыты"

# =============================================================================
log_section "node_exporter v${NODE_EXPORTER_VERSION}"
# =============================================================================
# Проверяем файл, а не PATH: под sudo действует secure_path,
# в котором /usr/local/bin может отсутствовать.
if [[ ! -x /usr/local/bin/node_exporter ]]; then
    cd /tmp
    FILE="node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64"
    curl -fsSL -o "${FILE}.tar.gz" \
        "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/${FILE}.tar.gz"
    tar xzf "${FILE}.tar.gz"
    mv "${FILE}/node_exporter" /usr/local/bin/ && chmod +x /usr/local/bin/node_exporter
    rm -rf "${FILE}" "${FILE}.tar.gz"
fi
id node_exporter &>/dev/null || useradd -r -s /sbin/nologin node_exporter

cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target
[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
  --collector.systemd --collector.processes \
  --collector.diskstats --collector.filesystem \
  --collector.netdev --collector.meminfo --collector.cpu
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now node_exporter
sleep 2
curl -sf http://localhost:9100/metrics | grep -q "node_cpu" && log_info "node_exporter ✓" || log_warn "node_exporter не отвечает"

# =============================================================================
log_section "MySQL пользователь exporter"
# =============================================================================
if [[ -n "${MYSQL_ROOT_PASSWORD:-}" ]]; then
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" 2>/dev/null << SQL && log_info "Пользователь exporter создан ✓" || log_warn "Создайте вручную"
CREATE USER IF NOT EXISTS 'exporter'@'localhost'
  IDENTIFIED BY '${MYSQL_EXPORTER_PASSWORD}'
  WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
GRANT SELECT ON performance_schema.* TO 'exporter'@'localhost';
GRANT SELECT ON information_schema.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
SQL
else
    log_warn "Создайте пользователя вручную:"
    echo "  mysql -u root -p << 'SQL'"
    echo "  CREATE USER IF NOT EXISTS 'exporter'@'localhost'"
    echo "    IDENTIFIED BY '${MYSQL_EXPORTER_PASSWORD}' WITH MAX_USER_CONNECTIONS 3;"
    echo "  GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';"
    echo "  GRANT SELECT ON performance_schema.* TO 'exporter'@'localhost';"
    echo "  GRANT SELECT ON information_schema.* TO 'exporter'@'localhost';"
    echo "  FLUSH PRIVILEGES;"
    echo "  SQL"
fi

# =============================================================================
log_section "mysqld_exporter v${MYSQLD_EXPORTER_VERSION}"
# =============================================================================
if [[ ! -x /usr/local/bin/mysqld_exporter ]]; then
    cd /tmp
    FILE="mysqld_exporter-${MYSQLD_EXPORTER_VERSION}.linux-amd64"
    curl -fsSL -o "${FILE}.tar.gz" \
        "https://github.com/prometheus/mysqld_exporter/releases/download/v${MYSQLD_EXPORTER_VERSION}/${FILE}.tar.gz"
    tar xzf "${FILE}.tar.gz"
    mv "${FILE}/mysqld_exporter" /usr/local/bin/ && chmod +x /usr/local/bin/mysqld_exporter
    rm -rf "${FILE}" "${FILE}.tar.gz"
fi

id mysqld_exporter &>/dev/null || useradd -r -s /sbin/nologin mysqld_exporter
mkdir -p /etc/mysqld_exporter

cat > /etc/mysqld_exporter/.my.cnf << EOF
[client]
user=exporter
password=${MYSQL_EXPORTER_PASSWORD}
host=127.0.0.1
EOF
chmod 600 /etc/mysqld_exporter/.my.cnf
chown -R mysqld_exporter:mysqld_exporter /etc/mysqld_exporter

cat > /etc/systemd/system/mysqld_exporter.service << 'EOF'
[Unit]
Description=MySQL Exporter for Prometheus
After=network.target mysqld.service mysql.service
[Service]
User=mysqld_exporter
Group=mysqld_exporter
ExecStart=/usr/local/bin/mysqld_exporter \
  --config.my-cnf=/etc/mysqld_exporter/.my.cnf \
  --collect.global_status --collect.global_variables \
  --collect.info_schema.processlist --collect.info_schema.innodb_metrics \
  --collect.info_schema.tablestats --collect.info_schema.tables \
  --collect.info_schema.userstats --collect.engine_innodb_status \
  --collect.perf_schema.eventsstatements --collect.perf_schema.eventsstatementssum \
  --collect.perf_schema.eventswaits --collect.slave_status \
  --web.listen-address=:9104
Restart=always
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mysqld_exporter
sleep 3

MYSQL_UP=$(curl -sf http://localhost:9104/metrics | grep "^mysql_up" | awk '{print $2}' || echo "0")
[[ "$MYSQL_UP" == "1" ]] && log_info "mysqld_exporter: mysql_up=1 ✓" || log_warn "mysql_up=${MYSQL_UP} — проверьте пользователя exporter"

# performance_schema
PS=$(mysql -u exporter -p"${MYSQL_EXPORTER_PASSWORD}" -h 127.0.0.1 \
    -se "SHOW VARIABLES LIKE 'performance_schema'" 2>/dev/null | awk '{print $2}' || echo "")
if [[ "$PS" != "ON" ]]; then
    log_warn "performance_schema OFF — добавляем в my.cnf (требует рестарт MySQL)"
    cat >> /etc/my.cnf << 'EOF'
[mysqld]
performance_schema=ON
slow_query_log=ON
slow_query_log_file=/var/log/mysql/slow.log
long_query_time=1
log_queries_not_using_indexes=ON
EOF
    mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true
    log_warn "Перезапустите MySQL: systemctl restart mysqld"
fi

log_info "Готово: ${CURRENT_IP}:9100 (node) | ${CURRENT_IP}:9104 (mysql)"
