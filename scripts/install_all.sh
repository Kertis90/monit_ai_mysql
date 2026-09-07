#!/usr/bin/env bash
# =============================================================================
#  install_all.sh — Установить всё на сервере мониторинга одной командой
#  (Prometheus + Alertmanager + Grafana + AI Agent + применение реестра)
#
#  Использование:
#    ./configure.sh              ← сначала настройка
#    sudo ./scripts/install_all.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

[[ -f "${SCRIPT_DIR}/../config.env" ]] || {
    echo -e "${RED}config.env не найден — сначала запустите ./configure.sh${NC}"; exit 1; }
[[ $EUID -ne 0 ]] && { echo -e "${RED}Нужен root (sudo)${NC}"; exit 1; }

# --clean пробрасывается дальше: полная перезапись конфигов стека
CLEAN_ARG=""
for arg in "$@"; do
    case "$arg" in
        --clean|--reset) CLEAN_ARG="--clean" ;;
        -h|--help)
            echo "Использование: $0 [--clean]"
            echo "  --clean   снести сгенерированные конфиги и создать заново"
            exit 0 ;;
    esac
done

echo -e "${BOLD}[1/3] Установка Prometheus + Alertmanager + Grafana...${NC}"
bash "${SCRIPT_DIR}/install_monitoring.sh" ${CLEAN_ARG}

echo -e "${BOLD}[2/3] Установка AI Agent...${NC}"
bash "${SCRIPT_DIR}/install_agent.sh"

echo -e "${BOLD}[3/3] Применение реестра кластеров...${NC}"
bash "${SCRIPT_DIR}/../manage_cluster.sh" apply || \
    echo "Реестр пуст — добавьте кластеры: ./manage_cluster.sh add"

source "${SCRIPT_DIR}/../config.env"
echo ""
echo -e "${GREEN}${BOLD}════════════ УСТАНОВКА ЗАВЕРШЕНА ════════════${NC}"
echo ""
echo "  Чат AI Agent : http://${MONITORING_IP}:${AGENT_PORT}/"
echo "  Grafana      : http://${MONITORING_IP}:3000"
echo "  Prometheus   : http://${MONITORING_IP}:9090"
echo "  Alertmanager : http://${MONITORING_IP}:9093"
echo ""
echo "  Осталось установить экспортёры на серверах MySQL:"
echo "    ./manage_cluster.sh install-exporters <имя_кластера>"
echo ""
