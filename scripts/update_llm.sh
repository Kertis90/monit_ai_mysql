#!/usr/bin/env bash
# =============================================================================
#  update_llm.sh — Обновить URL/токен/модель LLM без переустановки агента
#
#  Порядок:
#    1. ./configure.sh          ← изменить значения (или правьте config.env)
#    2. sudo ./scripts/update_llm.sh
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

AGENT_ENV="/opt/ai-alert-agent/.env"
[[ -f "$AGENT_ENV" ]] || { echo -e "${RED}Агент не установлен (нет ${AGENT_ENV})${NC}"; exit 1; }
[[ $EUID -ne 0 ]] && { echo -e "${RED}Нужен root (sudo)${NC}"; exit 1; }

echo ""
echo "Текущий конфиг агента:"
grep "LLM_" "$AGENT_ENV" | sed 's/\(LLM_API_KEY=\).*/\1***/'
echo ""
echo "Новые значения из config.env:"
echo "  LLM_BASE_URL = ${LLM_BASE_URL}"
echo "  LLM_MODEL    = ${LLM_MODEL}"
echo "  LLM_API_KEY  = ${LLM_API_KEY:0:12}***"
echo ""
read -rp "Применить? [y/N] " C
[[ "$C" =~ ^[Yy]$ ]] || { echo "Отменено"; exit 0; }

# Подпуть задан -> агент ходит в Prometheus через nginx, без порта
if [[ -n "${PROMETHEUS_ROOT_PATH:-}" ]]; then
    PROM_URL_FOR_AGENT="${INTERNAL_BASE_URL:-http://localhost}${PROMETHEUS_ROOT_PATH}"
else
    PROM_URL_FOR_AGENT="http://localhost:9090"
fi

cat > "$AGENT_ENV" << EOF
LLM_BASE_URL=${LLM_BASE_URL}
LLM_API_KEY=${LLM_API_KEY}
LLM_MODEL=${LLM_MODEL}
LLM_MAX_TOKENS=${LLM_MAX_TOKENS}
LLM_TEMPERATURE=${LLM_TEMPERATURE}
PROMETHEUS_URL=${PROM_URL_FOR_AGENT}
AGENT_PORT=${AGENT_PORT}
REGISTRY_PATH=/opt/ai-alert-agent/clusters.json
WEB_DIR=/opt/ai-alert-agent/web
EOF
chmod 600 "$AGENT_ENV"
chown aiagent:aiagent "$AGENT_ENV" 2>/dev/null || true

systemctl restart ai-alert-agent
sleep 3

if curl -sf "http://localhost:${AGENT_PORT}/health" >/dev/null; then
    echo -e "${GREEN}✓ Агент перезапущен с новой конфигурацией${NC}"
    curl -s "http://localhost:${AGENT_PORT}/config" | python3 -m json.tool
else
    echo -e "${RED}Агент не поднялся — логи:${NC}"
    journalctl -u ai-alert-agent --no-pager -n 15
    exit 1
fi
