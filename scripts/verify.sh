#!/usr/bin/env bash
# =============================================================================
#  verify.sh — Проверка всего стека, включая WebSocket
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config.env"

OK="  ${GREEN}✓${NC}"; FAIL="  ${RED}✗${NC}"; WARN="  ${YELLOW}!${NC}"

check() {
    if eval "$2" &>/dev/null; then echo -e "${OK} $1"; else echo -e "${FAIL} $1"; fi
}

echo ""
echo -e "${BOLD}${BLUE}══════════ MySQL AI Monitoring — проверка ══════════${NC}"
echo ""

echo -e "${CYAN}► Сервисы${NC}"
check "Prometheus"     "systemctl is-active prometheus"
check "Alertmanager"   "systemctl is-active alertmanager"
check "Grafana"        "systemctl is-active grafana-server"
check "AI Agent"       "systemctl is-active ai-alert-agent"
echo ""

echo -e "${CYAN}► HTTP${NC}"
check "Prometheus healthy"   "curl -sf http://localhost:9090/-/healthy"
check "Alertmanager healthy" "curl -sf http://localhost:9093/-/healthy"
check "Grafana healthy"      "curl -sf http://localhost:3000/api/health"
check "AI Agent /health"     "curl -sf http://localhost:${AGENT_PORT}/health"
check "AI Agent веб-UI"      "curl -sf http://localhost:${AGENT_PORT}/ | grep -q 'MySQL AI Agent'"
check "AI Agent статика JS"  "curl -sf http://localhost:${AGENT_PORT}/static/app.js | grep -q WebSocket"
echo ""

echo -e "${CYAN}► WebSocket${NC}"
# Тест WS через python
WS_RESULT=$(python3 - << PYEOF 2>/dev/null
import asyncio, json, sys
try:
    import websockets
except ImportError:
    # Использовать venv агента
    sys.path.insert(0, '/opt/ai-alert-agent/venv/lib/python3.9/site-packages')
    sys.path.insert(0, '/opt/ai-alert-agent/venv/lib/python3.11/site-packages')
    sys.path.insert(0, '/opt/ai-alert-agent/venv/lib/python3.12/site-packages')
    try:
        import websockets
    except ImportError:
        print("SKIP")
        sys.exit(0)

async def test():
    try:
        async with websockets.connect("ws://localhost:${AGENT_PORT}/ws",
                                      open_timeout=5) as ws:
            await ws.send(json.dumps({"type": "ping"}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(resp)
            print("OK" if data.get("type") == "pong" else "FAIL")
    except Exception as e:
        print(f"FAIL: {e}")

asyncio.run(test())
PYEOF
)
if [[ "$WS_RESULT" == "OK" ]]; then
    echo -e "${OK} WebSocket ping/pong работает"
elif [[ "$WS_RESULT" == "SKIP" ]]; then
    echo -e "${WARN} websockets-модуль недоступен для теста (сам агент работает через uvicorn)"
else
    echo -e "${FAIL} WebSocket: ${WS_RESULT}"
fi
echo ""

echo -e "${CYAN}► Кластеры и таргеты${NC}"
CLUSTERS=$(curl -sf "http://localhost:${AGENT_PORT}/clusters" 2>/dev/null | \
    python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d['clusters']))" 2>/dev/null || echo "0")
echo -e "  Кластеров в реестре: ${BOLD}${CLUSTERS}${NC}"

TARGETS=$(curl -sf "http://localhost:9090/api/v1/targets" 2>/dev/null)
if [[ -n "$TARGETS" ]]; then
    echo "$TARGETS" | python3 -c "
import json, sys
d = json.load(sys.stdin)
targets = d.get('data', {}).get('activeTargets', [])
up   = sum(1 for t in targets if t.get('health') == 'up')
down = sum(1 for t in targets if t.get('health') != 'up')
print(f'  Prometheus таргетов: UP={up}  DOWN={down}')
for t in targets:
    if t.get('health') != 'up':
        inst = t.get('labels', {}).get('instance', '?')
        cl   = t.get('labels', {}).get('cluster_label', '')
        print(f'    ✗ DOWN: {inst} {cl}')
"
fi
echo ""

echo -e "${CYAN}► LLM${NC}"
CONFIG_JSON=$(curl -sf "http://localhost:${AGENT_PORT}/config" 2>/dev/null || echo "{}")
echo "$CONFIG_JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f\"  URL:    {d.get('llm_base_url','?')}\")
print(f\"  Model:  {d.get('llm_model','?')}\")
print(f\"  Токен:  {'установлен' if d.get('auth_header_set') else 'НЕ УСТАНОВЛЕН!'}\")
" 2>/dev/null || echo "  Не удалось получить конфиг агента"

echo -e "  Тестовый запрос к LLM (до 30с)..."
CHAT_RESP=$(curl -sf -X POST "http://localhost:${AGENT_PORT}/chat" \
    -H "Content-Type: application/json" \
    -d '{"message":"Ответь одним словом: работаешь?"}' \
    --max-time 45 2>/dev/null || echo "")
if echo "$CHAT_RESP" | grep -q '"answer"'; then
    ANSWER=$(echo "$CHAT_RESP" | python3 -c \
        "import json,sys;print(json.load(sys.stdin)['answer'][:150])" 2>/dev/null)
    if [[ "$ANSWER" == \[Ошибка* ]]; then
        echo -e "${FAIL} LLM: ${ANSWER}"
    else
        echo -e "${OK} LLM ответил: ${ANSWER}"
    fi
else
    echo -e "${FAIL} Чат не ответил (проверьте LLM_BASE_URL / LLM_API_KEY)"
fi
echo ""

echo -e "${BOLD}${BLUE}── Точки доступа ──────────────────────────────${NC}"
echo ""
echo "  💬 Чат AI Agent : http://${MONITORING_IP}:${AGENT_PORT}/"
echo "  📊 Grafana      : http://${MONITORING_IP}:3000"
echo "  🔍 Prometheus   : http://${MONITORING_IP}:9090"
echo "  🔔 Alertmanager : http://${MONITORING_IP}:9093"
echo ""
