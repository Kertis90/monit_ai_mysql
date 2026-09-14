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
source "${SCRIPT_DIR}/lib_secrets.sh"
load_config "${SCRIPT_DIR}/../config.env"

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

# Правим только свои ключи, а не переписываем файл целиком. Раньше здесь
# был cat > .env с девятью строками — и всё остальное пропадало: секрет
# сессий, хеш пароля администратора, настройки LDAP, SSH и базы агента.
# После такой «смены модели» в агент нельзя было войти.
cp -p "$AGENT_ENV" "${AGENT_ENV}.bak.$(date +%Y%m%d-%H%M%S)"

set_env() {
    python3 - "$AGENT_ENV" "$1" "$2" << 'PY'
import io, sys

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
lines = io.open(path, encoding="utf-8").read().splitlines()
out, done = [], False
for line in lines:
    if line.startswith(key + "="):
        if not done:                 # дубликаты ключа схлопываем
            out.append("%s=%s" % (key, value))
            done = True
    else:
        out.append(line)
if not done:
    out.append("%s=%s" % (key, value))
io.open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
PY
}

set_env LLM_BASE_URL    "${LLM_BASE_URL}"
set_env LLM_API_KEY     "${LLM_API_KEY}"
set_env LLM_MODEL       "${LLM_MODEL}"
set_env LLM_MAX_TOKENS  "${LLM_MAX_TOKENS}"
set_env LLM_TEMPERATURE "${LLM_TEMPERATURE}"
set_env LLM_TOOLS       "${LLM_TOOLS:-auto}"
set_env LLM_TOOL_ROUNDS "${LLM_TOOL_ROUNDS:-4}"
set_env LLM_TOOL_ASK_S  "${LLM_TOOL_ASK_S:-120}"
set_env EMBED_MODE      "${EMBED_MODE:-auto}"
set_env EMBED_MODEL     "${EMBED_MODEL:-}"
set_env PROMETHEUS_URL  "${PROM_URL_FOR_AGENT}"
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
