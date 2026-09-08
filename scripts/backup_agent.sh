#!/usr/bin/env bash
# =============================================================================
#  backup_agent.sh — резервная копия базы агента
#
#  История инцидентов с записанными решениями копится месяцами и живёт в одном
#  файле. Потерять её — значит потерять всё, чему агент научился: чем
#  заканчивались аварии и что помогало.
#
#  Копия снимается штатным средством, а не cp: копировать файл SQLite во время
#  записи — верный способ получить битую базу.
#
#    ./scripts/backup_agent.sh                 # в /var/backups/ai-agent
#    ./scripts/backup_agent.sh /mnt/backup     # в указанный каталог
#    ./scripts/backup_agent.sh --restore ФАЙЛ  # восстановить
#
#  В cron раз в сутки:
#    15 3 * * * /opt/mysql-ai-monitoring/scripts/backup_agent.sh >/dev/null
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib_secrets.sh"
CONFIG="${SCRIPT_DIR}/../config.env"
[[ -f "$CONFIG" ]] && load_config "$CONFIG"

AGENT_ENV="/opt/ai-alert-agent/.env"
[[ -f "$AGENT_ENV" ]] && load_config "$AGENT_ENV"

DB_URL="${DB_URL:-}"
DB_PATH="${ALERTS_DB_PATH:-/opt/ai-alert-agent/alerts.db}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-30}"

# ── Восстановление ───────────────────────────────────────────────────────────
if [[ "${1:-}" == "--restore" ]]; then
    SRC="${2:-}"
    [[ -f "$SRC" ]] || { log_error "Файл не найден: $SRC"; exit 1; }
    [[ -n "$DB_URL" && "$DB_URL" == mysql* ]] && {
        log_error "Хранилище в MySQL — восстанавливайте через mysql < файл"
        exit 1; }

    log_warn "Агент будет остановлен на время восстановления"
    systemctl stop ai-alert-agent 2>/dev/null || true
    # Прежнюю базу не удаляем, а отодвигаем: если копия окажется битой,
    # вернуться будет некуда
    [[ -f "$DB_PATH" ]] && mv "$DB_PATH" "${DB_PATH}.before-restore.$(date +%s)"
    if [[ "$SRC" == *.gz ]]; then
        gunzip -c "$SRC" > "$DB_PATH"
    else
        cp "$SRC" "$DB_PATH"
    fi
    chown aiagent:aiagent "$DB_PATH" 2>/dev/null || true
    systemctl start ai-alert-agent 2>/dev/null || true
    log_info "Восстановлено из $SRC. Прежняя база рядом с суффиксом .before-restore"
    exit 0
fi

# ── Снятие копии ─────────────────────────────────────────────────────────────
DEST="${1:-/var/backups/ai-agent}"
mkdir -p "$DEST"
STAMP="$(date +%Y%m%d-%H%M%S)"

if [[ -n "$DB_URL" && "$DB_URL" == mysql* ]]; then
    # mysql+asyncmy://user:pass@host:port/db
    BODY="${DB_URL#*://}"
    CRED="${BODY%%@*}"; REST="${BODY#*@}"
    DB_USER="${CRED%%:*}"; DB_PASS="${CRED#*:}"
    HOSTPORT="${REST%%/*}"; DB_NAME="${REST#*/}"; DB_NAME="${DB_NAME%%\?*}"
    DB_HOST="${HOSTPORT%%:*}"; DB_PORT="${HOSTPORT#*:}"
    [[ "$DB_PORT" == "$DB_HOST" ]] && DB_PORT=3306

    OUT="${DEST}/agent-${STAMP}.sql.gz"
    log_info "Хранилище в MySQL: ${DB_HOST}:${DB_PORT}/${DB_NAME}"
    # Пароль через переменную окружения: в аргументах его видно в ps
    MYSQL_PWD="$DB_PASS" mysqldump --single-transaction --quick \
        -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" "$DB_NAME" | gzip > "$OUT"
else
    [[ -f "$DB_PATH" ]] || { log_error "База не найдена: $DB_PATH"; exit 1; }
    OUT="${DEST}/agent-${STAMP}.db.gz"
    log_info "Хранилище в SQLite: $DB_PATH"
    # .backup, а не cp: копирование файла во время записи даёт битую базу
    if command -v sqlite3 >/dev/null 2>&1; then
        TMP="$(mktemp)"
        sqlite3 "$DB_PATH" ".backup '$TMP'"
        gzip -c "$TMP" > "$OUT"
        rm -f "$TMP"
    else
        log_warn "sqlite3 не установлен — копирую средствами Python"
        python3 - "$DB_PATH" "$OUT" <<'PYEOF'
import gzip, shutil, sqlite3, sys, tempfile
src, dst = sys.argv[1], sys.argv[2]
tmp = tempfile.NamedTemporaryFile(delete=False).name
with sqlite3.connect(src) as source, sqlite3.connect(tmp) as target:
    source.backup(target)
with open(tmp, "rb") as f, gzip.open(dst, "wb") as g:
    shutil.copyfileobj(f, g)
PYEOF
    fi
fi

chmod 600 "$OUT"
SIZE="$(du -h "$OUT" | cut -f1)"
log_info "Копия: $OUT ($SIZE)"

# ── Чистка старых ────────────────────────────────────────────────────────────
REMOVED=$(find "$DEST" -maxdepth 1 -name 'agent-*.gz' -mtime "+${KEEP_DAYS}" -print -delete | wc -l)
[[ "$REMOVED" -gt 0 ]] && log_info "Удалено копий старше ${KEEP_DAYS} дн.: $REMOVED"

COUNT=$(find "$DEST" -maxdepth 1 -name 'agent-*.gz' | wc -l)
log_info "Всего копий в ${DEST}: $COUNT"
