"""
Можно ли сейчас трогать базу.

Вопрос, который задают перед каждым обслуживанием: перезапустить реплику,
сделать ALTER, снять бэкап. Ответ складывается из пяти-шести проверок, которые
дежурный выполняет по памяти и половину забывает.

Здесь они собраны в один список с явным вердиктом. Вердикт не запрещает
действие — решение принимает человек, задача агента показать, чего он может
не знать.
"""
from __future__ import annotations

import logging
from typing import Optional

from agent.services.mysql import cluster_db_creds, sql_execute
from agent.services.replication import collect_replication

logger = logging.getLogger("agent.readiness")

# Долгие транзакции: они держат снимок и блокируют очистку старых версий строк
LONG_TRX_SQL = """
SELECT trx_id, trx_state,
       TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS age_s,
       trx_rows_locked AS rows_locked, trx_rows_modified AS rows_modified,
       LEFT(COALESCE(trx_query, ''), 200) AS query
  FROM information_schema.INNODB_TRX
 WHERE trx_started < NOW() - INTERVAL 60 SECOND
 ORDER BY trx_started
 LIMIT 20"""

# Активные запросы, кроме служебных
LONG_QUERY_SQL = """
SELECT ID AS id, USER AS usr, DB AS db, TIME AS secs, STATE AS state,
       LEFT(COALESCE(INFO, ''), 200) AS query
  FROM information_schema.PROCESSLIST
 WHERE COMMAND NOT IN ('Sleep', 'Binlog Dump', 'Binlog Dump GTID', 'Daemon')
   AND TIME > 30
 ORDER BY TIME DESC
 LIMIT 20"""

# Незакрытые блокировки метаданных ловят ALTER намертво
METADATA_LOCK_SQL = """
SELECT OBJECT_SCHEMA AS db, OBJECT_NAME AS tbl, LOCK_TYPE AS lock_type,
       LOCK_STATUS AS status, OWNER_THREAD_ID AS thread
  FROM performance_schema.metadata_locks
 WHERE LOCK_STATUS = 'PENDING'
 LIMIT 20"""


def _rows(result: dict) -> list[dict]:
    cols = result.get("columns") or []
    return [dict(zip(cols, r)) for r in (result.get("rows") or [])]


def _num(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


async def check(cluster: dict, action: str = "restart",
                host: Optional[str] = None) -> dict:
    """Проверки перед действием. action: restart | alter | backup."""
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — проверить "
                         "состояние нельзя"}

    checks: list[dict] = []

    def add(ok: bool, title: str, detail: str, blocking: bool = False) -> None:
        checks.append({"ok": ok, "title": title, "detail": detail,
                       "blocking": blocking and not ok})

    # ── Долгие транзакции ───────────────────────────────────────────────────
    trx = await sql_execute(cluster, LONG_TRX_SQL, host)
    if trx.get("error"):
        add(False, "Долгие транзакции", "не проверить: " + trx["error"])
    else:
        items = _rows(trx)
        oldest = max((_num(t.get("age_s")) for t in items), default=0)
        add(not items,
            "Долгие транзакции",
            ("Нет транзакций старше минуты." if not items else
             "Открыто %d, самая старая идёт %.0f с. Перезапуск оборвёт их, "
             "а откат займёт примерно столько же, сколько шла сама транзакция."
             % (len(items), oldest)),
            blocking=oldest > 300)

    # ── Активные запросы ────────────────────────────────────────────────────
    procs = await sql_execute(cluster, LONG_QUERY_SQL, host)
    if not procs.get("error"):
        items = _rows(procs)
        longest = max((_num(p.get("secs")) for p in items), default=0)
        add(not items,
            "Долгие запросы",
            ("Ничего дольше 30 секунд не выполняется." if not items else
             "Выполняется %d запросов дольше 30 с, самый долгий — %.0f с."
             % (len(items), longest)),
            blocking=longest > 600)

    # ── Блокировки метаданных: важны именно для ALTER ───────────────────────
    if action == "alter":
        locks = await sql_execute(cluster, METADATA_LOCK_SQL, host)
        if not locks.get("error"):
            items = _rows(locks)
            add(not items, "Ожидание блокировок метаданных",
                ("Никто не ждёт блокировку." if not items else
                 "В очереди %d ожиданий. ALTER встанет за ними и заблокирует "
                 "всех, кто придёт следом, — включая обычные SELECT."
                 % len(items)),
                blocking=bool(items))

    # ── Репликация ──────────────────────────────────────────────────────────
    try:
        states = await collect_replication(cluster)
    except Exception as exc:
        states = []
        logger.info("Состояние репликации не прочитано: %s", exc)
    if states:
        bad = [s for s in states if not s.get("healthy")]
        over = max((_num(s.get("over_plan_s")) for s in states), default=0)
        add(not bad, "Репликация",
            ("Реплики в порядке." if not bad else
             "Проблемы: " + "; ".join(p for s in bad for p in s.get("problems", []))),
            blocking=bool(bad) or over > 600)

    # ── Свежесть данных для действия ────────────────────────────────────────
    if action == "restart":
        add(True, "После перезапуска",
            "Буферный пул будет пуст: первые минуты запросы пойдут с диска, "
            "и база будет заметно медленнее обычного. Это нормально и "
            "проходит по мере прогрева.")
    if action == "alter":
        add(True, "Про ALTER",
            "Проверьте, поддерживает ли изменение алгоритм INPLACE: иначе "
            "таблица перестраивается целиком, нужен свободный объём размером "
            "с неё, и всё это время идёт запись в журнал изменений.")
    if action == "backup":
        add(True, "Про снятие копии",
            "Снимайте с реплики, если она есть: на источнике длительный "
            "FLUSH TABLES WITH READ LOCK останавливает запись целиком.")

    blocking = [c for c in checks if c["blocking"]]
    return {
        "cluster": cluster["name"], "action": action,
        "host": host or cluster["primary_ip"],
        "checks": checks,
        "verdict": "stop" if blocking else "go",
        "blocking": [c["title"] for c in blocking],
    }


def fmt_readiness(data: dict) -> str:
    if data.get("error"):
        return "## Готовность к обслуживанию\n\n  %s" % data["error"]

    titles = {"restart": "перезапуску", "alter": "изменению схемы",
              "backup": "снятию копии"}
    head = ("## Готовность к %s — %s"
            % (titles.get(data["action"], data["action"]), data["host"]))
    verdict = ("  Помех не видно." if data["verdict"] == "go" else
               "  ЕСТЬ ПОМЕХИ: " + ", ".join(data["blocking"]))
    lines = [head, "", verdict, ""]
    for item in data["checks"]:
        mark = "ок " if item["ok"] else ("СТОП" if item["blocking"] else "!  ")
        lines.append("  [%s] %s" % (mark, item["title"]))
        lines.append("       " + item["detail"])
    lines.append("")
    lines.append("  Это подсказка, а не запрет: решение за вами.")
    return "\n".join(lines)
