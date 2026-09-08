"""
Состояние репликации: почему реплика отстала, а не только на сколько.

Лаг из метрик отвечает «на сколько», но не «почему». Причина лежит в выводе
SHOW REPLICA STATUS: остановленный поток, ошибка применения, забитый relay
log, запланированная задержка. Без неё ответ про отставание — половина
ответа.

MySQL 8.0.22 переименовал колонки (Slave_* → Replica_*, Master_* → Source_*),
поэтому читаем оба варианта: в одном кластере могут оказаться серверы разных
версий.
"""
from __future__ import annotations

import logging
from typing import Optional

from agent.services.mysql import cluster_db_creds, sql_execute

logger = logging.getLogger("agent.replication")

# Старое имя -> новое. Читаем по любому из них.
ALIASES = {
    "io_running":      ("Slave_IO_Running", "Replica_IO_Running"),
    "sql_running":     ("Slave_SQL_Running", "Replica_SQL_Running"),
    "io_state":        ("Slave_IO_State", "Replica_IO_State"),
    "sql_state":       ("Slave_SQL_Running_State", "Replica_SQL_Running_State"),
    "behind":          ("Seconds_Behind_Master", "Seconds_Behind_Source"),
    "last_errno":      ("Last_Errno",),
    "last_error":      ("Last_Error",),
    "io_errno":        ("Last_IO_Errno",),
    "io_error":        ("Last_IO_Error",),
    "sql_errno":       ("Last_SQL_Errno",),
    "sql_error":       ("Last_SQL_Error",),
    "delay":           ("SQL_Delay",),
    "remaining_delay": ("SQL_Remaining_Delay",),
    "relay_space":     ("Relay_Log_Space",),
    "auto_position":   ("Auto_Position",),
    "retrieved_gtid":  ("Retrieved_Gtid_Set",),
    "executed_gtid":   ("Executed_Gtid_Set",),
    "source_host":     ("Master_Host", "Source_Host"),
    "read_pos":        ("Read_Master_Log_Pos", "Read_Source_Log_Pos"),
    "exec_pos":        ("Exec_Master_Log_Pos", "Exec_Source_Log_Pos"),
    "source_file":     ("Master_Log_File", "Source_Log_File"),
    "relay_file":      ("Relay_Master_Log_File", "Relay_Source_Log_File"),
}


def _pick(row: dict, key: str):
    for name in ALIASES[key]:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return None


def _as_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def replica_status(cluster: dict, host: str) -> dict:
    """Разобранный SHOW REPLICA STATUS. Пустой словарь — сервер не реплика."""
    if not cluster_db_creds(cluster):
        return {"error": "не задана учётка db_user"}

    # 8.0.22+ понимает только REPLICA, более старые — только SLAVE
    for statement in ("SHOW REPLICA STATUS", "SHOW SLAVE STATUS"):
        result = await sql_execute(cluster, statement, host)
        if result.get("error"):
            continue
        rows = result.get("rows") or []
        if not rows:
            return {}                    # не реплика — это не ошибка
        row = dict(zip(result.get("columns") or [], rows[0]))
        return _describe(row, host)
    return {"error": "SHOW REPLICA STATUS недоступен: нужны права "
                     "REPLICATION CLIENT"}


def _describe(row: dict, host: str) -> dict:
    """Что важно знать про реплику, с уже сделанными выводами."""
    io_ok  = str(_pick(row, "io_running") or "").lower() == "yes"
    sql_ok = str(_pick(row, "sql_running") or "").lower() == "yes"
    behind = _as_int(_pick(row, "behind"))
    delay  = _as_int(_pick(row, "delay")) or 0
    remaining = _as_int(_pick(row, "remaining_delay"))

    problems = []
    if not io_ok:
        problems.append("поток ввода-вывода остановлен — реплика не получает "
                        "изменения с источника")
    if not sql_ok:
        problems.append("поток применения остановлен — полученное не "
                        "накатывается")
    for errno_key, err_key, what in (("sql_errno", "sql_error", "применения"),
                                     ("io_errno", "io_error", "подключения"),
                                     ("last_errno", "last_error", "последняя")):
        errno = _as_int(_pick(row, errno_key))
        text  = _pick(row, err_key)
        if errno and text:
            problems.append("ошибка %s (%d): %s" % (what, errno, str(text)[:300]))

    # Отставание сверх запланированного: у реплики с MASTER_DELAY отставание
    # на величину задержки — норма, и путать одно с другим нельзя
    over = None
    if behind is not None:
        over = max(0, behind - delay)
        if delay and over > 60:
            problems.append("отставание %d с превышает запланированные %d с "
                            "на %d с" % (behind, delay, over))
        elif not delay and behind > 60:
            problems.append("отставание %d с при незаданной задержке" % behind)

    read_pos, exec_pos = _as_int(_pick(row, "read_pos")), _as_int(_pick(row, "exec_pos"))
    same_file = _pick(row, "source_file") == _pick(row, "relay_file")
    backlog = (read_pos - exec_pos) if (read_pos and exec_pos and same_file) else None
    if backlog and backlog > 50 * 1024 * 1024:
        problems.append("не применено %.0f МБ уже полученного журнала — "
                        "упирается в применение, а не в сеть"
                        % (backlog / 1048576))

    retrieved = str(_pick(row, "retrieved_gtid") or "")
    executed  = str(_pick(row, "executed_gtid") or "")
    gtid_lag = bool(retrieved and executed and retrieved != executed)

    return {
        "host": host,
        "io_running": io_ok, "sql_running": sql_ok,
        "io_state": _pick(row, "io_state"), "sql_state": _pick(row, "sql_state"),
        "source": _pick(row, "source_host"),
        "behind_s": behind, "planned_delay_s": delay,
        "over_plan_s": over, "remaining_delay_s": remaining,
        "relay_space_mb": (lambda v: round(v / 1048576, 1) if v else None)(
            _as_int(_pick(row, "relay_space"))),
        "unapplied_bytes": backlog,
        "gtid_mode": bool(_as_int(_pick(row, "auto_position"))),
        "gtid_behind": gtid_lag,
        "healthy": io_ok and sql_ok and not problems,
        "problems": problems,
    }


def fmt_replication(items: list, label: str) -> str:
    """Блок про репликацию для подсказки модели и для человека."""
    known = [i for i in items if i and not i.get("error")]
    if not known:
        errors = [i["error"] for i in items if i and i.get("error")]
        if errors:
            return ("## Репликация %s\n\n  Состояние не прочитано: %s"
                    % (label, errors[0]))
        return ""

    lines = ["## Репликация %s" % label, ""]
    for state in known:
        if not state:
            continue
        head = "  %s: " % state["host"]
        head += "в порядке" if state["healthy"] else "ЕСТЬ ПРОБЛЕМЫ"
        lines.append(head)
        lines.append("      потоки: чтение %s, применение %s"
                     % ("идёт" if state["io_running"] else "ОСТАНОВЛЕН",
                        "идёт" if state["sql_running"] else "ОСТАНОВЛЕН"))
        if state["behind_s"] is not None:
            note = ""
            if state["planned_delay_s"]:
                note = (" (из них %d с — запланированная задержка, сверх плана %d с)"
                        % (state["planned_delay_s"], state["over_plan_s"] or 0))
            lines.append("      отставание: %d с%s" % (state["behind_s"], note))
        else:
            lines.append("      отставание: NULL — репликация не идёт или "
                         "поток применения не работает")
        if state["relay_space_mb"]:
            lines.append("      relay log: %.1f МБ" % state["relay_space_mb"])
        if state["gtid_behind"]:
            lines.append("      GTID: полученное не совпадает с применённым — "
                         "часть транзакций ещё не накатана")
        for problem in state["problems"]:
            lines.append("      ! %s" % problem)
    lines.append("")
    lines.append("  Seconds_Behind_Source считается по метке времени последней "
                 "применённой транзакции: на простаивающем источнике он "
                 "показывает 0 даже при реальном отставании. Сверяйте с "
                 "позицией журнала и метриками.")
    return "\n".join(lines)


async def collect_replication(cluster: dict) -> list:
    """Состояние на всех серверах кластера: реплика может быть не одна."""
    from agent.services.registry import cluster_hosts
    out = []
    for ip, role in cluster_hosts(cluster):
        if role == "primary":
            continue           # у источника своего статуса реплики нет
        try:
            state = await replica_status(cluster, ip)
        except Exception as exc:
            logger.error("Состояние репликации %s не прочитано: %s", ip, exc)
            state = {"error": str(exc)}
        if state:
            out.append(state)
    return out
