"""
Читающие запросы к кластерам.

Права нужны ровно SELECT: писать агент не должен ни при каких
обстоятельствах, поэтому запрет проверяется до отправки запроса, а не
надеждой на грант. Три режима подключения — прямой TCP, SSH-туннель и
выполнение клиентом mysql на самом сервере.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import socket
import time
from contextlib import closing
from typing import Optional

from agent.core.config import settings
from agent.services.registry import enabled_clusters
from agent.services.ssh import log_ssh

logger = logging.getLogger("agent.mysql")

SQL_TIMEOUT_S   = settings.sql.timeout_s
SQL_MAX_ROWS    = settings.sql.max_rows

# С какой длины колонка считается «длинной» и печатается отдельным абзацем,
# а не ячейкой таблицы. Ниже этого выравнивание в столбик читается лучше.
WIDE_COLUMN_CHARS = 90

# Предел на одно длинное значение. SHOW ENGINE INNODB STATUS на нагруженном
# сервере — это десятки килобайт со списком транзакций; начало и середина
# там информативны, а хвост из тысячи одинаковых записей — нет.
LONG_VALUE_CHARS = 20000
LOG_SSH_USER    = settings.ssh.user
LOG_SSH_PORT    = settings.ssh.port
LOG_SSH_KEY     = settings.ssh.key
LOG_SSH_TIMEOUT = settings.ssh.timeout

# Версии СУБД по кластерам: спрашиваем на старте, чтобы модель знала,
# о чём пишет — у 5.7 и 8.0 разные имена таблиц performance_schema
DB_VERSIONS: dict = {}

# Разрешены только читающие формы. SHOW/EXPLAIN/DESCRIBE нужны для диагностики.
SQL_ALLOWED_HEADS = ("select", "show", "explain", "describe", "desc", "with")

# Явный чёрный список — вторая линия после проверки первого слова: WITH ... может
# в MySQL 8 содержать изменяющие конструкции, а комментарии умеют их прятать.
SQL_FORBIDDEN = (
    "insert", "update", "delete", "drop", "truncate", "alter", "create",
    "rename", "replace", "grant", "revoke", "set", "call", "lock", "unlock",
    "load", "handler", "flush", "kill", "start", "commit", "rollback",
    "savepoint", "prepare", "execute", "outfile", "dumpfile",
)


def sql_strip_comments(sql: str) -> str:
    """Убрать комментарии: без этого запрет обходится через /*!*/ и -- ."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"#[^\n]*", " ", sql)
    return sql.strip()


def sql_validate(sql: str) -> tuple[bool, str]:
    """(можно ли выполнять, причина отказа)."""
    # MySQL ИСПОЛНЯЕТ содержимое /*! ... */ и /*+ ... */. Если просто вырезать
    # комментарии перед проверкой, туда прячется что угодно — поэтому такие
    # конструкции отклоняем целиком, до разбора.
    if re.search(r"/\*[!+]", sql):
        return False, "Исполняемые комментарии MySQL (/*! …) запрещены"

    clean = sql_strip_comments(sql)
    if not clean:
        return False, "Пустой запрос"

    # Несколько инструкций в одном запросе не пропускаем: точка с запятой
    # допустима только как завершающая.
    body = clean.rstrip(";").strip()
    if ";" in body:
        return False, "Разрешён только один запрос без ';' внутри"

    low = body.lower()
    head = low.split(None, 1)[0] if low.split() else ""
    if head not in SQL_ALLOWED_HEADS:
        return False, f"Разрешены только {', '.join(SQL_ALLOWED_HEADS).upper()}"

    # Границы слова с ОБЕИХ сторон: без хвостовой границы «created» ловился
    # как CREATE, и нормальные запросы отклонялись.
    flat = re.sub(r"\s+", " ", low)
    for bad in SQL_FORBIDDEN:
        if re.search(r"(?<![a-z0-9_])" + re.escape(bad) + r"(?![a-z0-9_])", flat):
            return False, f"Запрещённая конструкция: {bad.upper()}"

    return True, ""


def sql_add_limit(sql: str, max_rows: int = 0) -> str:
    """Дописать LIMIT, если его нет — чтобы не вытащить миллион строк."""
    body = sql_strip_comments(sql).rstrip(";").strip()
    if re.search(r"(?<![a-z_])limit\s+\d", body, re.I):
        return body
    if body.lower().startswith(("show", "explain", "describe", "desc")):
        return body           # у них LIMIT либо не нужен, либо не поддержан
    return f"{body} LIMIT {max_rows or SQL_MAX_ROWS}"


def cluster_db_creds(cluster: dict) -> Optional[tuple]:
    user = (cluster.get("db_user") or "").strip()
    if not user:
        return None
    return user, cluster.get("db_password") or ""


def cluster_db_mode(cluster: dict) -> str:
    """Как ходить в MySQL этого кластера: direct, exec или tunnel.

      direct — прямое TCP-соединение на 3306 сервера БД;
      exec   — SSH, запрос выполняет клиент mysql на самом сервере;
      tunnel — SSH пробрасывает локальный порт на 3306, дальше pymysql.

    Туннель отличается от exec тем, что на сервере не нужен клиент mysql, а
    значения приходят типами MySQL, а не текстом из TSV. Порт наружу при этом
    всё равно не открывается.

    Старое булево значение db_via_ssh продолжает работать и означает exec.
    """
    v = cluster.get("db_via_ssh")
    if v is None:
        v = os.environ.get("DB_VIA_SSH", "false")
    v = str(v).strip().lower()
    if v in ("tunnel", "ssh_tunnel", "туннель"):
        return "tunnel"
    if v in ("1", "true", "yes", "exec", "ssh"):
        return "exec"
    return "direct"


def cluster_via_ssh(cluster: dict) -> bool:
    """Не прямое TCP-соединение (exec или tunnel)."""
    return cluster_db_mode(cluster) != "direct"


def conn_hint(exc: Exception) -> str:
    """Подсказка к типовым отказам подключения.

    Самый частый — caching_sha2_password: MySQL 8.0 включает этот плагин по
    умолчанию, а pymysql без пакета cryptography его не умеет. Сообщение
    драйвера про «requires cryptography» без пояснения выглядит как поломка
    сервера, хотя чинится на стороне агента.
    """
    text = str(exc).lower()
    if "cryptography" in text or "caching_sha2" in text:
        return ("\n  Не установлен пакет cryptography — он нужен для плагина "
                "caching_sha2_password (в MySQL 8.0 он включён по умолчанию).\n"
                "  Поправить: sudo ./scripts/install_agent.sh — пакет ставится "
                "рядом с pymysql.\n"
                "  Если его нет во внутреннем индексе pip, переведите учётку "
                "агента на прежний плагин:\n"
                "  ALTER USER 'db_user'@'%' IDENTIFIED WITH "
                "mysql_native_password BY 'пароль';")
    if "access denied" in text:
        return "\n  Проверьте db_user и db_password в clusters.json."
    return ""


def sql_run(cluster: dict, sql: str, host: Optional[str] = None,
            max_rows: int = 0,
            endpoint: Optional[tuple] = None) -> dict:
    """Выполнить читающий запрос по TCP.

    endpoint — куда реально подключаться (адрес, порт). Нужен для туннеля: там
    соединение идёт на 127.0.0.1 со случайным портом, а в отчёте должен стоять
    адрес сервера БД. Пусто — подключаемся прямо к host:3306.

    Для режима exec есть sql_run_ssh; выбор делает sql_execute.
    """
    creds = cluster_db_creds(cluster)
    if not creds:
        return {"error": "Для этого кластера не задана учётка db_user — "
                         "SQL-запросы отключены"}
    ok, why = sql_validate(sql)
    if not ok:
        logger.warning(f"SQL отклонён ({why}): {sql[:120]}")
        return {"error": f"Запрос отклонён: {why}"}

    try:
        import pymysql
    except ImportError:
        return {"error": "Не установлен pymysql — переустановите агента "
                         "с заполненным db_user в clusters.json: "
                         "sudo ./scripts/install_agent.sh"}

    user, password = creds
    ip = host or cluster["primary_ip"]
    cap = max_rows or SQL_MAX_ROWS
    query = sql_add_limit(sql, cap)
    conn_host, conn_port = endpoint or (ip, 3306)
    try:
        conn = pymysql.connect(
            host=conn_host, port=conn_port, user=user, password=password,
            connect_timeout=SQL_TIMEOUT_S, read_timeout=SQL_TIMEOUT_S,
            charset="utf8mb4", cursorclass=pymysql.cursors.Cursor,
            autocommit=True)
    except Exception as e:
        return {"error": f"Не удалось подключиться к {ip}: {e}{conn_hint(e)}"}

    try:
        with conn.cursor() as cur:
            # Страховка на стороне сервера: даже если валидатор что-то упустил,
            # сессия не сможет писать.
            try:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
            except Exception:
                pass          # на реплике может быть уже read_only
            cur.execute(f"SET SESSION MAX_EXECUTION_TIME={SQL_TIMEOUT_S * 1000}")
            cur.execute(query)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchmany(cap)
        return {"host": ip, "query": query, "columns": cols,
                "rows": [list(r) for r in rows], "truncated": len(rows) >= cap}
    except Exception as e:
        return {"error": f"Ошибка выполнения на {ip}: {e}"}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def parse_mysql_batch(text: str) -> tuple:
    """Разобрать вывод `mysql -B`: TSV, первая строка — заголовки.

    В batch-режиме клиент экранирует управляющие символы внутри значений,
    поэтому строки не «разъезжаются», но обратные слэши надо развернуть.
    """
    lines = text.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return [], []

    def unesc(v):
        if v == "NULL":
            return None
        return (v.replace("\\t", "\t").replace("\\n", "\n")
                 .replace("\\0", "\0").replace("\\\\", "\\"))

    cols = lines[0].split("\t")
    rows = [[unesc(c) for c in ln.split("\t")] for ln in lines[1:]]
    return cols, rows


async def sql_run_ssh(cluster: dict, sql: str,
                      host: Optional[str] = None,
                      max_rows: int = 0) -> dict:
    """Читающий запрос через клиент mysql на самом сервере."""
    ok, why = sql_validate(sql)
    if not ok:
        logger.warning("SQL отклонён (%s): %s", why, sql[:120])
        return {"error": "Запрос отклонён: " + why}

    ip = host or cluster["primary_ip"]
    query = sql_add_limit(sql)
    creds = cluster_db_creds(cluster)

    # -B: табличный вывод через табуляцию, с заголовками
    # --connect-timeout / MAX_EXECUTION_TIME ограничивают зависание
    parts = ["mysql", "-B", "--connect-timeout=" + str(SQL_TIMEOUT_S)]
    env = {}
    if creds:
        user, password = creds
        parts += ["-u", shlex.quote(user), "-h", "127.0.0.1"]
        if password:
            # пароль в MYSQL_PWD, а не в аргументах: в ps его увидели бы все
            env["MYSQL_PWD"] = password
    # без creds полагаемся на ~/.my.cnf учётки, под которой заходим по SSH

    stmt = "SET SESSION MAX_EXECUTION_TIME={}; {}".format(
        SQL_TIMEOUT_S * 1000, query)
    parts += ["-e", shlex.quote(stmt)]
    cmd = " ".join(parts)

    ok, out = await log_ssh(ip, cmd, ok_codes=(0,), env=env)
    if not ok:
        # пароль в текст ошибки не попадает: он шёл переменной окружения
        return {"error": "Ошибка выполнения на {}: {}".format(ip, out[:300])}

    cols, rows = parse_mysql_batch(out)
    cap = max_rows or SQL_MAX_ROWS
    return {"host": ip, "query": query, "columns": cols,
            "rows": rows[:cap],
            "truncated": len(rows) > cap, "via": "ssh"}


def free_local_port() -> int:
    """Свободный порт на локальном интерфейсе для проброса.

    Между освобождением и тем, как ssh его займёт, порт теоретически может
    перехватить кто-то ещё. На сервере мониторинга это маловероятно, а ssh с
    ExitOnForwardFailure в таком случае сразу завершится с ошибкой, и мы это
    увидим, а не зависнем.
    """
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def wait_port(port: int, deadline: float) -> bool:
    """Дождаться, пока проброшенный порт начнёт принимать соединения."""
    while time.time() < deadline:
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except OSError:
            await asyncio.sleep(0.15)
    return False


async def sql_run_tunnel(cluster: dict, sql: str,
                         host: Optional[str] = None,
                         max_rows: int = 0) -> dict:
    """Запрос через SSH-туннель: локальный порт → 3306 на сервере БД.

    Туннель поднимается на время запроса и закрывается сразу после: держать
    постоянное соединение значит следить за его живостью и чинить обрывы, а
    выигрыш в доли секунды того не стоит.

    MySQL видит подключение как пришедшее с самого сервера, поэтому учётке
    достаточно прав 'ai_agent'@'localhost'.
    """
    ip = host or cluster["primary_ip"]
    if not LOG_SSH_USER:
        return {"error": "Не задан SSH_USER — туннель поднять не под кем. "
                         "Заполните его в config.env и переустановите агента."}
    if not cluster_db_creds(cluster):
        return {"error": "Для этого кластера не задана учётка db_user — "
                         "SQL-запросы отключены"}

    port = free_local_port()
    argv = ["ssh", "-N", "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
            "-o", "ConnectTimeout=" + str(LOG_SSH_TIMEOUT),
            "-p", str(LOG_SSH_PORT)]
    if LOG_SSH_KEY:
        argv += ["-i", LOG_SSH_KEY]
    argv += ["-L", "127.0.0.1:%d:127.0.0.1:3306" % port,
             LOG_SSH_USER + "@" + ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE)
    except Exception as e:
        return {"error": f"Не удалось запустить ssh для туннеля к {ip}: {e}"}

    try:
        ready = await wait_port(port, time.time() + LOG_SSH_TIMEOUT)
        if not ready:
            err = ""
            if proc.returncode is not None:      # ssh уже умер — есть причина
                try:
                    err = (await proc.stderr.read()).decode("utf-8", "replace")
                except Exception:
                    pass
            return {"error": f"Туннель к {ip} не поднялся"
                             + (f": {err.strip()[:200]}" if err.strip() else
                                f" за {LOG_SSH_TIMEOUT} с")}
        res = await asyncio.to_thread(sql_run, cluster, sql, ip, max_rows,
                                      ("127.0.0.1", port))
        if not res.get("error"):
            res["via"] = "tunnel"
        return res
    finally:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
        except Exception:
            pass


async def sql_execute(cluster: dict, sql: str,
                      host: Optional[str] = None,
                      max_rows: int = 0) -> dict:
    """Единая точка входа: сама выбирает режим доступа к БД.

    max_rows — предел строк для этого запроса. По умолчанию действует общий
    SQL_MAX_ROWS: он защищает вкладку SQL от «SELECT * FROM большая_таблица».
    Служебным запросам агента этот предел вредит: SHOW GLOBAL VARIABLES в
    MySQL 8 отдаёт больше шестисот строк, и на двухстах ответ обрывался
    посреди алфавита — version, sql_mode и sync_binlog просто не доезжали,
    а разбор настроек молча считал их отсутствующими.
    """
    mode = cluster_db_mode(cluster)
    if mode == "exec":
        return await sql_run_ssh(cluster, sql, host, max_rows)
    if mode == "tunnel":
        return await sql_run_tunnel(cluster, sql, host, max_rows)
    # pymysql блокирующий, поэтому уводим его из цикла событий
    return await asyncio.to_thread(sql_run, cluster, sql, host, max_rows)


def fmt_sql_result(res: dict) -> str:
    if res.get("error"):
        return f"## Результат SQL\n\n  {res['error']}"
    cols, rows = res["columns"], res["rows"]
    via = {"ssh": " через SSH", "tunnel": " через SSH-туннель"}.get(
        res.get("via"), "")
    head = [f"## Результат SQL ({res['host']}{via})",
            f"  Запрос: {res['query']}", ""]
    if not rows:
        head.append("  Строк не найдено.")
        return "\n".join(head)

    def text(v):
        return "NULL" if v is None else str(v)

    # Какие колонки не влезают в таблицу. Раньше их резали до шестидесяти
    # символов вместе со всеми остальными — и SHOW ENGINE INNODB STATUS
    # превращался в первую строку заголовка, а текст запроса в топе тяжёлых
    # обрывался на середине FROM. Ровно то, ради чего раздел и открывают.
    longest = [max([len(c)] + [len(text(r[i])) for r in rows])
               for i, c in enumerate(cols)]
    # Длинная колонка — или та, внутри которой есть перевод строки: он
    # разваливает таблицу независимо от длины, а именно так выглядит
    # SHOW ENGINE INNODB STATUS
    multiline = {i for i in range(len(cols))
                 if any("\n" in text(r[i]) for r in rows)}
    wide = {i for i, size in enumerate(longest)
            if size > WIDE_COLUMN_CHARS} | multiline

    if not wide:
        widths = longest
        head.append("  " + " | ".join(c.ljust(w) for c, w in zip(cols, widths)))
        head.append("  " + "-+-".join("-" * w for w in widths))
        for r in rows:
            head.append("  " + " | ".join(text(v).ljust(w)
                                          for v, w in zip(r, widths)))
        if res.get("truncated"):
            head.append(f"  (показаны первые {SQL_MAX_ROWS} строк)")
        return "\n".join(head)

    # Есть длинные значения: короткие колонки идут строкой, длинные —
    # отдельными абзацами и целиком
    for n, r in enumerate(rows, 1):
        short = ["%s=%s" % (cols[i], text(v))
                 for i, v in enumerate(r) if i not in wide]
        head.append("  %d) %s" % (n, "  ".join(short)) if short else "  %d)" % n)
        for i in sorted(wide):
            value = text(r[i])
            cut = len(value) > LONG_VALUE_CHARS
            if cut:
                value = value[:LONG_VALUE_CHARS] + (
                    "\n… далее ещё %d символов" % (len(text(r[i])) - LONG_VALUE_CHARS))
            head.append("     %s:" % cols[i])
            head += ["       " + line for line in value.split("\n")]
        head.append("")
    if res.get("truncated"):
        head.append(f"  (показаны первые {SQL_MAX_ROWS} строк)")
    return "\n".join(head)


async def refresh_db_versions() -> None:
    """Спросить версию у каждого кластера. Без этого агент советует синтаксис
    наугад: у 5.7 и 8.0 разные имена таблиц performance_schema и разный SHOW."""
    for c in enabled_clusters():
        if not cluster_db_creds(c):
            continue
        res = await sql_execute(c, "SELECT VERSION() AS v, @@version_comment AS c")
        if res.get("error") or not res.get("rows"):
            logger.warning(f"Версия БД {c['name']} не получена: "
                           f"{res.get('error', 'пустой ответ')}")
            continue
        ver = str(res["rows"][0][0])
        note = str(res["rows"][0][1]) if len(res["rows"][0]) > 1 else ""
        DB_VERSIONS[c["name"]] = f"{ver} ({note})".strip()
        logger.info(f"MySQL {c['label']}: {DB_VERSIONS[c['name']]}")


def db_versions_text() -> str:
    if not DB_VERSIONS:
        return ""
    lines = ["Версии MySQL (учитывай синтаксис именно этих версий):"]
    for c in enabled_clusters():
        v = DB_VERSIONS.get(c["name"])
        if v:
            lines.append(f"  {c['label']}: {v}")
    return "\n".join(lines) if len(lines) > 1 else ""
