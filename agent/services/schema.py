"""
Схема базы: снимается по кнопке, хранится у агента.

Без схемы агент отвечает на вопросы про нагрузку, но не может ответить на
вопрос про данные. «Сколько договоров с отрицательным балансом» — вопрос к
базе, а не к метрикам, и чтобы написать такую выборку, надо знать имена
таблиц и столбцов. Не зная их, модель либо отказывается, либо выдумывает.

Почему снимок, а не запрос каждый раз. Обход `information_schema` на базе с
тысячами таблиц — это не бесплатно: на боевом сервере такой запрос заметен,
а схема меняется раз в релиз, а не раз в минуту. Поэтому она снимается
однажды, хранится у агента и читается из его собственной базы — мгновенно и
не трогая продуктив. Пересъёмка — действие администратора: это нагрузка на
боевой сервер, и запускать её походя не стоит.

Снимок ограничен по объёму сознательно. В базе бывают тысячи таблиц, и
полный список бесполезен и человеку, и модели. Берём крупные — они же
интересные, — а о том, что осталось за кадром, пишем прямо.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from agent.core.jsonsafe import name_of, sanitize
from agent.core.words import count_of, plural
from agent.db.base import session_scope
from agent.db.models import SchemaSnapshot, SchemaVectors, to_iso
from agent.services.mysql import cluster_db_creds, sql_execute
from sqlalchemy import select

logger = logging.getLogger("agent.schema")

SYSTEM_DBS = ("mysql", "information_schema", "performance_schema", "sys")
_SYS_LIST = ", ".join("'%s'" % d for d in SYSTEM_DBS)

# Пределы снимка. Не ради экономии места: список из тысячи таблиц нечитаем,
# а подсказка модели, забитая именами, вытесняет всё остальное.
MAX_DBS = 20
MAX_TABLES_PER_DB = 80
# Представления считаем отдельно: их обычно немного, а вытеснять ими
# таблицы из снимка нельзя
MAX_VIEWS_PER_DB = 40
MAX_DETAIL_TABLES = 300
MAX_COLUMNS = 120
MAX_MATCHES = 40

# Сколько таблиц опрашивать запасным путём (SHOW FULL COLUMNS). Там запрос
# на таблицу, поэтому предел жёстче остальных.
FALLBACK_TABLES = 40


def _quote(value: str) -> str:
    """Строковый литерал для SQL: имена приходят от человека и от модели."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def _safe_name(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z_$\--￿]", "", str(value or ""))[:64]


def _ident(value: str) -> str:
    """Имя объекта в обратных кавычках: внутри они удваиваются."""
    return "`%s`" % str(value or "").replace("`", "``")


def split_table(name: str) -> tuple:
    """«lanbilling.agreements» -> ('lanbilling', 'agreements')."""
    raw = str(name or "").replace("`", "").strip()
    if "." in raw:
        db, _, tbl = raw.partition(".")
        return _safe_name(db), _safe_name(tbl)
    return "", _safe_name(raw)


def _rows(result: dict) -> list:
    """Строки словарями, уже приведённые к тому, что переживёт JSON.

    MySQL возвращает DECIMAL у всякого SUM и ROUND. Снимок хранится
    строкой JSON, и один такой столбец ронял всю съёмку: «Object of type
    Decimal is not JSON serializable» — при том что данные собраны и до
    сохранения оставался шаг.
    """
    cols = result.get("columns") or []
    return [sanitize(dict(zip(cols, row))) for row in (result.get("rows") or [])]


# MySQL 5.6 и старше дописывают в TABLE_COMMENT служебную приписку вроде
# «InnoDB free: 1024 kB», иногда вместо комментария целиком. В отчёте она
# выглядит как комментарий разработчика, которым не является.
JUNK_COMMENT = re.compile(
    r"\s*;?\s*(?:InnoDB\s+free\s*:\s*\d+\s*\w*|partitioned|VIEW)\s*;?\s*",
    re.I)


def clean_comment(value) -> str:
    """Комментарий без служебных приписок MySQL. Пусто — его и не было."""
    text = JUNK_COMMENT.sub(" ", str(value or ""))
    return " ".join(text.split())[:400]


def _kind_of(row: dict) -> str:
    """Таблица или представление. Разница видна и человеку, и модели."""
    return ("представление"
            if str(row.get("kind") or "").upper() == "VIEW" else "таблица")


def _num(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


# ── Съёмка ───────────────────────────────────────────────────────────────

async def collect(cluster: dict, host: Optional[str] = None) -> dict:
    """Обойти information_schema и собрать снимок.

    Столбцы и индексы берутся одним запросом на базу, а не по запросу на
    таблицу: на сотне таблиц это сотня обращений против одного.
    """
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — "
                         "схему прочитать нельзя"}

    dbs = await sql_execute(cluster, """
        SELECT TABLE_SCHEMA AS db, COUNT(*) AS tables,
               ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1048576) AS size_mb,
               SUM(TABLE_ROWS) AS rows_est
          FROM information_schema.TABLES
         WHERE TABLE_SCHEMA NOT IN (%s) AND TABLE_TYPE = 'BASE TABLE'
         GROUP BY TABLE_SCHEMA
         ORDER BY SUM(DATA_LENGTH + INDEX_LENGTH) DESC
         LIMIT %d""" % (_SYS_LIST, MAX_DBS), host, MAX_DBS + 5)
    if dbs.get("error"):
        return {"error": "Схема не прочитана: %s" % dbs["error"]}

    databases = _rows(dbs)
    snapshot = {"taken_at": to_iso(), "databases": databases,
                "tables": {}, "cut": []}

    detailed = 0
    for db in databases:
        name = _safe_name(db.get("db"))
        if not name:
            continue

        # Представления берём наравне с таблицами. Выбирать из них можно
        # так же, и без них агент выглядит выдумщиком: называет
        # существующий объект, а в снимке его нет — значит «придумал».
        # Сортировка по размеру ставит их в конец (размера у них нет),
        # поэтому берём отдельным запросом, чтобы таблицы их не вытеснили
        tbls = await sql_execute(cluster, """
            SELECT TABLE_NAME AS tbl, TABLE_TYPE AS kind, ENGINE AS engine,
                   TABLE_ROWS AS rows_est,
                   ROUND((DATA_LENGTH + INDEX_LENGTH) / 1048576) AS size_mb,
                   ROUND(INDEX_LENGTH / 1048576) AS idx_mb,
                   TABLE_COMMENT AS note
              FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'
             ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
             LIMIT %d""" % (_quote(name), MAX_TABLES_PER_DB),
            host, MAX_TABLES_PER_DB + 5)
        if tbls.get("error"):
            snapshot["cut"].append("%s — таблицы не прочитаны: %s"
                                   % (name, tbls["error"][:120]))
            continue

        rows = _rows(tbls)

        views = await sql_execute(cluster, """
            SELECT TABLE_NAME AS tbl, TABLE_TYPE AS kind, TABLE_COMMENT AS note
              FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'VIEW'
             ORDER BY TABLE_NAME
             LIMIT %d""" % (_quote(name), MAX_VIEWS_PER_DB),
            host, MAX_VIEWS_PER_DB + 5)
        if not views.get("error"):
            seen_views = _rows(views)
            rows += seen_views
            if seen_views:
                snapshot.setdefault("views", 0)
                snapshot["views"] += len(seen_views)

        if _num(db.get("tables")) and _num(db.get("tables")) > len(rows):
            snapshot["cut"].append(
                "%s — в снимке %d самых крупных таблиц из %s"
                % (name, len(rows), db.get("tables")))

        # Подробности берём не для всех: столбцы всех таблиц всех баз —
        # это мегабайты, из которых пригодятся десятки строк
        take = rows[:max(0, MAX_DETAIL_TABLES - detailed)]
        detailed += len(take)
        wanted = ", ".join(_quote(t["tbl"]) for t in take if t.get("tbl"))

        columns, indexes, links = {}, {}, {}
        if wanted:
            cols = await sql_execute(cluster, """
                SELECT TABLE_NAME AS tbl, COLUMN_NAME AS col,
                       COLUMN_TYPE AS type, IS_NULLABLE AS nullable,
                       COLUMN_KEY AS ckey, EXTRA AS extra,
                       COLUMN_COMMENT AS note
                  FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME IN (%s)
                 ORDER BY TABLE_NAME, ORDINAL_POSITION"""
                % (_quote(name), wanted), host, 20000)
            for row in _rows(cols):
                bucket = columns.setdefault(row["tbl"], [])
                if len(bucket) < MAX_COLUMNS:
                    item = {k: row[k] for k in
                            ("col", "type", "nullable", "ckey", "extra")
                            if k in row}
                    # Комментарий столбца — то, ради чего схему и снимают:
                    # «balance» ни о чём не говорит, «остаток на счёте» —
                    # говорит всё
                    item["note"] = clean_comment(row.get("note"))
                    bucket.append(item)

            idx = await sql_execute(cluster, """
                SELECT TABLE_NAME AS tbl, INDEX_NAME AS idx,
                       GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols,
                       MAX(NON_UNIQUE) AS non_unique,
                       MAX(CARDINALITY) AS cardinality
                  FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME IN (%s)
                 GROUP BY TABLE_NAME, INDEX_NAME
                 ORDER BY TABLE_NAME, (INDEX_NAME = 'PRIMARY') DESC, INDEX_NAME"""
                % (_quote(name), wanted), host, 20000)
            for row in _rows(idx):
                indexes.setdefault(row["tbl"], []).append(
                    {k: row[k] for k in ("idx", "cols", "non_unique",
                                         "cardinality") if k in row})

            # Связи между таблицами: без них запрос с JOIN — гадание
            keys = await sql_execute(cluster, """
                SELECT TABLE_NAME AS tbl, COLUMN_NAME AS col,
                       REFERENCED_TABLE_SCHEMA AS ref_db,
                       REFERENCED_TABLE_NAME AS ref_tbl,
                       REFERENCED_COLUMN_NAME AS ref_col
                  FROM information_schema.KEY_COLUMN_USAGE
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME IN (%s)
                   AND REFERENCED_TABLE_NAME IS NOT NULL
                 ORDER BY TABLE_NAME"""
                % (_quote(name), wanted), host, 5000)
            for row in _rows(keys):
                links.setdefault(row["tbl"], []).append({
                    "col": row.get("col"),
                    "ref": "%s.%s" % (row.get("ref_db") or name,
                                      row.get("ref_tbl")),
                    "ref_col": row.get("ref_col"),
                    "kind": "внешний ключ"})

        for t in rows:
            key = "%s.%s" % (name, t.get("tbl"))
            snapshot["tables"][key] = {
                "db": name, "table": t.get("tbl"),
                "engine": t.get("engine"), "kind": _kind_of(t),
                "rows_est": _num(t.get("rows_est")),
                "size_mb": _num(t.get("size_mb")), "idx_mb": _num(t.get("idx_mb")),
                "note": clean_comment(t.get("note")),
                "columns": columns.get(t.get("tbl"), []),
                "indexes": indexes.get(t.get("tbl"), []),
                "links": links.get(t.get("tbl"), []),
            }

    # Внешних ключей может не быть вовсе — на MyISAM их не бывает, да и на
    # InnoDB их часто не заводят. Тогда связи предполагаем по именам, но
    # честно помечаем: это догадка, а не то, что объявлено в базе
    guessed = _guess_links(snapshot)
    if guessed:
        snapshot["cut"].append(
            "внешних ключей в базе нет; %d связей предположены по именам "
            "столбцов и помечены как догадка" % guessed)

    source = "information_schema"
    if snapshot["tables"] and not any(_count_notes(snapshot)):
        # information_schema отдала комментарии пустыми. Это не приговор:
        # у тех же таблиц SHOW CREATE TABLE их показывает. Идём вторым путём
        if await _notes_via_show(cluster, host, snapshot):
            source = "SHOW"
            snapshot["cut"].append(
                "комментарии прочитаны через SHOW: information_schema на "
                "этом сервере вернула их пустыми")

    with_note, cols_with_note = _count_notes(snapshot)
    snapshot["comments"] = {"tables": with_note, "columns": cols_with_note,
                            "source": source}

    if detailed >= MAX_DETAIL_TABLES:
        snapshot["cut"].append(
            "столбцы и индексы сняты для %d самых крупных таблиц; "
            "для остальных известны только имена и размеры" % detailed)
    snapshot["host"] = dbs.get("host", "")
    return snapshot


# Столбец короче этого в догадках о связях бесполезен: «id» есть везде
MEANINGFUL_KEY = 3


def _guess_links(snapshot: dict) -> int:
    """Связи по именам столбцов, когда внешних ключей в базе нет.

    Правило простое: столбец называется так же, как первичный ключ другой
    таблицы, — вероятно, он на неё и ссылается. Имена вроде «id» из
    рассмотрения выкинуты: они есть везде и связали бы всё со всем.

    Догадку помечаем отдельно от объявленной связи. Модель должна видеть
    разницу: по внешнему ключу JOIN писать можно смело, по догадке —
    проверив.
    """
    tables = snapshot.get("tables") or {}
    if any(t.get("links") for t in tables.values()):
        return 0          # настоящие ключи есть, догадки не нужны

    # Чем является первичный ключ каждой таблицы
    owners: dict = {}
    for key, table in tables.items():
        primary = [c.get("col") for c in (table.get("columns") or [])
                   if str(c.get("ckey")) == "PRI"]
        if len(primary) != 1:
            continue      # составной ключ по имени столбца не угадать
        name = str(primary[0] or "").lower()
        if len(name) < MEANINGFUL_KEY or name in ("id", "pk", "num"):
            continue
        owners.setdefault(name, []).append(key)

    added = 0
    for key, table in tables.items():
        for col in table.get("columns") or []:
            name = str(col.get("col") or "").lower()
            found = owners.get(name) or []
            # Ссылается ровно на одну таблицу, и не сама на себя
            if len(found) != 1 or found[0] == key:
                continue
            table.setdefault("links", []).append({
                "col": col.get("col"), "ref": found[0],
                "ref_col": col.get("col"), "kind": "по имени столбца"})
            added += 1
    return added


def incoming(snapshot: dict, table_key: str) -> list:
    """Кто ссылается на эту таблицу. Для JOIN нужно обе стороны."""
    out = []
    for key, table in (snapshot.get("tables") or {}).items():
        if key == table_key:
            continue
        for link in table.get("links") or []:
            if link.get("ref") == table_key:
                out.append({"from": key, "col": link.get("col"),
                            "ref_col": link.get("ref_col"),
                            "kind": link.get("kind")})
    return out


def _count_notes(snapshot: dict) -> tuple:
    """Сколько комментариев набралось: у таблиц и у столбцов."""
    tables = (snapshot.get("tables") or {}).values()
    return (sum(1 for t in tables if t.get("note")),
            sum(1 for t in tables for c in (t.get("columns") or [])
                if c.get("note")))


async def _notes_via_show(cluster: dict, host, snapshot: dict) -> int:
    """Добрать комментарии через SHOW. Возвращает, сколько добрал.

    Второй путь к тем же данным нужен потому, что на живых серверах
    случается так: в information_schema комментарии пустые, а
    SHOW CREATE TABLE показывает их целиком.

    SHOW FULL COLUMNS, а не SHOW CREATE TABLE: комментарий приходит
    отдельным столбцом, а не внутри текста DDL, который пришлось бы
    разбирать регулярками — и ошибаться на каждой кавычке внутри
    комментария. Данные те же, разбирать нечего.

    Платим запросом на таблицу, поэтому сюда попадают только самые
    крупные и только когда первый путь не дал ничего.
    """
    tables = snapshot.get("tables") or {}
    added = 0

    # Таблицы — один запрос на базу, это дёшево
    for db in snapshot.get("databases") or []:
        name = _safe_name(db.get("db"))
        if not name:
            continue
        res = await sql_execute(cluster, "SHOW TABLE STATUS FROM %s"
                                % _ident(name), host, MAX_TABLES_PER_DB + 5)
        if res.get("error"):
            continue
        for row in _rows(res):
            key = "%s.%s" % (name, row.get("Name"))
            note = clean_comment(row.get("Comment"))
            if note and key in tables and not tables[key].get("note"):
                tables[key]["note"] = note
                added += 1

    # Столбцы — запрос на таблицу, поэтому с пределом
    biggest = sorted((t for t in tables.values() if t.get("columns")),
                     key=lambda t: -(t.get("size_mb") or 0))[:FALLBACK_TABLES]
    for t in biggest:
        res = await sql_execute(cluster, "SHOW FULL COLUMNS FROM %s.%s"
                                % (_ident(t["db"]), _ident(t["table"])),
                                host, MAX_COLUMNS + 10)
        if res.get("error"):
            continue
        notes = {}
        for row in _rows(res):
            notes[row.get("Field")] = clean_comment(row.get("Comment"))
        for col in t["columns"]:
            note = notes.get(col.get("col"))
            if note and not col.get("note"):
                col["note"] = note
                added += 1

    if added and len(biggest) >= FALLBACK_TABLES:
        snapshot["cut"].append(
            "комментарии столбцов через SHOW добраны для %d самых крупных "
            "таблиц: это запрос на таблицу, и делать его для всех дорого"
            % FALLBACK_TABLES)
    return added


# ── Хранение ─────────────────────────────────────────────────────────────

async def save(cluster_name: str, snapshot: dict) -> None:
    """Положить снимок к себе. Один снимок на кластер — прежний заменяется."""
    # sanitize второй раз: строки уже приведены, но в снимке есть и то,
    # что положили мимо _rows, — а терять съёмку на сохранении обиднее
    # всего, она уже состоялась
    payload = json.dumps(sanitize(snapshot), ensure_ascii=False,
                         default=name_of)
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaSnapshot).where(
                SchemaSnapshot.cluster == cluster_name))).scalar_one_or_none()
        counts = (len(snapshot.get("databases") or []),
                  len(snapshot.get("tables") or {}))
        if row is None:
            session.add(SchemaSnapshot(
                cluster=cluster_name, taken_at=snapshot.get("taken_at") or to_iso(),
                databases=counts[0], tables=counts[1], payload=payload))
        else:
            row.taken_at = snapshot.get("taken_at") or to_iso()
            row.databases, row.tables = counts
            row.payload = payload
    logger.info("Схема %s снята: баз %d, таблиц %d",
                cluster_name, counts[0], counts[1])


async def load(cluster_name: str) -> dict:
    """Снимок из хранилища агента. Пусто — ещё не снимали."""
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaSnapshot).where(
                SchemaSnapshot.cluster == cluster_name))).scalar_one_or_none()
    if row is None:
        return {}
    try:
        data = json.loads(row.payload)
    except ValueError:
        logger.error("Снимок схемы %s повреждён", cluster_name)
        return {}
    data["taken_at"] = row.taken_at
    return data


# ── Смысловой индекс ─────────────────────────────────────────────────────

# Индекс читается редко, но целиком и весит мегабайты. Держим разобранным
# в памяти процесса, ключ — время съёмки: пересняли схему, кэш протух сам
_INDEX_CACHE: dict = {}


def doc_for(table: dict) -> str:
    """Текст таблицы для векторизации.

    Кладём в один документ имя, комментарий и столбцы с их комментариями:
    смысл таблицы складывается из всего сразу. «vgroups» не говорит ничего,
    «vgroups, Абоненты, столбцы: login (логин), passwd (пароль)» говорит
    достаточно, чтобы найтись по запросу «учётные записи».
    """
    parts = ["%s.%s" % (table.get("db"), table.get("table"))]
    if table.get("note"):
        parts.append(str(table["note"]))

    fields = []
    for col in (table.get("columns") or [])[:40]:
        name = str(col.get("col") or "")
        note = str(col.get("note") or "")
        fields.append("%s (%s)" % (name, note) if note else name)
    if fields:
        parts.append("столбцы: " + ", ".join(fields))
    return ". ".join(parts)[:2000]


async def build_index(cluster_name: str, snapshot: dict) -> dict:
    """Построить смысловой индекс по снимку и сохранить.

    Зовётся один раз вместе со съёмкой схемы. Нет эндпоинта векторов —
    возвращаем пусто и работаем по словам: это не ошибка, а другая
    установка.
    """
    from agent.services import embed

    tables = snapshot.get("tables") or {}
    if not tables or not await embed.probe():
        return {}

    keys = list(tables)
    vectors = await embed.encode([doc_for(tables[k]) for k in keys])
    if not vectors:
        logger.info("Смысловой индекс %s не построен: векторов нет",
                    cluster_name)
        return {}

    index = {k: v for k, v in zip(keys, vectors) if v}
    payload = json.dumps(index, ensure_ascii=False)
    taken_at = snapshot.get("taken_at") or to_iso()
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaVectors).where(
                SchemaVectors.cluster == cluster_name))).scalar_one_or_none()
        if row is None:
            session.add(SchemaVectors(cluster=cluster_name, taken_at=taken_at,
                                      model=embed.EMBED_MODEL,
                                      items=len(index), payload=payload))
        else:
            row.taken_at, row.model = taken_at, embed.EMBED_MODEL
            row.items, row.payload = len(index), payload

    _INDEX_CACHE.pop(cluster_name, None)
    logger.info("Смысловой индекс %s: %d таблиц, модель %s",
                cluster_name, len(index), embed.EMBED_MODEL)
    return {"items": len(index), "model": embed.EMBED_MODEL}


async def load_index(cluster_name: str) -> dict:
    """Индекс из хранилища. Пусто — не строили или строить было нечем."""
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaVectors).where(
                SchemaVectors.cluster == cluster_name))).scalar_one_or_none()
    if row is None:
        return {}

    cached = _INDEX_CACHE.get(cluster_name)
    if cached and cached.get("taken_at") == row.taken_at:
        return cached
    try:
        index = json.loads(row.payload)
    except ValueError:
        logger.error("Смысловой индекс %s повреждён", cluster_name)
        return {}
    cached = {"taken_at": row.taken_at, "model": row.model, "index": index}
    _INDEX_CACHE[cluster_name] = cached
    return cached


# Сколько таблиц показываем модели, когда просим её выбрать. Больше — это
# уже полотно, в котором теряется и модель, и смысл затеи
MODEL_PICK_TABLES = 200


async def search_by_model(snapshot: dict, question: str,
                          limit: int = 3) -> list:
    """Спросить саму модель, про какие таблицы вопрос.

    Запасной путь для установок без модели векторов: скачать её бывает
    неоткуда, а генеративная модель уже есть и смысл слов понимает не
    хуже. Платим одним коротким запросом — и только тогда, когда по
    буквам не нашлось ничего.

    Ответ модели проверяем по снимку: имена, которых в схеме нет,
    отбрасываем молча. Придуманная таблица здесь опаснее, чем отсутствие
    ответа, — по ней будет построен запрос.
    """
    from agent.services.llm import llm_complete

    tables = snapshot.get("tables") or {}
    if not tables or not str(question or "").strip():
        return []

    listing = []
    for key, table in sorted(tables.items(),
                             key=lambda kv: -(kv[1].get("size_mb") or 0)):
        note = str(table.get("note") or "")
        listing.append("%s — %s" % (key, note) if note else key)
        if len(listing) >= MODEL_PICK_TABLES:
            break

    ask = ("Ниже список таблиц базы с комментариями из самой базы.\n\n"
           "%s\n\nВопрос человека: %s\n\n"
           "Выбери не больше %d таблиц, о которых этот вопрос. Ответь "
           "ТОЛЬКО именами из списка, по одному в строке, без пояснений. "
           "Если вопрос не про данные или подходящей таблицы нет, ответь "
           "одним словом: нет."
           % ("\n".join(listing), str(question)[:500], limit))

    try:
        answer = await llm_complete([{"role": "user", "content": ask}])
    except Exception as exc:
        logger.info("Выбор таблиц моделью не удался: %s", exc)
        return []

    found = []
    for line in str(answer or "").splitlines():
        name = line.strip().strip("-*`. ").split()[0] if line.strip() else ""
        # Проверяем по снимку: имя, которого в схеме нет, — выдумка
        if name in tables and name not in found:
            found.append(name)
        if len(found) >= limit:
            break
    if found:
        logger.info("Таблицы выбраны моделью: %s", ", ".join(found))
    return found


async def search_semantic(cluster_name: str, question: str,
                          limit: int = 3) -> list:
    """Таблицы, близкие вопросу по смыслу: [(ключ, близость), ...].

    Нужно там, где буквы не совпадают: «учётные записи» и «Абоненты» не
    имеют ни одной общей, но означают одно и то же.
    """
    from agent.services import embed

    if not str(question or "").strip():
        return []
    stored = await load_index(cluster_name)
    if not stored.get("index"):
        return []

    asked = await embed.encode([question])
    if not asked:
        return []
    return embed.nearest(asked[0], stored["index"], limit)


# ── Чтение снимка ────────────────────────────────────────────────────────

def describe(snapshot: dict, table: str) -> dict:
    """Столбцы и индексы таблицы — всё, что нужно, чтобы написать выборку."""
    tables = snapshot.get("tables") or {}
    db, tbl = split_table(table)
    if not tbl:
        return {"error": "Не указана таблица"}

    if db:
        found = tables.get("%s.%s" % (db, tbl))
        if not found:
            return {"error": "Таблицы %s.%s нет в снимке" % (db, tbl)}
        return _with_incoming(snapshot, "%s.%s" % (db, tbl), found)

    matches = [(k, v) for k, v in tables.items() if k.split(".", 1)[1] == tbl]
    if not matches:
        return {"error": "Таблицы %s нет в снимке схемы" % tbl}
    if len(matches) > 1:
        return {"error": "Таблица %s есть в нескольких базах: %s. "
                         "Укажите как база.таблица"
                         % (tbl, ", ".join(m[1]["db"] for m in matches))}
    return _with_incoming(snapshot, matches[0][0], matches[0][1])


def _with_incoming(snapshot: dict, key: str, table: dict) -> dict:
    """Описание вместе с тем, кто ссылается на эту таблицу."""
    found = incoming(snapshot, key)
    return dict(table, incoming=found) if found else table


def find(snapshot: dict, needle: str) -> dict:
    """Поиск таблиц и столбцов по куску имени.

    Нужен чаще, чем кажется: человек помнит, что «где-то есть про
    договоры», но не помнит — agreements, contracts или dogovor.
    """
    text = str(needle or "").strip().lower()
    if len(text) < 2:
        return {"error": "Слишком короткий запрос: нужно хотя бы два символа"}

    matches = []
    for key, table in (snapshot.get("tables") or {}).items():
        table_note = str(table.get("note") or "")
        # Совпадение по комментарию ценнее совпадения по имени: имена
        # английские, а спрашивают по-русски — «где про договоры»
        if text in str(table.get("table", "")).lower():
            matches.append({"db": table["db"], "tbl": table["table"],
                            "col": "", "type": "таблица", "note": table_note,
                            "by": "имени"})
        elif text in table_note.lower():
            matches.append({"db": table["db"], "tbl": table["table"],
                            "col": "", "type": "таблица", "note": table_note,
                            "by": "комментарию"})

        for col in table.get("columns") or []:
            col_note = str(col.get("note") or "")
            if text in str(col.get("col", "")).lower():
                matches.append({"db": table["db"], "tbl": table["table"],
                                "col": col.get("col"), "type": col.get("type"),
                                "note": col_note, "by": "имени"})
            elif text in col_note.lower():
                matches.append({"db": table["db"], "tbl": table["table"],
                                "col": col.get("col"), "type": col.get("type"),
                                "note": col_note, "by": "комментарию"})
        if len(matches) >= MAX_MATCHES:
            break

    # Найденное по комментарию — вперёд: если спрашивали по-русски, имя
    # совпало случайно, а комментарий — по смыслу
    matches.sort(key=lambda m: 0 if m.get("by") == "комментарию" else 1)
    return {"needle": text, "matches": matches[:MAX_MATCHES]}


# Слова короче этого в поиске по комментариям бесполезны: «по», «из»,
# «на» найдутся везде
MEANINGFUL_WORD = 4

# По скольким первым буквам считаем слова одним и тем же. Пять — потому
# что «платеж»/«платежи»/«платежей» совпадают, а «договор» и «догонять»
# уже нет.
STEM = 5


def mentioned(snapshot: dict, text: str, limit: int = 3) -> list:
    """Про какие таблицы спрашивают. Возвращает ключи «база.таблица».

    Нужно потому, что описание таблицы обязано попасть в подсказку само.
    Полагаться на то, что модель сходит за ним инструментом, нельзя: не
    всякий эндпоинт умеет вызовы функций, и тогда модель отвечает по
    смыслу имени — то есть выдумывает столбцы, которых нет.

    Сначала ищем по именам, потом по комментариям: имена в базе
    английские, а спрашивают по-русски.
    """
    tables = snapshot.get("tables") or {}
    if not tables or not str(text or "").strip():
        return []

    low = str(text).lower()
    words = set(re.findall(r"[0-9a-zа-яё_]{3,}", low))
    found = []

    # Полное имя «база.таблица» — самое надёжное совпадение
    for key in tables:
        if key.lower() in low:
            found.append(key)

    # Имя таблицы отдельным словом. Подстрокой нельзя: «log» найдётся в
    # половине схемы и утопит ответ в лишнем
    for key, table in tables.items():
        if key in found:
            continue
        if str(table.get("table", "")).lower() in words:
            found.append(key)

    if found:
        return _by_size(tables, found)[:limit]

    # По комментариям: «сколько платежей» должно находить таблицу с
    # комментарием «Платежи». Сравниваем по основе слова, иначе падежи и
    # числа не совпадут ни разу — а спрашивают именно ими.
    asked = {w[:STEM] for w in words if len(w) >= MEANINGFUL_WORD}
    for key, table in tables.items():
        note = str(table.get("note") or "").lower()
        if not note:
            continue
        stems = {w[:STEM] for w in re.findall(r"[0-9a-zа-яё_]{3,}", note)}
        if asked & stems:
            found.append(key)
    return _by_size(tables, found)[:limit]


def _by_size(tables: dict, keys: list) -> list:
    """Крупные вперёд: спрашивают обычно про них, а не про справочник."""
    seen, unique = set(), []
    for key in keys:
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return sorted(unique, key=lambda k: -(tables[k].get("size_mb") or 0))


# ── Вывод ────────────────────────────────────────────────────────────────

def fmt_snapshot(snapshot: dict, label: str) -> str:
    """Что в снимке: базы, крупные таблицы, когда снято."""
    if not snapshot:
        return ("## Схема базы — %s\n\n"
                "  Схема ещё не снята. Нажмите «Снять схему» на странице "
                "кластера — агент обойдёт information_schema один раз и "
                "запомнит результат у себя.\n"
                "  Пересъёмка доступна администраторам: это обращение к "
                "боевому серверу, и делать его походя не стоит." % label)

    lines = ["## Схема базы — %s" % label, "",
             "  Снято: %s. Числа строк — оценка InnoDB, не точный счёт."
             % str(snapshot.get("taken_at", ""))[:16].replace("T", " "), ""]
    for db in snapshot.get("databases") or []:
        lines.append("  %-24s %-14s %s МБ, строк ~%s"
                     % (db.get("db"),
                        count_of(db.get("tables"), "таблица", "таблицы",
                                 "таблиц"),
                        db.get("size_mb"), db.get("rows_est")))

    tables = snapshot.get("tables") or {}
    comments = snapshot.get("comments") or {}
    if tables:
        # Прямо говорим, нашлись ли комментарии: иначе по отчёту не понять,
        # то ли их не читали, то ли их нет в базе
        if comments.get("tables") or comments.get("columns"):
            via = ""
            if comments.get("source") == "SHOW":
                via = (" Прочитаны через SHOW: information_schema на этом "
                       "сервере вернула их пустыми.")
            lines += ["", "  Комментарии из базы прочитаны: у %s и %s.%s"
                      % (count_of(comments.get("tables", 0), "таблицы",
                                  "таблиц", "таблиц"),
                         count_of(comments.get("columns", 0), "столбца",
                                  "столбцов", "столбцов"), via)]
        elif "comments" not in snapshot:
            # Снимок снят до того, как агент научился читать COMMENT.
            # Сказать «комментариев нет» было бы неправдой: их не спрашивали
            lines += ["", "  Комментарии в этом снимке не читались — он снят "
                          "прежней версией агента. Нажмите «Снять схему» "
                          "заново: комментарии таблиц и столбцов подтянутся."]
        else:
            lines += ["", "  Комментариев (COMMENT) не нашлось ни у таблиц, ни "
                          "у столбцов — ни в information_schema, ни через "
                          "SHOW. Значит, в базе их действительно нет."]

        vectors = snapshot.get("vectors") or {}
        if vectors.get("items"):
            lines.append("  Смысловой поиск построен: %s, модель %s. Теперь "
                         "«учётные записи» найдут таблицу, подписанную "
                         "«Абоненты»."
                         % (count_of(vectors["items"], "таблица", "таблицы",
                                     "таблиц"), vectors.get("model", "")))
        else:
            lines.append("  Смыслового поиска нет: эндпоинт модели не отдаёт "
                         "/embeddings. Поиск по схеме идёт по словам.")

        biggest = sorted(tables.values(),
                         key=lambda t: -(t.get("size_mb") or 0))[:20]
        lines += ["", "  Самые крупные таблицы:"]
        for t in biggest:
            note = (" — " + t["note"][:120]) if t.get("note") else ""
            lines.append("    %-36s строк ~%-10s %s МБ%s"
                         % ("%s.%s" % (t["db"], t["table"]),
                            t.get("rows_est"), t.get("size_mb"), note))

    for note in snapshot.get("cut") or []:
        lines.append("  " + note)
    return "\n".join(lines)


def fmt_describe(data: dict) -> str:
    if data.get("error"):
        return "## Таблица\n\n  %s" % data["error"]
    if data.get("kind") == "представление":
        lines = ["## %s.%s — представление (VIEW)"
                 % (data["db"], data["table"]),
                 "  Выбирать из него можно так же, как из таблицы. Своих "
                 "данных и индексов у него нет: они у таблиц, на которых "
                 "оно построено."]
    else:
        lines = ["## %s.%s — строк ~%s, %s МБ"
                 % (data["db"], data["table"], data.get("rows_est"),
                    data.get("size_mb"))]
    if data.get("note"):
        lines.append("  " + data["note"])
    lines += ["", "  Столбцы:"]
    for c in data.get("columns") or []:
        marks = []
        key = str(c.get("ckey") or "")
        if key == "PRI":
            marks.append("первичный ключ")
        elif key == "UNI":
            marks.append("уникальный")
        elif key == "MUL":
            marks.append("в индексе")
        if str(c.get("nullable")).upper() == "NO":
            marks.append("NOT NULL")
        if c.get("extra"):
            marks.append(str(c["extra"]))
        # Комментарий отдельным столбцом, а не в общем ряду пометок: он
        # объясняет смысл поля, а остальное — его устройство
        lines.append("    %-26s %-20s %-26s %s"
                     % (c.get("col"), c.get("type"), ", ".join(marks),
                        str(c.get("note") or "")[:120]))
    if not data.get("columns"):
        lines.append("    Столбцы в снимок не попали: таблица не вошла в число "
                     "тех, для которых снимались подробности.")

    if data.get("links"):
        lines += ["", "  Ссылается на:"]
        for link in data["links"]:
            lines.append("    %-26s -> %s.%s  (%s)"
                         % (link.get("col"), link.get("ref"),
                            link.get("ref_col"), link.get("kind")))

    if data.get("incoming"):
        lines += ["", "  На неё ссылаются:"]
        for link in data["incoming"]:
            lines.append("    %-26s по столбцу %s  (%s)"
                         % (link.get("from"), link.get("col"),
                            link.get("kind")))

    if data.get("indexes"):
        lines += ["", "  Индексы:"]
        for i in data["indexes"]:
            kind = "уникальный" if str(i.get("non_unique")) == "0" else "обычный"
            lines.append("    %-26s (%s) — %s, различных значений ~%s"
                         % (i.get("idx"), i.get("cols"), kind,
                            i.get("cardinality")))
    return "\n".join(lines)


def fmt_find(data: dict) -> str:
    if data.get("error"):
        return "## Поиск по схеме\n\n  %s" % data["error"]
    matches = data.get("matches") or []
    lines = ["## Что нашлось по «%s»" % data.get("needle", ""), ""]
    if not matches:
        lines.append("  Ни таблиц, ни столбцов с таким именем в снимке нет.")
        return "\n".join(lines)
    for m in matches:
        where = "%s.%s" % (m.get("db"), m.get("tbl"))
        if m.get("col"):
            where += "." + m["col"]
        note = (" — " + m["note"][:110]) if m.get("note") else ""
        lines.append("  %s (%s)%s" % (where, m.get("type"), note))
    if len(matches) >= MAX_MATCHES:
        lines.append("  (показаны первые %d)" % MAX_MATCHES)
    return "\n".join(lines)


def fmt_semantic(snapshot: dict, needle: str, near: list) -> str:
    """Что нашлось по смыслу. Близость показываем: она и есть основание."""
    tables = snapshot.get("tables") or {}
    lines = ["## Что похоже по смыслу на «%s»" % needle, "",
             "  По буквам ничего не совпало, поэтому искали по смыслу "
             "комментариев. Проверь, та ли это таблица, прежде чем строить "
             "по ней запрос.", ""]
    for key, score in near:
        table = tables.get(key) or {}
        note = (" — " + str(table.get("note"))[:110]) if table.get("note") else ""
        lines.append("  %-36s близость %.2f%s" % (key, score, note))
    return "\n".join(lines)


def fmt_brief(snapshot: dict) -> str:
    """Короткая справка для подсказки модели: что вообще есть в базе.

    Именно короткая. Подробности модель дозапросит инструментом; а вот без
    этого верхнего слоя она не знает даже, о каких базах речь, и либо
    отказывается писать выборку, либо выдумывает имена.
    """
    if not snapshot or not snapshot.get("databases"):
        return ""
    lines = ["## Что есть в базе", "",
             "  Имена ниже — настоящие, из снимка схемы. Подробности по "
             "столбцам и индексам запрашивай инструментом get_schema, "
             "не угадывай."]
    # Обещать модели комментарии, которых в снимке нет, нельзя: она станет
    # ссылаться на них, а сослаться не на что
    if any(_count_notes(snapshot)):
        lines += ["  Рядом с именем — комментарий из базы: по нему и понимай, "
                  "что в таблице лежит.",
                  "  Ищешь таблицу по смыслу («про договоры», «про платежи») — "
                  "get_schema с search ищет и по комментариям."]
    else:
        lines.append("  Комментариев (COMMENT) в этом снимке нет — понимать "
                     "назначение таблицы придётся по имени и по данным. Если "
                     "не уверен, так и скажи, не выдумывай.")
    tables = snapshot.get("tables") or {}
    for db in (snapshot["databases"])[:6]:
        name = db.get("db")
        picked = sorted((t for t in tables.values() if t.get("db") == name),
                        key=lambda t: -(t.get("size_mb") or 0))[:25]
        lines.append("")
        lines.append("  %s (%s, %s МБ):"
                     % (name, count_of(db.get("tables"), "таблица", "таблицы",
                                       "таблиц"), db.get("size_mb")))
        # С комментарием — отдельной строкой: это главное, что объясняет
        # назначение таблицы. Без него — списком, чтобы не раздувать подсказку
        plain = []
        for t in picked:
            mark = " (VIEW)" if t.get("kind") == "представление" else ""
            if t.get("note"):
                lines.append("    %-30s — %s"
                             % (t["table"] + mark, t["note"][:90]))
            else:
                plain.append(t["table"] + mark)
        if plain:
            lines.append("    без комментария: " + ", ".join(plain))
    return "\n".join(lines)
