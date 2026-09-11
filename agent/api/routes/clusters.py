"""Состояние кластеров, ряды для графиков и диагностические запросы."""
from __future__ import annotations

import asyncio
import datetime
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from agent.core.config import settings
from agent.api.deps import (AdminUser, Audit, CurrentUser, DbSession,
                            MaybeUser)
from agent.db.repositories.notes import NoteRepository
from agent.services import (anomaly, audit, backups, config_audit,
                            config_history, forecast, growth, indexes,
                            explain, insight, memory, readiness,
                            tasks)
from agent.schemas.api import (ExplainRequest, InsightOut,
                               InsightRequest, SqlRequest, SqlResult)
from agent.services.analysis import (DIAG_QUERIES, collect_series_table,
                                     explain_top_queries, fmt_diagnostics,
                                     run_diagnostics)
from agent.services.logs import read_app_log, read_slow_log
from agent.services.replication import collect_replication, fmt_replication
from agent.services.ssh import remote_time
from agent.services.workload import (DEFAULT_WINDOW_S, fmt_workload,
                                     workload_delta)
from agent.services.mysql import db_versions_text, sql_execute
from agent.services.prometheus import (build_charts, collect_current,
                                       resolve_window,
                                       collect_history)
from agent.services.registry import (app_host, cluster_hosts,
                                     enabled_clusters, find_cluster)

logger = logging.getLogger("agent.api.clusters")
router = APIRouter(tags=["Кластеры"])

# Запас поверх таймаута модели: сбор контекста для разбора (состояние,
# события, заметки) тоже занимает время, и обрывать запрос ровно по
# таймауту самой модели было бы рано.
INSIGHT_GRACE_S = 30

# Сколько ждём тяжёлый разбор, прежде чем ответить «идёт, зайдите ещё раз».
# Обратный прокси ждёт своё (nginx — минуту) и на исходе отдаёт 504 с
# HTML-страницей; лучше ответить раньше него и по делу. Работа при этом не
# бросается: она досчитается в фоне, и повторное нажатие вернёт готовое.
DIAGNOSE_BUDGET_S = float(os.environ.get("DIAGNOSE_BUDGET_S", "40"))

# Поля реестра, которые наружу не отдаются ни при каких обстоятельствах
SECRET_FIELDS = {"mysql_exporter_password", "db_password"}


def _need(name: str) -> dict:
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(status_code=404, detail=f"Кластер '{name}' не найден")
    return cluster


@router.get("/clusters", summary="Список кластеров")
async def clusters(user: MaybeUser):
    return {"clusters": [{k: v for k, v in c.items() if k not in SECRET_FIELDS}
                         for c in enabled_clusters()]}


@router.get("/clusters/{name}/status", summary="Состояние кластера")
async def cluster_status(name: str, user: MaybeUser):
    return await collect_current(_need(name))


@router.get("/clusters/{name}/history", summary="История метрик кластера")
async def cluster_history(name: str, user: MaybeUser, hours: float = 24):
    return await collect_history(_need(name), hours)


@router.get("/status", summary="Состояние всех кластеров")
async def all_status(user: MaybeUser):
    items = enabled_clusters()
    return {"clusters": list(await asyncio.gather(
        *[collect_current(c) for c in items]))}


@router.get("/api/series/{name}", tags=["Диагностика"],
            summary="Ряд метрик по шагам")
async def series(name: str, user: CurrentUser, hours: float = 3,
                 step: int = 300):
    return await collect_series_table(_need(name), hours, step)


@router.get("/api/charts/{name}", tags=["Диагностика"],
            summary="Данные для графиков")
async def charts(name: str, user: CurrentUser, hours: float = 3,
                 since: float = 0, until: float = 0):
    """Период задаётся либо длиной (hours), либо границами (since/until).

    Границы — в Unix-времени: часовые пояса браузера и серверов кластера
    различаются, и «с 3:00» без уточнения, чьи это три часа, бессмысленно.
    """
    cluster = _need(name)
    start, end, span = resolve_window(hours, since, until)

    async def build():
        return {"cluster": name, "since": int(start), "until": int(end),
                "hours": round(span, 4),
                "charts": await build_charts(cluster, since=start, until=end)}

    # Ключ по фактическим границам, округлённым до минуты: соседние запросы
    # «за 3 часа» отличаются секундами, и без округления общая работа не
    # переиспользовалась бы ни разу
    key = "charts:%s:%d:%d" % (name, start // 60, end // 60)
    return await tasks.shared(key, build, ttl=30)


@router.get("/api/db/versions", tags=["Диагностика"],
            summary="Версии MySQL по кластерам")
async def db_versions(user: CurrentUser):
    return {"versions": db_versions_text()}


@router.post("/api/query", tags=["Диагностика"], response_model=SqlResult,
             summary="Читающий SQL-запрос к кластеру")
async def query(req: SqlRequest, user: CurrentUser, journal: Audit,
                request: Request) -> SqlResult:
    """Только чтение. Запрет проверяется до отправки, а не надеждой на грант:
    учётка агента и так имеет лишь SELECT, но ошибка в запросе не должна
    зависеть от того, правильно ли выданы права."""
    result = await sql_execute(_need(req.cluster), req.sql, req.host or None)
    await journal.add(action="SQL-запрос", username=user.get("username", ""),
                      target=req.cluster, detail=req.sql[:1000],
                      ip=audit.client_ip(request),
                      ok=not result.get("error"))
    return SqlResult(**result)


@router.get("/api/diagnose/{name}", tags=["Диагностика"],
            summary="Диагностический набор по кластеру")
async def diagnose(name: str, user: CurrentUser, deep: bool = False):
    """Готовые читающие запросы по методике из документации MySQL:
    performance_schema и представления sys."""
    cluster = _need(name)

    async def one_host(ip: str, role: str) -> list:
        items = await run_diagnostics(cluster, ip)
        out = []
        block = fmt_diagnostics(items, "%s · %s" % (cluster["label"], role), ip)
        if block:
            out.append(block)
        if deep:
            plans = await explain_top_queries(cluster, ip)
            if plans:
                out.append(plans)
        return out

    async def build():
        # По каждому серверу отдельно: у основного и реплики разная нагрузка,
        # и «диагностика кластера» без указания, где именно снято, бесполезна.
        # Серверы опрашиваем разом — ждать их по очереди значит складывать
        # время, а запросы независимы.
        done = await asyncio.gather(*[one_host(ip, role)
                                      for ip, role in cluster_hosts(cluster)])
        parts = [block for host_blocks in done for block in host_blocks]

        if not parts:
            parts.append(
                "## Диагностика Performance Schema\n\n"
                "  Ничего не собрано. Обычно причина одна из двух:\n"
                "  - у кластера не заполнена учётка db_user в clusters.json — "
                "тогда SQL-запросы отключены целиком;\n"
                "  - performance_schema выключена на сервере "
                "(SHOW VARIABLES LIKE 'performance_schema').")
        return {"cluster": name, "report": "\n\n".join(parts)}

    data, in_time = await tasks.shared_within(
        "diagnose:%s:%d" % (name, int(deep)), build,
        budget=DIAGNOSE_BUDGET_S, ttl=60)
    if in_time:
        return data
    return {"cluster": name, "running": True, "report": (
        "## Диагностика Performance Schema\n\n"
        "  Набор ещё выполняется — на большой базе он занимает больше %d с.\n"
        "  Работа не прервана и идёт дальше: нажмите «Выполнить» ещё раз "
        "через полминуты,\n  и готовый отчёт покажется сразу."
        % int(DIAGNOSE_BUDGET_S))}


@router.get("/api/workload/{name}", tags=["Диагностика"],
            summary="Что нагружает базу прямо сейчас")
async def workload(name: str, user: CurrentUser, seconds: float = 0,
                   host: str = ""):
    """Два среза performance_schema с интервалом и разница между ними.

    Именно разница: накопленные суммы показывают средние за всё время работы
    сервера и текущую проблему прячут.
    """
    async def build():
        data = await workload_delta(_need(name), seconds or DEFAULT_WINDOW_S,
                                    host or None)
        if not data.get("error"):
            data["text"] = fmt_workload(data, name)
        return data
    # Профиль снимается двумя срезами с паузой: два одновременных запроса
    # означали бы четыре обхода performance_schema ради одного ответа
    return await tasks.shared("workload:%s:%s:%g" % (name, host, seconds),
                              build, ttl=30)


@router.get("/api/replication/{name}", tags=["Диагностика"],
            summary="Состояние репликации кластера")
async def replication(name: str, user: CurrentUser):
    cluster = _need(name)

    async def build():
        states = await collect_replication(cluster)
        return {"cluster": name, "items": states,
                "text": fmt_replication(states, cluster["label"])}
    return await tasks.shared("replication:%s" % name, build, ttl=20)


@router.get("/api/logs/{name}", tags=["Диагностика"],
            summary="Slow-лог и логи ядра за период")
async def logs(name: str, user: CurrentUser, hours: float = 2,
               filter: str = "", kind: str = "all"):
    """kind: slow — только slow-лог, app — только ядро, all — оба.

    Период приводится ко времени того сервера, с которого читаем: пояса
    различаются, и grep пошёл бы не по тем датам.
    """
    cluster = _need(name)
    hours = max(0.25, min(float(hours), 48.0))

    key = "logs:%s:%s:%g:%s" % (name, kind, hours, filter)
    return await tasks.shared(key, lambda: _read_logs(cluster, name, hours,
                                                      filter, kind), ttl=60)


async def _read_logs(cluster: dict, name: str, hours: float,
                     filter: str, kind: str) -> dict:
    """Собственно чтение. Вынесено, чтобы одинаковые запросы делили работу:
    на большом логе это десятки секунд, и повторять их незачем."""
    parts = []

    if kind in ("all", "slow"):
        for ip, role in cluster_hosts(cluster):
            moment = await remote_time(ip)
            if moment is None:
                parts.append("### %s (%s)\n  Сервер не отвечает по SSH." % (ip, role))
                continue
            until, since = moment["epoch"], moment["epoch"] - hours * 3600
            local_until = moment["local"]
            local_since = local_until - datetime.timedelta(hours=hours)
            text = await read_slow_log(cluster, ip, local_since, local_until,
                                       filter, since, until)
            if text:
                parts.append(text)

    if kind in ("all", "app"):
        host = app_host(cluster)
        moment = await remote_time(host)
        if moment is None:
            parts.append("### Ядро (%s)\n  Сервер не отвечает по SSH." % host)
        else:
            until, since = moment["epoch"], moment["epoch"] - hours * 3600
            local_until = moment["local"]
            local_since = local_until - datetime.timedelta(hours=hours)
            text = await read_app_log(cluster, host, local_since, local_until,
                                      filter, since, until)
            if text:
                parts.append(text)

    return {"cluster": name, "hours": hours, "filter": filter,
            "text": "\n\n".join(parts) or "За этот период записей не найдено."}


@router.get("/api/diagnostics/templates", tags=["Диагностика"],
            summary="Готовые диагностические запросы")
async def templates(user: CurrentUser):
    """Набор из документации MySQL — чтобы не писать их по памяти."""
    return {"items": [{"key": q["key"], "title": q["title"],
                       "why": q.get("why", ""), "sql": q["sql"].strip()}
                      for q in DIAG_QUERIES]}


@router.get("/api/forecast/{name}", tags=["Диагностика"],
            summary="Когда кончится место, соединения и автоинкременты")
async def forecast_one(name: str, user: CurrentUser):
    """«Занято 85%» говорит о состоянии, «хватит на трое суток» — о запасе
    времени. Второе полезнее."""
    async def build():
        data = await forecast.collect(_need(name))
        data["text"] = forecast.fmt_forecast(data)
        return data
    return await tasks.shared("forecast:%s" % name, build, ttl=120)


@router.get("/api/config-audit/{name}", tags=["Диагностика"],
            summary="Разбор настроек MySQL")
async def config_audit_one(name: str, user: CurrentUser, host: str = ""):
    async def build():
        data = await config_audit.audit(_need(name), host or None)
        data["text"] = config_audit.fmt_audit(data)
        return data
    return await tasks.shared("config-audit:%s:%s" % (name, host), build, ttl=120)


@router.get("/api/growth/{name}", tags=["Диагностика"],
            summary="Что растёт: размеры таблиц и динамика")
async def growth_one(name: str, user: CurrentUser, days: int = 30):
    _need(name)

    async def build():
        data = await growth.report(name, max(1, min(days, 90)))
        data["text"] = growth.fmt_growth(data)
        return data
    return await tasks.shared("growth:%s:%d" % (name, days), build, ttl=300)


@router.post("/api/growth/{name}/snapshot", tags=["Диагностика"],
             summary="Снять срез размеров немедленно")
async def growth_snapshot(name: str, admin: AdminUser):
    """Первый снимок обычно нужен сразу, а не через сутки по расписанию."""
    return {"cluster": name, "tables": await growth.snapshot(_need(name))}


@router.get("/api/anomalies/{name}", tags=["Диагностика"],
            summary="Отклонения от обычного состояния")
async def anomalies_one(name: str, user: CurrentUser):
    """Половина поломок не пересекает ни одного порога: запросов вдвое
    меньше обычного — приложение отвалилось, а база здорова."""
    cluster = _need(name)

    async def build():
        items = await anomaly.check(cluster)
        return {"cluster": name, "items": items,
                "text": anomaly.fmt_anomalies(items, cluster["label"])}
    return await tasks.shared("anomalies:%s" % name, build, ttl=60)


@router.get("/api/readiness/{name}", tags=["Диагностика"],
            summary="Можно ли сейчас перезапускать, менять схему, снимать копию")
async def readiness_one(name: str, user: CurrentUser, action: str = "restart",
                        host: str = ""):
    if action not in ("restart", "alter", "backup"):
        raise HTTPException(status_code=400,
                            detail="action: restart, alter или backup")
    async def build():
        data = await readiness.check(_need(name), action, host or None)
        data["text"] = readiness.fmt_readiness(data)
        return data
    return await tasks.shared("readiness:%s:%s:%s" % (name, action, host),
                              build, ttl=30)


@router.get("/api/indexes/{name}", tags=["Диагностика"],
            summary="Дублирующие и избыточные индексы")
async def indexes_one(name: str, user: CurrentUser, host: str = ""):
    """Индекс по (a) не нужен, когда есть (a, b): он занимает место и
    обновляется при каждой вставке. Глазами в схеме такое не найти."""
    async def build():
        data = await indexes.analyse(_need(name), host or None)
        data["text"] = indexes.fmt_indexes(data)
        return data
    return await tasks.shared("indexes:%s:%s" % (name, host), build, ttl=600)


@router.get("/api/backups/{name}", tags=["Диагностика"],
            summary="Снимаются ли копии баз")
async def backups_one(name: str, user: CurrentUser):
    cluster = _need(name)

    async def build():
        data = await backups.check(cluster)
        data["text"] = backups.fmt_backups(data, cluster["label"])
        return data
    return await tasks.shared("backups:%s" % name, build, ttl=300)


@router.get("/api/config-changes/{name}", tags=["Диагностика"],
            summary="Что менялось в настройках и когда")
async def config_changes_one(name: str, user: CurrentUser, days: int = 30):
    cluster = _need(name)

    async def build():
        items = await config_history.changes(name, max(1, min(days, 180)))
        return {"cluster": name, "days": days, "items": items,
                "text": config_history.fmt_changes(items, cluster["label"], days)}
    return await tasks.shared("config-changes:%s:%d" % (name, days),
                              build, ttl=300)


@router.post("/api/config-changes/{name}/snapshot", tags=["Диагностика"],
             summary="Снять снимок настроек немедленно")
async def config_snapshot_now(name: str, admin: AdminUser):
    """Первый снимок нужен сразу: иначе сравнивать будет не с чем сутки."""
    return {"cluster": name, "values": await config_history.snapshot(_need(name))}


@router.post("/api/analyze", tags=["Диагностика"], response_model=InsightOut,
             summary="Разбор собранного моделью")
async def analyze_blocks(req: InsightRequest, user: CurrentUser,
                         journal: Audit, request: Request):
    """Объяснить один блок диагностики или всё собранное вместе.

    Разбирается то, что человек видит на экране, поэтому блоки приходят от
    браузера. Пересобирать их на сервере значило бы объяснять другой срез:
    профиль нагрузки через пять минут уже другой.
    """
    cluster = _need(req.cluster)
    blocks = [{"title": b.title, "text": b.text} for b in req.blocks]
    ok, text = True, ""
    try:
        # Ограничение сверху обязательно: без него молчащая модель оставляет
        # в интерфейсе вечно крутящееся кольцо, и человек не знает, ждать ему
        # или уже нет
        text = await asyncio.wait_for(
            insight.analyze(cluster, blocks, req.scope, req.question,
                            req.hours),
            timeout=settings.llm.timeout + INSIGHT_GRACE_S)
    except asyncio.TimeoutError:
        ok = False
        text = ("Модель не ответила за %d с. Проверьте её доступность на "
                "вкладке «Здоровье»."
                % int(settings.llm.timeout + INSIGHT_GRACE_S))
    except Exception as exc:
        ok = False
        logger.error("Разбор не выполнен: %s", exc)
        text = "Разбор не выполнен: %s" % exc

    await journal.add(action="Разбор ИИ", username=user.get("username", ""),
                      target=req.cluster,
                      detail="%s, блоков %d"
                             % ("всё вместе" if req.scope == "all"
                                else "один блок", len(blocks)),
                      ip=audit.client_ip(request), ok=ok)
    return {"cluster": req.cluster, "text": text}


@router.post("/api/explain", tags=["Диагностика"],
             summary="План выполнения запроса")
async def explain_query(req: ExplainRequest, user: CurrentUser,
                        journal: Audit, request: Request):
    """EXPLAIN для написанного запроса или для идущего соединения.

    Прав сверх SELECT не требует: EXPLAIN проверяет те же права, что и сам
    запрос. Исключения два — представления (нужен SHOW VIEW) и чужое
    соединение (нужен PROCESS); о них агент скажет отдельно, если упрётся.
    """
    cluster = _need(req.cluster)
    data = await explain.explain(cluster, req.sql, req.connection_id,
                                 req.host or None)
    data["text"] = explain.fmt_explain(data)
    await journal.add(action="EXPLAIN", username=user.get("username", ""),
                      target=req.cluster,
                      detail=(("соединение %d" % req.connection_id)
                              if req.connection_id else req.sql[:1000]),
                      ip=audit.client_ip(request),
                      ok=not data.get("error"))
    return data


@router.get("/api/memory/{name}", tags=["Диагностика"],
            summary="Память, своп и следы OOM")
async def memory_one(name: str, user: CurrentUser):
    """Самый неприятный вид аварии базы — тот, где база ни при чём: ядру
    не хватило памяти, и оно убило самый жирный процесс. Для сервера БД
    это всегда mysqld."""
    cluster = _need(name)

    async def build():
        data = await memory.collect(cluster)
        data["text"] = memory.fmt_memory(data, cluster["label"])
        return data
    return await tasks.shared("memory:%s" % name, build, ttl=60)


@router.get("/api/notes/{name}", tags=["Кластеры"],
            summary="Известные особенности кластера")
async def notes_list(name: str, user: CurrentUser, session: DbSession):
    _need(name)
    rows = await NoteRepository(session).list(name)
    return {"cluster": name,
            "items": [{"id": n.id, "text": n.text, "author": n.author,
                       "ts": n.ts, "enabled": bool(n.enabled)} for n in rows]}


@router.post("/api/notes/{name}", tags=["Кластеры"], summary="Добавить заметку")
async def notes_add(name: str, admin: AdminUser, session: DbSession,
                    journal: Audit, request: Request, text: str = ""):
    """Заметки подмешиваются в разбор: записанное один раз избавляет от
    повторных «открытий» планового бэкапа в каждом ответе."""
    _need(name)
    note = await NoteRepository(session).add(name, text,
                                             admin.get("username", ""))
    if note is None:
        raise HTTPException(status_code=400, detail="Пустая заметка")
    await journal.add(action="заметка добавлена", username=admin.get("username", ""),
                      target=name, detail=note.text[:500],
                      ip=audit.client_ip(request))
    return {"id": note.id, "text": note.text}


@router.patch("/api/notes/{note_id}", tags=["Кластеры"],
              summary="Включить или выключить заметку")
async def notes_toggle(note_id: int, admin: AdminUser, session: DbSession,
                       enabled: bool = True):
    if not await NoteRepository(session).toggle(note_id, enabled):
        raise HTTPException(status_code=404, detail="Заметка не найдена")
    return {"id": note_id, "enabled": enabled}


@router.delete("/api/notes/{note_id}", tags=["Кластеры"],
               summary="Удалить заметку")
async def notes_delete(note_id: int, admin: AdminUser, session: DbSession,
                       journal: Audit, request: Request):
    if not await NoteRepository(session).delete(note_id):
        raise HTTPException(status_code=404, detail="Заметка не найдена")
    await journal.add(action="заметка удалена", username=admin.get("username", ""),
                      target=str(note_id), ip=audit.client_ip(request))
    return {"id": note_id}
