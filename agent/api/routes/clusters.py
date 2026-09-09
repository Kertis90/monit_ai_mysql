"""Состояние кластеров, ряды для графиков и диагностические запросы."""
from __future__ import annotations

import asyncio
import datetime
import logging

from fastapi import APIRouter, HTTPException, Request

from agent.api.deps import (AdminUser, Audit, CurrentUser, DbSession,
                            MaybeUser)
from agent.db.repositories.notes import NoteRepository
from agent.services import (anomaly, audit, backups, config_audit,
                            config_history, forecast, growth, indexes,
                            readiness)
from agent.schemas.api import SqlRequest, SqlResult
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
                                       collect_history)
from agent.services.registry import (app_host, cluster_hosts,
                                     enabled_clusters, find_cluster)

logger = logging.getLogger("agent.api.clusters")
router = APIRouter(tags=["Кластеры"])

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
async def charts(name: str, user: CurrentUser, hours: float = 3):
    return {"cluster": name, "charts": await build_charts(_need(name), hours)}


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
    result  = await run_diagnostics(cluster)
    text    = fmt_diagnostics(result)
    if deep:
        text += "\n\n" + await explain_top_queries(cluster)
    return {"cluster": name, "report": text}


@router.get("/api/workload/{name}", tags=["Диагностика"],
            summary="Что нагружает базу прямо сейчас")
async def workload(name: str, user: CurrentUser, seconds: float = 0,
                   host: str = ""):
    """Два среза performance_schema с интервалом и разница между ними.

    Именно разница: накопленные суммы показывают средние за всё время работы
    сервера и текущую проблему прячут.
    """
    data = await workload_delta(_need(name), seconds or DEFAULT_WINDOW_S,
                                host or None)
    if not data.get("error"):
        data["text"] = fmt_workload(data, name)
    return data


@router.get("/api/replication/{name}", tags=["Диагностика"],
            summary="Состояние репликации кластера")
async def replication(name: str, user: CurrentUser):
    cluster = _need(name)
    states = await collect_replication(cluster)
    return {"cluster": name, "items": states,
            "text": fmt_replication(states, cluster["label"])}


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
    data = await forecast.collect(_need(name))
    data["text"] = forecast.fmt_forecast(data)
    return data


@router.get("/api/config-audit/{name}", tags=["Диагностика"],
            summary="Разбор настроек MySQL")
async def config_audit_one(name: str, user: CurrentUser, host: str = ""):
    data = await config_audit.audit(_need(name), host or None)
    data["text"] = config_audit.fmt_audit(data)
    return data


@router.get("/api/growth/{name}", tags=["Диагностика"],
            summary="Что растёт: размеры таблиц и динамика")
async def growth_one(name: str, user: CurrentUser, days: int = 30):
    _need(name)
    data = await growth.report(name, max(1, min(days, 90)))
    data["text"] = growth.fmt_growth(data)
    return data


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
    items = await anomaly.check(cluster)
    return {"cluster": name, "items": items,
            "text": anomaly.fmt_anomalies(items, cluster["label"])}


@router.get("/api/readiness/{name}", tags=["Диагностика"],
            summary="Можно ли сейчас перезапускать, менять схему, снимать копию")
async def readiness_one(name: str, user: CurrentUser, action: str = "restart",
                        host: str = ""):
    if action not in ("restart", "alter", "backup"):
        raise HTTPException(status_code=400,
                            detail="action: restart, alter или backup")
    data = await readiness.check(_need(name), action, host or None)
    data["text"] = readiness.fmt_readiness(data)
    return data


@router.get("/api/indexes/{name}", tags=["Диагностика"],
            summary="Дублирующие и избыточные индексы")
async def indexes_one(name: str, user: CurrentUser, host: str = ""):
    """Индекс по (a) не нужен, когда есть (a, b): он занимает место и
    обновляется при каждой вставке. Глазами в схеме такое не найти."""
    data = await indexes.analyse(_need(name), host or None)
    data["text"] = indexes.fmt_indexes(data)
    return data


@router.get("/api/backups/{name}", tags=["Диагностика"],
            summary="Снимаются ли копии баз")
async def backups_one(name: str, user: CurrentUser):
    cluster = _need(name)
    data = await backups.check(cluster)
    data["text"] = backups.fmt_backups(data, cluster["label"])
    return data


@router.get("/api/config-changes/{name}", tags=["Диагностика"],
            summary="Что менялось в настройках и когда")
async def config_changes_one(name: str, user: CurrentUser, days: int = 30):
    cluster = _need(name)
    items = await config_history.changes(name, max(1, min(days, 180)))
    return {"cluster": name, "days": days, "items": items,
            "text": config_history.fmt_changes(items, cluster["label"], days)}


@router.post("/api/config-changes/{name}/snapshot", tags=["Диагностика"],
             summary="Снять снимок настроек немедленно")
async def config_snapshot_now(name: str, admin: AdminUser):
    """Первый снимок нужен сразу: иначе сравнивать будет не с чем сутки."""
    return {"cluster": name, "values": await config_history.snapshot(_need(name))}


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
