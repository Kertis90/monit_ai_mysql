"""Состояние кластеров, ряды для графиков и диагностические запросы."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request

from agent.api.deps import Audit, CurrentUser, MaybeUser
from agent.services import audit
from agent.schemas.api import SqlRequest, SqlResult
from agent.services.analysis import (collect_series_table, explain_top_queries,
                                     fmt_diagnostics, run_diagnostics)
from agent.services.mysql import db_versions_text, sql_execute
from agent.services.prometheus import (build_charts, collect_current,
                                       collect_history)
from agent.services.registry import enabled_clusters, find_cluster

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
