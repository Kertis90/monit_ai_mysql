"""История событий, приём событий извне и память инцидентов."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from agent.api.deps import (AdminUser, Alerts, Audit, MaybeUser,
                            require_ingest_token)
from agent.schemas.api import AlertOut, IngestAlert, ResolveRequest
from agent.services.analysis import fmt_current, fmt_history, system_prompt
from agent.services.llm import llm_complete
from agent.services.prometheus import collect_current, collect_history
from agent.services import audit, followup
from agent.services.registry import find_cluster

logger = logging.getLogger("agent.api.alerts")
router = APIRouter(tags=["События"])


@router.get("/alerts/history", summary="История событий")
async def history(alerts: Alerts, user: MaybeUser,
                  cluster: str = "", hours: float = 24, limit: int = 20):
    rows = await alerts.recent(cluster=cluster or None, hours=hours, limit=limit)
    return {"total": len(rows),
            "items": [AlertOut.model_validate(r) for r in rows]}


@router.post("/api/alerts/ingest", summary="Зарегистрировать событие извне",
             dependencies=[Depends(require_ingest_token)])
async def ingest(payload: IngestAlert, alerts: Alerts):
    """Событие от внешней системы с тем же разбором, что и у Alertmanager.

    Пример для Zabbix (действие → webhook):

        curl -X POST https://host/ai-agent/api/alerts/ingest \\
             -H 'X-Ingest-Token: <token>' -H 'Content-Type: application/json' \\
             -d '{"alert":"Free disk space is low","severity":"critical",
                  "cluster":"kemerovo","instance":"10.1.0.1",
                  "summary":"/var 8% free","source":"zabbix"}'
    """
    name     = payload.alert.strip() or "ExternalAlert"
    severity = payload.severity.strip().lower() or "warning"
    if severity not in ("critical", "warning", "info"):
        severity = "warning"

    cluster = find_cluster(payload.cluster) if payload.cluster else None
    label   = cluster["label"] if cluster else (payload.cluster or "—")
    summary = payload.summary.strip() or name

    blocks = [f"## Событие из внешней системы ({payload.source})",
              f"  Имя:        {name}",
              f"  Важность:   {severity}",
              f"  Объект:     {payload.instance or '—'}",
              f"  Кластер:    {label}",
              f"  Описание:   {summary}"]
    if payload.description.strip():
        blocks.append(f"  Подробности: {payload.description.strip()}")

    # Если кластер узнали — подкладываем его метрики, иначе разбор идёт
    # только по тексту события
    if cluster:
        try:
            blocks.append(fmt_current(await collect_current(cluster)))
            blocks.append(fmt_history(await collect_history(cluster, 2),
                                      cluster["label"]))
        except Exception as exc:
            logger.error("Метрики для внешнего события не собраны: %s", exc)
    else:
        blocks.append("  (кластер не сопоставлен — метрик из Prometheus нет, "
                      "разбирай по описанию события)")

    prompt = "\n".join(blocks) + """

## Задача
1. Причина срабатывания (1-2 предложения).
2. Реальное влияние прямо сейчас.
3. 2-4 вероятных источника.
4. Немедленные команды для диагностики.
5. Шаги устранения.
6. Нужен ли срочный вызов DBA — да/нет."""

    try:
        analysis = await llm_complete([
            {"role": "system", "content": system_prompt()},
            {"role": "user",   "content": prompt},
        ])
    except Exception as exc:
        logger.error("LLM не разобрала внешнее событие: %s", exc)
        analysis = f"Разбор не выполнен: LLM недоступна ({exc})"

    await alerts.add(alert=name, cluster=cluster["name"] if cluster else "",
                     cluster_label=label, instance=payload.instance or "—",
                     severity=severity, summary=summary, analysis=analysis,
                     source=payload.source.strip().lower() or "api")
    logger.info("Принято событие из %s: %s (%s)", payload.source, name, severity)
    # Открытые вкладки узнают о событии сразу, а не по нажатию «Обновить»
    from agent.api.routes.chat import broadcast
    await broadcast({"type": "alert", "alert": name, "severity": severity,
                     "cluster": label, "summary": summary,
                     "source": payload.source})
    return {"ok": True, "alert": name, "severity": severity,
            "cluster": cluster["name"] if cluster else None,
            "source": payload.source,
            "analyzed": not analysis.startswith("Разбор не выполнен")}


@router.post("/api/alerts/{alert_id}/resolve",
             summary="Записать, чем закончился инцидент")
async def resolve(alert_id: int, req: ResolveRequest, alerts: Alerts,
                  journal: Audit, user: MaybeUser, request: Request):
    """Записанное решение подкладывается в разбор при повторе того же
    события — агент предложит проверенное вместо вывода с нуля."""
    if not req.resolution.strip():
        raise HTTPException(status_code=400, detail="Пустое решение")
    if not await alerts.resolve(alert_id, req.resolution.strip(),
                                (user or {}).get("username", "")):
        raise HTTPException(status_code=404, detail="Запись не найдена")

    # Через четверть часа агент сам посмотрит, не повторилось ли, и допишет
    # вывод к решению: иначе в памяти инцидентов копится то, что сделали,
    # а не то, что помогло
    await journal.add(action="решение записано",
                      username=(user or {}).get("username", ""),
                      target=str(alert_id), ip=audit.client_ip(request),
                      detail=req.resolution.strip()[:500])
    followup.schedule(alert_id)
    return {"ok": True, "id": alert_id,
            "check_in_minutes": followup.CHECK_MINUTES}


@router.get("/api/incidents/{alert_name}",
            summary="Как решали такой инцидент раньше")
async def incidents(alert_name: str, alerts: Alerts, cluster: str = ""):
    items = await alerts.similar(alert_name, cluster or None, limit=10)
    return {"alert": alert_name, "total": len(items),
            "items": [AlertOut.model_validate(i) for i in items]}


@router.delete("/api/alerts/{alert_id}", summary="Удалить запись истории")
async def delete_one(alert_id: int, admin: AdminUser, alerts: Alerts,
                     journal: Audit, request: Request):
    if not await alerts.delete(alert_id):
        raise HTTPException(status_code=404, detail="Запись не найдена")
    await journal.add(action="событие удалено",
                      username=admin.get("username", ""),
                      target=str(alert_id), ip=audit.client_ip(request))
    return {"ok": True, "id": alert_id}


@router.delete("/api/alerts", summary="Удалить все записи одного типа")
async def delete_by_name(admin: AdminUser, alerts: Alerts, journal: Audit,
                         request: Request, name: str = "",
                         cluster: str = ""):
    """Удалить пачку одинаковых записей — например, ложные срабатывания,
    нагенерированные ошибочным правилом."""
    if not name:
        raise HTTPException(status_code=400, detail="Укажите параметр name")
    removed = await alerts.delete_by_name(name, cluster or None)
    await journal.add(action="события удалены пачкой",
                      username=admin.get("username", ""), target=name,
                      ip=audit.client_ip(request),
                      detail="кластер: %s, записей: %d"
                             % (cluster or "все", removed))
    return {"ok": True, "alert": name, "removed": removed}
