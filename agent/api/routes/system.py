"""Вебхук Alertmanager, служебные ответы и страницы интерфейса."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from agent.api.deps import AdminUser, Alerts, MaybeUser
from agent.core.config import settings
from agent.services import access, digest, directory, oidc
from agent.services.analysis import fmt_current, fmt_history, system_prompt
from agent.services.llm import llm_complete
from agent.services.mysql import db_versions_text
from agent.services.prometheus import collect_current, collect_history
from agent.services.registry import (enabled_clusters, find_cluster,
                                     find_cluster_by_ip)

logger = logging.getLogger("agent.api.system")
router = APIRouter()

TASK = """
## Задача
1. Причина срабатывания (1-2 предложения).
2. Реальное влияние прямо сейчас.
3. 2-4 вероятных источника.
4. Немедленные команды для диагностики.
5. Шаги устранения.
6. Нужен ли срочный вызов DBA — да/нет."""


def _fmt_incidents(items, name: str) -> str:
    """Чем такое заканчивалось раньше, если дежурный записывал решение."""
    if not items:
        return ""
    lines = [f"## Так уже было: {name}", ""]
    for row in items:
        when = (row.resolved_at or row.ts or "")[:19].replace("T", " ")
        lines.append(f"  [{when} UTC] {row.cluster_label or '—'}: {row.resolution}")
    lines.append("")
    lines.append("Если картина совпадает, предложи проверенное решение первым.")
    return "\n".join(lines)


@router.post("/webhook", tags=["События"], summary="Приём от Alertmanager")
async def webhook(request: Request, alerts: Alerts):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    processed = 0
    for item in body.get("alerts", []):
        if item.get("status") != "firing":
            continue

        labels   = item.get("labels", {})
        name     = labels.get("alertname", "Unknown")
        instance = labels.get("instance", "")
        severity = labels.get("severity", "unknown")
        summary  = item.get("annotations", {}).get("summary", "")

        cluster = (find_cluster(labels.get("cluster", ""))
                   or find_cluster_by_ip(instance.split(":")[0]))
        label   = cluster["label"] if cluster else instance
        cname   = cluster["name"] if cluster else ""

        logger.info("[ALERT] %s | %s | %s", name, label, severity)

        # Повтор того же события разбирать заново незачем: Alertmanager шлёт
        # его по repeat_interval, пока проблема не ушла, и каждый повтор
        # стоил бы отдельного запроса к модели
        if await alerts.is_duplicate(alert=name, cluster=cname, instance=instance):
            previous = await alerts.recent(cluster=cname or None, hours=24,
                                           limit=1, name=name)
            analysis = previous[0].analysis if previous else ""
            logger.info("[ALERT] %s: повтор, разбор взят из истории", name)
            await alerts.add(alert=name, cluster=cname, cluster_label=label,
                             instance=instance, severity=severity,
                             summary=summary, analysis=analysis,
                             source="prometheus")
            processed += 1
            continue

        blocks = []
        if cluster:
            blocks.append(fmt_current(await collect_current(cluster)))
            blocks.append(fmt_history(await collect_history(cluster, 2), label))
        past = await alerts.similar(name, cname or None)
        if past:
            blocks.append(_fmt_incidents(past, name))

        prompt = f"""## Алерт

**Кластер:** {label}
**Алерт:** {name}  (severity: {severity})
**Инстанс:** {instance}
**Описание:** {summary}

{chr(10).join(blocks) if blocks else "Метрики недоступны."}
{TASK}"""

        try:
            analysis = await llm_complete([
                {"role": "system", "content": system_prompt()},
                {"role": "user",   "content": prompt},
            ])
        except Exception as exc:
            logger.error("LLM не разобрала алерт %s: %s", name, exc)
            analysis = f"Разбор не выполнен: LLM недоступна ({exc})"

        await alerts.add(alert=name, cluster=cname, cluster_label=label,
                         instance=instance, severity=severity, summary=summary,
                         analysis=analysis, source="prometheus")
        processed += 1

    return {"processed": processed}


@router.get("/api/digest", tags=["Служебные"], summary="Сводка за период")
async def digest_now(user: MaybeUser, rebuild: bool = False,
                     hours: float = 0):
    """Последняя собранная сводка либо новая по запросу.

    Ждать назначенного часа, чтобы посмотреть, что было ночью, незачем —
    поэтому есть rebuild.
    """
    if rebuild or not digest.last():
        return await digest.build(hours or digest.HOURS)
    return digest.last()


@router.post("/api/digest/send", tags=["Служебные"],
             summary="Собрать и разослать сводку сейчас")
async def digest_send(admin: AdminUser):
    """Проверить, что письмо и вебхук настроены, не дожидаясь утра."""
    data = await digest.run_once()
    return {"ok": not data["delivery_problems"],
            "problems": data["delivery_problems"],
            "total_alerts": data["total_alerts"]}


@router.get("/digest", include_in_schema=False)
async def digest_page(request: Request, user: MaybeUser):
    """Постоянная страница со сводкой: письмо может не дойти, а посмотреть надо."""
    data = digest.last() or await digest.build()
    text = (data.get("text") or "").replace("&", "&amp;")                                    .replace("<", "&lt;").replace(">", "&gt;")
    return HTMLResponse(
        "<html><head><meta charset=\"utf-8\"><title>Сводка мониторинга</title>"
        "</head><body style=\"background:#12151b;color:#c9d1d9;"
        "font:13px/1.6 ui-monospace,Consolas,monospace;padding:24px\">"
        "<pre>%s</pre></body></html>" % text)


@router.get("/health", tags=["Служебные"], summary="Живость агента")
async def health():
    return {"status": "ok", "version": settings.version,
            "clusters": len(enabled_clusters())}


@router.get("/config", tags=["Служебные"], summary="Сводка конфигурации")
async def config_info(user: MaybeUser):
    """Что агент про себя знает. Секретов здесь нет и быть не должно."""
    return {
        "version":    settings.version,
        "clusters":   [c["name"] for c in enabled_clusters()],
        "prometheus": settings.prometheus.url,
        "llm_model":  settings.llm.model,
        "storage":    "sqlite" if settings.db.is_sqlite else "mysql",
        "auth": {
            "enabled": settings.auth.enabled,
            "ldap":    settings.ldap.enabled,
            "oidc":    oidc.OIDC_ENABLED,
            "directory_search": not directory.directory_search_status(),
        },
        "db_versions": db_versions_text(),
    }


def _page(name: str, request: Request,
          values: dict[str, str] | None = None) -> HTMLResponse:
    """Отдать страницу, подставив префикс за nginx и значения шаблона.

    Префикс нужен, потому что при проксировании не в корень относительные
    пути иначе ломаются. Плейсхолдеры вида {{ИМЯ}} обязательны: страница
    входа подставляет их прямо в JavaScript, и незаменённый остаток —
    синтаксическая ошибка, из-за которой скрипт не выполняется целиком,
    а форма перестаёт отправляться.
    """
    path = Path(settings.web_dir) / name
    if not path.exists():
        return HTMLResponse(f"<h1>{name} не найден</h1>", status_code=500)

    prefix = (request.scope.get("root_path") or settings.prefix).rstrip("/")
    html = path.read_text(encoding="utf-8")
    html = html.replace('<base href="/">', f'<base href="{prefix}/">', 1)
    for key, value in (values or {}).items():
        html = html.replace("{{%s}}" % key, value)

    left = re.findall(r"\{\{[A-Z_]+\}\}", html)
    if left:
        logger.error("В %s остались незаполненные плейсхолдеры: %s — страница "
                     "работать не будет", name, ", ".join(sorted(set(left))))
    return HTMLResponse(html)


@router.get("/", include_in_schema=False)
async def index(request: Request):
    return _page("index.html", request)


@router.get("/login", include_in_schema=False)
async def login_page(request: Request):
    oidc_ready = bool(oidc.OIDC_ENABLED and oidc.OIDC_ISSUER and oidc.OIDC_CLIENT_ID)
    # Если настроен только SSO, поля пароля на форме не нужны
    sso_only = bool(access.SSO_ENABLED and not (settings.ldap.enabled
                                                or settings.auth.admin_password_hash))
    return _page("login.html", request, {
        "SSO_ONLY":         "true" if sso_only else "false",
        "OIDC_ENABLED":     "true" if oidc_ready else "false",
        "OIDC_BUTTON_TEXT": oidc.OIDC_BUTTON_TEXT,
    })


@router.get("/report", include_in_schema=False)
async def report_page(request: Request):
    """Печатная версия отчёта. PDF делает браузер (Ctrl+P → сохранить как PDF):
    так не нужны ни серверный рендер, ни новые зависимости."""
    return _page("report.html", request)
