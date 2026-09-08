"""
Сводка за период: агент сам приходит с новостями.

До сих пор он отвечал, только когда спросят. Дежурный, который не пришёл
утром и не спросил, не узнает, что ночью трижды падала реплика, а запрос,
которого раньше не было, вышел в топ.

Сводка собирается по расписанию и отправляется почтой и/или вебхуком, а
последняя всегда доступна страницей — на случай, если письмо не дошло или
почты нет вовсе.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Optional

import httpx

from agent.core.config import settings
from agent.db.base import session_scope
from agent.db.repositories.alerts import AlertRepository
from agent.services.analysis import collect_baseline, fmt_baseline
from agent.services.prometheus import collect_current, collect_history
from agent.services.registry import enabled_clusters
from agent.services.replication import collect_replication

logger = logging.getLogger("agent.digest")

ENABLED  = os.environ.get("DIGEST_ENABLED", "false").strip().lower() in ("1", "true", "yes")
AT       = os.environ.get("DIGEST_AT", "09:00").strip()
HOURS    = max(1.0, min(168.0, float(os.environ.get("DIGEST_HOURS", "24"))))
TO       = [a.strip() for a in os.environ.get("DIGEST_TO", "").split(",") if a.strip()]
WEBHOOK  = os.environ.get("DIGEST_WEBHOOK", "").strip()

SMTP_HOST = os.environ.get("ALERT_SMTP_HOST", "").strip()
SMTP_USER = os.environ.get("ALERT_SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("ALERT_SMTP_PASSWORD", "")
MAIL_FROM = os.environ.get("ALERT_EMAIL_FROM", "").strip() or SMTP_USER

# Последняя собранная сводка — её отдаёт страница /digest
_last: dict = {}


def last() -> dict:
    return dict(_last)


def _parse_at(value: str) -> tuple[int, int]:
    try:
        hh, mm = value.split(":")
        return max(0, min(23, int(hh))), max(0, min(59, int(mm)))
    except Exception:
        logger.warning("DIGEST_AT=%r не разобран, беру 09:00", value)
        return 9, 0


def _seconds_until(hh: int, mm: int) -> float:
    """Сколько ждать до следующего срабатывания по местному времени сервера."""
    now = datetime.datetime.now()
    target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return (target - now).total_seconds()


async def _cluster_part(cluster: dict, hours: float) -> dict:
    """Что произошло с одним кластером."""
    label = cluster["label"]
    part = {"cluster": cluster["name"], "label": label,
            "alerts": [], "counts": {}, "degraded": "", "replication": []}

    async with session_scope() as session:
        rows = await AlertRepository(session).recent(
            cluster=cluster["name"], hours=hours, limit=100)
    part["alerts"] = [{"ts": r.ts, "alert": r.alert, "severity": r.severity,
                       "summary": r.summary, "resolution": r.resolution}
                      for r in rows]
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.alert or "?"] = counts.get(r.alert or "?", 0) + 1
    part["counts"] = counts

    # Что изменилось относительно обычного такого же дня
    try:
        hist = await collect_history(cluster, hours)
        base = await collect_baseline(cluster, hours)
        part["degraded"] = fmt_baseline(hist, base, label)
    except Exception as exc:
        logger.error("Сводка: сравнение для %s не собрано: %s", label, exc)

    try:
        part["replication"] = [s for s in await collect_replication(cluster)
                               if s and not s.get("healthy")]
    except Exception as exc:
        logger.error("Сводка: репликация %s не прочитана: %s", label, exc)

    try:
        part["current"] = await collect_current(cluster)
    except Exception as exc:
        logger.error("Сводка: текущее состояние %s не собрано: %s", label, exc)
    return part


async def build(hours: float = HOURS) -> dict:
    """Собрать сводку по всем кластерам."""
    clusters = enabled_clusters()
    parts = [await _cluster_part(c, hours) for c in clusters]

    unresolved = []
    async with session_scope() as session:
        repo = AlertRepository(session)
        for row in await repo.recent(hours=hours, limit=200):
            if not (row.resolution or "").strip():
                unresolved.append({"id": row.id, "alert": row.alert,
                                   "cluster": row.cluster_label or row.cluster,
                                   "ts": row.ts, "summary": row.summary})

    data = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "hours": hours,
        "clusters": parts,
        "unresolved": unresolved[:20],
        "total_alerts": sum(len(p["alerts"]) for p in parts),
    }
    data["text"] = render_text(data)
    _last.clear()
    _last.update(data)
    return data


def render_text(data: dict) -> str:
    lines = ["Сводка за последние %g ч (собрана %s)"
             % (data["hours"], data["generated"]), ""]

    if not data["total_alerts"]:
        lines.append("Событий не было ни по одному кластеру.")
    for part in data["clusters"]:
        lines.append("── %s ──" % part["label"])
        if part["counts"]:
            lines.append("  События: " + ", ".join(
                "%s ×%d" % (k, v) for k, v in
                sorted(part["counts"].items(), key=lambda kv: -kv[1])))
        else:
            lines.append("  Событий не было.")

        for state in part["replication"]:
            lines.append("  Репликация %s: %s" % (
                state.get("host", "?"),
                "; ".join(state.get("problems") or ["состояние неизвестно"])))

        current = part.get("current") or {}
        prim = current.get("primary") or {}
        if prim:
            lines.append("  Сейчас: QPS %s, медленных %s/с, соединений %s%%, "
                         "CPU %s%%" % (prim.get("qps", "?"),
                                       prim.get("slow_qps", "?"),
                                       prim.get("connections_pct", "?"),
                                       prim.get("cpu_pct", "?")))
        if part["degraded"]:
            # Из блока сравнения берём только строки с метриками
            for row in part["degraded"].split("\n"):
                if row.strip().startswith(("qps", "slow_qps", "connections_pct",
                                           "cpu_pct", "iowait_pct")):
                    lines.append("  " + row.strip())
        lines.append("")

    if data["unresolved"]:
        lines.append("Без записанного решения (%d):" % len(data["unresolved"]))
        for item in data["unresolved"]:
            lines.append("  [%s] %s — %s"
                         % (str(item["ts"])[:16].replace("T", " "),
                            item["alert"], item["cluster"] or "—"))
        lines.append("")
        lines.append("Запишите, чем закончилось: через четверть часа агент "
                     "проверит, помогло ли, и сохранит это в память инцидентов.")
    return "\n".join(lines)


def render_html(data: dict) -> str:
    """Простой HTML: почтовые клиенты сложную вёрстку всё равно поломают."""
    body = (data.get("text") or "").replace("&", "&amp;") \
                                   .replace("<", "&lt;").replace(">", "&gt;")
    return ("<html><body style=\"font-family:ui-monospace,Consolas,monospace;"
            "font-size:13px;line-height:1.5\"><pre>%s</pre></body></html>" % body)


def _send_mail(subject: str, text: str, html: str) -> None:
    """Отправка письма. Синхронная: smtplib другого не умеет."""
    host, _, port = SMTP_HOST.partition(":")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = MAIL_FROM
    message["To"] = ", ".join(TO)
    message.set_content(text)
    message.add_alternative(html, subtype="html")

    with smtplib.SMTP(host, int(port or 25), timeout=30) as smtp:
        try:
            smtp.starttls()
        except smtplib.SMTPException:
            # Сервер без TLS — внутренний релей часто именно такой
            logger.info("SMTP %s без STARTTLS", host)
        if SMTP_USER:
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(message)


async def deliver(data: dict) -> list[str]:
    """Разослать сводку. Возвращает список того, что не получилось."""
    problems = []
    subject = "Сводка мониторинга MySQL за %g ч — событий: %d" % (
        data["hours"], data["total_alerts"])

    if TO and SMTP_HOST:
        try:
            await asyncio.to_thread(_send_mail, subject, data["text"],
                                    render_html(data))
            logger.info("Сводка отправлена: %s", ", ".join(TO))
        except Exception as exc:
            problems.append("почта: %s" % exc)
            logger.error("Сводка не отправлена почтой: %s", exc)
    elif TO and not SMTP_HOST:
        problems.append("почта: не задан ALERT_SMTP_HOST")

    if WEBHOOK:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                # text отдельным полем: у мессенджеров разные схемы, но
                # текстовое поле принимают почти все
                await client.post(WEBHOOK, json={"text": data["text"],
                                                 "subject": subject,
                                                 "hours": data["hours"],
                                                 "total_alerts": data["total_alerts"]})
            logger.info("Сводка отправлена вебхуком")
        except Exception as exc:
            problems.append("вебхук: %s" % exc)
            logger.error("Сводка не отправлена вебхуком: %s", exc)
    return problems


async def run_once() -> dict:
    data = await build()
    data["delivery_problems"] = await deliver(data)
    return data


async def scheduler() -> None:
    """Ждать назначенного часа и собирать сводку. Работает, пока жив агент."""
    hh, mm = _parse_at(AT)
    logger.info("Сводка включена: каждый день в %02d:%02d по времени сервера, "
                "период %g ч", hh, mm, HOURS)
    while True:
        try:
            await asyncio.sleep(_seconds_until(hh, mm))
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Сводка не собрана: %s", exc)
            # Не зацикливаемся на ошибке: ждём до следующего дня
            await asyncio.sleep(60)
