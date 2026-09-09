"""
Агент проверяет сам себя.

Мониторинг, который не следит за собственной работоспособностью, подводит
именно в тот момент, когда нужен. Протухший SSH-ключ, отозванные права
db_user, недоступная модель, переставший скрейпить экспортёр — всё это
обнаруживается в разгар аварии, когда агент зовут разбираться.

Проверки те же, что делает verify.sh, но по расписанию и с заведением
события: сломанный доступ приходит алертом, а не всплывает через месяц.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import httpx

from agent.core.config import settings
from agent.db.base import session_scope
from agent.db.repositories.alerts import AlertRepository
from agent.services.mysql import cluster_db_creds, sql_execute
from agent.services.registry import app_host, cluster_hosts, enabled_clusters
from agent.services.ssh import remote_time

logger = logging.getLogger("agent.selfcheck")

ENABLED = os.environ.get("SELFCHECK_ENABLED", "true").lower() in ("1", "true", "yes")
INTERVAL_MIN = max(10.0, float(os.environ.get("SELFCHECK_INTERVAL_MIN", "60")))


def _item(name: str, ok: bool, detail: str, fix: str = "") -> dict:
    return {"name": name, "ok": ok, "detail": detail, "fix": fix}


async def check_prometheus() -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(settings.prometheus.url + "/api/v1/query",
                                 params={"query": "up"})
            data = r.json()
        results = data.get("data", {}).get("result", [])
        down = [s["metric"].get("instance", "?") for s in results
                if s["value"][1] == "0"]
        if down:
            return _item("Prometheus", False,
                         "Не отвечают экспортёры: " + ", ".join(down[:6]),
                         "Проверьте службы node_exporter и mysqld_exporter "
                         "на этих серверах")
        return _item("Prometheus", True,
                     "Опрашивает %d целей, все отвечают" % len(results))
    except Exception as exc:
        return _item("Prometheus", False, "Недоступен: %s" % exc,
                     "systemctl status prometheus")


async def check_llm() -> dict:
    """Пробный запрос к модели. Дешёвый: один короткий ответ."""
    try:
        from agent.services.llm import llm_complete
        answer = await llm_complete(
            [{"role": "user", "content": "Ответь одним словом: работает"}])
        return _item("Модель", bool(answer),
                     "Отвечает (%s)" % (answer or "").strip()[:40])
    except Exception as exc:
        return _item("Модель", False, "Не отвечает: %s" % exc,
                     "Проверьте LLM_BASE_URL и LLM_API_KEY в config.env")


async def check_ssh() -> list[dict]:
    """SSH до каждого сервера: логи и туннель к базе держатся на нём."""
    out = []
    from agent.services.ssh import access_problem
    problem = access_problem()
    if problem:
        # Ключ и учётка проверяются до подключения: недоступный агенту ключ
        # иначе выглядит как недоступный сервер
        return [_item("SSH", False, problem,
                      "Поправьте SSH_USER и SSH_KEY в config.env, затем "
                      "sudo ./scripts/install_agent.sh")]
    if settings.ssh.key:
        out_note = "ключ %s" % settings.ssh.key
    else:
        out_note = "ключ по умолчанию"
    seen = set()
    for cluster in enabled_clusters():
        hosts = [(ip, role) for ip, role in cluster_hosts(cluster)]
        hosts.append((app_host(cluster), "ядро"))
        for ip, role in hosts:
            if ip in seen:
                continue
            seen.add(ip)
            moment = await remote_time(ip)
            out.append(_item(
                "SSH %s (%s)" % (ip, role), moment is not None,
                ("Отвечает (%s, %s)" % (settings.ssh.user, out_note)) if moment
                else "Не отвечает под учёткой " + settings.ssh.user,
                "" if moment else
                "ssh %s@%s — проверьте ключ и доступ" % (settings.ssh.user, ip)))
    return out


async def check_databases() -> list[dict]:
    """Права учётки агента: их отзывают при плановой смене паролей."""
    out = []
    for cluster in enabled_clusters():
        if not cluster_db_creds(cluster):
            out.append(_item("БД %s" % cluster["label"], True,
                             "db_user не задан — SQL-запросы отключены осознанно"))
            continue
        result = await sql_execute(cluster, "SELECT 1 AS ok")
        ok = not result.get("error")
        out.append(_item("БД %s" % cluster["label"], ok,
                         "Учётка работает" if ok else result["error"][:200],
                         "" if ok else
                         "Проверьте db_user/db_password в clusters.json и права SELECT"))
    return out


async def check_directory() -> Optional[dict]:
    if not settings.ldap.enabled:
        return None
    from agent.services import directory
    why = directory.directory_search_status()
    if why:
        return _item("Каталог", False, why,
                     "Поиск учёток во вкладке «Доступы» работать не будет")

    def probe():
        conn, own = directory._dir_conn(None)
        if conn is None:
            return False
        if own:
            try:
                conn.unbind()
            except Exception:
                pass
        return True

    ok = await asyncio.to_thread(probe)
    return _item("Каталог", ok,
                 "Подключение проходит" if ok else "Подключиться не удалось",
                 "" if ok else "sudo ./scripts/ldap_test.py")


async def run() -> dict:
    """Полная проверка. Возвращает список пунктов и общий вердикт."""
    parts: list[dict] = []
    prom, llm = await asyncio.gather(check_prometheus(), check_llm())
    parts.append(prom)
    parts.append(llm)
    parts.extend(await check_ssh())
    parts.extend(await check_databases())
    ldap = await check_directory()
    if ldap:
        parts.append(ldap)

    broken = [p for p in parts if not p["ok"]]
    return {"ok": not broken, "checks": parts,
            "broken": [p["name"] for p in broken]}


async def run_and_report() -> dict:
    """Проверить и, если что-то сломано, завести событие."""
    result = await run()
    if result["ok"]:
        return result

    summary = "Не работает: " + ", ".join(result["broken"])
    detail = "\n".join("  %s: %s%s" % (p["name"], p["detail"],
                                       ("\n      " + p["fix"]) if p["fix"] else "")
                       for p in result["checks"] if not p["ok"])
    async with session_scope() as session:
        repo = AlertRepository(session)
        # Ломается обычно надолго, а событие нужно одно
        if not await repo.is_duplicate(alert="Самопроверка агента", cluster="",
                                       instance="agent", minutes=180):
            await repo.add(alert="Самопроверка агента", cluster="",
                           cluster_label="Агент", instance="agent",
                           severity="critical", summary=summary,
                           analysis="Что именно не работает:\n" + detail,
                           source="selfcheck")
            logger.error("Самопроверка: %s", summary)
    return result


async def scheduler() -> None:
    logger.info("Самопроверка включена: каждые %g мин", INTERVAL_MIN)
    while True:
        try:
            # Первый прогон с задержкой: на старте экспортёры могут ещё
            # подниматься, и жаловаться на них рано
            await asyncio.sleep(INTERVAL_MIN * 60)
            await run_and_report()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Самопроверка не выполнена: %s", exc)


def fmt_selfcheck(data: dict) -> str:
    lines = ["## Самопроверка агента", "",
             "  " + ("Всё работает." if data["ok"]
                     else "Не работает: " + ", ".join(data["broken"])), ""]
    for item in data["checks"]:
        lines.append("  [%s] %-28s %s" % ("ок " if item["ok"] else "СБОЙ",
                                          item["name"], item["detail"]))
        if item.get("fix") and not item["ok"]:
            lines.append("       " + item["fix"])
    return "\n".join(lines)
