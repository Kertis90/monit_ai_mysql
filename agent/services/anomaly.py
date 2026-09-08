"""
Отклонения от нормы, на которые нет порога.

Алерты ловят пересечение границы: «соединений больше 90%», «реплика отстала».
Но половина настоящих поломок выглядит иначе: запросов вдвое меньше обычного —
значит, отвалилось приложение, а база при этом совершенно здорова и ни один
порог не сработает.

Медианная база сравнения у нас уже есть, но раньше её смотрели только когда
спросят. Здесь она проверяется по расписанию, и заметное расхождение
превращается в такое же событие, как обычный алерт.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from agent.db.base import session_scope
from agent.db.repositories.alerts import AlertRepository
from agent.services.analysis import collect_baseline
from agent.services.prometheus import collect_history
from agent.services.registry import enabled_clusters

logger = logging.getLogger("agent.anomaly")

ENABLED = os.environ.get("ANOMALY_ENABLED", "true").lower() in ("1", "true", "yes")
# Как часто сверяться. Чаще четверти часа смысла нет: база сравнения строится
# по часовым окнам, и шум забьёт полезное.
INTERVAL_MIN = max(15.0, float(os.environ.get("ANOMALY_INTERVAL_MIN", "30")))
# Окно, за которое берём текущее состояние
WINDOW_HOURS = 1.0

# Насколько надо отличаться от нормы, чтобы это стоило внимания.
# Метрики разные: соединения гуляют сильнее, чем поток запросов.
RULES = {
    "qps": {
        "title": "поток запросов",
        "drop": 0.5,   # упал вдвое
        "rise": 3.0,   # вырос втрое
        "min": 5,      # ниже этого сравнивать бессмысленно
        "drop_note": "запросов вдвое меньше обычного для этого часа — похоже, "
                     "перестало ходить приложение, а не база",
        "rise_note": "запросов втрое больше обычного — либо наплыв, либо "
                     "зациклившийся клиент",
    },
    "slow_qps": {
        "title": "медленные запросы",
        "rise": 4.0, "min": 0.2,
        "rise_note": "медленных запросов вчетверо больше обычного",
    },
    "connections_pct": {
        "title": "занятость пула соединений",
        "rise": 2.5, "min": 5,
        "rise_note": "соединений вдвое с лишним больше обычного для этого часа",
    },
    "iowait_pct": {
        "title": "ожидание дисков",
        "rise": 3.0, "min": 3,
        "rise_note": "процессор втрое дольше обычного ждёт диск",
    },
}


def compare(now: dict, base: dict) -> list[dict]:
    """Что заметно отличается от обычного. Чистая функция — её и проверяем."""
    out = []
    for key, rule in RULES.items():
        cur = (now.get(key) or {}).get("avg")
        old = (base.get(key) or {}).get("avg")
        if cur is None or not old:
            continue
        # У маленьких значений относительное отклонение ничего не значит:
        # 0.2 против 0.05 — это «в четыре раза», но никому не интересно
        if max(float(cur), float(old)) < rule["min"]:
            continue
        ratio = float(cur) / float(old)
        if "rise" in rule and ratio >= rule["rise"]:
            out.append({"metric": key, "title": rule["title"], "kind": "rise",
                        "now": round(float(cur), 2), "usual": round(float(old), 2),
                        "ratio": round(ratio, 1), "note": rule["rise_note"]})
        elif "drop" in rule and ratio <= rule["drop"]:
            out.append({"metric": key, "title": rule["title"], "kind": "drop",
                        "now": round(float(cur), 2), "usual": round(float(old), 2),
                        "ratio": round(ratio, 2), "note": rule["drop_note"]})
    return out


async def check(cluster: dict) -> list[dict]:
    """Сверить кластер с его обычным состоянием."""
    try:
        now, base = await asyncio.gather(
            collect_history(cluster, WINDOW_HOURS),
            collect_baseline(cluster, WINDOW_HOURS))
    except Exception as exc:
        logger.error("Сверка %s не выполнена: %s", cluster["name"], exc)
        return []
    if not base.get("weeks"):
        return []          # сравнивать не с чем: истории ещё нет
    return compare(now, base)


async def run_once() -> int:
    """Проверить все кластеры и завести события по находкам."""
    raised = 0
    for cluster in enabled_clusters():
        found = await check(cluster)
        for item in found:
            name = "Отклонение: " + item["title"]
            summary = ("%s: сейчас %s, обычно %s (%sx). %s"
                       % (item["title"], item["now"], item["usual"],
                          item["ratio"], item["note"]))
            async with session_scope() as session:
                repo = AlertRepository(session)
                # Тот же механизм подавления повторов, что и у обычных
                # алертов: отклонение держится часами, а событие нужно одно
                if await repo.is_duplicate(alert=name, cluster=cluster["name"],
                                           instance=cluster["primary_ip"]):
                    continue
                await repo.add(alert=name, cluster=cluster["name"],
                               cluster_label=cluster["label"],
                               instance=cluster["primary_ip"],
                               severity="warning", summary=summary,
                               analysis="", source="anomaly")
            raised += 1
            logger.info("Отклонение %s: %s", cluster["name"], summary)
            try:
                from agent.api.routes.chat import broadcast
                await broadcast({"type": "alert", "alert": name,
                                 "severity": "warning",
                                 "cluster": cluster["label"],
                                 "summary": summary, "source": "anomaly"})
            except Exception:
                pass
    return raised


async def scheduler() -> None:
    logger.info("Сверка с обычным состоянием включена: каждые %g мин", INTERVAL_MIN)
    while True:
        try:
            await asyncio.sleep(INTERVAL_MIN * 60)
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Сверка не выполнена: %s", exc)


def fmt_anomalies(items: list, label: str) -> str:
    if not items:
        return "## Отклонения от обычного — %s\n\n  Всё в пределах нормы." % label
    lines = ["## Отклонения от обычного — %s" % label, ""]
    for i in items:
        lines.append("  %s: сейчас %s, обычно %s (%sx)"
                     % (i["title"], i["now"], i["usual"], i["ratio"]))
        lines.append("      " + i["note"])
    return "\n".join(lines)
