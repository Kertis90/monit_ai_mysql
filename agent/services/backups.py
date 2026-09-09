"""
Снимаются ли резервные копии баз.

Свою базу агент бэкапит сам, а вот следит ли кто-то за копиями самих СУБД —
вопрос, на который обычно отвечают «наверное, снимаются». Проверить
восстановимость автоматически нельзя, а вот заметить «копий нет уже неделю»
или «вчерашняя вдвое меньше позавчерашней» — можно, и этого достаточно, чтобы
не обнаружить пропажу в день, когда копия понадобится.

Каталог задаётся у кластера полем backup_dir. Не задан — проверка молчит: не
у всех копии лежат на самих серверах БД.
"""
from __future__ import annotations

import datetime
import logging
import shlex
from typing import Optional

from agent.services.registry import cluster_hosts
from agent.services.ssh import log_ssh

logger = logging.getLogger("agent.backups")

# Суточные копии плюс запас на длительное снятие
DEFAULT_MAX_AGE_H = 26
# Насколько копия может похудеть относительно предыдущей, прежде чем это
# станет подозрительным. База растёт, поэтому уменьшение — сигнал, что дамп
# оборвался на середине.
SHRINK_LIMIT = 0.7


def _cfg(cluster: dict, key: str, default):
    value = cluster.get(key)
    return value if value not in (None, "") else default


async def check(cluster: dict) -> dict:
    """Возраст и размер последних копий на серверах кластера."""
    directory = str(_cfg(cluster, "backup_dir", "")).strip()
    if not directory:
        return {"configured": False,
                "note": "Каталог копий не задан. Укажите backup_dir у кластера "
                        "в clusters.json, если копии лежат на серверах БД."}

    pattern = str(_cfg(cluster, "backup_pattern", "*.gz")).strip()
    max_age = float(_cfg(cluster, "backup_max_age_hours", DEFAULT_MAX_AGE_H))
    cmd = ("find " + shlex.quote(directory) + " -maxdepth 1 -type f -name "
           + shlex.quote(pattern) + r" -printf '%T@ %s %p\n' 2>/dev/null"
           + " | sort -rn | head -10")

    hosts = []
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    for ip, role in cluster_hosts(cluster):
        ok, text = await log_ssh(ip, cmd)
        if not ok:
            hosts.append({"host": ip, "role": role, "ok": False,
                          "problem": "сервер не отвечает по SSH: " + text[:120]})
            continue

        files = []
        for line in text.splitlines():
            bits = line.strip().split(" ", 2)
            if len(bits) != 3:
                continue
            try:
                files.append({"mtime": float(bits[0]), "size": int(bits[1]),
                              "path": bits[2]})
            except ValueError:
                continue

        if not files:
            hosts.append({"host": ip, "role": role, "ok": False,
                          "problem": "в %s нет файлов по маске %s"
                                     % (directory, pattern)})
            continue

        newest = files[0]
        age_h = (now - newest["mtime"]) / 3600
        problems = []
        if age_h > max_age:
            problems.append("последняя копия старше %.0f ч (сделана %.1f ч назад)"
                            % (max_age, age_h))
        if len(files) > 1:
            previous = files[1]
            if previous["size"] and newest["size"] < previous["size"] * SHRINK_LIMIT:
                problems.append(
                    "последняя копия %.1f МБ против %.1f МБ у предыдущей — "
                    "похоже, снятие оборвалось"
                    % (newest["size"] / 1048576, previous["size"] / 1048576))
        if newest["size"] < 1024:
            problems.append("размер последней копии %d байт — она пустая"
                            % newest["size"])

        hosts.append({
            "host": ip, "role": role, "ok": not problems,
            "dir": directory, "count": len(files),
            "newest": newest["path"],
            "age_hours": round(age_h, 1),
            "size_mb": round(newest["size"] / 1048576, 1),
            "problem": "; ".join(problems),
        })

    return {"configured": True, "cluster": cluster["name"],
            "max_age_hours": max_age, "hosts": hosts,
            "ok": all(h["ok"] for h in hosts) if hosts else False}


def fmt_backups(data: dict, label: str) -> str:
    if not data.get("configured"):
        return "## Резервные копии — %s\n\n  %s" % (label, data.get("note", ""))

    lines = ["## Резервные копии — %s" % label, ""]
    for host in data["hosts"]:
        if not host["ok"] and "problem" in host and "count" not in host:
            lines.append("  %s (%s): %s" % (host["host"], host["role"],
                                            host["problem"]))
            continue
        lines.append("  %s (%s): %s" % (host["host"], host["role"],
                                        "в порядке" if host["ok"] else "ЕСТЬ ПРОБЛЕМЫ"))
        lines.append("      последняя: %s, %.1f МБ, сделана %.1f ч назад "
                     "(всего копий: %d)"
                     % (host["newest"], host["size_mb"], host["age_hours"],
                        host["count"]))
        if host["problem"]:
            lines.append("      ! " + host["problem"])
    lines.append("")
    lines.append("  Проверяется только наличие и размер. Восстановимость этим "
                 "не подтверждается: тестовое восстановление всё равно надо "
                 "делать руками и регулярно.")
    return "\n".join(lines)
