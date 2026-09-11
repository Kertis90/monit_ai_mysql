"""
Память, своп и OOM.

Самый неприятный вид аварии базы — тот, где база ни при чём. Ядро
выбирает самый жирный процесс и убивает его; для сервера БД это всегда
mysqld. В метриках такое видно косвенно: занятость памяти за секунду до
смерти, потом провал и рост подключений, — а причина остаётся в
kernel-логе, куда никто не смотрит, потому что смотрят в MySQL.

Своп отдельно от памяти: занятый своп сам по себе не беда — Linux может
годами держать там страницы, к которым не обращались. Беда — активная
подкачка: страницы ездят туда-обратно, и каждая обходится в дисковый
доступ там, где ожидался доступ к памяти. Поэтому смотрим не «сколько
занято», а pswpin/pswpout — сколько страниц переехало за период.

Данные берём из двух источников, потому что каждый по отдельности врёт:
node_exporter знает скорость и объёмы, но не знает, кого убили; kernel-лог
знает имя и время, но ничего не знает о том, что было до.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from agent.services.prometheus import http_client, prom_query
from agent.services.registry import app_host, cluster_hosts
from agent.services.ssh import log_ssh

logger = logging.getLogger("agent.memory")

# За какой период считаем подкачку. Час — чтобы разовый всплеск при
# ночном бэкапе не выглядел как постоянная беда.
RATE_WINDOW = "1h"

# Сколько строк kernel-лога забираем. Одно событие OOM — это десяток
# строк с таблицей процессов; нам нужны только строки с приговором.
OOM_LINES = 25

# Команды пробуем по очереди: dmesg на новых ядрах закрыт для обычного
# пользователя (kernel.dmesg_restrict), journalctl доступен тем, кто в
# группе systemd-journal или adm. Где-то работает одно, где-то другое.
OOM_COMMANDS = (
    ("dmesg -T 2>/dev/null | LC_ALL=C grep -iE "
     "'out of memory|oom-killer|killed process' | tail -n %d" % OOM_LINES),
    ("journalctl -k --no-pager --since '-7 days' 2>/dev/null | LC_ALL=C grep -iE "
     "'out of memory|oom-killer|killed process' | tail -n %d" % OOM_LINES),
    ("LC_ALL=C grep -hiE 'out of memory|oom-killer|killed process' "
     "/var/log/messages /var/log/syslog 2>/dev/null | tail -n %d" % OOM_LINES),
)


def _gb(value) -> float:
    try:
        return round(float(value) / 1073741824, 2)
    except (TypeError, ValueError):
        return 0.0


async def host_memory(ip: str) -> dict:
    """Память и своп одного сервера по метрикам node_exporter."""
    node = "%s:9100" % ip
    async with http_client() as client:
        total, avail, sw_total, sw_free, pin, pout, oom = await asyncio.gather(
            prom_query(client, 'node_memory_MemTotal_bytes{instance="%s"}' % node),
            prom_query(client, 'node_memory_MemAvailable_bytes{instance="%s"}' % node),
            prom_query(client, 'node_memory_SwapTotal_bytes{instance="%s"}' % node),
            prom_query(client, 'node_memory_SwapFree_bytes{instance="%s"}' % node),
            # Скорость подкачки, а не её объём: важно движение, а не остаток
            prom_query(client, 'rate(node_vmstat_pswpin{instance="%s"}[%s])'
                               % (node, RATE_WINDOW)),
            prom_query(client, 'rate(node_vmstat_pswpout{instance="%s"}[%s])'
                               % (node, RATE_WINDOW)),
            # Счётчик убийств ядром. Есть не во всех сборках node_exporter,
            # поэтому его отсутствие — не повод считать, что OOM не было
            prom_query(client, 'increase(node_vmstat_oom_kill{instance="%s"}[24h])'
                               % node))

    if total is None:
        return {"host": ip, "error": "метрик node_exporter по %s нет" % node}

    used_pct = None
    if avail is not None and total:
        used_pct = round((1 - avail / total) * 100, 1)

    swap_used_pct = None
    if sw_total and sw_free is not None:
        swap_used_pct = round((1 - sw_free / sw_total) * 100, 1)

    return {
        "host": ip,
        "total_gb": _gb(total),
        "available_gb": _gb(avail) if avail is not None else None,
        "used_pct": used_pct,
        "swap_total_gb": _gb(sw_total) if sw_total else 0.0,
        "swap_used_pct": swap_used_pct,
        # Страниц в секунду; страница — 4 КиБ
        "swap_in_s": round(pin, 2) if pin is not None else None,
        "swap_out_s": round(pout, 2) if pout is not None else None,
        "oom_kills_24h": int(oom) if oom else 0,
        "oom_counter": oom is not None,
    }


async def host_oom_log(ip: str) -> dict:
    """Следы OOM в журнале ядра. Кого именно убили и когда."""
    for command in OOM_COMMANDS:
        ok, out = await log_ssh(ip, command)
        if not ok:
            continue
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        if lines:
            killed = []
            for line in lines:
                # «Killed process 12345 (mysqld) total-vm:…»
                found = re.search(r"[Kk]illed process\s+(\d+)\s+\(([^)]+)\)", line)
                if found:
                    killed.append(found.group(2))
            return {"host": ip, "lines": lines[-OOM_LINES:],
                    "killed": sorted(set(killed))}
    return {"host": ip, "lines": [], "killed": []}


async def collect(cluster: dict) -> dict:
    """Память, своп и OOM по всем серверам кластера, включая ядро системы."""
    hosts = [(ip, role) for ip, role in cluster_hosts(cluster)]
    app = app_host(cluster)
    if app and app not in [ip for ip, _ in hosts]:
        hosts.append((app, "ядро"))

    metrics, logs = await asyncio.gather(
        asyncio.gather(*[host_memory(ip) for ip, _ in hosts]),
        asyncio.gather(*[host_oom_log(ip) for ip, _ in hosts]))

    items = []
    for (ip, role), mem, oom in zip(hosts, metrics, logs):
        items.append({**mem, "role": role, "oom_log": oom})
    return {"cluster": cluster["name"], "items": items}


def fmt_memory(data: dict, label: str) -> str:
    """Отчёт по памяти. Пишем и то, чего не нашли, — «следов OOM нет» это
    тоже ответ, и он снимает подозрение, а не оставляет его висеть."""
    lines = ["## Память, своп и OOM — %s" % label, ""]

    for item in data.get("items") or []:
        head = "  %s (%s)" % (item["host"], item.get("role", ""))
        if item.get("error"):
            lines.append(head + ": " + item["error"])
            lines.append("")
            continue

        used = ("занято %.0f%% из %.1f ГБ" % (item["used_pct"], item["total_gb"])
                if item.get("used_pct") is not None
                else "%.1f ГБ всего" % item["total_gb"])
        lines.append(head + ": " + used)

        if not item.get("swap_total_gb"):
            lines.append("      Свопа нет. Значит, при нехватке памяти ядро "
                         "сразу убивает процесс, а не замедляет его.")
        else:
            swap = "      Своп %.1f ГБ" % item["swap_total_gb"]
            if item.get("swap_used_pct") is not None:
                swap += ", занято %.0f%%" % item["swap_used_pct"]
            lines.append(swap)
            moving = max(item.get("swap_in_s") or 0, item.get("swap_out_s") or 0)
            if moving > 1:
                lines.append("      ПОДКАЧКА ИДЁТ ПРЯМО СЕЙЧАС: %.1f стр/с внутрь, "
                             "%.1f наружу. Каждое такое обращение — поход на диск "
                             "там, где ожидалась память."
                             % (item.get("swap_in_s") or 0,
                                item.get("swap_out_s") or 0))
            elif item.get("swap_used_pct"):
                lines.append("      Активной подкачки нет: занятый своп сам по "
                             "себе не мешает, там лежат давно не нужные страницы.")

        if item.get("oom_kills_24h"):
            lines.append("      ЯДРО УБИВАЛО ПРОЦЕССЫ: %d раз за сутки (счётчик "
                         "node_exporter)." % item["oom_kills_24h"])

        oom = item.get("oom_log") or {}
        if oom.get("killed"):
            lines.append("      В журнале ядра убиты: %s"
                         % ", ".join(oom["killed"]))
            for line in oom["lines"][-4:]:
                lines.append("        " + line[:220])
        elif oom.get("lines"):
            lines.append("      В журнале ядра есть записи о нехватке памяти:")
            for line in oom["lines"][-4:]:
                lines.append("        " + line[:220])
        else:
            lines.append("      Следов OOM в журнале ядра нет.")
        lines.append("")

    if not data.get("items"):
        lines.append("  Серверы не опрошены.")
    return "\n".join(lines)
