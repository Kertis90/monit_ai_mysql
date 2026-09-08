"""
Чтение slow-логов MySQL и логов ядра системы.

Файл целиком не читается никогда: сначала stat по каталогам, потом выбор
нужных файлов по времени изменения, потом grep с ограничением по строкам.
Архивы читаются zgrep напрямую — распаковывать на диск не нужно.

Период приводится ко времени того сервера, с которого читаем: пояса
различаются, и смешивать их значит грепать не те даты.
"""
from __future__ import annotations

import datetime
import logging
import os
import shlex
from typing import Optional

from agent.core.config import settings
from agent.services.registry import slow_log_archive, slow_log_path
from agent.services.ssh import log_ssh, remote_now, remote_time

logger = logging.getLogger("agent.logs")

LOG_MAX_LINES   = settings.log_max_lines
LOG_SSH_TIMEOUT = settings.ssh.timeout

LOG_KEYWORDS = (
    "лог", "логи", "логе", "логах", "slow log", "slow-лог", "слоу", "журнал",
    "lanbilling", "ланбиллинг", "биллинг",
)


def log_pick_files(files: list, since_epoch: float, until_epoch: float,
                   limit: int = 4) -> list:
    """Какие файлы могли содержать нужный период.

    Границы — Unix-время: mtime тоже в нём, и часовой пояс сервера на
    сравнение не влияет.

    Берём все файлы, изменённые внутри окна, плюс ОДИН последний, изменённый
    до его начала: логи ротируются по размеру, и запись за начало периода
    часто оказывается в предыдущем файле.
    """
    inside = [f for f in files if since_epoch <= f["mtime"] <= until_epoch + 3600]
    before = sorted([f for f in files if f["mtime"] < since_epoch],
                    key=lambda f: -f["mtime"])[:1]
    picked = inside + before
    return sorted(picked, key=lambda f: -f["mtime"])[:limit]


def log_date_patterns(since, until, extra_utc=False) -> list:
    """Шаблоны дат для grep -F.

    Формат метки зависит от того, кто пишет лог, поэтому отдаём все
    распространённые виды:

      2026-09-07   ISO — slow-лог MySQL 5.7+, syslog, большинство сервисов
      260907       старый формат MySQL (5.6 и раньше)
      07.09.2026   логи приложения Lanbilling:
                   «07.09.2026 17:30:01.123456 DEBUG LWP410005 [file:func] текст»
      07/09/2026   встречается в веб-серверах и части приложений

    extra_utc — добавить те же даты по UTC. Нужно для slow-лога: начиная
    с MySQL 5.7.2 переменная log_timestamps по умолчанию UTC, то есть метки
    в нём могут отличаться от локального времени сервера. На границе суток
    без этого можно промахнуться на день.
    """
    days, day = [], since.replace(hour=0, minute=0, second=0, microsecond=0)
    while day <= until and len(days) < 8:
        days.append(day)
        day += datetime.timedelta(days=1)

    if extra_utc:
        # смещение сервера неизвестно этой функции, поэтому просто добавляем
        # соседние сутки: разница поясов никогда не больше 14 часов
        edge = [days[0] - datetime.timedelta(days=1),
                days[-1] + datetime.timedelta(days=1)]
        days = edge[:1] + days + edge[1:]

    pats = []
    for d in days:
        pats.append(d.strftime("%Y-%m-%d"))    # 2026-09-07
        pats.append(d.strftime("%y%m%d"))      # 260907
        pats.append(d.strftime("%d.%m.%Y"))    # 07.09.2026
        pats.append(d.strftime("%d/%m/%Y"))    # 07/09/2026
    # порядок сохраняем, дубли убираем
    seen, out = set(), []
    for p in pats:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def log_reader_cmd(path: str, args: str) -> str:
    """Команда чтения под формат файла.

    Сжатые логи читаем zgrep — он работает с .gz напрямую, распаковывать
    файл на диск не нужно.
    """
    q = shlex.quote(path)
    if path.lower().endswith(".gz"):
        return "LC_ALL=C zgrep -a -F " + args + " " + q + " 2>/dev/null"
    # LC_ALL=C — grep по байтам вместо UTF-8: на гигабайтных файлах
    # это ускоряет поиск в несколько раз
    return "LC_ALL=C grep -a -F " + args + " " + q + " 2>/dev/null"


async def log_grep(host: str, path: str, patterns: list,
                   extra: str = "", max_lines: int = 0) -> tuple:
    """grep по файлу с ограничением вывода — файл целиком не читаем."""
    max_lines = max_lines or LOG_MAX_LINES
    args = " ".join("-e " + shlex.quote(p) for p in patterns)
    cmd = log_reader_cmd(path, args)
    if extra:
        # дополнительный фильтр тоже фиксированной строкой, не регуляркой
        cmd += " | grep -a -F -i " + shlex.quote(extra)
    cmd += " | tail -n " + str(int(max_lines))
    return await log_ssh(host, cmd)


async def log_list_files(host: str, dirs: list, pattern: str) -> list:
    """Файлы логов на сервере: путь, размер, время изменения. Свежие первыми.

    Одним find по всем каталогам сразу: текущий и архивный лог ищутся по одной
    маске, а лишний SSH-заход на каждый каталог только замедлил бы ответ.
    Несуществующий каталог даёт код 1 — он в списке допустимых, остальные
    каталоги при этом обрабатываются.
    """
    if not dirs:
        return []
    where = " ".join(shlex.quote(d) for d in dirs)
    cmd = ("find " + where + " -maxdepth 1 -type f -name "
           + shlex.quote(pattern)
           + r" -printf '%T@ %s %p\n' 2>/dev/null")
    ok, text = await log_ssh(host, cmd)
    if not ok:
        return []
    files = []
    for line in text.splitlines():
        bits = line.strip().split(" ", 2)
        if len(bits) != 3:
            continue
        try:
            files.append({"mtime": float(bits[0]), "size": int(bits[1]),
                          "path": bits[2]})
        except ValueError:
            continue          # мусор в выводе find игнорируем молча
    return sorted(files, key=lambda f: -f["mtime"])


async def read_log_group(host: str, dirs: list, pattern: str, since, until,
                         title: str, extra: str = "", hint: str = "",
                         since_epoch: float = 0, until_epoch: float = 0,
                         utc_dates: bool = False) -> str:
    """Общий путь чтения: stat -> выбор файлов по времени -> grep.

    Одинаково работает и для slow-лога, и для логов приложения: оба
    ротируются, и нужный кусок может оказаться в архиве.
    """
    files = await log_list_files(host, dirs, pattern)
    if not files:
        return ("### " + title + " " + host + "\n"
                "  В каталогах " + ", ".join(dirs) +
                " файлов по маске " + pattern + " нет.")

    # Выбор по абсолютному времени: mtime не зависит от пояса сервера
    picked = log_pick_files(files, since_epoch or since.timestamp(),
                            until_epoch or until.timestamp())
    if not picked:
        newest = datetime.datetime.fromtimestamp(files[0]["mtime"])
        return ("### " + title + " " + host + "\n"
                "  Файлов за этот период нет. Всего найдено {}, самый свежий "
                "изменён {:%Y-%m-%d %H:%M}.".format(len(files), newest))

    out = ["### " + title + " " + host,
           "  Просмотрено файлов: {} из {} (выбраны по времени изменения)"
           .format(len(picked), len(files))]
    per_file = max(LOG_MAX_LINES // len(picked), 40)
    found_any = False
    for f in picked:
        mt = datetime.datetime.fromtimestamp(f["mtime"])
        out.append("  {} — {:.1f} МБ, изменён {:%Y-%m-%d %H:%M}"
                   .format(f["path"], f["size"] / 1048576, mt))
        ok, text = await log_grep(host, f["path"],
                                  log_date_patterns(since, until, utc_dates),
                                  extra, per_file)
        lines = [l for l in text.splitlines() if l.strip()] if ok else []
        if not ok:
            out.append("      не прочитан: " + text[:120])
        elif not lines:
            out.append("      совпадений за период нет")
        else:
            found_any = True
            out += ["      " + l[:300] for l in lines]
    if not found_any and hint:
        out.append("  " + hint)
    return "\n".join(out)


def log_dir_and_pattern(path: str) -> tuple:
    """Из пути к текущему логу — каталог и маска с учётом ротации.

    /var/log/mysql/slow.log -> ('/var/log/mysql', 'slow.log*'), чтобы
    подхватились slow.log.1, slow.log-20260907.gz и прочие ротированные.
    """
    path = path.strip().rstrip("/")
    directory = os.path.dirname(path) or "/var/log"
    base = os.path.basename(path) or "slow.log"
    return directory, base + "*"


async def read_slow_log(cluster: dict, host: str, since, until,
                        extra: str = "",
                        since_epoch: float = 0, until_epoch: float = 0) -> str:
    """Slow-лог MySQL за период. Ротированные файлы тоже просматриваются."""
    raw = slow_log_path(cluster, host)
    directory, pattern = log_dir_and_pattern(raw)
    dirs = [directory]
    # архив slow-лога может лежать в отдельном каталоге
    arch = slow_log_archive(cluster, host)
    if arch and arch not in dirs:
        dirs.append(arch)
    return await read_log_group(
        host, dirs, pattern, since, until, "Slow-лог", extra,
        utc_dates=True,
        hint="Записей за период нет. Возможно, slow_query_log выключен "
             "или long_query_time слишком велик.",
        since_epoch=since_epoch, until_epoch=until_epoch)


async def read_app_log(cluster: dict, host: str, since, until,
                       extra: str = "",
                       since_epoch: float = 0, until_epoch: float = 0) -> str:
    """Логи ядра системы: текущие и архивные, включая tar.gz.

    host здесь — сервер ядра (app_ip), а не сервер БД: приложение пишет свои
    логи у себя.
    """
    dirs = [d.strip() for d in (cluster.get("app_log_dirs") or "").split(",")
            if d.strip()]
    if not dirs:
        return ""
    pattern = (cluster.get("app_log_pattern") or "*.log*").strip()
    return await read_log_group(host, dirs, pattern, since, until,
                                "Логи приложения", extra,
                                since_epoch=since_epoch,
                                until_epoch=until_epoch)


def detect_log_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in LOG_KEYWORDS)
