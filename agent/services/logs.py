"""
Чтение slow-логов MySQL и логов ядра системы.

Файл целиком не читается никогда: сначала stat по каталогам, потом выбор
нужных файлов по времени изменения, потом grep с ограничением по строкам.
Архивы читаются zgrep напрямую — распаковывать на диск не нужно.

Период приводится ко времени того сервера, с которого читаем: пояса
различаются, и смешивать их значит грепать не те даты.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os
import shlex
from typing import Optional

from agent.core.config import settings
from agent.services.logscan import (BISECT_MIN_BYTES, bisect_script, date_key,
                                    human_size, take_slice_note)
from agent.services.registry import slow_log_archive, slow_log_path
from agent.services.ssh import log_ssh, remote_now, remote_time

logger = logging.getLogger("agent.logs")

LOG_MAX_LINES    = settings.log_max_lines
LOG_SSH_TIMEOUT  = settings.ssh.timeout
LOG_READ_TIMEOUT = settings.log_read_timeout

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


# До какого окна имеет смысл искать по часам. Дальше шаблонов становится
# больше, чем строк в выводе grep, и проще отобрать по суткам.
HOUR_PATTERN_LIMIT = 26


def log_hour_patterns(since, until) -> list:
    """Шаблоны «дата и час» для grep -F.

    Поиск по одной дате возвращает целые сутки: человек просит логи за два
    часа, а получает всё, что случилось за день, обрезанное по числу строк
    с конца. Здесь в шаблон входит и час — «11.09.2026 09:», — и в выводе
    оказывается именно запрошенное окно.

    Разделитель между датой и часом у разных логов свой: slow-лог MySQL
    5.7+ пишет ISO с «T», syslog и приложения — с пробелом. Отдаём оба.
    """
    hours, point = [], since.replace(minute=0, second=0, microsecond=0)
    while point <= until:
        hours.append(point)
        point += datetime.timedelta(hours=1)
        if len(hours) > HOUR_PATTERN_LIMIT:
            return []          # слишком широкое окно, отбираем по суткам

    out = []
    for h in hours:
        out.append(h.strftime("%Y-%m-%dT%H:"))    # 2026-09-11T09:  slow-лог 5.7+
        out.append(h.strftime("%Y-%m-%d %H:"))    # 2026-09-11 09:  syslog
        out.append(h.strftime("%d.%m.%Y %H:"))    # 11.09.2026 09:  Lanbilling
        out.append(h.strftime("%d/%m/%Y %H:"))    # 11/09/2026 09:
    return out


def log_window_patterns(since, until, since_epoch: float = 0,
                        until_epoch: float = 0, utc_dates: bool = False) -> list:
    """Чем отбирать строки за период. Час, если окно узкое, иначе сутки.

    utc_dates — метки в файле пишутся в UTC, а не в поясе сервера. Так по
    умолчанию делает MySQL 5.7.2+ со своим log_timestamps=UTC: сервер живёт
    во Владивостоке, а в slow-логе стоит время на семь часов назад. Отсюда
    и брались «не те» строки: запрашиваешь последние два часа по местному
    времени, а в файле это время наступит только к вечеру.

    Поэтому для таких файлов окно пересчитывается в UTC — из абсолютного
    времени, которое от пояса не зависит вовсе. Локальные шаблоны при этом
    остаются: в одном каталоге могут лежать логи, писанные и так и так.
    """
    windows = [(since, until)]
    if utc_dates and since_epoch and until_epoch:
        def as_utc(ts):
            # fromtimestamp с явным поясом вместо utcfromtimestamp: та
            # объявлена устаревшей и в 3.12 уже предупреждает
            return (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
                    .replace(tzinfo=None))

        windows.append((as_utc(since_epoch), as_utc(until_epoch)))

    out = []
    for start, end in windows:
        narrow = log_hour_patterns(start, end)
        out += narrow if narrow else log_date_patterns(start, end)

    seen, unique = set(), []
    for pattern in out:
        if pattern not in seen:
            seen.add(pattern)
            unique.append(pattern)
    return unique


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
                   extra: str = "", max_lines: int = 0, size: int = 0,
                   since=None, until=None) -> tuple:
    """grep по файлу с ограничением вывода — файл целиком не читаем.

    На большом файле даже grep слишком долог: 17 ГБ он читает минутами и не
    укладывается ни в какой разумный таймаут. Логи отсортированы по времени,
    поэтому нужный кусок ищется делением файла пополам, и grep'у достаётся
    несколько десятков мегабайт вместо всего файла.

    Сжатые файлы так читать нельзя — в них нет соответствия «смещение ↔
    время», поэтому для .gz остаётся zgrep целиком.
    """
    max_lines = max_lines or LOG_MAX_LINES
    args = " ".join("-e " + shlex.quote(p) for p in patterns)
    # дополнительный фильтр тоже фиксированной строкой, не регуляркой
    extra_cmd = (" | grep -a -F -i " + shlex.quote(extra)) if extra else ""
    tail_cmd = " | tail -n " + str(int(max_lines))

    huge = (size >= BISECT_MIN_BYTES and not path.lower().endswith(".gz")
            and since is not None and until is not None)
    if huge:
        pipeline = "LC_ALL=C grep -a -F " + args + extra_cmd + tail_cmd
        cmd = bisect_script(path, date_key(since), date_key(until), pipeline)
    else:
        cmd = log_reader_cmd(path, args) + extra_cmd + tail_cmd
    return await log_ssh(host, cmd, timeout=LOG_READ_TIMEOUT)


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

    narrow = len(patterns) > 0 and ":" in patterns[0]
    out = ["### " + title + " " + host,
           "  Период: {:%d.%m %H:%M} — {:%d.%m %H:%M} по времени сервера{}"
           .format(since, until,
                   ", метки в файле в UTC — окно пересчитано" if utc_dates else ""),
           "  Отбор по {}; просмотрено файлов: {} из {}"
           .format("дате и часу" if narrow else "дате",
                   len(picked), len(files))]
    per_file = max(LOG_MAX_LINES // len(picked), 40)
    patterns = log_window_patterns(since, until, since_epoch, until_epoch,
                                   utc_dates)

    # Файлы читаем разом, а не по очереди: это независимые команды на одном
    # сервере, и ждать их последовательно значит складывать таймауты
    results = await asyncio.gather(*[
        log_grep(host, f["path"], patterns, extra, per_file,
                 size=f.get("size", 0), since=since, until=until)
        for f in picked])

    found_any = False
    for f, (ok, text) in zip(picked, results):
        mt = datetime.datetime.fromtimestamp(f["mtime"])
        note, text = take_slice_note(text) if ok else ("", text)
        out.append("  {} — {}, изменён {:%Y-%m-%d %H:%M}{}"
                   .format(f["path"], human_size(f["size"]), mt,
                           (" · " + note) if note else ""))
        lines = [l for l in text.splitlines() if l.strip()] if ok else []
        if not ok:
            out.append("      не прочитан: " + text[:200])
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
