"""
Разбор логов АСР Lanbilling.

Логи ядра мы уже читаем, но читать их глазами бесполезно: за два часа
набегают десятки тысяч строк, и среди них одна и та же ошибка повторяется
сотни раз. Человек видит стену текста и делает вывод по последним двадцати
строкам, которые попались на глаза.

Здесь строки сворачиваются в образцы: числа, адреса, идентификаторы
заменяются на метки, и «ошибка соединения 12345», «ошибка соединения 12346»
и ещё четыреста таких становятся одной записью с числом повторов. Это тот же
приём, которым pt-query-digest сворачивает запросы, и работает он ровно по
той же причине: важна не отдельная строка, а то, сколько раз она случилась и
когда началась.

Чего здесь сознательно нет: знания о внутренностях Lanbilling — таблицах,
процессах, кодах возврата. Ими агент не располагает, и выдумывать их значит
уверенно врать. Зато есть то, что видно в любом логе биллинга: всплески
ошибок, их классы (база недоступна, дедлок, таймаут, нет места) и время
начала — по нему уже можно идти в метрики и сопоставлять.
"""
from __future__ import annotations

import datetime
import logging
import re
from collections import Counter, defaultdict
from typing import Optional

from agent.services.logs import read_app_log
from agent.services.registry import app_host
from agent.services.ssh import remote_time

logger = logging.getLogger("agent.lanbilling")

# Формат строки ядра:
#   07.09.2026 17:30:01.123456 DEBUG LWP410005 [file:func] текст
# Код и место в скобках встречаются не всегда, поэтому они необязательны.
LINE_RE = re.compile(
    r"^\s*(?P<date>\d{2}\.\d{2}\.\d{4})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r"\s+(?P<level>[A-Z]{3,8})\b"
    r"(?:\s+(?P<code>[A-Z]{2,6}\d{4,9}))?"
    r"(?:\s*\[(?P<where>[^\]]{0,120})\])?"
    r"\s*(?P<text>.*)$")

# Уровни, которые считаем бедой. NOTICE и INFO — обычная жизнь.
BAD_LEVELS = ("ERROR", "ERR", "CRIT", "CRITICAL", "FATAL", "ALERT", "EMERG")
WARN_LEVELS = ("WARN", "WARNING")

# Сколько образцов показываем. Больше десятка не читает никто.
TOP_PATTERNS = 10
SAMPLE_LEN = 220

# Классы бед. Каждый — то, что видно в логе любой системы, работающей с
# MySQL, и о чём агент может сказать, куда идти дальше.
CLASSES = (
    {
        "key": "db_down",
        "name": "Потеря соединения с базой",
        "marks": ("can't connect", "cant connect", "lost connection",
                  "server has gone away", "connection refused",
                  "2002", "2003", "2006", "не удалось подключиться",
                  "соединение с базой", "mysql server"),
        "why": "ядро не смогло дойти до MySQL. Для биллинга это остановка "
               "обслуживания, а не замедление",
        "do": "проверить блок «Память, своп и OOM» (не убило ли ядро mysqld) "
              "и «Запас по ресурсам» — упор в max_connections выглядит так же",
    },
    {
        "key": "deadlock",
        "name": "Взаимные блокировки",
        "marks": ("deadlock", "lock wait timeout", "дедлок",
                  "ожидание блокировки"),
        "why": "две транзакции ждут друг друга; MySQL убивает одну из них, и "
               "для приложения это ошибка записи",
        "do": "открыть «Диагностика Performance Schema» — там ожидания "
              "блокировок и кто кого держит",
    },
    {
        "key": "timeout",
        "name": "Таймауты",
        "marks": ("timeout", "timed out", "таймаут", "истекло время"),
        "why": "запрос или внешний вызов не уложился в отведённое время",
        "do": "посмотреть «Что нагружает базу»: план долгого запроса агент "
              "строит сам прямо на работающем соединении",
    },
    {
        "key": "memory",
        "name": "Нехватка памяти",
        "marks": ("out of memory", "bad_alloc", "cannot allocate",
                  "не хватает памяти", "недостаточно памяти"),
        "why": "процессу не хватило памяти. Дальше обычно вмешивается ядро "
               "системы и убивает самый крупный процесс",
        "do": "блок «Память, своп и OOM» — там же видно, кого убивало ядро",
    },
    {
        "key": "disk",
        "name": "Нет места на диске",
        "marks": ("no space left", "disk full", "нет места",
                  "недостаточно места"),
        "why": "запись не проходит. У биллинга это потеря начислений, а не "
               "только ошибка в логе",
        "do": "блок «Запас по ресурсам»: там срок, через который место "
              "кончится, а не только текущая занятость",
    },
    {
        "key": "auth",
        "name": "Отказ в доступе",
        "marks": ("access denied", "authentication failed", "permission denied",
                  "отказано в доступе", "неверный пароль"),
        "why": "учётка отвергнута. Часто следствие плановой смены паролей, о "
               "которой не знали все стороны",
        "do": "проверить учётки в clusters.json и права на стороне MySQL",
    },
    {
        "key": "license",
        "name": "Лицензия",
        "marks": ("license", "лиценз"),
        "why": "ограничение лицензии останавливает обслуживание так же "
               "надёжно, как авария",
        "do": "вопрос к поставщику АСР, метриками не решается",
    },
    {
        "key": "external",
        "name": "Внешние системы",
        "marks": ("radius", "no response from", "no answer", "нет ответа",
                  "unreachable", "недоступен"),
        "why": "не ответила смежная система — RADIUS, шлюз оплаты, внешний "
               "сервис",
        "do": "беда не в базе: проверять сеть и сам смежный сервис",
    },
)


def plural(count: int, one: str, few: str, many: str) -> str:
    """«1 строка», «3 строки», «12 строк». Отчёт читают люди."""
    count = abs(int(count))
    if count % 10 == 1 and count % 100 != 11:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def template(text: str) -> str:
    """Свернуть строку в образец: без чисел, адресов и идентификаторов.

    «connection 12345 to 10.0.0.7 failed» и «connection 12346 to 10.0.0.8
    failed» — одна и та же беда, случившаяся дважды. Считать их разными
    значит утонуть в четырёхстах одинаковых строках.
    """
    out = str(text or "").strip()
    out = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<адрес>", out)
    out = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<идентификатор>", out)
    out = re.sub(r"'[^']*'|\"[^\"]*\"", "<значение>", out)
    out = re.sub(r"\b\d+\b", "<N>", out)
    out = re.sub(r"\s+", " ", out)
    return out[:300]


def classify(text: str) -> Optional[dict]:
    """К какому классу бед относится строка. Пусто — к известным не относится."""
    low = str(text or "").lower()
    for item in CLASSES:
        if any(mark in low for mark in item["marks"]):
            return item
    return None


def parse(log_text: str) -> list:
    """Разобрать строки лога. Неразобранные не выбрасываем, а считаем."""
    parsed, unparsed = [], 0
    for line in str(log_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        found = LINE_RE.match(line)
        if not found:
            unparsed += 1
            continue
        got = found.groupdict()
        try:
            when = datetime.datetime.strptime(
                got["date"] + " " + got["time"], "%d.%m.%Y %H:%M:%S")
        except ValueError:
            unparsed += 1
            continue
        parsed.append({
            "when": when,
            "level": (got["level"] or "").upper(),
            "code": got["code"] or "",
            "where": got["where"] or "",
            "text": got["text"] or "",
        })
    return parsed, unparsed


def analyse(log_text: str) -> dict:
    """Что в логе есть: уровни, образцы бед, всплески, классы."""
    records, unparsed = parse(log_text)
    if not records:
        return {"records": 0, "unparsed": unparsed}

    levels = Counter(r["level"] for r in records)
    troubles = [r for r in records
                if r["level"] in BAD_LEVELS or r["level"] in WARN_LEVELS]

    # Образцы: одна беда — одна строка отчёта, с числом повторов
    groups = defaultdict(lambda: {"count": 0, "first": None, "last": None,
                                  "sample": "", "code": "", "level": ""})
    for r in troubles:
        key = (r["level"], r["code"], template(r["text"]))
        item = groups[key]
        item["count"] += 1
        item["first"] = item["first"] or r["when"]
        item["last"] = r["when"]
        item["level"] = r["level"]
        item["code"] = r["code"]
        if not item["sample"]:
            item["sample"] = r["text"][:SAMPLE_LEN]

    patterns = sorted(groups.values(), key=lambda g: -g["count"])[:TOP_PATTERNS]

    # Всплеск: минута с наибольшим числом бед. По ней и идут в метрики
    by_minute = Counter(r["when"].replace(second=0) for r in troubles)
    peak = by_minute.most_common(1)[0] if by_minute else (None, 0)

    # Классы: сколько строк каждого рода
    found_classes = defaultdict(int)
    for r in troubles:
        item = classify(r["text"])
        if item:
            found_classes[item["key"]] += 1

    return {
        "records": len(records),
        "unparsed": unparsed,
        "levels": dict(levels),
        "troubles": len(troubles),
        "errors": sum(levels.get(l, 0) for l in BAD_LEVELS),
        "warnings": sum(levels.get(l, 0) for l in WARN_LEVELS),
        "patterns": patterns,
        "peak_minute": peak[0],
        "peak_count": peak[1],
        "classes": dict(found_classes),
        "from": records[0]["when"],
        "to": records[-1]["when"],
    }


async def collect(cluster: dict, hours: float = 2.0,
                  filter_text: str = "") -> dict:
    """Прочитать лог ядра за период и разобрать его."""
    host = app_host(cluster)
    if not host:
        return {"error": "У кластера не указан сервер ядра системы (app_ip)"}
    if not (cluster.get("app_log_dirs") or "").strip():
        return {"error": "Не указаны каталоги логов ядра (app_log_dirs) — "
                         "читать нечего"}

    moment = await remote_time(host)
    if moment is None:
        return {"error": "Сервер ядра %s не отвечает по SSH" % host}

    until_epoch = moment["epoch"]
    since_epoch = until_epoch - hours * 3600
    local_until = moment["local"]
    local_since = local_until - datetime.timedelta(hours=hours)

    text = await read_app_log(cluster, host, local_since, local_until,
                              filter_text, since_epoch, until_epoch)
    data = analyse(text)
    data["host"] = host
    data["hours"] = hours
    data["raw"] = text
    return data


def fmt_report(data: dict, label: str) -> str:
    """Отчёт: сначала беды и когда началось, потом кто повторяется."""
    if data.get("error"):
        return "## АСР Lanbilling — %s\n\n  %s" % (label, data["error"])

    if not data.get("records"):
        return ("## АСР Lanbilling — %s\n\n"
                "  За период в логе ядра нет ни одной строки известного "
                "формата.\n"
                "  Либо в этот период ничего не писалось, либо формат другой "
                "— агент ждёт\n"
                "  строки вида «07.09.2026 17:30:01.123456 DEBUG LWP410005 "
                "[файл:функция] текст»." % label)

    lines = ["## АСР Lanbilling — %s (%s)" % (label, data.get("host", "")), ""]
    lines.append("  Разобрано строк: %d за %g ч, с %s по %s."
                 % (data["records"], data.get("hours", 0),
                    data["from"].strftime("%d.%m %H:%M"),
                    data["to"].strftime("%d.%m %H:%M")))
    if data.get("unparsed"):
        lines.append("  Не разобрано строк: %d — это продолжения многострочных "
                     "записей и вывод сторонних модулей." % data["unparsed"])

    if not data.get("troubles"):
        lines.append("")
        lines.append("  Ошибок и предупреждений за период нет. Если жалуются "
                     "на работу АСР,")
        lines.append("  причина не в ядре: смотрите базу и сеть.")
        return "\n".join(lines)

    lines.append("  Ошибок: %d, предупреждений: %d."
                 % (data.get("errors", 0), data.get("warnings", 0)))
    if data.get("peak_minute") is not None and data.get("peak_count", 0) > 1:
        lines.append("  Всплеск: %d за минуту в %s — с неё и начинайте "
                     "сопоставление с метриками."
                     % (data["peak_count"],
                        data["peak_minute"].strftime("%d.%m %H:%M")))

    if data.get("classes"):
        lines += ["", "  Что именно происходит:"]
        known = {c["key"]: c for c in CLASSES}
        for key, count in sorted(data["classes"].items(), key=lambda kv: -kv[1]):
            item = known.get(key)
            if not item:
                continue
            lines.append("    %s — %d %s"
                         % (item["name"], count,
                            plural(count, "строка", "строки", "строк")))
            lines.append("        %s" % item["why"])
            lines.append("        куда смотреть: %s" % item["do"])

    lines += ["", "  Повторяющиеся записи (свёрнуты по образцу):"]
    for i, p in enumerate(data.get("patterns") or [], 1):
        when = ""
        if p.get("first") and p.get("last"):
            when = (" в %s" % p["first"].strftime("%H:%M")
                    if p["first"] == p["last"]
                    else " с %s до %s" % (p["first"].strftime("%H:%M"),
                                          p["last"].strftime("%H:%M")))
        lines.append("  %d. %s%s — %d %s%s"
                     % (i, p["level"], (" " + p["code"]) if p["code"] else "",
                        p["count"],
                        plural(p["count"], "раз", "раза", "раз"), when))
        lines.append("       " + " ".join(p["sample"].split())[:SAMPLE_LEN])
    return "\n".join(lines)
