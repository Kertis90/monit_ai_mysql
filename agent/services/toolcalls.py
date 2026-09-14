"""
Вызовы инструментов, пришедшие текстом.

Часть моделей не умеет штатный tool calling, но обучена писать вызовы прямо
в ответ. Пользователь при этом видит в чате что-то вроде

    <tool_call><function><parameter=cluster>vladivostok</parameter>
    <parameter=sql>SELECT ...</parameter></function></tool_call>

вместо ответа. Формально модель сделала своё дело — просто её никто не
услышал: агент считал это обычным текстом и показывал как есть.

Здесь такие вызовы вылавливаются из потока, выполняются теми же функциями,
что и штатные, а результат возвращается модели, чтобы она дописала ответ
по данным. Разметка при этом до пользователя не доходит ни при каком
исходе: даже если вызов не разобран, показывать её незачем.

Форматов несколько, и единого стандарта нет, поэтому разбор нарочно
терпимый: понимаются и JSON внутри тега, и разметка с <parameter=имя>, и
вызов вообще без имени функции — по набору параметров видно, что имелось
в виду.
"""
from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger("agent.toolcalls")

# Открывающий тег: по нему же ловим оборванную генерацию
OPEN_TAG = "<tool_call>"

BLOCK_RE = re.compile(r"<tool_call>(.*?)</tool_call>", re.S | re.I)

# Рассуждающие модели пишут ход мысли прямо в ответ. Человек просил
# результат, а не протокол размышлений, — в чат это попадать не должно.
THINK_TAGS = ("think", "thinking", "reasoning", "reflection", "scratchpad",
              "analysis")
_TAGS = "|".join(THINK_TAGS)
THINK_RE = re.compile(r"<(%s)\b[^>]*>.*?</\1\s*>" % _TAGS, re.S | re.I)
THINK_OPEN_RE = re.compile(r"<(?:%s)\b[^>]*>" % _TAGS, re.I)
# Закрывающий тег без открывающего — не поломка, а частый случай: ряд
# провайдеров отдаёт рассуждение без открывающего тега. Тогда рассуждение
# — всё, что было до закрывающего.
THINK_CLOSE_RE = re.compile(r"</(?:%s)\s*>" % _TAGS, re.I)

# Хвост, который ещё может оказаться началом любого тега. Держим его, пока
# не станет ясно: «<th» — это и начало <think>, и начало обычного текста.
TAG_START_RE = re.compile(r"<[/A-Za-z_]*$")

# <function=run_sql> либо <function name="run_sql"> либо <name>run_sql</name>
NAME_RES = (
    re.compile(r"<function\s*=\s*([A-Za-z_][\w]*)", re.I),
    re.compile(r"<function[^>]*\sname\s*=\s*[\"']([A-Za-z_][\w]*)", re.I),
    re.compile(r"<name>\s*([A-Za-z_][\w]*)\s*</name>", re.I),
    re.compile(r"[\"']name[\"']\s*:\s*[\"']([A-Za-z_][\w]*)", re.I),
)

# <parameter=cluster>значение</parameter> и <parameter name="cluster">…
PARAM_RES = (
    re.compile(r"<parameter\s*=\s*([\w.-]+)\s*>(.*?)</parameter>", re.S | re.I),
    re.compile(r"<parameter[^>]*\sname\s*=\s*[\"']([\w.-]+)[\"']\s*>(.*?)</parameter>",
               re.S | re.I),
)

# По каким параметрам узнаётся инструмент, если имя не названо. Порядок
# важен: сначала самые характерные признаки.
BY_PARAMS = (
    ("sql",          "run_sql"),
    ("kind",         "read_logs"),
    ("step_seconds", "get_breakdown"),
    ("seconds",      "get_workload"),
    ("hours",        "get_history"),
    ("cluster",      "get_current_metrics"),
)


def _guess_name(params: dict) -> str:
    """Какой инструмент имелся в виду, если имя не написали."""
    for key, tool in BY_PARAMS:
        if key in params:
            return tool
    return ""


def _parse_block(body: str) -> dict:
    """Один вызов из содержимого тега. Пусто — разобрать не удалось."""
    body = body.strip()

    # Вариант первый: внутри лежит обычный JSON
    if body.startswith("{"):
        try:
            data = json.loads(body)
            args = data.get("arguments") or data.get("parameters") or {}
            if isinstance(args, str):
                args = json.loads(args)
            name = str(data.get("name") or "")
            if not name:
                name = _guess_name(args if isinstance(args, dict) else {})
            if name:
                return {"name": name,
                        "args": args if isinstance(args, dict) else {}}
        except (ValueError, AttributeError):
            pass          # не JSON — разбираем как разметку

    params: dict = {}
    for regex in PARAM_RES:
        for key, value in regex.findall(body):
            params.setdefault(key.strip(), value.strip())

    name = ""
    for regex in NAME_RES:
        found = regex.search(body)
        if found:
            name = found.group(1)
            break
    if not name:
        # Имя функции модель иногда опускает вовсе — узнаём по параметрам
        name = _guess_name(params)
        if name:
            logger.info("Имя инструмента не указано, определено как %s", name)
    if not name:
        return {}
    return {"name": name, "args": params}


def find_calls(text: str) -> list:
    """Все вызовы из текста ответа."""
    calls = []
    for body in BLOCK_RE.findall(text or ""):
        call = _parse_block(body)
        if call:
            calls.append(call)
        else:
            logger.warning("Вызов инструмента не разобран: %s", body[:200])
    return calls


def strip_thinking(text: str) -> str:
    """Убрать рассуждения модели.

    Три случая, и все встречаются. Парный блок вырезаем целиком.
    Закрывающий тег без открывающего означает, что рассуждением было всё
    до него. Открывающий без закрывающего — генерацию прервали посреди
    мысли, показывать её половину незачем.
    """
    text = THINK_RE.sub("", text or "")

    last = None
    for found in THINK_CLOSE_RE.finditer(text):
        last = found
    if last:
        text = text[last.end():].lstrip()

    open_tag = THINK_OPEN_RE.search(text)
    if open_tag:
        text = text[:open_tag.start()]
    return text


def strip_calls(text: str) -> str:
    """Убрать из текста всё, что предназначалось не человеку.

    Незакрытый тег отрезается вместе с хвостом: генерацию могли прервать
    посреди вызова, и показывать половину разметки тем более незачем.
    """
    text = BLOCK_RE.sub("", text or "")
    cut = text.lower().find(OPEN_TAG)
    if cut >= 0:
        text = text[:cut]
    return strip_thinking(text)


class StreamFilter:
    """Поток без разметки вызовов.

    Тег приходит по кускам, поэтому решение «показывать или нет» нельзя
    принять по одному токену: `<to` может оказаться и началом вызова, и
    просто текстом. Придерживаем хвост, пока он похож на начало тега, —
    задержка в несколько символов незаметна, а разметка не мелькает.
    """

    def __init__(self) -> None:
        self.raw = ""
        # Ровно то, что уже ушло человеку: по нему видно, совпадает ли
        # новое начало с показанным или показанное придётся стереть
        self._sent = ""

    def _visible(self, hold: bool) -> str:
        text = strip_calls(self.raw)
        if not hold:
            return text
        # Незакрытый тег придерживаем: «</th» станет ясно через пару токенов
        found = TAG_START_RE.search(text)
        return text[:found.start()] if found else text

    def feed(self, token: str) -> tuple:
        """Добавить токен. Вернуть (что показать, стереть ли показанное).

        Стереть приходится в одном случае: пришёл закрывающий тег
        рассуждения, а открывающего не было. Тогда всё показанное было
        рассуждением, и честнее убрать его, чем оставить висеть над
        ответом.
        """
        self.raw += token
        text = self._visible(hold=True)
        if text.startswith(self._sent):
            out = text[len(self._sent):]
            self._sent = text
            return out, False
        self._sent = text
        return text, True

    def finish(self) -> tuple:
        """Остаток после конца потока."""
        text = self._visible(hold=False)
        if text.startswith(self._sent):
            out = text[len(self._sent):]
            self._sent = text
            return out, False
        self._sent = text
        return text, True

    @property
    def calls(self) -> list:
        return find_calls(self.raw)

    @property
    def clean(self) -> str:
        return self._visible(hold=False)
