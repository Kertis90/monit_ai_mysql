"""
Обращение к модели: обычный вызов, стриминг и работа с инструментами.

Инструменты — основной путь: модель сама решает, какие данные ей нужны.
Список ключевых слов приходилось расширять после каждой новой формулировки,
и «статистика», «детально», «за последний час» промахивались по очереди.

Режим опциональный: не всякий OpenAI-совместимый эндпоинт умеет tool calling.
При LLM_TOOLS=auto делается пробный запрос, и при отказе агент работает по
ключевым словам.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
from typing import AsyncGenerator, Optional

import httpx

from agent.core.config import settings

logger = logging.getLogger("agent.llm")

LLM_BASE_URL    = settings.llm.base_url
LLM_API_KEY     = settings.llm.api_key
LLM_MODEL       = settings.llm.model
LLM_MAX_TOKENS  = settings.llm.max_tokens
LLM_TEMPERATURE = settings.llm.temperature
LLM_TOOLS       = settings.llm.tools
LLM_TOOL_ROUNDS = settings.llm.tool_rounds
LLM_TIMEOUT     = settings.llm.timeout

# Заголовок собираем один раз: ключ задают и с "Bearer", и без него
AUTH_HEADER = (LLM_API_KEY if LLM_API_KEY.startswith("Bearer ")
               else "Bearer " + LLM_API_KEY)

# Умеет ли эндпоинт инструменты. None — ещё не проверяли: проба делается
# один раз при первом вопросе, а не на каждом
TOOLS_SUPPORTED = None


async def llm_probe_tools() -> bool:
    """Поддерживает ли эндпоинт инструменты. Проверяем один раз."""
    global TOOLS_SUPPORTED
    # Внутри функции, а не сверху: assistant импортирует llm, и импорт
    # на уровне модуля замкнул бы кольцо
    from agent.services.assistant import tool_specs
    if TOOLS_SUPPORTED is not None:
        return TOOLS_SUPPORTED
    if LLM_TOOLS == "off":
        TOOLS_SUPPORTED = False
        return False
    if LLM_TOOLS == "on":
        TOOLS_SUPPORTED = True
        return True
    try:
        headers = {"Content-Type": "application/json",
                   "Authorization": AUTH_HEADER}
        payload = {"model": LLM_MODEL, "max_tokens": 16,
                   "messages": [{"role": "user", "content": "ping"}],
                   "tools": tool_specs()[:1]}
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(f"{LLM_BASE_URL}/chat/completions",
                                  headers=headers, json=payload)
        TOOLS_SUPPORTED = r.status_code == 200
    except Exception as e:
        logger.warning(f"Проверка поддержки инструментов не удалась: {e}")
        TOOLS_SUPPORTED = False
    logger.info("Инструменты LLM: %s",
                "поддерживаются" if TOOLS_SUPPORTED else
                "не поддерживаются, работаем по ключевым словам")
    return TOOLS_SUPPORTED


async def llm_stream(messages: list[dict]) -> AsyncGenerator[str, None]:
    """Стриминг токенов из удалённой LLM (SSE)."""
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    payload = {
        "model":       LLM_MODEL,
        "max_tokens":  LLM_MAX_TOKENS,
        "temperature": LLM_TEMPERATURE,
        "messages":    messages,
        "stream":      True,
    }
    try:
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST", f"{LLM_BASE_URL}/chat/completions",
                headers=headers, json=payload, timeout=LLM_TIMEOUT,
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield f"[Ошибка LLM: HTTP {resp.status_code}] {body.decode()[:200]}"
                    return
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        return
                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            yield token
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue
    except httpx.ConnectError:
        yield f"[Ошибка: не удалось подключиться к LLM {LLM_BASE_URL}]"
    except Exception as e:
        yield f"[Ошибка LLM: {e}]"


async def llm_complete(messages: list[dict]) -> str:
    """Обычный (нестриминговый) вызов — для вебхуков алертов."""
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    payload = {"model": LLM_MODEL, "max_tokens": LLM_MAX_TOKENS,
               "temperature": LLM_TEMPERATURE, "messages": messages}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{LLM_BASE_URL}/chat/completions",
                                  headers=headers, json=payload,
                                  timeout=LLM_TIMEOUT)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        logger.error(f"LLM HTTP {e.response.status_code}")
        return f"[Ошибка LLM: HTTP {e.response.status_code}]"
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return f"[Ошибка LLM: {e}]"
