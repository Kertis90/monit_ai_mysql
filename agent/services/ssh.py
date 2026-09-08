"""
Выполнение команд на серверах БД по SSH.

Одна точка входа: команды собираются только здесь и экранируются, поэтому
пользовательский текст в оболочку не попадает ни при каких обстоятельствах.
Ходим под той же учёткой, что указана при развёртывании.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import shlex
from typing import Optional

from agent.core.config import settings

logger = logging.getLogger("agent.ssh")

LOG_SSH_USER    = settings.ssh.user
LOG_SSH_PORT    = settings.ssh.port
LOG_SSH_KEY     = settings.ssh.key
LOG_SSH_TIMEOUT = settings.ssh.timeout


async def log_ssh(host: str, remote_cmd: str, ok_codes: tuple = (0, 1),
                  env: Optional[dict] = None) -> tuple:
    """Выполнить готовую команду на сервере. Возвращает (успех, вывод).

    ok_codes — какие коды возврата считать успехом. У grep код 1 означает
    «ничего не найдено» и ошибкой не является, а у mysql — именно ошибку,
    поэтому вызывающий указывает свой набор.

    env — переменные для удалённой команды. Через них передаётся пароль
    (MYSQL_PWD): в аргументах командной строки он был бы виден всем в ps.
    """
    if not LOG_SSH_USER:
        return False, ("Не задан SSH_USER — чтение логов недоступно. "
                       "Заполните его в config.env и переустановите агента.")
    argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=" + str(LOG_SSH_TIMEOUT),
            "-p", str(LOG_SSH_PORT)]
    if LOG_SSH_KEY:
        argv += ["-i", LOG_SSH_KEY]
    if env:
        # SendEnv требует настройки на сервере, поэтому подставляем
        # присваивание прямо в команду — значение экранировано
        prefix = " ".join(k + "=" + shlex.quote(str(v)) for k, v in env.items())
        remote_cmd = prefix + " " + remote_cmd
    argv += [LOG_SSH_USER + "@" + host, remote_cmd]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(),
                                          timeout=LOG_SSH_TIMEOUT + 10)
    except asyncio.TimeoutError:
        return False, "Таймаут при выполнении команды на " + host
    except Exception as e:
        return False, "Не удалось подключиться к {}: {}".format(host, e)

    text = out.decode("utf-8", "replace")
    if proc.returncode not in ok_codes:
        msg = err.decode("utf-8", "replace").strip()
        return False, msg or "Команда вернула код {}".format(proc.returncode)
    return True, text


async def remote_time(host: str):
    """Время сервера: абсолютное и локальное одновременно.

    Нужны оба. Файлы выбираем по mtime — это Unix-время, одинаковое везде.
    Метки внутри логов пишутся в ЛОКАЛЬНОМ поясе сервера, и grep идёт по ним.
    Пояса серверов различаются (Владивосток и Кемерово — 4 часа), поэтому
    смешивать эти величины нельзя: файл выбрался бы не тот.

    Возвращает {"epoch": int, "local": datetime, "offset": "+1000", "tz": "..."}
    или None, если сервер недоступен.
    """
    ok, out = await log_ssh(host, "date '+%s|%Y-%m-%dT%H:%M:%S|%z|%Z'")
    if not ok or not out.strip():
        return None
    parts = out.strip().split("|")
    if len(parts) < 3:
        return None
    try:
        return {
            "epoch":  int(parts[0]),
            "local":  datetime.datetime.strptime(parts[1][:19], "%Y-%m-%dT%H:%M:%S"),
            "offset": parts[2],
            "tz":     parts[3] if len(parts) > 3 else "",
        }
    except (ValueError, IndexError):
        return None


async def remote_now(host: str):
    """Локальное время сервера (обратная совместимость)."""
    t = await remote_time(host)
    return t["local"] if t else None
