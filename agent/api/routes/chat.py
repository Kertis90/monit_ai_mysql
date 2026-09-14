

"""
Чат: WebSocket со стримингом, тот же разговор через REST, история и оценки.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional

from fastapi import (APIRouter, HTTPException, Request, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import JSONResponse

from agent.api.deps import AdminUser, Alerts, Chats, Feedbacks, MaybeUser
from agent.core.config import settings
from agent.db.base import session_scope
from agent.db.repositories.chats import ChatRepository, FeedbackRepository
from agent.db.repositories.users import normalize
from agent.schemas.api import ChatRequest, FeedbackRequest
from agent.services import access, jobs
from agent.services.analysis import system_prompt
from agent.services.assistant import (UNFINISHED_NOTE, build_chat_context,
                                      llm_with_tools, looks_unfinished,
                                      run_tool, sql_from_answer)
from agent.services.toolcalls import StreamFilter
from agent.services.intents import detect_chart_intent, detect_export_intent
from agent.core.words import count_of
from agent.services.llm import (LLM_TOOL_ASK_S, llm_complete, llm_probe_tools,
                                llm_stream)
from agent.services.prometheus import build_charts

logger = logging.getLogger("agent.api.chat")
router = APIRouter(tags=["Чат"])

# Живые соединения: при остановке агента их надо закрыть самим, иначе uvicorn
# ждёт, пока клиент отключится сам, а вкладка чата держит сокет часами
ws_clients: set = set()
# История разговоров в памяти процесса; постоянная копия лежит в базе
ws_sessions: dict[str, list[dict]] = {}

AUTH_ENABLED          = settings.auth.enabled
CHAT_CONTEXT_MESSAGES = settings.chat_context_messages


def history_to_messages(history: list[dict]) -> list[dict]:
    """Роль summary в OpenAI-совместимый API отправлять нельзя — подаём её
    системным сообщением с пометкой, что это конспект."""
    out = []
    for m in history:
        if m.get("role") == "summary":
            out.append({"role": "system",
                        "content": "Конспект более ранней части разговора:\n"
                                   + m["content"]})
        else:
            out.append({"role": m["role"], "content": m["content"]})
    return out


async def chat_restore(client_id: str, thread_id: str = "") -> list[dict]:
    """Поднять переписку разговора при первом сообщении в этом процессе."""
    if not client_id:
        return []
    async with session_scope() as session:
        rows = await ChatRepository(session).history(
            client_id, limit=CHAT_CONTEXT_MESSAGES * 2,
            thread_id=thread_id or None)
    return [{"role": r.role, "content": r.content} for r in rows]


async def chat_save(client_id: str, session_id: str, role: str,
                    content: str, fingerprint: str = "") -> None:
    if not client_id:
        return
    async with session_scope() as session:
        await ChatRepository(session).add(
            client_id=client_id, session_id=session_id, role=role,
            content=content, fingerprint=fingerprint)


async def chat_summarize(client_id: str, older: list[dict]) -> str:
    """Сжать вытесняемую часть переписки в короткую выжимку.

    Вызывается, когда история упирается в окно контекста. Без этого старые
    сообщения просто отбрасывались, и агент «забывал» ранее выясненное —
    например, что отставание реплики уже разобрали и оно плановое.
    """
    if not older:
        return ""
    dialog = "\n".join(
        f"{'Пользователь' if m['role'] == 'user' else 'Агент'}: {m['content']}"
        for m in older)[:12000]

    prompt = [
        {"role": "system",
         "content": "Ты ведёшь конспект технической переписки по мониторингу MySQL."},
        {"role": "user",
         "content": (
             "Сожми переписку ниже в выжимку до 15 строк. Сохрани только то, "
             "что понадобится дальше: какие кластеры обсуждали, какие проблемы "
             "нашли и чем закончилось, какие выводы уже сделаны (в том числе "
             "«проблемы нет»), какие значения метрик назывались, что решили "
             "сделать. Без вступлений и без воды.\n\n" + dialog)},
    ]
    try:
        return (await llm_complete(prompt)).strip()
    except Exception as e:
        logger.error(f"Не удалось построить выжимку истории: {e}")
        return ""


async def chat_save_summary(client_id: str, session_id: str, text: str) -> None:
    if text:
        await chat_save(client_id, session_id, "summary", text)


async def chat_compact(client_id: str, session_id: str,
                       history: list[dict]) -> list[dict]:
    """Ужать историю до окна контекста, вытесненное — в выжимку.

    Возвращает новую историю: [выжимка] + последние сообщения.
    """
    if len(history) <= CHAT_CONTEXT_MESSAGES:
        return history

    keep  = CHAT_CONTEXT_MESSAGES // 2          # что оставляем дословно
    older = [m for m in history[:-keep] if m.get("role") in ("user", "assistant")]
    tail  = history[-keep:]

    digest = await chat_summarize(client_id, older)
    if not digest:
        # выжимка не получилась — ведём себя как раньше, просто обрезаем
        return history[-CHAT_CONTEXT_MESSAGES:]

    await chat_save_summary(client_id, session_id, digest)
    logger.info("История %s: %d сообщений сжаты в выжимку", client_id, len(older))
    return [{"role": "summary", "content": digest}] + tail


# Сколько раз подряд разбираем вызовы, написанные текстом. Больше двух —
# признак того, что модель зациклилась на запросах вместо ответа.
INLINE_TOOL_ROUNDS = 2


# С чего начинается согласие. Человек пишет как привык — «да», «давай»,
# «продолжай», — а не как удобно программе
YES_RE = re.compile(
    r"^\W*(да|ага|угу|давай|продолж|ещ[её]|дальше|конечно|верно|ок|ok|yes|y|\+)",
    re.I)


def means_yes(text: str) -> bool:
    """Согласие ли это. Всё, что не согласие, — отказ.

    Толковать сомнительное как «нет» безопаснее: отказ заканчивает сбор и
    даёт ответ по собранному, а согласие тратит запросы к боевой базе.
    """
    return bool(YES_RE.match(str(text or "").strip()))


async def stream_answer(messages: list, job) -> tuple:
    """Стримить ответ, вырезая из потока разметку вызовов инструментов.

    Возвращает (чистый текст, вызовы). Разметка до пользователя не доходит
    ни при каком исходе: даже нераспознанный вызов показывать незачем.
    """
    flt = StreamFilter()
    # Вызовы штатным полем: раньше они пропадали молча, и в чат попадало
    # вступление «сейчас посмотрю» без самого ответа
    native: list = []
    async for token in llm_stream(messages, native):
        if job.stop_event.is_set():
            break
        visible, reset = flt.feed(token)
        # Рассуждение шло без открывающего тега и опозналось только по
        # закрывающему: стираем показанное, иначе оно повиснет над ответом
        if reset:
            await job.emit({"type": "reset"})
        if visible:
            await job.emit({"type": "token", "text": visible})
    tail, reset = flt.finish()
    if reset:
        await job.emit({"type": "reset"})
    if tail:
        await job.emit({"type": "token", "text": tail})
    # Разметкой в тексте или штатным полем — для нас это одно и то же
    return flt.clean, flt.calls + native


async def generate(owner: str, thread_id: str, thread_title: str, text: str,
                   fp: str, sid: str, history: list, job) -> None:
    """Собрать контекст и получить ответ.

    Выполняется отдельной задачей, а не в обработчике сокета: закрытая вкладка
    или обновление страницы больше не отменяют разбор, на который агент уже
    потратил сбор метрик и чтение логов. Всё, что раньше уходило в сокет,
    теперь публикуется в задачу — сокет это только пересказывает.

    Вопрос сохраняется в историю ДО генерации: если человек перезагрузит
    страницу, он должен увидеть свой вопрос на месте, а не пустой чат.
    """
    await chat_save(owner, thread_id, "user", text, fp)
    async with session_scope() as db:
        await ChatRepository(db).touch_thread(thread_id, text)

    async def say(what: str) -> None:
        """Рассказать, чем агент занят прямо сейчас."""
        await job.emit({"type": "step", "text": what})

    await say("Разбираю вопрос")
    try:
        context_text, cluster, hours = await build_chat_context(text, say)
    except Exception as exc:
        logger.error("Context error: %s", exc)
        await job.emit({"type": "error", "text": "Ошибка сбора метрик: %s" % exc})
        await job.emit({"type": "done", "stopped": False})
        return

    await job.emit({
        "type":      "context",
        "cluster":   cluster["label"] if cluster else None,
        "hours":     hours if hours > 0 else None,
        "thread_id": thread_id,
        "title":     thread_title,
    })

    # Графики строим ТОЛЬКО если их попросили. Иначе шлём лёгкое предложение
    # без данных: строка со ссылками под ответом, десять запросов в Prometheus
    # зря не делаем.
    if cluster and hours > 0:
        want_charts = detect_chart_intent(text)
        want_export = detect_export_intent(text)
        try:
            charts = await build_charts(cluster, hours) if want_charts else []
            await job.emit({
                "type":          "charts",
                "mode":          "inline" if want_charts else "offer",
                "highlight_pdf": want_export,
                "cluster":       cluster["name"],
                "cluster_label": cluster["label"],
                "hours":         hours,
                "charts":        charts,
            })
        except Exception as exc:
            logger.error("Не удалось собрать графики: %s", exc)

    messages = [{"role": "system", "content": system_prompt()}]
    # Выжимка вытесненной части + последние реплики дословно
    messages += history_to_messages(history[-CHAT_CONTEXT_MESSAGES:])
    messages.append({"role": "user",
                     "content": "%s\n\n## Вопрос\n\n%s" % (context_text, text)})

    # Если эндпоинт умеет инструменты — даём модели дозапросить недостающее
    # самой, вместо угадывания по ключевым словам. Собранный контекст
    # остаётся: он покрывает типовые вопросы без лишних раундов к модели.
    if await llm_probe_tools():
        await say("Спрашиваю модель, каких данных не хватает")

        async def ask_more(done: int, rounds: int) -> bool:
            """Порция инструментов кончилась — спросить, продолжать ли.

            Сбор данных идёт не бесплатно: это запросы к боевой базе и
            чтение логов по SSH. Решать, тратить ли ещё, должен человек, а
            не предел в настройках. Не ответил — заканчиваем тем, что
            собрано: это безопасный исход, ответ всё равно будет.
            """
            if not LLM_TOOL_ASK_S:
                return False
            answer = await job.ask(
                "Агент сделал %s и пока не закончил сбор. Продолжаем?"
                % count_of(done, "запрос", "запроса", "запросов"),
                [{"value": "yes", "label": "Продолжить сбор"},
                 {"value": "no", "label": "Ответить по тому, что есть"}],
                LLM_TOOL_ASK_S)
            if answer == "yes":
                await say("Продолжаю сбор")
                return True
            logger.info("Сбор остановлен: ответ человека «%s»",
                        answer or "не дождались")
            return False

        try:
            messages, used = await llm_with_tools(messages, ask_more)
            if used:
                await job.emit({"type": "tools", "used": used})
        except Exception as exc:
            logger.error("Режим инструментов не сработал: %s", exc)

    await say("Формулирую ответ")
    answer, calls = await stream_answer(messages, job)

    # Модель могла попросить инструменты текстом, а не штатным полем: часть
    # моделей обучена писать <tool_call> прямо в ответ. Разметку пользователь
    # уже не увидел — осталось выполнить и дать модели дописать по данным.
    # А могла и вовсе ответить планом: «выполните вот такой SELECT». План —
    # не ответ: человек просил число, и доступ к базе есть у агента, а не у
    # него. Тогда запрос из ответа выполняем сами.
    planned = not calls
    if planned:
        calls = sql_from_answer(answer, cluster)

    rounds = 0
    while calls and rounds < INLINE_TOOL_ROUNDS and not job.stop_event.is_set():
        rounds += 1
        names = [c["name"] for c in calls]
        logger.info("Инструменты из текста ответа: %s", ", ".join(names))
        await say("Выполняю: " + ", ".join(names))
        results = []
        for call in calls:
            try:
                out = await run_tool(call["name"], call["args"])
            except Exception as exc:
                out = "Инструмент не выполнен: %s" % exc
            results.append("## %s\n\n%s" % (call["name"], str(out)[:20000]))
        await job.emit({"type": "tools", "used": names})

        if planned:
            # Инструкция уже показана человеку. Оставлять её над ответом
            # незачем: он просил результат, а не указание, что ему сделать
            ask = ("Ты написал запрос вместо ответа — агент его выполнил. "
                   "Вот что вернула база:\n\n%s\n\nТеперь ответь на вопрос "
                   "по этим данным: назови числа. Запрос приведи рядом, чтобы "
                   "результат можно было проверить. Инструменты больше не "
                   "вызывай.")
            await job.emit({"type": "reset"})
            answer = ""
        else:
            ask = ("Данные, которые ты запросил:\n\n%s\n\nТеперь ответь на "
                   "вопрос по этим данным. Инструменты больше не вызывай.")

        messages = messages + [
            {"role": "assistant", "content": answer or "(запрос данных)"},
            {"role": "user", "content": ask % "\n\n".join(results)}]
        if answer.strip():
            await job.emit({"type": "token", "text": "\n\n"})
            answer += "\n\n"
        more, calls = await stream_answer(messages, job)
        answer += more
        # Второй заход тоже мог кончиться планом вместо ответа
        if not calls:
            calls = sql_from_answer(more, cluster)
            planned = bool(calls)
    # Ответ мог кончиться вступлением: «сейчас получу то и это:» — и всё.
    # Просим договорить: данные уже собраны, спрашивать больше нечего.
    if not job.stop_event.is_set() and looks_unfinished(answer):
        logger.info("Ответ выглядит вступлением, прошу договорить: %s",
                    answer[:120])
        await say("Прошу модель договорить")
        again = messages + [
            {"role": "assistant", "content": answer or "(пусто)"},
            {"role": "user", "content": UNFINISHED_NOTE}]
        await job.emit({"type": "reset"})
        shown, answer = answer, ""
        more, _ = await stream_answer(again, job)
        if more.strip():
            answer = more
        else:
            # Договорить не вышло — возвращаем то, что было: пустой экран
            # хуже вступления
            answer = shown
            await job.emit({"type": "token", "text": shown})

    if job.stop_event.is_set():
        # Прерванный ответ всё равно сохраняем: пользователь его видел и в
        # следующем вопросе может на него сослаться
        answer += "\n\n[генерация остановлена]"
        await job.emit({"type": "token", "text": "\n\n[остановлено]"})
        logger.info("Генерация остановлена пользователем: %s", sid)

    await chat_save(owner, thread_id, "assistant", answer, fp)
    history.append({"role": "user",      "content": text})
    history.append({"role": "assistant", "content": answer})

    await job.emit({"type": "done", "stopped": job.stop_event.is_set()})

    # Упёрлись в окно контекста — не выбрасываем старое, а сжимаем.
    # После done: выжимку строит модель, и ждать её пользователю незачем.
    if len(history) > CHAT_CONTEXT_MESSAGES:
        history[:] = await chat_compact(owner, thread_id, history)


async def relay(ws: WebSocket, job, resume: bool) -> None:
    """Пересказать клиенту то, что происходит в задаче.

    resume — клиент вернулся к уже идущему ответу: сначала отдаём накопленное,
    потом продолжаем вживую. Без этого после перезагрузки страницы человек
    видел бы пустоту до самого конца генерации.
    """
    queue = job.subscribe()
    try:
        if resume:
            await ws.send_json({"type": "resume", "thread_id": job.thread_id,
                                "question": job.question})
        for event in list(job.events):
            await ws.send_json(event)
            if event.get("type") == "done":
                return
        while True:
            event = await queue.get()
            if event is None:          # задача завершилась
                return
            await ws.send_json(event)
            if event.get("type") == "done":
                return
    finally:
        job.unsubscribe(queue)


@router.websocket("/ws")
async def websocket_chat(ws: WebSocket):
    """
    Протокол:
      Клиент → {"type": "message", "text": "...", "session_id": "...",
                "client_id": "...", "fingerprint": "..."}
      Сервер → {"type": "context",  "cluster": "...", "hours": N}   — что определил агент
      Сервер → {"type": "token",    "text": "..."}                  — стриминг токенов
      Сервер → {"type": "reset"}                                    — стереть показанное
      Сервер → {"type": "done"}                                     — конец ответа
      Сервер → {"type": "error",    "text": "..."}
      Клиент → {"type": "ping"} / Сервер → {"type": "pong"}
      Сервер → {"type": "ask",      "question": "...", "options": [...]}
                                                                    — вопрос человеку
      Сервер → {"type": "asked",    "value": "..."}                  — вопрос закрыт
      Клиент → {"type": "stop"}  — прервать генерацию текущего ответа
      Клиент → {"type": "answer", "value": "yes"}  — ответ на вопрос агента
    """
    await ws.accept()

    # HTTP-middleware на WebSocket не распространяется — проверяем отдельно.
    # У WebSocket те же .cookies/.headers/.client, поэтому current_user подходит.
    ws_user = None
    if AUTH_ENABLED:
        ws_user = await access.current_user(ws)
        if not ws_user:
            await ws.send_json({"type": "error",
                                "text": "Сессия истекла — обновите страницу и войдите."})
            await ws.close(code=4401)
            return

    ws_clients.add(ws)
    session_id = f"ws-{id(ws)}"
    logger.info(f"WS connected: {session_id}"
                + (f" user={ws_user['username']}" if ws_user else ""))

    # Пока идёт стриминг, основной цикл занят и receive_text() не вызывается —
    # значит «стоп» никто бы не услышал. Поэтому чтение вынесено в отдельную
    # задачу: она разбирает служебные сообщения сразу, а вопросы кладёт в очередь.
    inbox: asyncio.Queue = asyncio.Queue()

    async def reader():
        try:
            await _read_loop()
        finally:
            # Разрыв соединения виден только здесь: исключение возникает
            # внутри этой задачи и до основного цикла не доходит. Без метки
            # он навсегда остался бы ждать очередь, а вместе с ним — и сама
            # задача-читатель: по вкладке чата на каждое закрытие.
            await inbox.put(None)

    async def _read_loop():
        while True:
            raw = await ws.receive_text()
            try:
                m = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "text": "Невалидный JSON"})
                continue
            kind = m.get("type")
            if kind == "ping":
                await ws.send_json({"type": "pong"})
            elif kind == "stop":
                jobs.stop(str(m.get("thread_id") or "").strip()[:128])
            elif kind == "answer":
                # Ответ на «продолжаем сбор?»
                jobs.reply(str(m.get("thread_id") or "").strip()[:128],
                           str(m.get("value") or ""))
            elif kind in ("message", "attach"):
                await inbox.put(m)

    reader_task = asyncio.create_task(reader())

    # Пересказ идёт отдельной задачей, а не прямо здесь. Иначе сокет висит
    # внутри одного разговора до конца ответа и не слышит ничего: человек
    # переключился на другой чат, вернулся — а его attach всё ещё в очереди,
    # и вместо ответа он видит пустоту.
    relay_task: Optional[asyncio.Task] = None

    async def stop_relay() -> None:
        nonlocal relay_task
        if relay_task is None:
            return
        task, relay_task = relay_task, None
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    async def start_relay(job, resume: bool) -> None:
        """Пересказывать этот разговор. Прежний пересказ прекращаем.

        Два пересказа в один сокет писали бы вперемешку, а смотрит человек
        всё равно в один чат — тот, что открыт.
        """
        nonlocal relay_task
        await stop_relay()
        relay_task = asyncio.create_task(relay(ws, job, resume))

    # Клиент мог вернуться к ответу, который считается прямо сейчас, —
    # например, обновив страницу или переключив чат.
    async def resume_if_running(thread_id: str) -> None:
        job = jobs.running(thread_id)
        if job is not None:
            await start_relay(job, resume=True)
        else:
            # В этом разговоре ничего не считается: прекращаем пересказ
            # прежнего, иначе его токены сыпались бы в чужой чат
            await stop_relay()

    try:
        while True:
            msg = await inbox.get()
            if msg is None:            # клиент отключился
                break

            # Чей это разговор. Когда включена аутентификация, ключ — ИМЯ
            # ПОЛЬЗОВАТЕЛЯ: агентом пользуются несколько человек, и история
            # одного не должна попадать в контекст другого. По браузеру
            # (client_id) делим только когда логина нет вовсе — иначе двое
            # за одной машиной видели бы переписку друг друга, а один человек
            # с ноутбука и с телефона имел бы две несвязанные истории.
            browser_id = str(msg.get("client_id") or "").strip()[:128]
            fp  = str(msg.get("fingerprint") or "").strip()[:128]
            sid = msg.get("session_id", session_id)
            cid = (f"user:{normalize(ws_user['username'])}"
                   if ws_user else browser_id)
            owner = cid or sid

            thread_id = str(msg.get("thread_id") or "").strip()[:128]
            text = str(msg.get("text") or "").strip()

            # Возврат к идущему ответу: вопроса нет, только просьба
            # подключиться обратно
            if msg.get("type") == "attach":
                if thread_id:
                    await resume_if_running(thread_id)
                continue

            if not text:
                continue

            # Пока висит вопрос агента, написанное в чат — ответ на него, а
            # не новый вопрос. Разбирается на сервере нарочно: тогда это
            # работает с любым интерфейсом, даже со старым, взятым браузером
            # из кэша, где кнопок под вопросом может не оказаться вовсе.
            if jobs.waiting(thread_id):
                said_yes = means_yes(text)
                jobs.reply(thread_id, "yes" if said_yes else "no")
                logger.info("Ответ на вопрос агента словами: «%s» -> %s",
                            text[:40], "продолжаем" if said_yes else "хватит")
                continue

            # В каком разговоре отвечаем. Клиент присылает выбранный; если не
            # прислал — берём последний, а при первом обращении заводим новый.
            async with session_scope() as db:
                repo = ChatRepository(db)
                thread = (await repo.get_thread(owner, thread_id)
                          if thread_id else None)
                if thread is None:
                    thread = await repo.current_thread(owner)
                thread_id, thread_title = thread.id, thread.title

            history = ws_sessions.get(thread_id)
            if history is None:
                # первое сообщение в этом процессе — поднимаем историю из БД
                history = await chat_restore(owner, thread_id)
                ws_sessions[thread_id] = history

            # Генерация живёт в задаче, а не в этом обработчике: закрытая
            # вкладка больше не отменяет разбор
            job = await jobs.start(
                thread_id, text,
                lambda j: generate(owner, thread_id, thread_title, text,
                                   fp, sid, history, j))
            await start_relay(job, resume=job.question != text)

    except WebSocketDisconnect:
        logger.info(f"WS disconnected: {session_id}")
        ws_sessions.pop(session_id, None)
    except Exception as e:
        logger.error(f"WS error: {e}")
        try:
            await ws.close()
        except Exception:
            pass
    finally:
        ws_clients.discard(ws)
        await stop_relay()
        # Без этого задача-читатель переживёт соединение и повиснет
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass


@router.post("/chat", summary="Задать вопрос агенту (без стриминга)")
async def rest_chat(req: ChatRequest):
    """REST-версия чата (без стриминга) — для curl и интеграций."""
    context_text, cluster, hours = await build_chat_context(req.message)
    history = ws_sessions.setdefault(req.session_id, [])

    messages = [{"role": "system", "content": system_prompt()}]
    for m in history[-6:]:
        messages.append(m)
    messages.append({"role": "user",
                     "content": f"{context_text}\n\n## Вопрос\n\n{req.message}"})

    answer = await llm_complete(messages)

    history.append({"role": "user",      "content": req.message})
    history.append({"role": "assistant", "content": answer})
    if len(history) > 16:
        history[:] = history[-16:]

    return {
        "answer":        answer,
        "cluster":       cluster["name"]  if cluster else None,
        "cluster_label": cluster["label"] if cluster else None,
        "hours":         hours if hours > 0 else None,
    }


@router.get("/chat", summary="Задать вопрос агенту (GET)")
async def rest_chat_get(message: str, session_id: str = "rest"):
    """Тот же ответ, что и POST /chat. Удобен для быстрой проверки из curl."""
    return await rest_chat(ChatRequest(message=message, session_id=session_id))


async def chat_key(request: Request, client_id: str = "") -> str:
    """Чей это разговор.

    Когда вход включён, ключ — имя пользователя: агентом пользуются несколько
    человек, и переписка одного не должна попадать в контекст другого. По
    браузеру делим только при выключенном входе — иначе двое за одной машиной
    видели бы историю друг друга, а один человек с ноутбука и с телефона имел
    бы две несвязанные.
    """
    if settings.auth.enabled:
        user = await access.current_user(request)
        if user:
            return "user:" + normalize(user["username"])
    return client_id


@router.get("/chat/threads", summary="Список своих чатов")
async def list_threads(request: Request, chats: Chats, client_id: str = ""):
    """Разбор аварии и вопрос про настройку — разные истории, и держать их
    в одной ленте значит портить контекст обеим."""
    key = await chat_key(request, client_id)
    if not key:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    return {"owner": key, "items": await chats.threads(key)}


@router.post("/chat/threads", summary="Создать чат")
async def create_thread(request: Request, chats: Chats,
                        client_id: str = "", title: str = ""):
    key = await chat_key(request, client_id)
    if not key:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    thread = await chats.create_thread(key, title)
    return {"id": thread.id, "title": thread.title,
            "created_at": thread.created_at}


@router.patch("/chat/threads/{thread_id}", summary="Переименовать чат")
async def rename_thread(thread_id: str, request: Request, chats: Chats,
                        title: str = "", client_id: str = ""):
    key = await chat_key(request, client_id)
    if not await chats.rename_thread(key, thread_id, title):
        raise HTTPException(status_code=404, detail="Чат не найден")
    return {"id": thread_id, "title": title.strip()[:200]}


@router.delete("/chat/threads/{thread_id}", summary="Удалить чат")
async def delete_thread(thread_id: str, request: Request, chats: Chats,
                        client_id: str = ""):
    key = await chat_key(request, client_id)
    removed = await chats.delete_thread(key, thread_id)
    if removed < 0:
        raise HTTPException(status_code=404, detail="Чат не найден")
    ws_sessions.pop(thread_id, None)        # и из памяти процесса тоже
    return {"id": thread_id, "removed": removed}


@router.get("/chat/history", summary="История переписки")
async def chat_history(request: Request, chats: Chats, client_id: str = "",
                       limit: int = 50, thread: str = ""):
    """Сообщения выбранного чата. Без параметра — последнего активного."""
    key = await chat_key(request, client_id)
    if not key:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    if thread:
        if await chats.get_thread(key, thread) is None:
            raise HTTPException(status_code=404, detail="Чат не найден")
    else:
        # Чат НЕ создаём: чтение не должно ничего создавать. Раньше открытие
        # страницы заводило чат, и нажатие «Новый чат» давало сразу два.
        existing = await chats.threads(key)
        thread = existing[0]["id"] if existing else ""

    rows = (await chats.history(key, limit=limit, thread_id=thread)
            if thread else [])
    return {"client_id": key, "thread_id": thread or None, "total": len(rows),
            "items": [{"ts": r.ts, "role": r.role, "content": r.content}
                      for r in rows],
            "retention_days": settings.db.chats_retention_days,
            "persistent": True}


@router.delete("/chat/history", summary="Очистить историю")
async def chat_history_clear(request: Request, chats: Chats,
                             client_id: str = "", thread: str = ""):
    """Без параметра thread очищается вся переписка владельца, с ним — один чат."""
    key = await chat_key(request, client_id)
    if not key:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    removed = await chats.forget(key, thread_id=thread or None)
    if thread:
        ws_sessions.pop(thread, None)
    else:
        for item in await chats.threads(key):
            ws_sessions.pop(item["id"], None)
    return {"client_id": key, "thread_id": thread or None, "removed": removed}


@router.post("/api/feedback", summary="Оценить ответ агента")
async def add_feedback(req: FeedbackRequest, request: Request,
                       feedbacks: Feedbacks, user: MaybeUser):
    await feedbacks.add(rating=req.rating, question=req.question,
                        answer=req.answer, comment=req.comment,
                        client_id=req.client_id,
                        username=(user or {}).get("username", ""))
    return {"ok": True}


@router.get("/api/feedback/stats", summary="Сводка по оценкам ответов")
async def feedback_stats(admin: AdminUser, feedbacks: Feedbacks,
                         days: int = 30):
    return await feedbacks.stats(days)


@router.get("/api/search", summary="Поиск по переписке и событиям")
async def search(request: Request, chats: Chats, alerts: Alerts,
                 q: str = "", client_id: str = "", limit: int = 30):
    """Чатов и инцидентов со временем становится много, и найти нужное
    прокруткой невозможно. Ищем сразу в обоих местах."""
    text = (q or "").strip()
    if len(text) < 2:
        raise HTTPException(status_code=400,
                            detail="Запрос должен быть не короче двух символов")
    key = await chat_key(request, client_id)
    found_chats = await chats.search(key, text, limit=limit) if key else []
    found_alerts = await alerts.search(text, limit=limit)
    return {
        "query": text,
        "messages": found_chats,
        "alerts": [{"id": a.id, "ts": a.ts, "alert": a.alert,
                    "cluster": a.cluster, "cluster_label": a.cluster_label,
                    "severity": a.severity, "summary": a.summary,
                    "resolution": a.resolution} for a in found_alerts],
    }


async def broadcast(payload: dict) -> None:
    """Разослать событие всем открытым вкладкам.

    Отдельного канала не заводим: сокет чата уже открыт у каждого, кто
    смотрит интерфейс. Мониторинг, в котором новое событие не появляется
    само, а ждёт нажатия «Обновить», — это справочник, а не монитор.
    """
    for client in list(ws_clients):
        try:
            await client.send_json(payload)
        except Exception:
            ws_clients.discard(client)
