"""
Сборка ответа: инструменты модели и подготовка контекста.

Инструменты — основной путь. Модель сама решает, какие данные ей нужны:
список ключевых слов приходилось расширять после каждой новой формулировки,
и «статистика», «детально», «за последний час» промахивались по очереди.
Ключевые слова остались запасным путём для эндпоинтов без tool calling.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
from typing import Optional

import httpx

from agent.core.config import settings
from agent.db.base import session_scope
from agent.db.repositories.alerts import AlertRepository
from agent.db.repositories.chats import ChatRepository
from agent.services.analysis import (build_timeline, collect_baseline,
                                     collect_config_diff, collect_series_table,
                                     collect_series_tables, explain_top_queries,
                                     fmt_alerts, fmt_baseline, fmt_current,
                                     fmt_diagnostics, fmt_history,
                                     fmt_series_table, run_diagnostics,
                                     system_prompt)
from agent.services.intents import (detect_alert_intent, detect_breakdown_intent,
                                    detect_chart_intent, detect_diagnose_intent,
                                    detect_history_intent, detect_time_hours,
                                    extract_sql, parse_step_seconds)
from agent.services.llm import (AUTH_HEADER, LLM_BASE_URL, LLM_MAX_TOKENS,
                                LLM_MODEL, LLM_TEMPERATURE, LLM_TOOL_ROUNDS,
                                llm_complete)
from agent.services.logs import detect_log_intent, read_app_log, read_slow_log
from agent.services.mysql import (cluster_db_creds, fmt_sql_result, sql_execute)
from agent.services.prometheus import (build_charts, collect_current,
                                       collect_history)
from agent.db.repositories.notes import NoteRepository
from agent.services import config_history
from agent.services.replication import collect_replication, fmt_replication
from agent.services.workload import fmt_workload, workload_delta
from agent.services.registry import (app_host, cluster_hosts,
                                     detect_cluster_in_text, enabled_clusters,
                                     find_cluster)
from agent.services.ssh import remote_time

logger = logging.getLogger("agent.assistant")

LOG_SSH_USER = settings.ssh.user
SERIES_MAX_ROWS = settings.prometheus.series_max_rows
ALERTS_RETENTION_DAYS = settings.db.alerts_retention_days


async def cluster_notes(cluster_name: str) -> str:
    """Известные особенности кластера — их дежурный знает, а агент нет.

    Без них он в каждом разборе заново «открывает» плановые вещи: всплеск в
    три часа ночи, растущую по расписанию таблицу, привычный для этого железа
    iowait — и предлагает с ними разобраться.
    """
    async with session_scope() as session:
        rows = await NoteRepository(session).list(cluster_name, only_enabled=True)
    if not rows:
        return ""
    lines = ["## Известные особенности кластера", "",
             "  Это записали люди, которые его обслуживают. Учитывай при "
             "разборе и не предлагай разбираться с тем, что здесь названо "
             "нормой.", ""]
    for note in rows:
        lines.append("  - " + " ".join(note.text.split()))
    return "\n".join(lines)


async def recent_alerts(cluster: Optional[str] = None, hours: float = 24,
                        limit: int = 20) -> list[dict]:
    """Свежие события словарями — в том виде, в каком их ждут форматтеры."""
    async with session_scope() as session:
        rows = await AlertRepository(session).recent(
            cluster=cluster, hours=hours, limit=limit)
        return [r.as_context() for r in rows]

CHAT_CONTEXT_MESSAGES = settings.chat_context_messages
MAX_METRICS_HOURS     = settings.prometheus.max_metrics_hours


def tool_specs() -> list:
    """Описание инструментов в формате OpenAI function calling."""
    names = [c["name"] for c in enabled_clusters()] or ["<нет кластеров>"]
    cl = {"type": "string", "description": "имя кластера: " + ", ".join(names)}
    hrs = {"type": "number",
           "description": f"окно в часах, максимум {MAX_METRICS_HOURS:g}"}
    return [
        {"type": "function", "function": {
            "name": "get_current_metrics",
            "description": "Текущие метрики кластера: доступность, QPS, "
                           "подключения, CPU, отставание реплики.",
            "parameters": {"type": "object", "properties": {"cluster": cl},
                           "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "get_history",
            "description": "Агрегаты min/avg/max за период и сравнение "
                           "с тем же периодом неделю назад.",
            "parameters": {"type": "object",
                           "properties": {"cluster": cl, "hours": hrs},
                           "required": ["cluster", "hours"]}}},
        {"type": "function", "function": {
            "name": "get_breakdown",
            "description": "Детальная статистика по интервалам: значения "
                           "CPU, iowait, памяти, дисков, QPS по каждому шагу. "
                           "Отдельная таблица на каждый сервер кластера.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl, "hours": hrs,
                "step_seconds": {"type": "integer",
                                 "description": "шаг разбивки, по умолчанию 300"}},
                "required": ["cluster", "hours"]}}},
        {"type": "function", "function": {
            "name": "get_schema",
            "description": "Схема базы из снимка агента: список таблиц, "
                           "столбцы и индексы конкретной таблицы, поиск "
                           "таблиц и столбцов по куску имени. Нужен, чтобы "
                           "писать выборки по настоящим именам, а не по "
                           "выдуманным. Читается мгновенно: боевой сервер "
                           "при этом не трогается.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl,
                "table": {"type": "string",
                          "description": "имя таблицы или база.таблица — "
                                         "вернёт столбцы и индексы"},
                "search": {"type": "string",
                           "description": "кусок имени: найдёт таблицы и "
                                          "столбцы, где он встречается"}},
                "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "explain_query",
            "description": "План выполнения запроса (EXPLAIN) с разбором: "
                           "полные сканирования, сортировки без индекса, "
                           "соединения без индекса, зависимые подзапросы. "
                           "Вместо sql можно указать connection_id — тогда "
                           "объясняется запрос, идущий в этом соединении "
                           "прямо сейчас.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl,
                "sql": {"type": "string",
                        "description": "читающий запрос целиком"},
                "connection_id": {"type": "integer",
                                  "description": "id соединения из "
                                                 "SHOW PROCESSLIST"}},
                "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "run_diagnostics",
            "description": "Диагностика Performance Schema: тяжёлые запросы, "
                           "полные сканирования, блокировки, ожидания, "
                           "планы выполнения и схемы таблиц.",
            "parameters": {"type": "object", "properties": {"cluster": cl},
                           "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "get_workload",
            "description": "Что нагружает базу ПРЯМО СЕЙЧАС: два среза "
                           "performance_schema с интервалом и разница между "
                           "ними. В отличие от run_diagnostics, показывает "
                           "не суммы с момента запуска сервера, а то, что "
                           "исполнялось в эти секунды.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl,
                "seconds": {"type": "number",
                            "description": "окно наблюдения, 5-60 с"}},
                "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "get_replication",
            "description": "Состояние репликации: работают ли потоки, ошибки "
                           "применения, отставание сверх запланированного, "
                           "непринятый relay log. Отвечает на вопрос ПОЧЕМУ "
                           "реплика отстала, а не только на сколько.",
            "parameters": {"type": "object", "properties": {"cluster": cl},
                           "required": ["cluster"]}}},
        {"type": "function", "function": {
            "name": "run_sql",
            "description": "Читающий SQL-запрос к кластеру. Разрешены только "
                           "SELECT, SHOW, EXPLAIN, DESCRIBE.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl,
                "sql": {"type": "string", "description": "текст запроса"}},
                "required": ["cluster", "sql"]}}},
        {"type": "function", "function": {
            "name": "read_logs",
            "description": "Slow-лог MySQL и логи приложения за период "
                           "с серверов кластера.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl, "hours": hrs,
                "filter": {"type": "string",
                           "description": "дополнительная строка поиска"}},
                "required": ["cluster", "hours"]}}},
        {"type": "function", "function": {
            "name": "get_alerts",
            "description": "История сработавших алертов с разбором.",
            "parameters": {"type": "object", "properties": {
                "cluster": cl, "hours": hrs},
                "required": []}}},
    ]


async def run_tool(name: str, args: dict) -> str:
    """Выполнить инструмент и вернуть текст для модели."""
    cname   = str(args.get("cluster") or "").strip()
    cluster = find_cluster(cname) if cname else None
    hours   = min(float(args.get("hours") or 6), MAX_METRICS_HOURS)

    if name in ("get_current_metrics", "get_history", "get_breakdown",
                "run_diagnostics", "run_sql", "read_logs", "explain_query",
                "get_schema", "get_workload", "get_replication") and not cluster:
        return f"Кластер «{cname}» не найден. Доступные: " + \
               ", ".join(c["name"] for c in enabled_clusters())

    try:
        if name == "get_schema":
            from agent.services import schema as schema_service
            snapshot = await schema_service.load(cluster["name"])
            if not snapshot:
                return schema_service.fmt_snapshot({}, cluster["label"])
            if args.get("table"):
                return schema_service.fmt_describe(
                    schema_service.describe(snapshot, str(args["table"])))
            if args.get("search"):
                return schema_service.fmt_find(
                    schema_service.find(snapshot, str(args["search"])))
            return schema_service.fmt_snapshot(snapshot, cluster["label"])

        if name == "explain_query":
            from agent.services import explain as explain_service
            data = await explain_service.explain(
                cluster, str(args.get("sql") or ""),
                int(args.get("connection_id") or 0))
            return explain_service.fmt_explain(data)

        if name == "get_current_metrics":
            return fmt_current(await collect_current(cluster))

        if name == "get_history":
            hist  = await collect_history(cluster, hours)
            parts = [fmt_history(hist, cluster["label"])]
            base  = await collect_baseline(cluster, hours)
            cmp_  = fmt_baseline(hist, base, cluster["label"])
            if cmp_:
                parts.append(cmp_)
            return "\n\n".join(parts)

        if name == "get_breakdown":
            step = int(args.get("step_seconds") or 300)
            tabs = await collect_series_tables(cluster, hours, max(step, 15))
            return "\n\n".join(fmt_series_table(t, cluster["label"]) for t in tabs)

        if name == "run_diagnostics":
            out = []
            live = await workload_delta(cluster)
            if not live.get("error"):
                out.append(fmt_workload(live, cluster["label"]))
            repl = fmt_replication(await collect_replication(cluster),
                                   cluster["label"])
            if repl:
                out.append(repl)
            for ip, role in cluster_hosts(cluster):
                diag = await run_diagnostics(cluster, ip)
                if diag:
                    out.append(fmt_diagnostics(
                        diag, f"{cluster['label']} · {role}", ip))
            cfg = await collect_config_diff(cluster)
            if cfg:
                out.append(cfg)
            plans = await explain_top_queries(cluster, cluster["primary_ip"])
            if plans:
                out.append(plans)
            return "\n\n".join(out) or "Диагностика недоступна: не задан db_user."

        if name == "get_workload":
            live = await workload_delta(cluster,
                                        float(args.get("seconds") or 15))
            if live.get("error"):
                return live["error"]
            return fmt_workload(live, cluster["label"])

        if name == "get_replication":
            states = await collect_replication(cluster)
            if not states:
                return ("В кластере нет реплик либо сервер не настроен как "
                        "реплика — состояние репликации отсутствует.")
            return fmt_replication(states, cluster["label"])

        if name == "run_sql":
            return fmt_sql_result(
                await sql_execute(cluster, str(args.get("sql") or "")))

        if name == "read_logs":
            out = []
            for ip, role in cluster_hosts(cluster):
                t = await remote_time(ip)
                if t is None:
                    out.append(f"{ip}: сервер недоступен по SSH")
                    continue
                ue, se = t["epoch"], t["epoch"] - hours * 3600
                lu = t["local"]
                ls = lu - datetime.timedelta(hours=hours)
                flt = str(args.get("filter") or "")
                out.append(await read_slow_log(cluster, ip, ls, lu, flt, se, ue))

            # Логи ядра лежат на своём сервере — читаем их один раз, а не
            # по разу на каждый сервер БД
            ah = app_host(cluster)
            t  = await remote_time(ah)
            if t is None:
                out.append(f"{ah}: сервер ядра недоступен по SSH")
            else:
                ue, se = t["epoch"], t["epoch"] - hours * 3600
                lu = t["local"]
                ls = lu - datetime.timedelta(hours=hours)
                app = await read_app_log(cluster, ah, ls, lu,
                                         str(args.get("filter") or ""), se, ue)
                if app:
                    out.append(app)
            return "\n\n".join(p for p in out if p) or "Логи прочитать не удалось."

        if name == "get_alerts":
            rows = await recent_alerts(cluster=cluster["name"] if cluster else None,
                                hours=hours, limit=20)
            return fmt_alerts(rows, f"последние {hours:g} ч.",
                              cluster["label"] if cluster else None)

        return f"Неизвестный инструмент: {name}"
    except Exception as e:
        logger.error(f"Инструмент {name} упал: {e}")
        return f"Инструмент {name} завершился ошибкой: {e}"


async def llm_with_tools(messages: list) -> tuple:
    """Диалог с инструментами. Возвращает (сообщения для финального ответа,
    список выполненных инструментов)."""
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    used = []
    convo = list(messages)

    for _ in range(LLM_TOOL_ROUNDS):
        payload = {"model": LLM_MODEL, "max_tokens": LLM_MAX_TOKENS,
                   "temperature": LLM_TEMPERATURE, "messages": convo,
                   "tools": tool_specs(), "tool_choice": "auto"}
        try:
            async with httpx.AsyncClient(
                    timeout=settings.llm.timeout) as client:
                r = await client.post(f"{LLM_BASE_URL}/chat/completions",
                                      headers=headers, json=payload)
                r.raise_for_status()
                msg = r.json()["choices"][0]["message"]
        except Exception as e:
            logger.error(f"Раунд с инструментами не удался: {e}")
            break

        calls = msg.get("tool_calls") or []
        if not calls:
            break                      # модель готова отвечать

        convo.append(msg)
        for call in calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            logger.info(f"Инструмент: {name} {args}")
            result = await run_tool(name, args)
            used.append(name)
            convo.append({"role": "tool", "tool_call_id": call.get("id", ""),
                          "name": name, "content": result[:20000]})
    return convo, used


async def build_chat_context(user_message: str, progress=None
                             ) -> tuple[str, Optional[dict], float]:
    """Определить кластер и временное окно, собрать контекст метрик.

    progress — куда сообщать, чем агент занят. Сбор данных для тяжёлого
    вопроса идёт минуту и дольше: два среза performance_schema, EXPLAIN по
    десятку запросов, чтение логов по SSH. Всё это время человек смотрел на
    три точки и не знал, работает агент или завис.
    """
    async def say(text: str) -> None:
        """Рассказать, чем агент занят. Имя нарочно не «step»: рядом уже
        есть шаг разбивки в секундах, и переменная затирала бы функцию."""
        if progress is not None:
            try:
                await progress(text)
            except Exception:          # рассказ о работе не должен её ломать
                pass

    cluster = detect_cluster_in_text(user_message)
    hours   = detect_time_hours(user_message)
    blocks  = []
    # Чего собрать не удалось. Без этого списка отсутствующий блок выглядит
    # для модели так же, как отсутствие проблемы, и она отвечает уверенно,
    # опираясь на половину данных.
    gaps: list[str] = []

    # Обрезаем окно метрик, но не молча: если просили неделю, а отдаём сутки,
    # LLM должна об этом сказать, иначе ответ будет вводить в заблуждение.
    asked_hours = hours
    if hours > MAX_METRICS_HOURS:
        hours = MAX_METRICS_HOURS
        blocks.append(
            f"## Ограничение периода\n\n"
            f"  Запрошено {asked_hours:g} ч, метрики отданы за последние "
            f"{hours:g} ч — это максимум для одного разбора.\n"
            f"  Обязательно предупреди об этом в ответе.")

    if cluster:
        notes = await cluster_notes(cluster["name"])
        if notes:
            blocks.append(notes)

        if hours > 0:
            await say("Читаю метрики Prometheus за %g ч" % hours)
            hist = await collect_history(cluster, hours)
            blocks.append(fmt_history(hist, cluster["label"]))
            # С чем сравнивать: те же метрики неделю назад
            await say("Сравниваю с тем же периодом неделю назад")
            try:
                base = await collect_baseline(cluster, hours)
                cmp_block = fmt_baseline(hist, base, cluster["label"])
                if cmp_block:
                    blocks.append(cmp_block)
            except Exception as e:
                logger.error(f"База для сравнения не собрана: {e}")
                gaps.append("не собрана база для сравнения (те же метрики "
                            "неделю назад): %s" % e)
            # Просили разбивку по интервалам — агрегатов недостаточно:
            # по min/avg/max не видно, когда был всплеск и с чем он совпал
            if detect_breakdown_intent(user_message):
                step = parse_step_seconds(user_message) or 300
                # по таблице на каждый сервер: у кластера с репликой их два,
                # и ресурсы у них разные
                for tb in await collect_series_tables(cluster, hours, step):
                    blocks.append(fmt_series_table(tb, cluster["label"]))
        # Что вообще есть в базе. Из снимка, поэтому бесплатно; без этого
        # верхнего слоя модель не знает имён и либо отказывается писать
        # выборку, либо придумывает таблицы
        try:
            from agent.services import schema as schema_service
            brief = schema_service.fmt_brief(
                await schema_service.load(cluster["name"]))
            if brief:
                blocks.append(brief)
        except Exception as exc:
            logger.info("Справка по схеме не добавлена: %s", exc)

        await say("Снимаю текущее состояние " + cluster["label"])
        current = await collect_current(cluster)
        blocks.append(fmt_current(current))

        # Пользователь написал SQL — выполняем и кладём результат рядом
        # с метриками. Валидатор пропустит только читающие конструкции.
        user_sql = extract_sql(user_message)
        if user_sql and cluster_db_creds(cluster):
            blocks.append(fmt_sql_result(await sql_execute(cluster, user_sql)))

        # Просят разобраться, почему медленно — собираем диагностический
        # набор сами, по каждому серверу. Советовать «посмотрите
        # performance_schema» бессмысленно, если можно просто посмотреть.
        if detect_diagnose_intent(user_message) and not cluster_db_creds(cluster):
            gaps.append("не задана учётка db_user — ни диагностический набор, "
                        "ни профиль нагрузки, ни состояние репликации "
                        "прочитать нельзя")

        if detect_diagnose_intent(user_message) and cluster_db_creds(cluster):
            # Что грузит базу ПРЯМО СЕЙЧАС. Накопленная статистика показывает
            # средние за всё время работы сервера и текущую проблему прячет.
            await say("Снимаю профиль нагрузки: два среза performance_schema")
            live = await workload_delta(cluster)
            if live.get("error"):
                gaps.append("не снят профиль нагрузки: %s" % live["error"])
            else:
                blocks.append(fmt_workload(live, cluster["label"]))

            # Лаг говорит «на сколько», состояние репликации — «почему»
            await say("Проверяю состояние репликации")
            repl = await collect_replication(cluster)
            block = fmt_replication(repl, cluster["label"])
            if block:
                blocks.append(block)
            for state in repl:
                if state.get("error"):
                    gaps.append("состояние репликации не прочитано: %s"
                                % state["error"])

            for ip, role in cluster_hosts(cluster):
                await say("Диагностические запросы на %s (%s)" % (ip, role))
                diag = await run_diagnostics(cluster, ip)
                if diag:
                    blocks.append(fmt_diagnostics(
                        diag, f"{cluster['label']} · {role}", ip))

            # Расхождения параметров между серверами кластера
            try:
                cfg = await collect_config_diff(cluster)
                if cfg:
                    blocks.append(cfg)
            except Exception as e:
                logger.error(f"Сравнение конфигураций не удалось: {e}")
                gaps.append("не прочитаны параметры серверов: %s" % e)

            # Планы выполнения — превращают «запрос медленный»
            # в конкретную рекомендацию по индексам
            await say("Строю планы выполнения тяжёлых запросов")
            try:
                plans = await explain_top_queries(cluster, cluster["primary_ip"])
                if plans:
                    blocks.append(plans)
            except Exception as e:
                logger.error(f"EXPLAIN не выполнен: {e}")
                gaps.append("не получены планы выполнения (EXPLAIN): %s" % e)

            # Лента событий: причинно-следственную связь видно сразу.
            # Изменения настроек идут туда же — «что вчера поменяли» самый
            # частый вопрос при внезапной деградации.
            changed = await config_history.changes(cluster["name"], days=14)
            tl = build_timeline(
                await recent_alerts(cluster=cluster["name"],
                                    hours=hours if hours > 0 else 24, limit=40),
                config_history.as_events(changed[:15]))
            if tl:
                blocks.append(tl)

        # Логи читаем по SSH с самих серверов. Период приводим к ВРЕМЕНИ
        # СЕРВЕРА: метки в логах пишутся в его часовом поясе, и разница
        # с сервером мониторинга дала бы grep не по тем датам.
        if detect_log_intent(user_message):
            win = hours if hours > 0 else 2.0
            for ip, role in cluster_hosts(cluster):
                await say("Читаю логи на %s по SSH" % ip)
                t = await remote_time(ip)
                if t is None:
                    gaps.append("логи с %s (%s) не прочитаны: сервер не "
                                "отвечает по SSH под учёткой %s"
                                % (ip, role, LOG_SSH_USER or "(не задана)"))
                    continue

                # Два разных отсчёта. Файлы выбираем по абсолютному времени
                # (mtime), а grep идёт по локальным меткам внутри логов.
                # Пояса серверов различаются, смешивать нельзя.
                until_epoch = t["epoch"]
                since_epoch = until_epoch - win * 3600
                local_until = t["local"]
                local_since = local_until - datetime.timedelta(hours=win)

                part = await read_slow_log(cluster, ip, local_since,
                                           local_until, "",
                                           since_epoch, until_epoch)
                if part:
                    blocks.append(
                        f"## Логи {cluster['label']} · {role} ({ip}), "
                        f"период {local_since:%Y-%m-%d %H:%M} — "
                        f"{local_until:%H:%M} по времени сервера "
                        f"(пояс {t['tz'] or t['offset']}, смещение {t['offset']})"
                        f"\n\n" + part)

            # Ядро системы — отдельный сервер, у него свой часовой пояс
            ah = app_host(cluster)
            t  = await remote_time(ah)
            if t is None:
                blocks.append(
                    f"## Логи ядра {cluster['label']} ({ah})\n\n"
                    f"  Сервер недоступен по SSH под учёткой "
                    f"{LOG_SSH_USER or '(не задана)'} — логи прочитать нельзя.")
            else:
                until_epoch = t["epoch"]
                since_epoch = until_epoch - win * 3600
                local_until = t["local"]
                local_since = local_until - datetime.timedelta(hours=win)
                part = await read_app_log(cluster, ah, local_since, local_until,
                                          "", since_epoch, until_epoch)
                if part:
                    blocks.append(
                        f"## Логи ядра {cluster['label']} ({ah}), "
                        f"период {local_since:%Y-%m-%d %H:%M} — "
                        f"{local_until:%H:%M} по времени сервера "
                        f"(пояс {t['tz'] or t['offset']}, смещение {t['offset']})"
                        f"\n\n" + part)
    else:
        # Обзор всех
        clusters = enabled_clusters()
        results  = await asyncio.gather(*[collect_current(c) for c in clusters])
        lines = ["## Краткий статус всех кластеров\n"]
        for s in results:
            p   = s["primary"]
            lag = s.get("replica", {}).get("replication_lag_over_plan_s", "—")
            lines.append(
                f"  {s['cluster_label']:20} up={p.get('mysql_up','?')}  "
                f"QPS={p.get('qps','?')}  slow={p.get('slow_qps','?')}/s  "
                f"conn={p.get('connections_pct','?')}%  "
                f"CPU={p.get('cpu_pct','?')}%  лаг={lag}s")
        blocks.append("\n".join(lines))

        # Спросили про историю, но город не назвали — раньше в контекст
        # уходил только текущий статус, и агент отвечал, что данных нет.
        # Собираем историю по всем кластерам (их обычно единицы).
        if hours > 0 and clusters:
            hists = await asyncio.gather(
                *[collect_history(c, hours) for c in clusters])
            for c, h in zip(clusters, hists):
                if h:
                    blocks.append(fmt_history(h, c["label"]))

            # И детализацию тоже: раньше таблица строилась только когда
            # в вопросе назван город, а «по метрикам ОС» города не содержит
            if detect_breakdown_intent(user_message):
                step = parse_step_seconds(user_message) or 300
                # бюджет строк делим между кластерами, иначе контекст распухнет
                budget = max(SERIES_MAX_ROWS // max(len(clusters), 1), 40)
                grouped = await asyncio.gather(
                    *[collect_series_tables(c, hours, step, budget)
                      for c in clusters])
                for c, tables in zip(clusters, grouped):
                    for tb in tables:
                        blocks.append(fmt_series_table(tb, c["label"]))

    # Спросили про алерты/инциденты — подмешиваем историю из БД
    if detect_alert_intent(user_message):
        period = (f"последние {hours:g} ч."
                  if hours > 0 else f"последние {ALERTS_RETENTION_DAYS} дн.")
        rows = await recent_alerts(cluster=cluster["name"] if cluster else None,
                            hours=hours if hours > 0 else None,
                            limit=20)
        blocks.append(fmt_alerts(rows, period,
                                 cluster["label"] if cluster else None))

    if gaps:
        blocks.append("## Чего собрать не удалось\n\n"
                      + "\n".join("  - " + g for g in gaps)
                      + "\n\n  Об этих данных выводов не делай и в ответе "
                        "прямо скажи, какой проверки не хватило.")

    return "\n\n".join(blocks), cluster, hours
