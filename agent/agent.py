"""
MySQL AI Agent v3 — WebSocket streaming chat + мульти-кластер
================================================================
Возможности:
  - WebSocket-чат (/ws) со стримингом токенов от удалённой LLM
  - REST API (совместимость: /chat, /status, /clusters, /alerts/history)
  - Мульти-кластерный реестр (clusters.json)
  - Определение города и временного окна из вопроса на русском
  - Анализ алертов Alertmanager через вебхук
  - Статический веб-интерфейс из /opt/ai-alert-agent/web/
"""

import os
import json
import logging
import datetime
import asyncio
import re
import sqlite3
import httpx
from contextlib import closing
from pathlib import Path
from typing import Optional, AsyncGenerator
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

LLM_BASE_URL    = os.environ.get("LLM_BASE_URL",    "https://your-llm-server.com/v1")
LLM_API_KEY     = os.environ.get("LLM_API_KEY",     "your-token-here")
LLM_MODEL       = os.environ.get("LLM_MODEL",       "gpt-4o-mini")
LLM_MAX_TOKENS  = int(os.environ.get("LLM_MAX_TOKENS", "2048"))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.3"))
PROMETHEUS_URL  = os.environ.get("PROMETHEUS_URL",  "http://localhost:9090")
AGENT_PORT      = int(os.environ.get("AGENT_PORT",  "5001"))
REGISTRY_PATH   = os.environ.get("REGISTRY_PATH",   "/opt/ai-alert-agent/clusters.json")
WEB_DIR         = os.environ.get("WEB_DIR",         "/opt/ai-alert-agent/web")

# Префикс, под которым агент виден снаружи через nginx (например "/ai-agent").
# Пусто = агент отдаётся в корне. Сами маршруты FastAPI остаются без префикса:
# префикс срезает nginx (proxy_pass со слэшем на конце), а ROOT_PATH нужен лишь
# чтобы страница знала, от какого адреса строить свои ссылки.
ROOT_PATH       = "/" + os.environ.get("ROOT_PATH", "").strip().strip("/")
ROOT_PATH       = "" if ROOT_PATH == "/" else ROOT_PATH

# История алертов: SQLite рядом с агентом, окно хранения в днях
ALERTS_DB_PATH        = os.environ.get("ALERTS_DB_PATH", "/opt/ai-alert-agent/alerts.db")
ALERTS_RETENTION_DAYS = int(os.environ.get("ALERTS_RETENTION_DAYS", "30"))

AUTH_HEADER = LLM_API_KEY if LLM_API_KEY.startswith("Bearer ") else f"Bearer {LLM_API_KEY}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/ai-alert-agent.log")],
)
logger = logging.getLogger("agent")

app = FastAPI(title="MySQL AI Agent v3", version="3.0.0", root_path=ROOT_PATH)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

alert_history: list[dict] = []   # запасная копия в памяти, если БД недоступна
ws_sessions:   dict[str, list[dict]] = {}   # session_id -> messages


# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ АЛЕРТОВ
#  SQLite из стандартной библиотеки — переживает рестарт агента, новых
#  pip-зависимостей не требует. Записи старше ALERTS_RETENTION_DAYS удаляются.
# ══════════════════════════════════════════════════════════════════════════════

def alerts_db() -> sqlite3.Connection:
    conn = sqlite3.connect(ALERTS_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def alerts_cutoff() -> str:
    """Нижняя граница окна хранения, ISO-8601 UTC (формат совпадает с ts)."""
    return (datetime.datetime.utcnow()
            - datetime.timedelta(days=ALERTS_RETENTION_DAYS)).isoformat()


def alerts_init() -> bool:
    try:
        Path(ALERTS_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        with closing(alerts_db()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts            TEXT NOT NULL,
                    alert         TEXT,
                    cluster       TEXT,
                    cluster_label TEXT,
                    instance      TEXT,
                    severity      TEXT,
                    summary       TEXT,
                    analysis      TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
            conn.execute("DELETE FROM alerts WHERE ts < ?", (alerts_cutoff(),))
        logger.info(f"История алертов: {ALERTS_DB_PATH}, хранение {ALERTS_RETENTION_DAYS} дн.")
        return True
    except Exception as e:
        logger.error(f"Хранилище алертов недоступно ({ALERTS_DB_PATH}): {e}. "
                     f"История будет только в памяти и потеряется при рестарте.")
        return False


ALERTS_DB_OK = alerts_init()


def alerts_save(rec: dict) -> None:
    """Записать алерт в БД. Копия в памяти — страховка на случай сбоя БД."""
    alert_history.insert(0, rec)
    if len(alert_history) > 200:
        alert_history.pop()

    if not ALERTS_DB_OK:
        return
    try:
        with closing(alerts_db()) as conn, conn:
            conn.execute(
                "INSERT INTO alerts (ts, alert, cluster, cluster_label,"
                " instance, severity, summary, analysis)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rec["timestamp"], rec["alert"], rec["cluster"],
                 rec["cluster_label"], rec["instance"], rec["severity"],
                 rec["summary"], rec["analysis"]))
            conn.execute("DELETE FROM alerts WHERE ts < ?", (alerts_cutoff(),))
    except Exception as e:
        logger.error(f"Не удалось сохранить алерт в {ALERTS_DB_PATH}: {e}")


def alerts_query(cluster: Optional[str] = None,
                 hours: Optional[float] = None,
                 limit: int = 20) -> list[dict]:
    """Выборка алертов для чата: по кластеру и/или окну времени."""
    if not ALERTS_DB_OK:
        rows = [r for r in alert_history
                if not cluster or r.get("cluster") == cluster]
        return rows[:limit]
    try:
        since = alerts_cutoff()
        if hours and hours > 0:
            asked = (datetime.datetime.utcnow()
                     - datetime.timedelta(hours=hours)).isoformat()
            # обе метки в одном ISO-формате, поэтому сравнение строк корректно:
            # не выходим за пределы окна хранения, даже если спросили больше
            since = max(since, asked)

        sql    = ("SELECT ts AS timestamp, alert, cluster, cluster_label,"
                  "       instance, severity, summary, analysis"
                  "  FROM alerts WHERE ts >= ?")
        params: list = [since]
        if cluster:
            sql += " AND cluster = ?"
            params.append(cluster)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        with closing(alerts_db()) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except Exception as e:
        logger.error(f"Не удалось выбрать алерты для чата: {e}")
        return []


def alerts_load(limit: int) -> tuple[int, list[dict]]:
    """Отдать историю за окно хранения: (всего за период, последние limit)."""
    if not ALERTS_DB_OK:
        return len(alert_history), alert_history[:limit]
    try:
        cutoff = alerts_cutoff()
        with closing(alerts_db()) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= ?", (cutoff,)).fetchone()[0]
            rows = conn.execute(
                "SELECT ts AS timestamp, alert, cluster, cluster_label, instance,"
                "       severity, summary, analysis"
                "  FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit)).fetchall()
        return total, [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Не удалось прочитать историю алертов: {e}")
        return len(alert_history), alert_history[:limit]


# ══════════════════════════════════════════════════════════════════════════════
#  РЕЕСТР КЛАСТЕРОВ
# ══════════════════════════════════════════════════════════════════════════════

def load_registry() -> dict:
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Реестр не загружен ({REGISTRY_PATH}): {e}")
        return {"clusters": []}


def enabled_clusters() -> list[dict]:
    return [c for c in load_registry()["clusters"] if c.get("enabled", True)]


def find_cluster(name: str) -> Optional[dict]:
    for c in enabled_clusters():
        if c["name"].lower() == name.lower():
            return c
    return None


def find_cluster_by_ip(ip: str) -> Optional[dict]:
    for c in enabled_clusters():
        if c.get("primary_ip") == ip or c.get("replica_ip") == ip:
            return c
    return None


def detect_cluster_in_text(text: str) -> Optional[dict]:
    """Найти кластер по названию города в тексте (регистронезависимо, с учётом падежей)."""
    t = text.lower()
    for c in enabled_clusters():
        label = c["label"].lower()
        # Точное вхождение label / name
        if label in t or c["name"].lower() in t:
            return c
        # Морфологическая обрезка: "Кемерово" находит "в Кемерове",
        # "Новосибирск" находит "в Новосибирске"
        stem = label[:max(4, len(label) - 2)]
        if len(stem) >= 4 and stem in t:
            return c
        for tag in c.get("tags", []):
            if tag.lower() in t:
                return c
    return None


def clusters_index_text() -> str:
    cs = enabled_clusters()
    if not cs:
        return "Кластеры не настроены."
    lines = []
    for c in cs:
        lines.append(
            f"  - name={c['name']}  город='{c['label']}'  "
            f"primary={c['primary_ip']}  replica={c.get('replica_ip') or 'нет'}  "
            f"описание='{c.get('description', '')}'"
        )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  ВРЕМЕННЫЕ ОКНА (для "вчера", "2 часа назад" и т.п.)
# ══════════════════════════════════════════════════════════════════════════════

TIME_KEYWORDS = {
    "вчера": 30, "позавчера": 54,
    "прошлый день": 30, "прошлой ночью": 16,
    "утром": 14, "ночью": 12, "вечером": 12, "днём": 12, "днем": 12,
    "последние сутки": 26, "за сутки": 26, "сутки": 26,
    "за день": 26, "за неделю": 170, "неделю": 170,
    "час назад": 2, "часа назад": 4, "часов назад": 8,
}


# Вопросы, при которых в контекст подмешивается история алертов из БД.
# Держим список узким: лишний блок только раздувает промпт.
ALERT_KEYWORDS = (
    "алерт", "alert", "инцидент", "авари", "срабатыв", "сработа",
    "тревог", "происшеств", "что случилось", "сбой", "сбои", "сбоя",
    "были проблем", "была проблем", "проблемы были", "падал", "падени",
)


def detect_alert_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in ALERT_KEYWORDS)


def detect_time_hours(text: str) -> float:
    t = text.lower()
    m = re.search(r'за\s+послед[ниеюю]+\s+(\d+)\s+час', t)
    if m:
        return float(m.group(1)) + 0.5
    m = re.search(r'за\s+(\d+)\s+час', t)
    if m:
        return float(m.group(1)) + 0.5
    m = re.search(r'(\d+)\s+час[а-яё]*\s+назад', t)
    if m:
        return float(m.group(1)) + 1
    for kw, hours in TIME_KEYWORDS.items():
        if kw in t:
            return float(hours)
    return 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  PROMETHEUS
# ══════════════════════════════════════════════════════════════════════════════

async def prom_query(client: httpx.AsyncClient, query: str) -> Optional[float]:
    try:
        r = await client.get(f"{PROMETHEUS_URL}/api/v1/query",
                             params={"query": query}, timeout=10.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            return round(float(d["data"]["result"][0]["value"][1]), 3)
    except Exception:
        pass
    return None


async def prom_range_summary(client: httpx.AsyncClient, query: str,
                             hours: float) -> dict:
    """Мин/макс/среднее за период + время пиков."""
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)
    step  = "300" if hours > 6 else "60"
    try:
        r = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query,
                    "start": start.isoformat() + "Z",
                    "end":   end.isoformat() + "Z",
                    "step":  step},
            timeout=15.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            vals = [(v[0], float(v[1])) for v in d["data"]["result"][0]["values"]]
            if not vals:
                return {}
            vs      = [v[1] for v in vals]
            max_i   = vs.index(max(vs))
            min_i   = vs.index(min(vs))
            fmt     = lambda ts: datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M UTC")
            return {
                "min":      round(min(vs), 2),
                "max":      round(max(vs), 2),
                "avg":      round(sum(vs) / len(vs), 2),
                "max_time": fmt(vals[max_i][0]),
                "min_time": fmt(vals[min_i][0]),
            }
    except Exception:
        pass
    return {}


async def collect_current(cluster: dict) -> dict:
    """Текущие метрики кластера (async, параллельно)."""
    async with httpx.AsyncClient() as client:
        async def metrics_for(ip: str) -> dict:
            inst  = f"{ip}:9104"
            node  = f"{ip}:9100"
            queries = {
                "mysql_up":            f'mysql_up{{instance="{inst}"}}',
                "qps":                 f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
                "slow_qps":            f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
                "connections_pct":     f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
                "connections_now":     f'mysql_global_status_threads_connected{{instance="{inst}"}}',
                "innodb_hit_pct":      f'(1-rate(mysql_global_status_innodb_buffer_pool_reads{{instance="{inst}"}}[5m])/rate(mysql_global_status_innodb_buffer_pool_read_requests{{instance="{inst}"}}[5m]))*100',
                "row_lock_waits":      f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
                "aborted_connects":    f'rate(mysql_global_status_aborted_connects{{instance="{inst}"}}[5m])',
                "cpu_pct":             f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{node}"}}[5m]))*100)',
                "memory_pct":          f'(node_memory_MemTotal_bytes{{instance="{node}"}}-node_memory_MemAvailable_bytes{{instance="{node}"}})/node_memory_MemTotal_bytes{{instance="{node}"}}*100',
                "disk_free_pct":       f'node_filesystem_avail_bytes{{instance="{node}",mountpoint="/"}}/node_filesystem_size_bytes{{instance="{node}",mountpoint="/"}}*100',
                "iowait_pct":          f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{node}"}}[5m]))*100',
            }
            keys    = list(queries.keys())
            results = await asyncio.gather(*[prom_query(client, queries[k]) for k in keys])
            return {k: (str(v) if v is not None else "нет данных")
                    for k, v in zip(keys, results)}

        out = {
            "cluster_name":  cluster["name"],
            "cluster_label": cluster["label"],
            "primary":       await metrics_for(cluster["primary_ip"]),
        }
        repl_ip = cluster.get("replica_ip")
        if repl_ip:
            rep  = await metrics_for(repl_ip)
            inst = f"{repl_ip}:9104"
            lag, io, sql = await asyncio.gather(
                prom_query(client, f'mysql_slave_status_seconds_behind_master{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_io_running{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_sql_running{{instance="{inst}"}}'),
            )
            rep["replication_lag_s"]  = str(lag) if lag is not None else "нет данных"
            rep["replication_io_up"]  = str(io)  if io  is not None else "нет данных"
            rep["replication_sql_up"] = str(sql) if sql is not None else "нет данных"
            out["replica"] = rep
        return out


async def collect_history(cluster: dict, hours: float) -> dict:
    """История: min/avg/max + время пиков по ключевым метрикам."""
    prim = cluster["primary_ip"]
    repl = cluster.get("replica_ip", "")
    inst = f"{prim}:9104"

    async with httpx.AsyncClient() as client:
        queries = {
            "qps":             f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
            "slow_qps":        f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
            "connections_pct": f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
            "cpu_pct":         f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{prim}:9100"}}[5m]))*100)',
            "iowait_pct":      f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{prim}:9100"}}[5m]))*100',
            "row_lock_waits":  f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
        }
        if repl:
            queries["replication_lag_s"] = \
                f'mysql_slave_status_seconds_behind_master{{instance="{repl}:9104"}}'

        keys    = list(queries.keys())
        results = await asyncio.gather(
            *[prom_range_summary(client, queries[k], hours) for k in keys])

        return {"period_hours": hours,
                **{k: v for k, v in zip(keys, results)}}


# ══════════════════════════════════════════════════════════════════════════════
#  LLM — обычный вызов и стриминг
# ══════════════════════════════════════════════════════════════════════════════

def system_prompt() -> str:
    return f"""Ты — опытный DBA и SRE со специализацией на MySQL/InnoDB и репликации.
Ты обслуживаешь MySQL-кластеры (primary + replica) в разных городах.

Доступные кластеры:
{clusters_index_text()}

Правила:
1. Отвечай ТОЛЬКО на русском языке.
2. Структурируй ответ, давай конкретные команды MySQL/Linux.
3. Если есть исторические данные — ссылайся на конкретные значения и время пиков.
4. Если данных недостаточно — честно об этом говори.
5. Интерпретируй числа, а не пересказывай их.
6. Если приложен блок «Алерты за …» — это реальная история срабатываний
   за {ALERTS_RETENTION_DAYS} дн. Опирайся на неё: называй даты и время,
   ищи повторяющиеся и связанные инциденты. Блок с фразой «Ни одного алерта
   за этот период не было» означает именно это — не придумывай инциденты."""


def fmt_alerts(rows: list[dict], period: str, label: Optional[str] = None) -> str:
    scope = f" по кластеру {label}" if label else ""
    if not rows:
        return (f"## Алерты{scope} за {period}\n\n"
                f"  Ни одного алерта за этот период не было.")

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["alert"]] = counts.get(r["alert"], 0) + 1

    lines = [f"## Алерты{scope} за {period} — записей: {len(rows)}", "",
             "Сводка: " + ", ".join(f"{k}: {v}" for k, v in
                                    sorted(counts.items(), key=lambda kv: -kv[1])),
             ""]
    for i, r in enumerate(rows):
        ts = (r.get("timestamp") or "")[:19].replace("T", " ")
        lines.append(f"  [{ts} UTC] {(r.get('severity') or '?'):8} "
                     f"{r.get('alert')} — {r.get('cluster_label') or '—'} / "
                     f"{r.get('instance') or '—'}")
        if r.get("summary"):
            lines.append(f"      {r['summary']}")
        # Разбор от LLM только для трёх последних: он длинный, а промпт не резиновый
        if i < 3 and r.get("analysis"):
            a = " ".join(r["analysis"].split())
            lines.append(f"      прошлый разбор: {a[:400]}"
                         f"{'…' if len(a) > 400 else ''}")
    return "\n".join(lines)


def fmt_current(m: dict) -> str:
    lines = [f"## Текущие метрики: {m['cluster_label']} ({m['cluster_name']})",
             "\n### Primary"]
    lines += [f"  {k}: {v}" for k, v in m["primary"].items()]
    if "replica" in m:
        lines.append("\n### Replica")
        lines += [f"  {k}: {v}" for k, v in m["replica"].items()]
    return "\n".join(lines)


def fmt_history(h: dict, label: str) -> str:
    lines = [f"## История кластера {label} за последние {h['period_hours']} ч. "
             f"(min / avg / max, время пиков в UTC)"]
    for k, v in h.items():
        if k == "period_hours":
            continue
        if v:
            lines.append(f"  {k}: min={v['min']} avg={v['avg']} max={v['max']} "
                         f"(пик в {v['max_time']}, минимум в {v['min_time']})")
        else:
            lines.append(f"  {k}: нет данных")
    return "\n".join(lines)


async def build_chat_context(user_message: str) -> tuple[str, Optional[dict], float]:
    """Определить кластер и временное окно, собрать контекст метрик."""
    cluster = detect_cluster_in_text(user_message)
    hours   = detect_time_hours(user_message)
    blocks  = []

    if cluster:
        if hours > 0:
            hist = await collect_history(cluster, hours)
            blocks.append(fmt_history(hist, cluster["label"]))
        current = await collect_current(cluster)
        blocks.append(fmt_current(current))
    else:
        # Обзор всех
        clusters = enabled_clusters()
        results  = await asyncio.gather(*[collect_current(c) for c in clusters])
        lines = ["## Краткий статус всех кластеров\n"]
        for s in results:
            p   = s["primary"]
            lag = s.get("replica", {}).get("replication_lag_s", "—")
            lines.append(
                f"  {s['cluster_label']:20} up={p.get('mysql_up','?')}  "
                f"QPS={p.get('qps','?')}  slow={p.get('slow_qps','?')}/s  "
                f"conn={p.get('connections_pct','?')}%  "
                f"CPU={p.get('cpu_pct','?')}%  лаг={lag}s")
        blocks.append("\n".join(lines))

    # Спросили про алерты/инциденты — подмешиваем историю из БД
    if detect_alert_intent(user_message):
        period = (f"последние {hours:g} ч."
                  if hours > 0 else f"последние {ALERTS_RETENTION_DAYS} дн.")
        rows = alerts_query(cluster=cluster["name"] if cluster else None,
                            hours=hours if hours > 0 else None,
                            limit=20)
        blocks.append(fmt_alerts(rows, period,
                                 cluster["label"] if cluster else None))

    return "\n\n".join(blocks), cluster, hours


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
                headers=headers, json=payload, timeout=120.0,
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
                                  headers=headers, json=payload, timeout=90.0)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        logger.error(f"LLM HTTP {e.response.status_code}")
        return f"[Ошибка LLM: HTTP {e.response.status_code}]"
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return f"[Ошибка LLM: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET ЧАТ
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_chat(ws: WebSocket):
    """
    Протокол:
      Клиент → {"type": "message", "text": "...", "session_id": "..."}
      Сервер → {"type": "context",  "cluster": "...", "hours": N}   — что определил агент
      Сервер → {"type": "token",    "text": "..."}                  — стриминг токенов
      Сервер → {"type": "done"}                                     — конец ответа
      Сервер → {"type": "error",    "text": "..."}
      Клиент → {"type": "ping"} / Сервер → {"type": "pong"}
    """
    await ws.accept()
    session_id = f"ws-{id(ws)}"
    logger.info(f"WS connected: {session_id}")

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "text": "Невалидный JSON"})
                continue

            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong"})
                continue

            if msg.get("type") != "message":
                continue

            text = msg.get("text", "").strip()
            sid  = msg.get("session_id", session_id)
            if not text:
                continue

            history = ws_sessions.setdefault(sid, [])

            # 1. Собрать контекст (метрики) — сообщаем клиенту что нашли
            try:
                context_text, cluster, hours = await build_chat_context(text)
            except Exception as e:
                logger.error(f"Context error: {e}")
                await ws.send_json({"type": "error",
                                    "text": f"Ошибка сбора метрик: {e}"})
                continue

            await ws.send_json({
                "type":    "context",
                "cluster": cluster["label"] if cluster else None,
                "hours":   hours if hours > 0 else None,
            })

            # 2. Собрать messages
            messages = [{"role": "system", "content": system_prompt()}]
            for m in history[-6:]:
                messages.append(m)
            messages.append({
                "role": "user",
                "content": f"{context_text}\n\n## Вопрос\n\n{text}",
            })

            # 3. Стримить ответ
            full_answer = []
            async for token in llm_stream(messages):
                full_answer.append(token)
                await ws.send_json({"type": "token", "text": token})

            answer = "".join(full_answer)
            await ws.send_json({"type": "done"})

            # 4. Сохранить историю (без огромного контекста метрик)
            history.append({"role": "user",      "content": text})
            history.append({"role": "assistant", "content": answer})
            if len(history) > 16:
                history[:] = history[-16:]

    except WebSocketDisconnect:
        logger.info(f"WS disconnected: {session_id}")
        ws_sessions.pop(session_id, None)
    except Exception as e:
        logger.error(f"WS error: {e}")
        try:
            await ws.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ALERTMANAGER WEBHOOK
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    processed = 0
    for alert in body.get("alerts", []):
        if alert.get("status") != "firing":
            continue

        labels   = alert.get("labels", {})
        name     = labels.get("alertname", "Unknown")
        instance = labels.get("instance", "")
        severity = labels.get("severity", "unknown")
        summary  = alert.get("annotations", {}).get("summary", "")

        cluster = (find_cluster(labels.get("cluster", ""))
                   or find_cluster_by_ip(instance.split(":")[0]))
        cluster_label = cluster["label"] if cluster else instance

        logger.info(f"[ALERT] {name} | {cluster_label} | {severity}")

        blocks = []
        if cluster:
            current = await collect_current(cluster)
            blocks.append(fmt_current(current))
            hist = await collect_history(cluster, 2)
            blocks.append(fmt_history(hist, cluster_label))
        ctx = "\n\n".join(blocks) if blocks else "Метрики недоступны."

        prompt = f"""## Алерт

**Кластер:** {cluster_label}
**Алерт:** {name}  (severity: {severity})
**Инстанс:** {instance}
**Описание:** {summary}

{ctx}

## Задача
1. Причина срабатывания (1-2 предложения).
2. Реальное влияние прямо сейчас.
3. 2-4 вероятных источника.
4. Немедленные команды для диагностики.
5. Шаги устранения.
6. Нужен ли срочный вызов DBA — да/нет."""

        analysis = await llm_complete([
            {"role": "system", "content": system_prompt()},
            {"role": "user",   "content": prompt},
        ])

        alerts_save({
            "timestamp":     datetime.datetime.utcnow().isoformat(),
            "alert":         name,
            "cluster":       cluster["name"] if cluster else None,
            "cluster_label": cluster_label,
            "instance":      instance,
            "severity":      severity,
            "summary":       summary,
            "analysis":      analysis,
        })
        processed += 1

    return {"processed": processed}


# ══════════════════════════════════════════════════════════════════════════════
#  REST API
# ══════════════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = "rest"


@app.post("/chat")
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


@app.get("/chat")
async def rest_chat_get(message: str, session_id: str = "rest"):
    return await rest_chat(ChatRequest(message=message, session_id=session_id))


@app.get("/clusters")
def api_clusters():
    # Не отдаём пароли наружу
    safe = []
    for c in enabled_clusters():
        c2 = {k: v for k, v in c.items() if k != "mysql_exporter_password"}
        safe.append(c2)
    return {"clusters": safe}


@app.get("/clusters/{name}/status")
async def api_cluster_status(name: str):
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(404, f"Кластер '{name}' не найден")
    return await collect_current(cluster)


@app.get("/clusters/{name}/history")
async def api_cluster_history(name: str, hours: float = 24):
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(404, f"Кластер '{name}' не найден")
    return await collect_history(cluster, hours)


@app.get("/status")
async def api_all_status():
    clusters = enabled_clusters()
    results  = await asyncio.gather(*[collect_current(c) for c in clusters])
    return {"clusters": results}


@app.get("/alerts/history")
def api_alerts(limit: int = 30):
    total, items = alerts_load(limit)
    return {"total": total, "items": items,
            "retention_days": ALERTS_RETENTION_DAYS,
            "persistent": ALERTS_DB_OK}


@app.get("/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "clusters":  len(enabled_clusters()),
        "llm_model": LLM_MODEL,
    }


@app.get("/config")
def config_info():
    return {
        "llm_base_url":    LLM_BASE_URL,
        "llm_model":       LLM_MODEL,
        "auth_header_set": "your-token" not in AUTH_HEADER,
        "prometheus_url":  PROMETHEUS_URL,
        "registry_path":   REGISTRY_PATH,
        "clusters":        len(enabled_clusters()),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТИКА (веб-интерфейс)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    index_path = Path(WEB_DIR) / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h1>MySQL AI Agent</h1><p>web/index.html не найден</p>")

    # Все ссылки страницы относительные, поэтому базовый адрес подставляется
    # здесь: под nginx на подпути это "/ai-agent/", в корне — "/".
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    html = index_path.read_text(encoding="utf-8")
    html = html.replace('<base href="/">', f'<base href="{prefix}/">', 1)
    return HTMLResponse(html)


if Path(WEB_DIR).exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"MySQL AI Agent v3 | :{AGENT_PORT} | LLM={LLM_BASE_URL} model={LLM_MODEL}")
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT, log_level="info")
