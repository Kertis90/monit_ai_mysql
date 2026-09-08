"""
Реестр кластеров: clusters.json.

Файл, а не таблица: его правят руками и через manage_cluster.sh, он лежит в
git вместе с остальной конфигурацией, и агент к нему только читатель.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from agent.core.config import settings

logger = logging.getLogger("agent.registry")

REGISTRY_PATH = settings.registry_path


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


def cluster_hosts(cluster: dict) -> list:
    """[(адрес, роль)] всех серверов кластера — primary и, если есть, replica."""
    hosts = [(cluster["primary_ip"], "primary")]
    if cluster.get("replica_ip"):
        hosts.append((cluster["replica_ip"], "replica"))
    return hosts


def app_host(cluster: dict) -> str:
    """Адрес ядра системы, работающей с этой БД (Lanbilling и подобные).

    Логи ядра лежат на своём сервере, а не на серверах БД. Если адрес не задан,
    считаем, что ядро стоит рядом с primary — так было до появления поля.
    """
    return (cluster.get("app_ip") or "").strip() or cluster["primary_ip"]


def slow_log_path(cluster: dict, host: str) -> str:
    """Путь к slow-логу конкретного сервера.

    У реплики он часто другой: другой диск, другое имя файла. Пусто —
    берём общий путь кластера.
    """
    if host and host == (cluster.get("replica_ip") or "").strip():
        own = (cluster.get("replica_slow_log_path") or "").strip()
        if own:
            return own
    return (cluster.get("slow_log_path") or "/var/log/mysql/slow.log").strip()


def slow_log_archive(cluster: dict, host: str) -> str:
    """Каталог архивов slow-лога конкретного сервера."""
    if host and host == (cluster.get("replica_ip") or "").strip():
        own = (cluster.get("replica_slow_log_archive_dir") or "").strip()
        if own:
            return own
    return (cluster.get("slow_log_archive_dir") or "").strip()
