"""
Модели хранилища.

Схема повторяет ту, что создавал прежний агент: существующие базы должны
подхватываться без переноса данных.

Время хранится строкой ISO-8601 в UTC, а не типом DATETIME. Причина не в
лени: так сравнение по периоду («всё, что старше») остаётся одинаковым в
SQLite и MySQL, лексикографический порядок совпадает с хронологическим, и
уже накопленные базы читаются как есть. Помощники to_iso/from_iso ниже
избавляют остальной код от работы со строками.
"""
from __future__ import annotations

import datetime
from typing import Optional

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from agent.db.base import Base

# Длины подобраны под MySQL: там у VARCHAR обязана быть длина, а индекс по
# слишком длинной колонке не помещается в ключ.
TS_LEN    = 32
NAME_LEN  = 190
LABEL_LEN = 255


def to_iso(moment: Optional[datetime.datetime] = None) -> str:
    """Момент времени в том виде, в каком он лежит в базе (UTC, ISO-8601)."""
    moment = moment or datetime.datetime.now(datetime.timezone.utc)
    if moment.tzinfo is not None:
        moment = moment.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return moment.isoformat()


def from_iso(value: Optional[str]) -> Optional[datetime.datetime]:
    """Обратное преобразование. None, если строка пустая или битая."""
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError:
        return None


def cutoff_iso(days: int) -> str:
    """Граница хранения: всё, что старше, подлежит удалению."""
    moment = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=days))
    return to_iso(moment)


class Alert(Base):
    """Событие мониторинга и разбор, который сделал агент.

    Разбор храним вместе с событием: без него повтор той же аварии заставляет
    LLM разбирать всё заново, а это и деньги, и время.
    """
    __tablename__ = "alerts"

    id:            Mapped[int] = mapped_column(Integer, primary_key=True,
                                               autoincrement=True)
    ts:            Mapped[str] = mapped_column(String(TS_LEN), nullable=False)
    alert:         Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    cluster:       Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    cluster_label: Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    instance:      Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    severity:      Mapped[Optional[str]] = mapped_column(String(32))
    summary:       Mapped[Optional[str]] = mapped_column(Text)
    analysis:      Mapped[Optional[str]] = mapped_column(Text)
    # Откуда пришло: alertmanager или внешняя система через /api/alerts/ingest
    source:        Mapped[Optional[str]] = mapped_column(String(64))
    # Память инцидентов: чем закончилось и кто закрыл
    resolution:    Mapped[Optional[str]] = mapped_column(Text)
    resolved_by:   Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    resolved_at:   Mapped[Optional[str]] = mapped_column(String(TS_LEN))

    def as_context(self) -> dict:
        """Словарь для блоков контекста и ленты событий.

        Ключ времени называется timestamp, а не ts: так его ждут форматтеры,
        и переименование ничего бы не улучшило, зато сломало бы вывод.
        """
        return {"id": self.id, "timestamp": self.ts, "alert": self.alert,
                "cluster": self.cluster, "cluster_label": self.cluster_label,
                "instance": self.instance, "severity": self.severity,
                "summary": self.summary, "analysis": self.analysis,
                "source": self.source, "resolution": self.resolution,
                "resolved_by": self.resolved_by, "resolved_at": self.resolved_at}

    __table_args__ = (
        Index("idx_alerts_ts", "ts"),
        # Поиск похожих инцидентов идёт по имени алерта и кластеру
        Index("idx_alerts_name", "alert", "cluster"),
    )


class User(Base):
    """Кому разрешён вход.

    Проверки пароля в домене мало: учётка должна быть выдана явно или попасть
    сюда автоматически по членству в разрешённой группе. Локального
    администратора здесь нет — это bootstrap-учётка, которой список и наполняют.
    """
    __tablename__ = "users"

    username:     Mapped[str] = mapped_column(String(NAME_LEN), primary_key=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    email:        Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    role:         Mapped[str] = mapped_column(String(16), nullable=False,
                                              default="user", server_default="user")
    enabled:      Mapped[int] = mapped_column(Integer, nullable=False,
                                              default=1, server_default="1")
    granted_by:   Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    granted_at:   Mapped[Optional[str]] = mapped_column(String(TS_LEN))

    @property
    def is_admin(self) -> bool:
        return bool(self.enabled) and self.role == "admin"


class ChatMessage(Base):
    """История переписки, разделённая по client_id.

    client_id — стабильный идентификатор браузера из localStorage. Логина у
    чата нет, поэтому история приватна ровно настолько, насколько приватен
    сам браузер; в интерфейсе это сказано прямо.
    """
    __tablename__ = "chat_messages"

    id:          Mapped[int] = mapped_column(Integer, primary_key=True,
                                             autoincrement=True)
    client_id:   Mapped[str] = mapped_column(String(NAME_LEN), nullable=False)
    session_id:  Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    ts:          Mapped[str] = mapped_column(String(TS_LEN), nullable=False)
    role:        Mapped[str] = mapped_column(String(16), nullable=False)
    content:     Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))

    __table_args__ = (Index("idx_chat_client_ts", "client_id", "ts"),)


class Feedback(Base):
    """Оценка ответа.

    Без неё непонятно, на каких вопросах агент промахивается систематически,
    и улучшения делаются вслепую.
    """
    __tablename__ = "feedback"

    id:        Mapped[int] = mapped_column(Integer, primary_key=True,
                                           autoincrement=True)
    ts:        Mapped[str] = mapped_column(String(TS_LEN), nullable=False)
    client_id: Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    username:  Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    rating:    Mapped[int] = mapped_column(Integer, nullable=False)
    question:  Mapped[Optional[str]] = mapped_column(Text)
    answer:    Mapped[Optional[str]] = mapped_column(Text)
    comment:   Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (Index("idx_feedback_ts", "ts"),)


class AuditEntry(Base):
    """Кто что сделал.

    Раньше это оседало в журнале systemd вперемешку с остальным выводом.
    При разборе «почему у него был доступ» или «кто снёс эти события» искать
    там неудобно, а после ротации журнала — уже негде.

    Таблица новая, поэтому создаётся сама и на существующих базах: create_all
    добавляет отсутствующие таблицы, хотя колонки в существующие не дописывает.
    """
    __tablename__ = "audit"

    id:       Mapped[int] = mapped_column(Integer, primary_key=True,
                                          autoincrement=True)
    ts:       Mapped[str] = mapped_column(String(TS_LEN), nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String(NAME_LEN))
    action:   Mapped[str] = mapped_column(String(64), nullable=False)
    target:   Mapped[Optional[str]] = mapped_column(String(LABEL_LEN))
    detail:   Mapped[Optional[str]] = mapped_column(Text)
    ip:       Mapped[Optional[str]] = mapped_column(String(64))
    ok:       Mapped[int] = mapped_column(Integer, nullable=False,
                                          default=1, server_default="1")

    __table_args__ = (Index("idx_audit_ts", "ts"),)
