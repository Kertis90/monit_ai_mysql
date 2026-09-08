"""
Схемы запросов и ответов.

Вынесены из роутов отдельно: по ним строится Swagger, и внешние системы
(Zabbix и прочие) берут формат события именно отсюда.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    username: str
    password: str


class GrantRequest(BaseModel):
    """Выдача доступа. Роль ограничена двумя значениями осознанно:
    промежуточные права порождают вопросы «а что именно ему можно»."""
    username:     str
    display_name: str = ""
    email:        str = ""
    role:         str = "user"

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in ("user", "admin"):
            raise ValueError("Роль должна быть user или admin")
        return v

    @field_validator("username")
    @classmethod
    def _not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Пустой логин")
        return v


class UserOut(BaseModel):
    username:     str
    display_name: Optional[str] = ""
    email:        Optional[str] = ""
    role:         str = "user"
    enabled:      int = 1
    granted_by:   Optional[str] = ""
    granted_at:   Optional[str] = ""

    model_config = {"from_attributes": True}


class ChatRequest(BaseModel):
    message:    str
    session_id: Optional[str] = "rest"


class FeedbackRequest(BaseModel):
    rating:    int = Field(description="1 — ответ помог, -1 — не помог")
    question:  str = ""
    answer:    str = ""
    comment:   str = ""
    client_id: str = ""

    @field_validator("rating")
    @classmethod
    def _rating(cls, v: int) -> int:
        if v not in (1, -1):
            raise ValueError("Оценка: 1 или -1")
        return v


class IngestAlert(BaseModel):
    """Событие от внешней системы мониторинга.

    Формат намеренно плоский: его заполняют скриптом на стороне Zabbix, и чем
    меньше вложенности, тем меньше поводов ошибиться.
    """
    alert:       str = Field(description="Имя или тип события")
    summary:     str = Field("", description="Краткое описание")
    severity:    str = Field("warning", description="critical | warning | info")
    cluster:     str = Field("", description="Имя из clusters.json, если применимо")
    instance:    str = Field("", description="Хост:порт или просто хост")
    description: str = Field("", description="Подробности от внешней системы")
    source:      str = Field("api", description="zabbix, nagios, custom…")


class AlertOut(BaseModel):
    id:            int
    ts:            str
    alert:         Optional[str] = ""
    cluster:       Optional[str] = ""
    cluster_label: Optional[str] = ""
    instance:      Optional[str] = ""
    severity:      Optional[str] = ""
    summary:       Optional[str] = ""
    analysis:      Optional[str] = ""
    source:        Optional[str] = ""
    resolution:    Optional[str] = None
    resolved_by:   Optional[str] = None
    resolved_at:   Optional[str] = None

    model_config = {"from_attributes": True}


class ResolveRequest(BaseModel):
    resolution: str


class SqlRequest(BaseModel):
    cluster: str
    sql:     str
    host:    str = Field("", description="Пусто — primary кластера")


class SqlResult(BaseModel):
    host:      str = ""
    query:     str = ""
    columns:   list[str] = Field(default_factory=list)
    rows:      list[list[Any]] = Field(default_factory=list)
    truncated: bool = False
    via:       Optional[str] = None
    error:     Optional[str] = None


class DirectoryEntry(BaseModel):
    username:        str
    display_name:    str = ""
    email:           str = ""
    already_granted: bool = False


class DirectorySearchOut(BaseModel):
    items: list[DirectoryEntry] = Field(default_factory=list)
    query: str = ""
    error: str = ""


class UsersOut(BaseModel):
    items:              list[UserOut] = Field(default_factory=list)
    ldap_search:        bool = False
    ldap_search_reason: str = ""


class OkOut(BaseModel):
    ok: bool = True
