"""
Вход через OIDC: Authorization Code Flow с PKCE.

Подпись ID-токена не проверяем: личность берём с userinfo, запрошенного по
TLS напрямую у провайдера с полученным access-токеном. Так не нужен разбор
JWKS и JWT, а доверие опирается на TLS к issuer.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time

from starlette.requests import Request
from typing import Optional

import httpx

from agent.core.config import settings


def _flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")

logger = logging.getLogger("agent.oidc")

OIDC_ENABLED       = _flag("OIDC_ENABLED")
OIDC_ISSUER        = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID     = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URL  = os.environ.get("OIDC_REDIRECT_URL", "")
OIDC_SCOPES        = os.environ.get("OIDC_SCOPES", "openid profile email")
OIDC_USERNAME_CLAIM = os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username")
OIDC_BUTTON_TEXT   = os.environ.get("OIDC_BUTTON_TEXT", "Войти через SSO")
OIDC_TLS_VERIFY    = _flag("OIDC_TLS_VERIFY", "true")

# Незавершённые входы: state -> (verifier, время). Живут минуты, поэтому
# память, а не база: перезапуск агента и так обрывает начатый вход.
_oidc_states: dict = {}
# Столько живёт начатый вход. Меньше — рвутся медленные
# провайдеры, больше — дольше висит одноразовый state
_OIDC_STATE_TTL = 600

# Ответ discovery меняется редко — держим его в памяти процесса
_OIDC_META: dict = {}

# Префикс за nginx нужен, чтобы собрать корректный redirect_uri
ROOT_PATH = settings.prefix


def _oidc_states_gc() -> None:
    now = time.time()
    for k in [k for k, (_, exp) in _oidc_states.items() if exp < now]:
        _oidc_states.pop(k, None)


async def oidc_discover() -> dict:
    """Метаданные провайдера. Кешируем — конфиг меняется редко."""
    global _OIDC_META
    if _OIDC_META:
        return _OIDC_META
    url = OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10, verify=OIDC_TLS_VERIFY) as client:
        r = await client.get(url)
        r.raise_for_status()
        _OIDC_META = r.json()
    return _OIDC_META


def _pkce_pair() -> tuple[str, str]:
    verifier  = secrets.token_urlsafe(64)[:96]
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


async def oidc_exchange_code(code: str, verifier: str, redirect_uri: str) -> dict:
    meta = await oidc_discover()
    data = {
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     OIDC_CLIENT_ID,
        "code_verifier": verifier,
    }
    if OIDC_CLIENT_SECRET:
        data["client_secret"] = OIDC_CLIENT_SECRET
    async with httpx.AsyncClient(timeout=15, verify=OIDC_TLS_VERIFY) as client:
        r = await client.post(meta["token_endpoint"], data=data)
        r.raise_for_status()
        return r.json()


async def oidc_userinfo(access_token: str) -> dict:
    meta = await oidc_discover()
    endpoint = meta.get("userinfo_endpoint")
    if not endpoint:
        raise RuntimeError("Провайдер не сообщил userinfo_endpoint")
    async with httpx.AsyncClient(timeout=15, verify=OIDC_TLS_VERIFY) as client:
        r = await client.get(endpoint,
                             headers={"Authorization": f"Bearer {access_token}"})
        r.raise_for_status()
        return r.json()


def oidc_redirect_uri(request: Request) -> str:
    """Явный OIDC_REDIRECT_URL надёжнее: за прокси схема и хост подменяются."""
    if OIDC_REDIRECT_URL:
        return OIDC_REDIRECT_URL
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    return str(request.base_url).rstrip("/") + prefix + "/auth/oidc/callback"
