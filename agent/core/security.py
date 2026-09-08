"""
Пароли и сессии.

Пароль администратора хранится только PBKDF2-хешем, сессия — подписанная
HMAC строка в HttpOnly-cookie. Ни то, ни другое не требует внешних библиотек:
в закрытом контуре каждая зависимость — отдельная история с внутренним
индексом pip.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from typing import Optional

from agent.core.config import settings

logger = logging.getLogger("agent.security")

AUTH_SECRET = settings.auth.secret
AUTH_SESSION_TTL_HOURS = settings.auth.session_ttl_hours
AUTH_COOKIE = "ai_agent_session"
# Столько же, сколько ставит configure.sh при создании хеша:
# при расхождении уже выданные пароли перестали бы подходить
PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: str = "", iterations: int = PBKDF2_ITERATIONS) -> str:
    """pbkdf2_sha256$<итераций>$<соль>$<хеш>. Только stdlib, без bcrypt."""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), int(iterations))
        # сравнение постоянного времени — не даём подбирать хеш по таймингу
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def make_session(username: str, source: str) -> str:
    exp     = int(time.time() + AUTH_SESSION_TTL_HOURS * 3600)
    payload = f"{username}|{source}|{exp}"
    sig     = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def read_session(token: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, source, exp, sig = raw.rsplit("|", 3)
        expected = hmac.new(AUTH_SECRET.encode(),
                            f"{username}|{source}|{exp}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < time.time():
            return None
        return {"username": username, "source": source, "expires": int(exp)}
    except Exception:
        return None
