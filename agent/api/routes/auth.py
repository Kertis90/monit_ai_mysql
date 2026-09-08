"""Вход, выход и текущий пользователь: локальный админ, каталог, OIDC."""
from __future__ import annotations

import logging
import os
import secrets
import time
import urllib.parse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from agent.api.deps import Audit, MaybeUser
from agent.core.config import settings
from agent.core.security import AUTH_COOKIE, make_session
from agent.db.repositories.users import normalize
from agent.schemas.api import LoginRequest
from agent.services import access, audit, oidc

logger = logging.getLogger("agent.api.auth")
router = APIRouter(tags=["Доступ"])

# Куда отправить после выхода, если вход шёл через внешний портал
SSO_LOGOUT_URL = os.environ.get("SSO_LOGOUT_URL", "")


def _set_session(response: Response, username: str, source: str) -> None:
    response.set_cookie(
        AUTH_COOKIE, make_session(username, source),
        max_age=int(settings.auth.session_ttl_hours * 3600),
        httponly=True,      # недоступна из JS — защита от кражи сессии через XSS
        samesite="lax",
        path="/")


@router.post("/api/login", summary="Вход")
async def login(req: LoginRequest, response: Response, request: Request,
                journal: Audit):
    if not settings.auth.enabled:
        return {"ok": True, "username": "anonymous", "source": "disabled"}

    username = req.username.strip()
    source, err = await access.authenticate(username, req.password)
    if not source:
        logger.warning("Неудачный вход: %r — %s", username, err)
        await journal.add(action="вход отклонён", username=username,
                          detail=err, ip=audit.client_ip(request), ok=False)
        # Фиксируем до исключения: иначе откат транзакции унесёт с собой
        # запись именно о том, что важнее всего сохранить
        await journal.session.commit()
        # 403 именно для «доступ не выдан»: учётка верна, не хватает прав,
        # и человеку надо идти к администратору, а не подбирать пароль
        code = 403 if err == access.ERR_NO_ACCESS else 401
        raise HTTPException(status_code=code, detail=err)

    _set_session(response, username, source)
    logger.info("Вход: %s (источник: %s)", username, source)
    await journal.add(action="вход", username=username,
                      detail="источник: %s" % source,
                      ip=audit.client_ip(request))
    return {"ok": True, "username": username, "source": source}


@router.post("/api/logout", summary="Выход")
async def logout(response: Response):
    response.delete_cookie(AUTH_COOKIE, path="/")
    return {"ok": True, "sso_logout_url": SSO_LOGOUT_URL or None}


@router.get("/api/me", summary="Текущий пользователь")
async def me(user: MaybeUser):
    if not settings.auth.enabled:
        return {"authenticated": True, "username": "anonymous",
                "source": "disabled", "is_admin": True}
    if not user:
        raise HTTPException(status_code=401, detail="Требуется вход")
    return {"authenticated": True, "is_admin": await access.is_admin(user), **user}


# ── OIDC: Authorization Code Flow с PKCE ─────────────────────────────────────

@router.get("/auth/oidc/login", include_in_schema=False)
async def oidc_login(request: Request):
    if not (oidc.OIDC_ENABLED and oidc.OIDC_ISSUER and oidc.OIDC_CLIENT_ID):
        raise HTTPException(status_code=404, detail="OIDC не настроен")
    try:
        meta = await oidc.oidc_discover()
    except Exception as exc:
        logger.error("OIDC discovery не удался: %s", exc)
        raise HTTPException(status_code=502, detail="Провайдер OIDC недоступен")

    oidc._oidc_states_gc()
    verifier, challenge = oidc._pkce_pair()
    state = secrets.token_urlsafe(32)
    oidc._oidc_states[state] = (verifier, time.time() + oidc._OIDC_STATE_TTL)

    params = {
        "response_type":         "code",
        "client_id":             oidc.OIDC_CLIENT_ID,
        "redirect_uri":          oidc.oidc_redirect_uri(request),
        "scope":                 oidc.OIDC_SCOPES,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(
        meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params),
        status_code=302)


@router.get("/auth/oidc/callback", include_in_schema=False)
async def oidc_callback(request: Request, code: str = "", state: str = "",
                        error: str = ""):
    prefix = (request.scope.get("root_path") or settings.prefix).rstrip("/")

    def back(reason: str) -> RedirectResponse:
        return RedirectResponse(
            f"{prefix}/login?oidc_error=" + urllib.parse.quote(reason),
            status_code=302)

    if error:
        return back(error)
    if not code or not state:
        return back("Провайдер не вернул код авторизации")

    oidc._oidc_states_gc()
    # state одноразовый: так возврат нельзя воспроизвести повторно
    entry = oidc._oidc_states.pop(state, None)
    if not entry:
        return back("Сессия входа истекла, попробуйте ещё раз")
    verifier, _ = entry

    try:
        tokens = await oidc.oidc_exchange_code(code, verifier,
                                               oidc.oidc_redirect_uri(request))
        info   = await oidc.oidc_userinfo(tokens["access_token"])
    except Exception as exc:
        logger.error("OIDC: обмен кода не удался: %s", exc)
        return back("Не удалось получить данные пользователя")

    raw = str(info.get(oidc.OIDC_USERNAME_CLAIM) or info.get("email") or "").strip()
    if not raw:
        logger.error("OIDC: в userinfo нет поля %s", oidc.OIDC_USERNAME_CLAIM)
        return back("Провайдер не сообщил имя пользователя")

    username = normalize(raw)
    if not await access.access_allowed(username, "oidc"):
        logger.warning("OIDC-вход %s: доступ не выдан", username)
        return RedirectResponse(f"{prefix}/login?denied=1", status_code=302)

    resp = RedirectResponse(f"{prefix}/" if prefix else "/", status_code=302)
    _set_session(resp, username, "oidc")
    logger.info("Вход: %s (источник: oidc)", username)
    return resp
