"""
Каталог: LDAP и Active Directory.

Здесь только работа с каталогом — проверка пароля, поиск людей, членство в
группах и netgroup. Решение «пускать или нет» принимается слоем выше
(services/access.py): оно зависит ещё и от списка доступов в базе.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from agent.core.config import settings
from agent.db.repositories.users import normalize as norm_username

logger = logging.getLogger("agent.directory")

# Active Directory на любой отказ bind отвечает кодом 49, а настоящую причину
# прячет в тексте: "80090308: LdapErr ..., data 52e, ...". Без расшифровки
# просроченный пароль и отключённая учётка выглядят как опечатка в пароле.
AD_BIND_ERRORS = {
    "525": "пользователь не найден в каталоге",
    "52e": "неверный пароль",
    "530": "вход запрещён в это время суток",
    "531": "вход с этого компьютера запрещён",
    "532": "срок действия пароля истёк",
    "533": "учётная запись отключена",
    "701": "срок действия учётной записи истёк",
    "773": "требуется смена пароля при следующем входе",
    "775": "учётная запись заблокирована",
}

_L = settings.ldap
LDAP_ENABLED      = _L.enabled
LDAP_URL          = _L.url
LDAP_BIND_TEMPLATE = _L.bind_template
LDAP_BASE_DN      = _L.base_dn
LDAP_USER_BASE    = _L.user_base
LDAP_USER_FILTER  = _L.user_filter
LDAP_SEARCH_USER  = _L.search_user
LDAP_SEARCH_PASSWORD = _L.search_password
LDAP_SEARCH_FILTER = _L.search_filter
LDAP_SEARCH_MODE  = _L.search_mode
LDAP_ALLOWED_GROUPS = _L.allowed_groups
LDAP_ALLOWED_NETGROUPS = _L.allowed_netgroups
LDAP_NETGROUP_BASE = _L.netgroup_base
LDAP_NETGROUP_FILTER = _L.netgroup_filter
LDAP_NESTED_GROUPS = _L.nested_groups
LDAP_TLS_VERIFY   = _L.tls_verify
LDAP_TIMEOUT      = _L.timeout

# По этим атрибутам ищем человека. Логин в AD и в OpenLDAP называется
# по-разному, а фамилия — отдельная история: в posix-каталогах cn обычно
# равен логину, и настоящее ФИО лежит в sn, givenName или gecos. Без них
# поиск по фамилии не находил никого.
SEARCH_ATTRS = ("sAMAccountName", "uid", "cn", "displayName",
                "sn", "givenName", "gecos", "mail")

# (хост, пользователь, домен). Пробелы вокруг полей каталоги ставят по-разному.
NETGROUP_TRIPLE = re.compile(r"^\(\s*([^,]*?)\s*,\s*([^,]*?)\s*,\s*([^)]*?)\s*\)$")

# Коды, при которых каталог обрывает поиск сам. Различать обязательно: это
# не "никого нет", а "искать так нельзя".
LDAP_LIMIT_CODES = {
    3:  ("timeLimitExceeded", "каталог прервал поиск по времени"),
    4:  ("sizeLimitExceeded", "каталог вернул не всё: превышен предел записей"),
    11: ("adminLimitExceeded",
         "каталог прервал поиск по административному лимиту"),
}


def ad_reason(text: str) -> str:
    """Расшифровка кода AD из текста ошибки bind. Пусто, если кода нет."""
    m = re.search(r"data ([0-9a-fA-F]{3})", text or "")
    return AD_BIND_ERRORS.get(m.group(1).lower(), "") if m else ""


def ldap_conn(user: str, password: str):
    """Соединение с каталогом. Отдельная функция: bind нужен и для проверки
    пароля пользователя, и для чтения каталога.

    Пустое имя — анонимный bind. Так работает nslcd без binddn: во многих
    каталогах чтение открыто всем, и требовать сервисную учётку значило бы
    запрещать то, что каталог разрешает.
    """
    from ldap3 import Server, Connection, Tls, ALL
    import ssl as _ssl
    tls = Tls(validate=_ssl.CERT_REQUIRED if LDAP_TLS_VERIFY else _ssl.CERT_NONE)
    server = Server(LDAP_URL, get_info=ALL, tls=tls, connect_timeout=LDAP_TIMEOUT)
    if not user:
        return Connection(server, auto_bind=True, receive_timeout=LDAP_TIMEOUT)
    return Connection(server, user=user, password=password, auto_bind=True,
                      receive_timeout=LDAP_TIMEOUT)


def schema_attrs(conn) -> set:
    """Имена атрибутов, известные серверу, в нижнем регистре.

    Пустое множество означает «схему прочитать не удалось» — тогда ничего
    не отфильтровываем, чтобы не отрезать лишнего.
    """
    try:
        out = set()
        for key, val in (conn.server.schema.attribute_types or {}).items():
            out.add(str(key).lower())
            for alias in (getattr(val, "name", None) or ()):
                out.add(str(alias).lower())
        return out
    except Exception:
        return set()


def user_object_class() -> str:
    """Условие «это учётная запись человека» — из LDAP_USER_FILTER.

    Фильтр приходит из nslcd (строка `filter passwd`), то есть описывает
    ровно те объекты, которые каталог считает пользователями. Это надёжнее
    любых догадок про objectClass. Если условия там нет, перечисляем
    привычные варианты для AD и posix-каталогов.
    """
    m = re.search(r"\(objectClass=([A-Za-z0-9_-]+)\)", LDAP_USER_FILTER or "",
                  re.I)
    if m:
        return "(objectClass=%s)" % m.group(1)
    return "(|(objectClass=person)(objectClass=posixAccount))"


def build_search_filter(known: set, safe_query: str) -> str:
    """Фильтр поиска только из тех атрибутов, что есть в схеме."""
    usable = [a for a in SEARCH_ATTRS
              if not known or a.lower() in known] or ["cn"]
    tmpl = "*%s*" if LDAP_SEARCH_MODE == "contains" else "%s*"
    pat  = tmpl % safe_query
    return ("(&" + user_object_class() + "(|"
            + "".join("(%s=%s)" % (a, pat) for a in usable) + "))")


def limit_advice(base: str) -> str:
    """Что делать, если сервер оборвал поиск."""
    tips = []
    if LDAP_SEARCH_MODE == "contains":
        tips.append("уберите LDAP_SEARCH_MODE=contains — поиск по вхождению "
                    "не может использовать индекс")
    if not LDAP_USER_BASE:
        tips.append("сузьте ветку поиска: задайте LDAP_USER_BASE, например "
                    "ou=people,%s" % base)
    tips.append("либо задайте свой LDAP_SEARCH_FILTER по индексированному "
                "атрибуту")
    return "; ".join(tips)


def login_attr() -> str:
    """Атрибут имени входа — тот же, по которому проверяется пароль.

    Иначе доступ выдаётся на одно имя, а входит человек под другим: в AD это
    sAMAccountName, в OpenLDAP — uid.
    """
    m = re.search(r"\(([A-Za-z]+)=\{username\}\)", LDAP_USER_FILTER or "")
    return m.group(1) if m else "sAMAccountName"


def directory_search_status() -> str:
    """Пусто — поиск по каталогу доступен. Иначе причина, почему нет.

    Раньше поиск просто исчезал из интерфейса, и администратор видел пустой
    список без единой подсказки, что чинить.
    """
    if not LDAP_ENABLED:
        return "LDAP выключен: LDAP_ENABLED=false в config.env"
    if not LDAP_URL:
        return "не задан LDAP_URL"
    if not (LDAP_USER_BASE or LDAP_BASE_DN):
        return "не заданы ни LDAP_USER_BASE, ни LDAP_BASE_DN — негде искать"
    return ""


def ldap_search_users(query: str, limit: int = 25) -> tuple:
    """(найденные, ошибка) — поиск кандидатов на выдачу доступа.

    Ошибку возвращаем текстом, а не глотаем: пустой список и неверная
    настройка выглядят в интерфейсе одинаково, и искать причину негде.
    """
    why = directory_search_status()
    if why:
        logger.error("Поиск по каталогу недоступен: " + why)
        return [], why
    q = (query or "").strip()
    if len(q) < 2:
        return [], ""
    try:
        from ldap3 import Server, Connection, Tls, ALL, SUBTREE
        from ldap3.utils.conv import escape_filter_chars
        import ssl as _ssl
    except ImportError:
        logger.error("Поиск по каталогу требует пакета ldap3")
        return [], "не установлен пакет ldap3"
    try:
        safe = escape_filter_chars(q)      # защита от инъекции в LDAP-фильтр
        tls = Tls(validate=_ssl.CERT_REQUIRED if LDAP_TLS_VERIFY else _ssl.CERT_NONE)
        server = Server(LDAP_URL, get_info=ALL, tls=tls, connect_timeout=LDAP_TIMEOUT)
        conn = (Connection(server, auto_bind=True,
                           receive_timeout=LDAP_TIMEOUT)
                if not LDAP_SEARCH_USER else
                Connection(server, user=LDAP_SEARCH_USER,
                           password=LDAP_SEARCH_PASSWORD, auto_bind=True,
                           receive_timeout=LDAP_TIMEOUT))
        known = schema_attrs(conn)
        flt = (LDAP_SEARCH_FILTER.replace("{query}", safe)
               if LDAP_SEARCH_FILTER else build_search_filter(known, safe))
        base = LDAP_USER_BASE or LDAP_BASE_DN
        logger.info(
            "Поиск в каталоге: сервер %s, вход %s, база %s, режим %s",
            LDAP_URL, LDAP_SEARCH_USER or "анонимно", base, LDAP_SEARCH_MODE)
        logger.info("Поиск в каталоге: схема %s, фильтр %s",
                    ("прочитана, %d атрибутов" % len(known)) if known
                    else "НЕ прочитана", flt)
        # Порядок важен: сначала атрибут, по которому идёт вход, иначе доступ
        # будет выдан на имя, под которым человек не входит
        primary = login_attr()
        names = [primary] + [a for a in ("sAMAccountName", "uid",
                                         "userPrincipalName")
                             if a.lower() != primary.lower()]
        # Запрашивать атрибут, которого нет в схеме, нельзя: ldap3 сверяет
        # имена и бросает LDAPAttributeError ещё до отправки запроса
        names = [a for a in names if not known or a.lower() in known]
        if not names:
            return [], ("в схеме каталога нет ни одного из атрибутов имени "
                        "(%s) — укажите свой LDAP_USER_FILTER"
                        % ", ".join((primary, "sAMAccountName", "uid")))
        extra = [a for a in ("displayName", "cn", "mail")
                 if not known or a.lower() in known]
        conn.search(base, flt, search_scope=SUBTREE,
                    attributes=names + extra, size_limit=limit)
        res = getattr(conn, "result", None) or {}
        logger.info(
            "Поиск в каталоге: запрошены %s, ответ %s (%s), записей %d",
            names + extra, res.get("description", "?"),
            res.get("message") or "без пояснений", len(conn.entries))

        code = res.get("result")
        if code in LDAP_LIMIT_CODES and not conn.entries:
            name, human = LDAP_LIMIT_CODES[code]
            advice = limit_advice(LDAP_BASE_DN)
            logger.error("Поиск в каталоге: %s (%s). %s", human, name, advice)
            return [], "%s (%s). %s" % (human, name, advice)
        if not conn.entries:
            # Тот же поиск без условия по objectClass: если так находится,
            # значит дело именно в нём, а не в атрибутах или базе
            probe = "(|" + "".join("(%s=*%s*)" % (a, safe)
                                   for a in (names + extra)) + ")"
            try:
                conn.search(base, probe, search_scope=SUBTREE,
                            attributes=[], size_limit=5)
                if conn.entries:
                    logger.warning(
                        "Поиск в каталоге: без условия %s нашлось %d записей "
                        "(например %s). Условие не подходит вашему каталогу — "
                        "задайте LDAP_SEARCH_FILTER вручную",
                        user_object_class(), len(conn.entries),
                        conn.entries[0].entry_dn)
                else:
                    logger.info(
                        "Поиск в каталоге: и без условия по objectClass "
                        "ничего нет — под базой %s такого текста не найдено",
                        base)
            except Exception as probe_err:
                logger.info("Поиск в каталоге: проверочный запрос не удался: %s",
                            probe_err)
            conn.search(base, flt, search_scope=SUBTREE,
                        attributes=names + extra, size_limit=limit)
        out = []
        for e in conn.entries:
            def attr(name):
                v = getattr(e, name, None)
                return str(v) if v and str(v) != "[]" else ""
            login = next((attr(n) for n in names if attr(n)), "")
            if not login:
                continue
            out.append({
                "username":     norm_username(login),
                "display_name": attr("displayName") or attr("cn") or login,
                "email":        attr("mail"),
            })
        conn.unbind()
        return out, ""
    except Exception as e:
        logger.error(f"Поиск по каталогу не удался: {e}")
        why = ad_reason(str(e))
        hint = ("" if LDAP_SEARCH_USER else
                ". Искали анонимно — если каталог этого не разрешает, "
                "заполните LDAP_SEARCH_USER и LDAP_SEARCH_PASSWORD")
        return [], ((f"каталог ответил: {why}" if why
                     else f"{type(e).__name__}: {e}") + hint)


def _dir_conn(conn):
    """(соединение, открыли ли мы его сами) для поиска по каталогу.

    Отдельно, потому что проверок теперь две — группы и netgroup, — и открывать
    ради них два соединения незачем.
    """
    if conn is not None:
        return conn, False
    try:
        return ldap_conn(LDAP_SEARCH_USER, LDAP_SEARCH_PASSWORD), True
    except Exception as e:
        how = "сервисной учёткой" if LDAP_SEARCH_USER else "анонимно"
        logger.error(f"Не удалось подключиться к каталогу {how}: {e}"
                     + ("" if LDAP_SEARCH_USER else
                        ". Каталог не разрешает анонимное чтение — заполните "
                        "LDAP_SEARCH_USER и LDAP_SEARCH_PASSWORD"))
        return None, False


def _attr(entry, name: str) -> list:
    """Значения атрибута без оглядки на регистр имени, всегда списком."""
    data = entry.entry_attributes_as_dict
    for key, val in data.items():
        if key.lower() == name.lower():
            if val is None:
                return []
            return val if isinstance(val, list) else [val]
    return []


def netgroup_members(conn, name: str, seen=None, depth: int = 0) -> tuple:
    """(имена пользователей, есть ли триплет-шаблон) в netgroup и вложенных.

    Пустое поле пользователя в триплете по правилам NIS означает «любой», а
    дефис — «никто». Различать обязательно: (-,,) открыл бы вход всем.
    """
    seen = seen if seen is not None else set()
    users, any_user = set(), False
    key = name.lower()
    if key in seen or depth > 10:      # netgroup умеет ссылаться сама на себя
        return users, any_user
    seen.add(key)

    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    base = LDAP_NETGROUP_BASE or LDAP_BASE_DN
    flt  = "(&%s(cn=%s))" % (LDAP_NETGROUP_FILTER, escape_filter_chars(name))
    conn.search(base, flt, search_scope=SUBTREE,
                attributes=["nisNetgroupTriple", "memberNisNetgroup"])
    if not conn.entries:
        logger.warning(f"Netgroup {name} не найдена в {base}")
        return users, any_user

    for entry in conn.entries:
        for triple in _attr(entry, "nisNetgroupTriple"):
            m = NETGROUP_TRIPLE.match(str(triple).strip())
            if not m:
                continue
            who = m.group(2)
            if who == "":
                any_user = True        # шаблон: подходит кто угодно
            elif who != "-":
                users.add(who.lower())
        for nested in _attr(entry, "memberNisNetgroup"):
            sub_users, sub_any = netgroup_members(conn, str(nested), seen, depth + 1)
            users |= sub_users
            any_user = any_user or sub_any
    return users, any_user


def ldap_matched_netgroups(username: str, conn=None) -> list:
    """Какие из разрешённых netgroup содержат пользователя."""
    if not LDAP_ALLOWED_NETGROUPS:
        return []
    if not (LDAP_NETGROUP_BASE or LDAP_BASE_DN):
        logger.error("Заданы netgroup, но искать негде: пусты и "
                     "LDAP_NETGROUP_BASE, и LDAP_BASE_DN")
        return []
    try:
        from ldap3 import SUBTREE  # noqa: F401
    except ImportError:
        logger.error("Проверка netgroup требует пакета ldap3")
        return []

    conn, own_conn = _dir_conn(conn)
    if conn is None:
        return []
    who = (username or "").lower()
    matched = []
    try:
        for ng in LDAP_ALLOWED_NETGROUPS:
            try:
                users, any_user = netgroup_members(conn, ng, set())
            except Exception as e:
                logger.error(f"Netgroup {ng}: ошибка чтения — {e}")
                continue
            if any_user:
                logger.warning(
                    f"Netgroup {ng} содержит триплет с пустым полем "
                    f"пользователя — по правилам NIS это «любой», вход "
                    f"открыт всем в каталоге")
            if any_user or who in users:
                matched.append(ng)
    finally:
        if own_conn:
            try:
                conn.unbind()
            except Exception:
                pass
    return matched


def ldap_matched_groups(username: str, conn=None) -> list:
    """Какие из разрешённых групп содержат пользователя.

    Пустой список означает «ни в одной». Если список разрешённых групп
    не задан, возвращается ['*'] — членство не проверяется.

    conn — уже открытое соединение (например, bind самого пользователя).
    Если его нет, ищем сервисной учёткой: для SSO и OIDC пароля пользователя
    у нас нет вовсе.
    """
    if not LDAP_ALLOWED_GROUPS:
        return ["*"]
    if not LDAP_BASE_DN:
        logger.error("Заданы группы доступа, но LDAP_BASE_DN пуст — "
                     "проверить членство невозможно")
        return []

    try:
        from ldap3 import SUBTREE
        from ldap3.utils.conv import escape_filter_chars
    except ImportError:
        logger.error("Проверка групп требует пакета ldap3")
        return []

    conn, own_conn = _dir_conn(conn)
    if conn is None:
        return []

    # 1.2.840.113556.1.4.1941 — правило AD «член в том числе через вложенность».
    # Без него пользователь во вложенной группе выглядит как посторонний,
    # а вложенные группы в AD встречаются постоянно.
    known = schema_attrs(conn)
    if known and "memberof" not in known:
        logger.warning(
            "В схеме каталога нет memberOf — проверка групп пропущена. "
            "Так бывает в OpenLDAP без overlay memberof; используйте "
            "LDAP_ALLOWED_NETGROUPS")
        if own_conn:
            try:
                conn.unbind()
            except Exception:
                pass
        return []

    rule = ":1.2.840.113556.1.4.1941:" if LDAP_NESTED_GROUPS else ""
    safe = escape_filter_chars(username)
    matched = []
    try:
        for grp in LDAP_ALLOWED_GROUPS:
            flt = ("(&" + LDAP_USER_FILTER.format(username=safe) +
                   "(memberOf" + rule + "=" + grp + "))")
            conn.search(LDAP_BASE_DN, flt, search_scope=SUBTREE, attributes=["cn"])
            if conn.entries:
                matched.append(grp)
    except Exception as e:
        logger.error(f"Поиск групп для {username} не удался: {e}")
        matched = []
    finally:
        if own_conn:
            try:
                conn.unbind()
            except Exception:
                pass
    return matched


def ldap_authenticate(username: str, password: str) -> bool:
    """Проверка пароля в каталоге. Членство в группах проверяется отдельно —
    в authenticate(), чтобы разделить «неверный пароль» и «нет доступа»."""
    if not (LDAP_ENABLED and LDAP_URL and username and password):
        return False
    try:
        import ldap3  # noqa: F401
    except ImportError:
        logger.error("LDAP включён, но пакет ldap3 не установлен. "
                     "Поставьте: /opt/ai-alert-agent/venv/bin/pip install ldap3")
        return False
    try:
        conn = ldap_conn(LDAP_BIND_TEMPLATE.format(username=username), password)
        conn.unbind()
        return True
    except Exception as e:
        # Тип исключения важен: LDAPBindError — это просто неверный пароль,
        # а всё остальное (struct.error, LDAPSocketOpenError, LDAPException)
        # означает неисправную настройку, и по одному тексту их не различить.
        kind = type(e).__name__
        if kind in ("LDAPBindError", "LDAPInvalidCredentialsResult"):
            why = ad_reason(str(e))
            logger.warning(
                f"LDAP: bind {LDAP_BIND_TEMPLATE.format(username=username)} "
                f"отклонён — {why or 'каталог не назвал причину'}. "
                f"Ответ сервера: {e}")
        else:
            logger.error(f"LDAP-аутентификация {username} не прошла "
                         f"({kind}): {e}. Это сбой подключения или настройки, "
                         f"а не пароль пользователя")
        return False
