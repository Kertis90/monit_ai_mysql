#!/usr/bin/env python3
"""
Проверка LDAP-входа: что именно отвечает каталог.

Форма входа отправляет пароль в JSON, оболочка его не трогает — поэтому
спецсимволы сами по себе вход не ломают. Причина почти всегда в другом: не тот
формат имени для bind, истёкший пароль, заблокированная учётка или опечатка в
DN группы. Каталог это знает, но агент пишет в лог коротко.

Скрипт берёт настройки из config.env, спрашивает логин и пароль и перебирает
все разумные формы имени, показывая ответ сервера по каждой.

    sudo ./scripts/ldap_test.py
    sudo ./scripts/ldap_test.py --user ivkop
"""
import getpass
import os
import re
import sys

# ldap3 стоит в окружении агента, а не в системном Python
try:
    import ldap3  # noqa: F401
except ImportError:
    VENV = "/opt/ai-alert-agent/venv/bin/python3"
    if os.path.exists(VENV) and os.environ.get("_LDAPTEST_REEXEC") != "1":
        os.environ["_LDAPTEST_REEXEC"] = "1"
        os.execv(VENV, [VENV, os.path.abspath(__file__)] + sys.argv[1:])
    print("Не найден пакет ldap3. Установите:")
    print("  /opt/ai-alert-agent/venv/bin/pip install ldap3")
    sys.exit(1)

import ssl
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars

# Та же таблица, что в agent.py: AD прячет причину в тексте ошибки
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


def ad_reason(text: str) -> str:
    m = re.search(r"data ([0-9a-fA-F]{3})", text or "")
    return AD_BIND_ERRORS.get(m.group(1).lower(), "") if m else ""


def read_config(path: str) -> dict:
    """Прочитать config.env, сняв кавычки. Секреты записаны в одинарных."""
    vals = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if not re.match(r"^[A-Z_][A-Z0-9_]*$", key):
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] == "'":
                val = val[1:-1].replace("'" + chr(92) + "''", "'")
            elif len(val) >= 2 and val[0] == val[-1] == '"':
                val = val[1:-1]
            vals[key] = val
    return vals


def connect(cfg: dict, user: str, password: str):
    """Bind под указанным именем. Исключение отдаём наверх целиком."""
    verify = (cfg.get("LDAP_TLS_VERIFY", "true").lower() == "true")
    tls = Tls(validate=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
    timeout = max(1, int(float(cfg.get("LDAP_TIMEOUT") or 8)))
    server = Server(cfg["LDAP_URL"], get_info=ALL, tls=tls,
                    connect_timeout=timeout)
    return Connection(server, user=user, password=password, auto_bind=True,
                      receive_timeout=timeout)


def describe_password(pw: str) -> None:
    """Состав пароля без его раскрытия — видно, дошёл ли он целиком."""
    letters   = sum(c.isalpha() for c in pw)
    digits    = sum(c.isdigit() for c in pw)
    special   = sum((not c.isalnum()) for c in pw)
    non_ascii = sum(ord(c) > 127 for c in pw)
    print("  символов: %d, в UTF-8 байт: %d" % (len(pw), len(pw.encode())))
    print("  букв: %d, цифр: %d, спецсимволов: %d, не-ASCII: %d"
          % (letters, digits, special, non_ascii))
    if non_ascii:
        print("  ! Есть не-ASCII символы. Сам по себе это не запрет, но в")
        print("    некоторых каталогах пароль хранится в другой кодировке.")


def candidates(cfg: dict, username: str) -> list:
    """Формы имени для bind — от настроенной к запасным."""
    base = cfg.get("LDAP_BASE_DN", "")
    dcs  = re.findall(r"DC=([^,]+)", base, re.I)
    out  = []

    tpl = cfg.get("LDAP_BIND_TEMPLATE", "{username}")
    out.append(("как настроено (LDAP_BIND_TEMPLATE)",
                tpl.format(username=username)))
    seen = {out[0][1]}
    if dcs:
        upn = "%s@%s" % (username, ".".join(dcs))
        if upn not in seen:
            out.append(("UPN из LDAP_BASE_DN", upn)); seen.add(upn)
        netbios = "%s%s%s" % (dcs[0].upper(), chr(92), username)
        if netbios not in seen:
            out.append(("домен\\имя (NetBIOS)", netbios)); seen.add(netbios)
    if username not in seen:
        out.append(("просто имя без домена", username))
    return out


def find_user_dn(cfg: dict, username: str):
    """Найти DN пользователя сервисной учёткой — самый надёжный вариант."""
    if not (cfg.get("LDAP_SEARCH_USER") and cfg.get("LDAP_BASE_DN")):
        return None, "не задан LDAP_SEARCH_USER — поиск по каталогу пропущен"
    try:
        conn = connect(cfg, cfg["LDAP_SEARCH_USER"],
                       cfg.get("LDAP_SEARCH_PASSWORD", ""))
    except Exception as e:
        why = ad_reason(str(e))
        return None, "сервисная учётка не подключается: %s%s" % (
            e, " (%s)" % why if why else "")
    flt = cfg.get("LDAP_USER_FILTER", "(sAMAccountName={username})").format(
        username=escape_filter_chars(username))
    try:
        conn.search(cfg["LDAP_BASE_DN"], flt, search_scope=SUBTREE,
                    attributes=["distinguishedName"])
        if not conn.entries:
            return None, "по фильтру %s никого не найдено" % flt
        return str(conn.entries[0].entry_dn), ""
    except Exception as e:
        return None, "ошибка поиска: %s" % e
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def check_groups(cfg: dict, username: str, conn) -> None:
    """Существуют ли указанные группы и входит ли в них пользователь."""
    raw = cfg.get("LDAP_ALLOWED_GROUPS", "").strip()
    if not raw:
        print("  LDAP_ALLOWED_GROUPS пуст — вход только по явной выдаче")
        print("  во вкладке «Доступы»")
        return
    groups = [g.strip() for g in raw.split(";") if g.strip()]
    base   = cfg.get("LDAP_BASE_DN", "")
    nested = cfg.get("LDAP_NESTED_GROUPS", "true").lower() == "true"
    rule   = ":1.2.840.113556.1.4.1941:" if nested else ""
    flt_u  = cfg.get("LDAP_USER_FILTER", "(sAMAccountName={username})").format(
        username=escape_filter_chars(username))

    for grp in groups:
        # Сначала проверяем, что такая группа вообще есть: опечатка в DN
        # выглядит точно так же, как отсутствие членства
        try:
            conn.search(base,
                        "(distinguishedName=%s)" % escape_filter_chars(grp),
                        search_scope=SUBTREE, attributes=["cn"])
            if not conn.entries:
                print("  [нет] %s" % grp)
                print("        группы с таким DN нет — проверьте строку целиком")
                continue
        except Exception as e:
            print("  [?]   %s — не удалось проверить: %s" % (grp, e))
            continue
        try:
            conn.search(base,
                        "(&%s(memberOf%s=%s))" % (flt_u, rule,
                                                  escape_filter_chars(grp)),
                        search_scope=SUBTREE, attributes=["cn"])
            mark = "[да]  входит      " if conn.entries else "[--]  не входит   "
            print("  %s %s" % (mark, grp))
        except Exception as e:
            print("  [?]   %s — ошибка проверки: %s" % (grp, e))


def main():
    args = sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    cfgp = os.path.join(os.path.dirname(here), "config.env")
    if not os.path.exists(cfgp):
        print("Не найден %s" % cfgp)
        sys.exit(1)
    cfg = read_config(cfgp)

    if not cfg.get("LDAP_URL"):
        print("LDAP_URL не задан в config.env")
        sys.exit(1)

    print("Настройки из config.env:")
    for k in ("LDAP_ENABLED", "LDAP_URL", "LDAP_BASE_DN", "LDAP_BIND_TEMPLATE",
              "LDAP_USER_FILTER", "LDAP_TLS_VERIFY", "LDAP_TIMEOUT",
              "LDAP_SEARCH_USER", "LDAP_NESTED_GROUPS"):
        print("  %-20s %s" % (k, cfg.get(k) or "(пусто)"))
    print("  %-20s %s" % ("LDAP_SEARCH_PASSWORD",
                          "задан" if cfg.get("LDAP_SEARCH_PASSWORD")
                          else "(пусто)"))
    print("")

    username = ""
    for i, a in enumerate(args):
        if a == "--user" and i + 1 < len(args):
            username = args[i + 1]
    if not username:
        username = input("Логин: ").strip()
    password = getpass.getpass("Пароль (не отображается): ")
    if not password:
        print("Пустой пароль каталог обычно принимает как анонимный bind —")
        print("проверка была бы бессмысленной.")
        sys.exit(1)

    print("")
    print("Что получил скрипт:")
    describe_password(password)

    print("")
    print("Пробую формы имени:")
    good = None
    for label, dn in candidates(cfg, username):
        try:
            conn = connect(cfg, dn, password)
            print("  [да]  %s" % dn)
            print("        %s — bind прошёл" % label)
            good = good or (dn, label)
            conn.unbind()
        except Exception as e:
            why = ad_reason(str(e))
            print("  [нет] %s" % dn)
            print("        %s: %s" % (label, why or type(e).__name__))
            if not why:
                print("        ответ: %s" % str(e)[:200])

    dn, err = find_user_dn(cfg, username)
    if dn:
        print("")
        print("DN пользователя в каталоге: %s" % dn)
        try:
            conn = connect(cfg, dn, password)
            print("  [да]  bind по полному DN прошёл")
            good = good or (dn, "полный DN")
            conn.unbind()
        except Exception as e:
            why = ad_reason(str(e))
            print("  [нет] bind по полному DN: %s" % (why or e))
    elif err:
        print("")
        print("Поиск в каталоге: %s" % err)

    if not good:
        print("")
        print("Итог: ни одна форма имени не подошла.")
        print("Если везде «неверный пароль» — дело действительно в пароле.")
        print("Если причина другая (истёк, заблокирован, отключён) — она")
        print("названа выше, и настройки агента менять не нужно.")
        sys.exit(1)

    print("")
    print("Итог: подходит %s" % good[0])
    tpl_now = cfg.get("LDAP_BIND_TEMPLATE", "")
    tpl_ok  = good[0].replace(username, "{username}")
    if tpl_now != tpl_ok:
        print("Сейчас в config.env: LDAP_BIND_TEMPLATE=\"%s\"" % tpl_now)
        print("Замените на:         LDAP_BIND_TEMPLATE=\"%s\"" % tpl_ok)
        print("и переустановите агента: sudo ./scripts/install_agent.sh")

    print("")
    print("Проверка групп доступа:")
    try:
        conn = connect(cfg, good[0], password)
        check_groups(cfg, username, conn)
        conn.unbind()
    except Exception as e:
        print("  не удалось проверить: %s" % e)


if __name__ == "__main__":
    main()
