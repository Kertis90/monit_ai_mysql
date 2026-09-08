#!/usr/bin/env python3
"""
Импорт настроек LDAP из /etc/nslcd.conf в config.env.

Зачем: параметры подключения к каталогу уже описаны в nslcd — переписывать их
руками значит рисковать опечаткой в DN. Скрипт читает готовый конфиг и
заполняет всё, кроме групп доступа: их указывает администратор.

    sudo ./scripts/import_nslcd.py                 # показать, что получится
    sudo ./scripts/import_nslcd.py --write         # записать в config.env
    sudo ./scripts/import_nslcd.py --write \\
         --groups 'CN=DBA,OU=Groups,DC=company,DC=ru'
    sudo ./scripts/import_nslcd.py --write --netgroups 'dba;monitoring'

Соответствие параметров:

    nslcd.conf              config.env
    ----------------------  ---------------------------
    uri                     LDAP_URL
    base                    LDAP_BASE_DN
    binddn / bindpw         LDAP_SEARCH_USER / LDAP_SEARCH_PASSWORD
    filter passwd           LDAP_USER_FILTER (шаблон с {username})
    ssl / tls_reqcert       LDAP_TLS_VERIFY
    bind_timelimit          LDAP_TIMEOUT
    base passwd             LDAP_USER_BASE
    base netgroup           LDAP_NETGROUP_BASE
    filter netgroup         LDAP_NETGROUP_FILTER

Строка "base <карта> <dn>" задаёт ветку только для этой карты и общий base
не заменяет — иначе пользователей искали бы в ветке netgroup.
"""
import os
import re
import sys

NSLCD = "/etc/nslcd.conf"


def parse_nslcd(path: str) -> dict:
    """Разобрать nslcd.conf. Формат простой: ключ, пробел, значение."""
    cfg = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].lower(), parts[1].strip()
            # base, map и filter встречаются несколько раз — храним списком.
            # base особенно важен: строка "base netgroup ou=..." затёрла бы
            # общий base, и агент искал бы пользователей в ветке netgroup.
            if key in ("map", "filter", "base"):
                cfg.setdefault(key, []).append(val)
            else:
                cfg[key] = val
    return cfg


# Карты nslcd: "base <карта> <dn>" задаёт ветку только для неё
NSLCD_MAPS = {"alias", "aliases", "ether", "ethers", "group", "host", "hosts",
              "netgroup", "network", "networks", "passwd", "protocol",
              "protocols", "rpc", "service", "services", "shadow"}


def bases(cfg: dict) -> dict:
    """Ветки поиска: ключ "" — общая, остальные — по имени карты."""
    out = {}
    for val in cfg.get("base", []):
        parts = val.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in NSLCD_MAPS:
            out.setdefault(parts[0].lower(), parts[1].strip())
        else:
            out.setdefault("", val.strip())
    return out


def map_filter(cfg: dict, name: str) -> str:
    """Строка "filter <карта> (...)" — фильтр объектов этой карты."""
    for f in cfg.get("filter", []):
        parts = f.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == name:
            return parts[1].strip()
    return ""


def user_filter(cfg: dict) -> str:
    """Фильтр поиска пользователя с подстановкой {username}.

    В nslcd фильтр записан как `filter passwd (...)` и НЕ содержит места для
    имени: nslcd подставляет его сам через map. Поэтому берём objectClass из
    фильтра и добавляем условие по атрибуту имени.
    """
    uid_attr = ""
    for m in cfg.get("map", []):
        # напр.: map passwd uid sAMAccountName
        parts = m.split()
        if len(parts) >= 4 and parts[0] == "passwd" and parts[1] == "uid":
            uid_attr = parts[3]
            break

    obj = ""
    for f in cfg.get("filter", []):
        if f.startswith("passwd "):
            body = f[len("passwd "):].strip()
            m = re.search(r"objectClass=([A-Za-z0-9_-]+)", body, re.I)
            if m:
                obj = m.group(1)
            break

    if not uid_attr:
        # map не задан — угадываем по типу каталога: в AD имя входа лежит
        # в sAMAccountName, в OpenLDAP/posix — в uid
        ad = (obj or "").lower() in ("user", "person", "organizationalperson")
        uid_attr = "sAMAccountName" if ad else "uid"

    cond = "(%s={username})" % uid_attr
    return "(&(objectClass=%s)%s)" % (obj, cond) if obj else cond


def bind_template(cfg: dict) -> str:
    """Шаблон bind-DN для проверки пароля пользователя.

    Сам nslcd так не делает — он ищет DN сервисной учёткой, а потом биндится.
    Нам нужен шаблон. Для AD надёжнее всего UPN: user@domain, домен собираем
    из base DN.
    """
    b = bases(cfg)
    base = b.get("") or b.get("passwd", "")
    dcs = re.findall(r"DC=([^,]+)", base, re.I)
    return "{username}@" + ".".join(dcs) if dcs else "{username}"


def tls_verify(cfg: dict) -> str:
    """tls_reqcert never|allow — проверка отключена."""
    req = (cfg.get("tls_reqcert") or "").lower()
    return "false" if req in ("never", "allow") else "true"


def build(cfg: dict, groups: str, netgroups: str = "") -> dict:
    uri = (cfg.get("uri") or "").split()[0] if cfg.get("uri") else ""
    b   = bases(cfg)
    # Ветка netgroup обычно своя; если отдельной строки нет, ищем от общей
    ng_base   = b.get("netgroup", "")
    ng_filter = map_filter(cfg, "netgroup") or "(objectClass=nisNetgroup)"
    return {
        "LDAP_ENABLED":         "true",
        "LDAP_URL":             uri,
        "LDAP_BASE_DN":         b.get("") or b.get("passwd", ""),
        "LDAP_USER_BASE":       b.get("passwd", ""),
        "LDAP_ALLOWED_NETGROUPS": netgroups,
        "LDAP_NETGROUP_BASE":   ng_base,
        "LDAP_NETGROUP_FILTER": ng_filter,
        "LDAP_BIND_TEMPLATE":   bind_template(cfg),
        "LDAP_USER_FILTER":     user_filter(cfg),
        "LDAP_SEARCH_USER":     cfg.get("binddn", ""),
        "LDAP_SEARCH_PASSWORD": cfg.get("bindpw", ""),
        "LDAP_TLS_VERIFY":      tls_verify(cfg),
        "LDAP_TIMEOUT":         cfg.get("bind_timelimit", "8"),
        "LDAP_ALLOWED_GROUPS":  groups,
        "LDAP_NESTED_GROUPS":   "true",
    }


def write_config(path: str, values: dict) -> None:
    """Заменить существующие строки, недостающие дописать в конец."""
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()

    left = dict(values)
    for i, line in enumerate(lines):
        m = re.match(r'^\s*([A-Z_]+)\s*=', line)
        if m and m.group(1) in left:
            key = m.group(1)
            lines[i] = '%s="%s"\n' % (key, left.pop(key))
    if left:
        lines.append("\n# Импортировано из %s\n" % NSLCD)
        lines += ['%s="%s"\n' % (k, v) for k, v in left.items()]

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.chmod(path, 0o600)


def main():
    args   = sys.argv[1:]
    write  = "--write" in args
    src    = NSLCD
    groups = ""
    netgroups = ""
    for i, a in enumerate(args):
        if a == "--groups" and i + 1 < len(args):
            groups = args[i + 1]
        if a == "--netgroups" and i + 1 < len(args):
            netgroups = args[i + 1]
        if a == "--file" and i + 1 < len(args):
            src = args[i + 1]

    if not os.path.exists(src):
        print("Не найден %s. Укажите путь: --file /путь/к/nslcd.conf" % src)
        sys.exit(1)

    cfg    = parse_nslcd(src)
    values = build(cfg, groups, netgroups)

    if not values["LDAP_URL"]:
        print("В %s нет параметра uri — подключаться некуда." % src)
        sys.exit(1)

    print("Из %s получено:\n" % src)
    for k, v in values.items():
        shown = "***" if k.endswith("PASSWORD") and v else (v or "(пусто)")
        print("  %-22s %s" % (k, shown))

    if not values["LDAP_SEARCH_USER"]:
        print("")
        print("  В nslcd.conf нет binddn — каталог опрашивается анонимно.")
        print("  Агент тоже будет читать его анонимно: и вход, и поиск учёток")
        print("  во вкладке «Доступы». Если каталог анонимное чтение не")
        print("  разрешает, поиск об этом скажет — тогда пропишите сервисную")
        print("  учётку вручную в config.env:")
        print("    LDAP_SEARCH_USER=\"CN=svc-ldap,OU=Service,DC=company,DC=ru\"")
        print("    LDAP_SEARCH_PASSWORD=\"...\"")

    if not (groups or netgroups):
        print("")
        print("  Ни группы, ни netgroup не заданы — вход будет только по")
        print("  явно выданным доступам. Укажите то, чем у вас описан состав:")
        print("    --groups    'CN=DBA,OU=Groups,DC=company,DC=ru'")
        print("    --netgroups 'dba;monitoring'")
        if values["LDAP_NETGROUP_BASE"]:
            print("")
            print("  В nslcd.conf есть ветка netgroup — %s"
                  % values["LDAP_NETGROUP_BASE"])
            print("  Посмотреть, какие netgroup там лежат:")
            print("    ldapsearch -x -b '%s' '(objectClass=nisNetgroup)' cn"
                  % values["LDAP_NETGROUP_BASE"])

    if not write:
        print("\nЭто предпросмотр. Для записи добавьте --write")
        return

    here   = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(os.path.dirname(here), "config.env")
    if not os.path.exists(target):
        print("\nНе найден %s — сначала запустите ./configure.sh" % target)
        sys.exit(1)

    write_config(target, values)
    print("\nЗаписано в %s" % target)
    print("Дальше: sudo ./scripts/install_agent.sh")


if __name__ == "__main__":
    main()
