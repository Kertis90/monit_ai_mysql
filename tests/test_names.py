"""Каждое глобальное имя, которое код загружает, должно существовать.

Ловит ровно тот класс ошибок, из-за которого рвался чат: функция перенесена
в другой модуль, а импорт за ней не поехал. Статически такое видно плохо,
а до выполнения этой ветки может пройти неделя.
"""
import builtins
import dis
import importlib
import os
import pkgutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

sys.stdout.reconfigure(encoding="utf-8")
os.environ.setdefault("DB_URL", "sqlite+aiosqlite:///"
                      + os.path.join(tempfile.gettempdir(), "names.db").replace("\\", "/"))
os.environ.setdefault("WEB_DIR", str(ROOT / "web"))
os.environ.setdefault("LDAP_ENABLED", "false")
os.environ.setdefault("REGISTRY_PATH", str(ROOT / "clusters.json"))
os.environ.setdefault("NSLCD_CONF", "")

import agent

CODE = type((lambda: None).__code__)


def codes(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, CODE):
            yield from codes(const)


bad = 0
for info in pkgutil.walk_packages(agent.__path__, "agent."):
    name = info.name
    try:
        module = importlib.import_module(name)
    except Exception as exc:
        print("  %-32s НЕ ИМПОРТИРУЕТСЯ: %s" % (name, exc)); bad += 1; continue

    missing = {}
    for value in vars(module).values():
        fn = getattr(value, "__wrapped__", value)
        code = getattr(fn, "__code__", None)
        if code is None or getattr(fn, "__module__", None) != name:
            continue
        for co in codes(code):
            for ins in dis.get_instructions(co):
                if ins.opname != "LOAD_GLOBAL":
                    continue
                ref = ins.argval
                if ref in vars(module) or hasattr(builtins, ref):
                    continue
                missing.setdefault(ref, fn.__name__)
    if missing:
        bad += 1
        print("  %-32s %s" % (name, ", ".join(
            "%s (в %s)" % (k, v) for k, v in sorted(missing.items()))))

print("")
print("модулей с неразрешёнными именами:", bad)
sys.exit(1 if bad else 0)
