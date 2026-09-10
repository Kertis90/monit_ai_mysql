"""Каждый вызов своей же функции должен подходить под её сигнатуру.

Ловит класс ошибок, который дважды доходил до боевого агента: у функции
поменяли сигнатуру, поправили один вызов из трёх, а остальные упали уже у
пользователя — `fmt_diagnostics() missing 2 required positional arguments`.
Имена при этом разрешаются, и test_names.py такое пропускает.

Проверяются только вызовы функций самого агента и только там, где всё
известно статически: без `*args`, `**kwargs` и вычисляемых имён. Всё
неоднозначное пропускается молча — задача не «поймать всё», а не пропускать
то, что видно наверняка.
"""
import ast
import importlib
import inspect
import os
import pkgutil
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

sys.stdout.reconfigure(encoding="utf-8")
os.environ.setdefault("DB_URL", "sqlite+aiosqlite:///"
                      + os.path.join(tempfile.gettempdir(), "calls.db").replace("\\", "/"))
os.environ.setdefault("WEB_DIR", str(ROOT / "web"))
os.environ.setdefault("LDAP_ENABLED", "false")
os.environ.setdefault("REGISTRY_PATH", str(ROOT / "clusters.json"))
os.environ.setdefault("NSLCD_CONF", "")

import agent


def target(node: ast.Call, namespace: dict):
    """Что вызывают: функция агента или ничего, что мы умеем проверить."""
    func = node.func
    if isinstance(func, ast.Name):
        found = namespace.get(func.id)
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        holder = namespace.get(func.value.id)
        # Только модули: у объекта атрибут может появиться в любой момент,
        # и статически про него ничего не известно
        if not isinstance(holder, types.ModuleType):
            return None
        found = getattr(holder, func.attr, None)
    else:
        return None

    if found is None:
        return None
    owner = getattr(found, "__module__", "") or ""
    if not owner.startswith("agent"):
        return None                     # чужой код — не наша забота
    if not (inspect.isfunction(found) or inspect.isclass(found)):
        return None
    return found


def problem(node: ast.Call, func) -> str:
    """Пусто, если вызов сходится с сигнатурой."""
    if any(isinstance(a, ast.Starred) for a in node.args):
        return ""                       # разворачивают список — счёт не известен
    if any(kw.arg is None for kw in node.keywords):
        return ""                       # **kwargs — то же самое
    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return ""                       # встроенное или обёрнутое — пропускаем
    args = [None] * len(node.args)
    kwargs = {kw.arg: None for kw in node.keywords}
    try:
        sig.bind(*args, **kwargs)
    except TypeError as exc:
        return str(exc)
    return ""


def shadowed(tree: ast.AST):
    """Вложенные функции, чьё имя в той же области затирают переменной.

    Ровно так сломался сбор метрик: внутри build_chat_context объявлена
    функция step(), а ниже по коду `step = parse_step_seconds(...)` —
    и следующий её вызов упал с «'int' object is not callable». Имена
    разрешаются, сигнатуры сходятся, а работает до первой такой строки.
    """
    SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

    def own_nodes(scope):
        """Узлы этой области: во вложенные функции не заходим — там своё
        пространство имён, и присваивание в них ничего не затирает."""
        stack = list(ast.iter_child_nodes(scope))
        while stack:
            node = stack.pop()
            yield node
            if not isinstance(node, SCOPES):
                stack.extend(ast.iter_child_nodes(node))

    found = []
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, SCOPES)]
    for scope in scopes:
        body = getattr(scope, "body", [])
        if not isinstance(body, list):
            continue
        defs = {c.name: c.lineno for c in body
                if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if not defs:
            continue
        for node in own_nodes(scope):
            targets = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                targets = [node.target]
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                targets = [node.target]
            for t in targets:
                for name in ast.walk(t):
                    if isinstance(name, ast.Name) and name.id in defs:
                        found.append((name.id, defs[name.id], name.lineno))
    return found


bad = 0
checked = 0
for info in pkgutil.walk_packages(agent.__path__, "agent."):
    name = info.name
    try:
        module = importlib.import_module(name)
    except Exception as exc:
        print("  %-32s НЕ ИМПОРТИРУЕТСЯ: %s" % (name, exc))
        bad += 1
        continue

    source_file = getattr(module, "__file__", None)
    if not source_file or not source_file.endswith(".py"):
        continue
    try:
        tree = ast.parse(Path(source_file).read_text(encoding="utf-8"))
    except SyntaxError as exc:
        print("  %-32s НЕ РАЗБИРАЕТСЯ: %s" % (name, exc))
        bad += 1
        continue

    for name_, def_line, use_line in shadowed(tree):
        bad += 1
        print("  %s:%d  переменная затирает функцию %s() (объявлена на %d)"
              % (name, use_line, name_, def_line))

    namespace = vars(module)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = target(node, namespace)
        if func is None:
            continue
        checked += 1
        why = problem(node, func)
        if why:
            bad += 1
            print("  %s:%d  %s(...) — %s"
                  % (name, node.lineno, getattr(func, "__name__", "?"), why))

print("")
print("проверено вызовов: %d, несогласованных: %d" % (checked, bad))
sys.exit(1 if bad else 0)
