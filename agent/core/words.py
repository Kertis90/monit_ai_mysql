"""
Склонения в отчётах.

Отчёты читают люди, и «2 таблиц» спотыкает взгляд ровно так же, как
опечатка. Правило одно на весь агент, чтобы в одном разделе не было
«3 строки», а в соседнем «3 строк».
"""
from __future__ import annotations


def plural(count, one: str, few: str, many: str) -> str:
    """«1 таблица», «3 таблицы», «12 таблиц»."""
    try:
        number = abs(int(count))
    except (TypeError, ValueError):
        return many
    if number % 10 == 1 and number % 100 != 11:
        return one
    if 2 <= number % 10 <= 4 and not 12 <= number % 100 <= 14:
        return few
    return many


def count_of(count, one: str, few: str, many: str) -> str:
    """Число вместе со словом: «12 таблиц»."""
    return "%s %s" % (count, plural(count, one, few, many))
