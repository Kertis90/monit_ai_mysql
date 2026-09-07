#!/usr/bin/env python3
"""
Генерация recording rules для эффективного лага реплик.

Вызывается из manage_cluster.sh apply:
    python3 scripts/gen_replication_rules.py clusters.json /etc/prometheus/rules/replication_delay.yml

Зачем: реплики могут работать с намеренной задержкой (MASTER_DELAY). У таких
реплик сырой Seconds_Behind_Master всегда примерно равен этой задержке, поэтому
алерты по нему горят непрерывно. Правила считают, насколько реплика отстала
СВЕРХ запланированного — по этой метрике и надо алертить.
"""
import json
import sys


def build(clusters):
    """Правила эффективного лага.

    Задержка берётся ИЗ САМОЙ РЕПЛИКИ — метрика mysql_slave_status_sql_delay
    (это SQL_Delay из SHOW SLAVE STATUS). Значение replica_delay_seconds из
    реестра используется только как запасное, если экспортёр эту метрику не
    отдаёт. Так расчёт не разъезжается с реальным MASTER_DELAY: поменяли его
    на реплике — дашборд и алерты сразу считают по-новому, править реестр
    не нужно.

    Про "+ 0" и "* 0 + N": арифметика убирает __name__. Без этого оператор or
    сравнивал бы серии вместе с именем метрики, не нашёл совпадений и вернул
    бы обе стороны сразу вместо выбора одной.
    """
    lag_parts, delay_parts = [], []
    for c in clusters:
        if not c.get("enabled", True) or not c.get("replica_ip"):
            continue
        name     = c["name"]
        fallback = int(c.get("replica_delay_seconds", 0) or 0)
        sbm      = 'mysql_slave_status_seconds_behind_master{cluster="%s"}' % name
        sql_d    = 'mysql_slave_status_sql_delay{cluster="%s"}' % name

        planned = ("((%s + 0)\n               or (%s * 0 + %d))"
                   % (sql_d, sbm, fallback))

        lag_parts.append("          clamp_min(%s\n            - %s, 0)"
                         % (sbm, planned))
        delay_parts.append("          %s" % planned)

    if not lag_parts:
        return "groups: []\n"

    sep = "\n          or\n"
    return (
        "groups:\n"
        "  - name: replication_effective_lag\n"
        "    rules:\n"
        "      # Отставание реплики СВЕРХ запланированной задержки.\n"
        "      # Задержка — из SQL_Delay самой реплики; значение из реестра\n"
        "      # применяется, только если экспортёр метрику не отдаёт.\n"
        "      - record: mysql:replica_effective_lag_seconds\n"
        "        expr: |\n"
        + sep.join(lag_parts) + "\n"
        "\n"
        "      # Сама плановая задержка — для графика и для ответов ИИ\n"
        "      - record: mysql:replica_configured_delay_seconds\n"
        "        expr: |\n"
        + sep.join(delay_parts) + "\n"
    )


def main():
    registry, out_path = sys.argv[1], sys.argv[2]
    with open(registry, encoding="utf-8") as f:
        data = json.load(f)

    body = build(data["clusters"])
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(body)

    print("Recording rules для реплик: %d" % body.count("clamp_min("))


if __name__ == "__main__":
    main()
