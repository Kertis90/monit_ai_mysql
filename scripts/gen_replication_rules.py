#!/usr/bin/env python3
"""
Генерация recording rules для эффективного лага реплик.

Вызывается из manage_cluster.sh apply:
    python3 scripts/gen_replication_rules.py clusters.json /etc/prometheus/rules/replication_delay.yml

Зачем: реплики могут работать с намеренной задержкой (MASTER_DELAY,
поле replica_delay_seconds в реестре). У таких реплик сырой
Seconds_Behind_Master всегда равен этой задержке, поэтому алерты по нему
горят непрерывно. Правила ниже считают, насколько реплика отстала
СВЕРХ запланированного — по этой метрике и надо алертить.
"""
import json
import sys


def build(clusters):
    lag_parts, delay_parts = [], []
    for c in clusters:
        if not c.get("enabled", True) or not c.get("replica_ip"):
            continue
        name  = c["name"]
        delay = int(c.get("replica_delay_seconds", 0) or 0)
        sbm   = 'mysql_slave_status_seconds_behind_master{cluster="%s"}' % name
        lag_parts.append("          clamp_min(%s - %d, 0)" % (sbm, delay))
        # "* 0 + N" переносит все метки серии и подставляет константу
        delay_parts.append("          (%s * 0 + %d)" % (sbm, delay))

    if not lag_parts:
        return "groups: []\n"

    sep = "\n          or\n"
    return (
        "groups:\n"
        "  - name: replication_effective_lag\n"
        "    rules:\n"
        "      # Отставание реплики СВЕРХ запланированного MASTER_DELAY\n"
        "      - record: mysql:replica_effective_lag_seconds\n"
        "        expr: |\n"
        + sep.join(lag_parts) + "\n"
        "\n"
        "      # Запланированная задержка — чтобы её было видно на дашборде\n"
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

    n = body.count("clamp_min(")
    print("Recording rules для реплик: %d" % n)


if __name__ == "__main__":
    main()
