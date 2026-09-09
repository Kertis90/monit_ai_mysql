#!/usr/bin/env python3
"""
Правила предупреждения: место кончится через N дней.

Вызывается из manage_cluster.sh apply:
    python3 scripts/gen_forecast_rules.py clusters.json /etc/prometheus/rules/forecast.yml

Зачем отдельно от агента: прогноз, который видит только открывший вкладку, до
дежурного не доходит. Правило же идёт обычным путём — Alertmanager, почта,
смена. «Место кончится через трое суток» приходит тогда, когда с этим ещё
можно что-то сделать, в отличие от «занято 90%», которое приходит, когда уже
поздно.

predict_linear экстраполирует по неделе наблюдений: рывки он не предскажет, но
равномерный рост базы — именно то, для чего он и нужен.
"""
import json
import sys

# По неделе наблюдений: за сутки в оценку попадает суточная волна и прогноз
# скачет, за месяц — уже устаревшие темпы после чисток
WINDOW = "7d"

# Файловые системы, которые считать не надо
EXCLUDE_FS = "tmpfs|overlay|squashfs|ramfs|fuse.*"


def build(clusters):
    """Правила по всем серверам всех включённых кластеров."""
    hosts = []
    for cluster in clusters:
        if not cluster.get("enabled", True):
            continue
        for key in ("primary_ip", "replica_ip", "app_ip"):
            ip = (cluster.get(key) or "").strip()
            if ip and ip not in hosts:
                hosts.append(ip)
    if not hosts:
        return {"groups": []}

    # Одно правило на всех: instance приходит меткой, и дробить незачем
    selector = ('{instance=~"%s", fstype!~"%s"}'
                % ("|".join("%s:9100" % h for h in hosts), EXCLUDE_FS))

    rules = [
        {
            # Три дня — успеть заказать диск или почистить
            "alert": "DiskWillFillIn3Days",
            "expr": ('predict_linear(node_filesystem_avail_bytes%s[%s], 3*24*3600) < 0'
                     ' and node_filesystem_avail_bytes%s / '
                     'node_filesystem_size_bytes%s < 0.3'
                     % (selector, WINDOW, selector, selector)),
            "for": "1h",
            "labels": {"severity": "critical"},
            "annotations": {
                "summary": "На {{ $labels.instance }} ({{ $labels.mountpoint }}) "
                           "место кончится в ближайшие трое суток",
                "description": "Прогноз по росту за неделю. Свободно "
                               "{{ with printf \"node_filesystem_avail_bytes{instance='%s',mountpoint='%s'}\" "
                               ".Labels.instance .Labels.mountpoint | query }}"
                               "{{ . | first | value | humanize1024 }}B{{ end }}. "
                               "Заполненный диск под MySQL — это остановка записи.",
            },
        },
        {
            # Две недели — спокойно спланировать
            "alert": "DiskWillFillIn14Days",
            "expr": ('predict_linear(node_filesystem_avail_bytes%s[%s], 14*24*3600) < 0'
                     ' and node_filesystem_avail_bytes%s / '
                     'node_filesystem_size_bytes%s < 0.5'
                     % (selector, WINDOW, selector, selector)),
            "for": "6h",
            "labels": {"severity": "warning"},
            "annotations": {
                "summary": "На {{ $labels.instance }} ({{ $labels.mountpoint }}) "
                           "место кончится в ближайшие две недели",
                "description": "Прогноз по росту за неделю. Время спланировать "
                               "чистку или расширение, пока не горит.",
            },
        },
    ]

    # Соединения: предел известен, рост виден — считаем так же
    mysql = "|".join("%s:9104" % h for h in hosts)
    rules.append({
        "alert": "ConnectionsWillHitLimit",
        "expr": ('predict_linear(mysql_global_status_max_used_connections'
                 '{instance=~"%s"}[%s], 7*24*3600) >= '
                 'mysql_global_variables_max_connections{instance=~"%s"}'
                 % (mysql, WINDOW, mysql)),
        "for": "2h",
        "labels": {"severity": "warning"},
        "annotations": {
            "summary": "На {{ $labels.instance }} соединения упрутся в предел "
                       "в ближайшую неделю",
            "description": "При нынешнем росте max_used_connections достигнет "
                           "max_connections. Дальше приложение начнёт получать "
                           "отказ в подключении.",
        },
    })

    return {"groups": [{"name": "forecast",
                        # Прогноз меняется медленно, чаще считать незачем
                        "interval": "5m",
                        "rules": rules}]}


def to_yaml(data, indent=0):
    """Свой сериализатор: PyYAML в закрытом контуре может не оказаться, а
    структура здесь простая и полностью нам известна."""
    pad = "  " * indent
    out = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                out.append("%s%s:" % (pad, key))
                out.append(to_yaml(value, indent + 1))
            else:
                out.append("%s%s: %s" % (pad, key, quote(value)))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                first = True
                for key, value in item.items():
                    prefix = "%s- " % pad if first else "%s  " % pad
                    first = False
                    if isinstance(value, (dict, list)):
                        out.append("%s%s:" % (prefix, key))
                        out.append(to_yaml(value, indent + 2))
                    else:
                        out.append("%s%s: %s" % (prefix, key, quote(value)))
            else:
                out.append("%s- %s" % (pad, quote(item)))
    return "\n".join(l for l in out if l)


def quote(value):
    text = str(value)
    # Выражения и описания содержат кавычки, двоеточия и фигурные скобки —
    # без кавычек YAML их разберёт неправильно
    if any(c in text for c in ':{}[]",\n#') or text.strip() != text:
        return '"%s"' % text.replace('\\', '\\\\').replace('"', '\\"')
    return text


def main():
    if len(sys.argv) < 3:
        print("Использование: gen_forecast_rules.py clusters.json выходной.yml")
        return 1
    with open(sys.argv[1], encoding="utf-8") as f:
        registry = json.load(f)

    rules = build(registry.get("clusters", []))
    if not rules["groups"]:
        print("Кластеров нет — правила прогноза не нужны")
        return 0

    body = ("# Сгенерировано gen_forecast_rules.py — правьте не здесь,\n"
            "# а в clusters.json, и запускайте ./manage_cluster.sh apply\n"
            + to_yaml(rules) + "\n")
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(body)
    print("Правила прогноза записаны: %s (%d)"
          % (sys.argv[2], len(rules["groups"][0]["rules"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
