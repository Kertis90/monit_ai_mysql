# MySQL AI Monitoring — полный стек с WebSocket-чатом

Мониторинг неограниченного количества MySQL-кластеров (primary + replica) с ИИ-анализом
алертов и чатом на русском языке. LLM — **удалённая** (ваш OpenAI-совместимый API),
локально ничего не разворачивается.

---

## Содержание

1. [Архитектура](#архитектура)
2. [Состав пакета](#состав-пакета)
3. [Требования](#требования)
4. [Установка шаг за шагом](#установка-шаг-за-шагом)
5. [Установка в закрытом контуре](#установка-в-закрытом-контуре)
6. [Управление кластерами](#управление-кластерами)
7. [Чат и API](#чат-и-api)
8. [WebSocket-протокол](#websocket-протокол)
9. [Алерты](#алерты)
10. [Обновление настроек LLM](#обновление-настроек-llm)
11. [HTTPS / WSS через nginx](#https--wss-через-nginx)
12. [Диагностика проблем](#диагностика-проблем)

---

## Архитектура

```
             clusters.json (реестр городов)
                    │
        ┌───────────┴────────────┐
        │   manage_cluster.sh    │  add / remove / enable / apply
        └───────────┬────────────┘
                    │ генерирует
                    ▼
     /etc/prometheus/prometheus.yml
                    │
   ┌────────────────┼───────────────────────┐
   ▼                ▼                       ▼
Кемерово        Новосибирск             ... любой город
primary+replica  primary+replica
mysqld_exporter  mysqld_exporter        (порт 9104)
node_exporter    node_exporter          (порт 9100)
   │                │                       │
   └────────────────┴───────────┬───────────┘
                                ▼
                       Prometheus :9090 ──► Grafana :3000
                                │
                       Alertmanager :9093
                                │ webhook
                                ▼
                     ┌─────────────────────┐
                     │  AI Agent :5001      │
                     │  FastAPI + WebSocket │
                     │  /ws  — стрим-чат    │
                     │  /webhook — алерты   │
                     │  web/ — интерфейс    │
                     └──────────┬──────────┘
                                │ HTTPS + Bearer
                                ▼
                     Удалённая LLM (ваш API)
                     /v1/chat/completions
```

**Как работает чат.** Вы пишете «Вчера в Кемерово БД было плохо. Почему?».
Агент: (1) находит кластер `kemerovo` по слову «Кемерово» (включая падежи —
«в Кемерове» тоже сработает); (2) распознаёт «вчера» → загружает историю метрик
за 30 часов из Prometheus (min/avg/max + время пиков); (3) добавляет текущие
метрики; (4) отправляет всё в вашу LLM; (5) стримит ответ токен за токеном
в браузер через WebSocket.

---

## Состав пакета

```
mysql-ai-monitoring/
├── configure.sh                  ← ШАГ 1: интерактивная настройка (создаёт config.env)
├── config.env                    ← генерируется configure.sh (можно править вручную)
├── clusters.json                 ← реестр кластеров (города, IP, описания)
├── manage_cluster.sh             ← управление кластерами (add/remove/apply/...)
├── README.md                     ← этот файл
│
├── scripts/
│   ├── install_all.sh            ← установить всё одной командой
│   ├── install_monitoring.sh     ← Prometheus + Alertmanager + Grafana
│   ├── install_agent.sh          ← AI Agent + веб-интерфейс
│   ├── install_exporters.sh      ← экспортёры (запускается на MySQL-серверах)
│   ├── update_llm.sh             ← смена LLM URL/токена без переустановки
│   └── verify.sh                 ← проверка всего стека
│
├── agent/
│   └── agent.py                  ← FastAPI: WebSocket-чат, REST, вебхук алертов
│
├── web/
│   ├── index.html                ← интерфейс чата
│   ├── style.css                 ← тёмная тема
│   └── app.js                    ← WebSocket-клиент со стримингом и реконнектом
│
└── docs/
    └── architecture.drawio       ← схема архитектуры: потоки данных, порты,
                                     протоколы. Открыть: app.diagrams.net
                                     (File → Open) или desktop draw.io
```

---

## Требования

| Компонент | Требование |
|-----------|-----------|
| ОС | Oracle Enterprise Linux 8 / RHEL 8 / Rocky 8 (dnf, systemd, firewalld) |
| Python | 3.9+ (ставится автоматически через dnf) |
| Сеть | Сервер мониторинга должен достигать: портов 9100/9104 всех MySQL-серверов, вашего LLM API, а также github.com и grafana.com — либо их зеркал (см. ниже). MySQL-серверы качают экспортёры сами, поэтому зеркало GitHub должно быть доступно и с них |
| pip | Публичный PyPI либо внутренний репозиторий — задаётся в `./configure.sh` (`PIP_INDEX_URL`) и прописывается в venv агента |
| Зеркала | Для закрытого контура: `GITHUB_BASE_URL` (бинари) и `GRAFANA_COM_URL` (дашборды) — подменяют домен, путь достраивается как на оригинале |
| LLM | Любой OpenAI-совместимый API: эндпоинт `POST {BASE_URL}/chat/completions`, поддержка `"stream": true` (SSE), авторизация `Authorization: Bearer <token>` |
| MySQL | 5.7+ / 8.0+, доступ root для создания пользователя `exporter` (или создать вручную) |
| SSH | Для авто-установки экспортёров: с сервера мониторинга SSH-доступ по ключу на MySQL-серверы под вашей учётной записью (`SSH_USER` из `config.env`), и для неё — `sudo` без пароля на этих серверах. Не обязательно — можно ставить вручную |

---

## Установка шаг за шагом

### Шаг 0. Распаковать и настроить

```bash
tar -xzf mysql-ai-monitoring.tar.gz
cd mysql-ai-monitoring
chmod +x configure.sh manage_cluster.sh scripts/*.sh

./configure.sh
```

Мастер спросит:
- IP сервера мониторинга
- **URL вашей LLM** (например `https://llm.company.ru/v1`)
- **Bearer-токен** (можно с префиксом `Bearer ` или без — нормализуется автоматически)
- Название модели
- Пароль Grafana
- Email для алертов (Enter — пропустить, тогда алерты идут только в AI-агента)
- **SSH-учётку для MySQL-серверов** (`SSH_USER`/`SSH_PORT`/`SSH_KEY`) — под ней
  ставятся экспортёры, команды выполняются через `sudo`
- **pip-репозиторий** (`PIP_INDEX_URL`) — Enter, если доступен публичный PyPI;
  для закрытого контура укажите внутренний Nexus/Artifactory
- **Зеркала GitHub и grafana.com** (`GITHUB_BASE_URL`, `GRAFANA_COM_URL`) — Enter,
  если есть выход в интернет

В конце мастер **проверит соединение с LLM** тестовым запросом и, если задан
внутренний pip-репозиторий, **доступность репозитория**.

### Шаг 1. Добавить кластеры

```bash
./manage_cluster.sh add
```

Пример диалога:
```
  Машинное имя (латиница, без пробелов, напр. kemerovo): kemerovo
  Отображаемое название (напр. Кемерово): Кемерово
  Описание (кратко): Основная БД торговой площадки Кемерово
  IP primary-сервера MySQL: 10.1.0.1
  IP replica-сервера (Enter — пропустить): 10.1.0.2
  Пароль пользователя exporter в MySQL: ********
  Теги через запятую (напр. siberia,production): siberia,production
```

Повторите для каждого города. Или отредактируйте `clusters.json` вручную —
формат самодокументирован (поле `_schema` внутри файла).

### Шаг 2. Установить всё на сервере мониторинга

```bash
sudo ./scripts/install_all.sh
```

Это выполнит по порядку:
1. `install_monitoring.sh` — Prometheus, Alertmanager, Grafana + импорт 4 дашбордов
2. `install_agent.sh` — AI Agent с веб-интерфейсом
3. `manage_cluster.sh apply` — генерация scrape-конфигов из реестра

### Шаг 3. Установить экспортёры на MySQL-серверах

Установка идёт по SSH под учётной записью из `config.env` (`SSH_USER`, спрашивается
в `./configure.sh`), а команды на MySQL-серверах выполняются через `sudo`.
Root-логин по SSH не нужен.

**Подготовка — один раз на каждом MySQL-сервере** (под root):

```bash
# 1. Пустить ключ учётки мониторинга (выполняется с сервера мониторинга)
ssh-copy-id dbadmin@10.1.0.1

# 2. Разрешить этой учётке sudo без пароля (на MySQL-сервере)
echo 'dbadmin ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/mysql_monit
chmod 440 /etc/sudoers.d/mysql_monit
visudo -c                      # проверка синтаксиса
```

**Вариант А — автоматически по SSH:**

```bash
./manage_cluster.sh install-exporters kemerovo
./manage_cluster.sh install-exporters novosibirsk

# разовое переопределение учётки/порта/ключа:
./manage_cluster.sh install-exporters omsk --user other_admin --port 2222 --key ~/.ssh/omsk_rsa
```

Перед установкой скрипт проверяет на каждом хосте SSH-доступ и `sudo -n true`,
и при неудаче печатает нужную строку для `/etc/sudoers.d/`. Проверка идёт сразу
по primary и replica, чтобы кластер не остался наполовину настроенным.

**Вариант Б — вручную** на каждом сервере (primary и replica):

```bash
scp scripts/install_exporters.sh dbadmin@10.1.0.1:/tmp/
ssh dbadmin@10.1.0.1
sudo env MYSQL_EXPORTER_PASSWORD='ваш_пароль_из_clusters.json' \
     bash /tmp/install_exporters.sh
```

Скрипт: откроет порты 9100/9104, поставит node_exporter + mysqld_exporter,
покажет SQL для создания пользователя `exporter` (или создаст сам, если передать
`MYSQL_ROOT_PASSWORD=...`), включит performance_schema и slow_query_log.

### Шаг 4. Применить и проверить

```bash
sudo ./manage_cluster.sh apply     # если добавляли кластеры после install_all
./scripts/verify.sh
```

`verify.sh` проверит: сервисы, HTTP-эндпоинты, **WebSocket ping/pong**,
Prometheus-таргеты (покажет какие DOWN), и сделает **тестовый запрос к вашей LLM**.

### Готово

| Что | Где |
|-----|-----|
| 💬 **Чат AI Agent** | `http://MONITORING_IP:5001/` |
| 📊 Grafana | `http://MONITORING_IP:3000` (admin / ваш пароль) |
| 🔍 Prometheus | `http://MONITORING_IP:9090` |
| 🔔 Alertmanager | `http://MONITORING_IP:9093` |

---

## Установка в закрытом контуре

Стек тянет извне три вещи, и каждая переопределяется в `./configure.sh`:

| Что качается | Откуда по умолчанию | Переменная |
|--------------|---------------------|------------|
| Prometheus, Alertmanager, node_exporter, mysqld_exporter | `https://github.com` | `GITHUB_BASE_URL` |
| Дашборды Grafana (1860, 7362, 11323, 7371) | `https://grafana.com` | `GRAFANA_COM_URL` |
| Python-зависимости агента | публичный PyPI | `PIP_INDEX_URL` |

Зеркала подменяют **только домен** (можно с префиксом пути), остальное скрипты
достраивают сами:

```
GITHUB_BASE_URL="https://my.ru/proxy"
  → https://my.ru/proxy/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz

GRAFANA_COM_URL="https://my.ru/graf"
  → https://my.ru/graf/api/dashboards/1860/revisions/latest/download
```

Хвостовой слэш в URL допустим — он убирается автоматически.

⚠️ `GITHUB_BASE_URL` пробрасывается на MySQL-серверы по SSH: экспортёры качаются
**с них самих**, а не с сервера мониторинга. Зеркало должно быть доступно
и оттуда.

Остаётся один внешний источник, который пока не параметризован, — RPM-репозиторий
самой Grafana (`packages.grafana.com` в [install_monitoring.sh](scripts/install_monitoring.sh)).
Если Grafana ставится из внутреннего репозитория, замените блок `grafana.repo`
вручную или поставьте пакет заранее — скрипт пропускает установку, если
`grafana-server` уже есть.

---

## Управление кластерами

```bash
./manage_cluster.sh list                       # таблица всех кластеров
./manage_cluster.sh add                        # добавить (интерактивно)
./manage_cluster.sh show kemerovo              # детали
./manage_cluster.sh disable kemerovo           # приостановить мониторинг
./manage_cluster.sh enable kemerovo            # возобновить
./manage_cluster.sh remove kemerovo            # удалить из реестра
./manage_cluster.sh install-exporters omsk     # экспортёры по SSH (SSH_USER + sudo)
./manage_cluster.sh install-exporters omsk --user dbadmin   # другая учётка разово

sudo ./manage_cluster.sh apply                 # ⚠ ПОСЛЕ ЛЮБЫХ ИЗМЕНЕНИЙ
```

`apply` делает три вещи: генерирует `prometheus.yml` со всеми enabled-кластерами
(с метками `cluster`, `cluster_label`, `role`), перезагружает Prometheus без
рестарта (`/-/reload`), копирует реестр агенту и перезапускает его.

---

## Чат и API

### Примеры вопросов в чате

| Вопрос | Что делает агент |
|--------|-----------------|
| «Как дела в Кемерово?» | Текущие метрики kemerovo |
| «Вчера в Новосибирске было плохо. Почему?» | История 30ч (min/avg/max + время пиков) + текущие |
| «За последние 3 часа в Омске вырос slow query rate» | История 3.5ч |
| «Какой кластер хуже всего себя чувствует?» | Сводка по всем кластерам |
| «Есть ли лаг репликации где-нибудь?» | Сводка по всем кластерам |

Распознавание города работает с падежами: «в Кемерове», «Новосибирска» — найдётся.
Распознавание времени: «вчера», «позавчера», «за N часов», «N часов назад»,
«утром», «за сутки», «за неделю».

### REST API

```bash
# Чат без стриминга (для скриптов/интеграций)
curl -X POST http://IP:5001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Вчера в Кемерово было плохо. Почему?"}'

curl "http://IP:5001/chat?message=Как+дела+в+Новосибирске"

# Данные
curl http://IP:5001/clusters                        # реестр (без паролей)
curl http://IP:5001/clusters/kemerovo/status        # текущие метрики
curl "http://IP:5001/clusters/kemerovo/history?hours=24"
curl http://IP:5001/status                          # все кластеры
curl http://IP:5001/alerts/history                  # разобранные алерты
curl http://IP:5001/health
curl http://IP:5001/config                          # конфиг без секретов
```

---

## WebSocket-протокол

Эндпоинт: `ws://IP:5001/ws` (или `wss://` за nginx — см. ниже).

**Клиент → сервер:**
```json
{"type": "message", "text": "Как дела в Кемерово?", "session_id": "my-session"}
{"type": "ping"}
```

**Сервер → клиент:**
```json
{"type": "context", "cluster": "Кемерово", "hours": 30}   // что определил агент
{"type": "token",   "text": "Судя"}                        // стриминг токенов
{"type": "token",   "text": " по"}
{"type": "done"}                                           // конец ответа
{"type": "error",   "text": "..."}
{"type": "pong"}
```

`session_id` хранит историю диалога (последние 8 пар) — можно задавать
уточняющие вопросы («а что с репликацией там же?»).

Пример клиента на Python:
```python
import asyncio, json, websockets

async def main():
    async with websockets.connect("ws://IP:5001/ws") as ws:
        await ws.send(json.dumps({"type": "message",
                                  "text": "Как дела в Кемерово?"}))
        while True:
            msg = json.loads(await ws.recv())
            if msg["type"] == "token": print(msg["text"], end="", flush=True)
            elif msg["type"] == "done": break

asyncio.run(main())
```

Встроенный веб-клиент (`web/app.js`) умеет: автопереподключение с экспоненциальной
задержкой, keepalive-ping каждые 25с, мигающий курсор при стриминге, чипы
контекста (какой кластер/период определён), панель кластеров с живыми бейджами.

---

## Алерты

Все правила используют метки, поэтому работают для любого количества кластеров
без правок:

| Алерт | Условие | Severity |
|-------|---------|----------|
| MySQLDown | mysql_up == 0 | critical |
| MySQLConnectionsCritical | > 95% max_connections | critical |
| MySQLHighConnections | > 80% | warning |
| MySQLSlowQueriesHigh | > 5/s | warning |
| MySQLInnoDBBufferPoolLowHitRate | hit rate < 95% | warning |
| MySQLHighRowLockWaits | > 10/s | warning |
| MySQLQPSDropped | падение QPS > 50% за 10 мин | warning |
| ReplicationIOThreadDown / SQLThreadDown | thread не работает | critical |
| ReplicationLagWarning / Critical | > 10s / > 60s | warning / critical |
| ReplicaNotReadOnly | реплика принимает запись | critical |
| HighCPUUsage / HighMemoryUsage | > 85% / > 90% | warning |
| DiskSpaceLow / Critical | < 15% / < 5% | warning / critical |
| HighDiskIOWait | > 20% | warning |

Маршрутизация: **critical** → AI-агент + email (если настроен);
**warning** → только AI-агент. При алерте агент собирает текущие метрики +
историю за 2ч, отправляет в LLM и сохраняет диагноз — виден во вкладке
«Алерты» веб-интерфейса и через `/alerts/history`.

---

## Обновление настроек LLM

```bash
./configure.sh                    # изменить URL/токен/модель (пере-спросит всё)
# или отредактировать config.env вручную
sudo ./scripts/update_llm.sh      # применить к агенту (с подтверждением)
```

Требования к API: `POST {LLM_BASE_URL}/chat/completions`, формат OpenAI,
поддержка `stream: true`. Подходит: OpenAI, vLLM, LiteLLM, TGI (openai-режим),
llama.cpp server, LM Studio, любой корпоративный шлюз с этим форматом.

---

## HTTPS / WSS через nginx

Для продакшна поставьте nginx перед агентом:

```nginx
server {
    listen 443 ssl;
    server_name dba-ai.company.ru;

    ssl_certificate     /etc/pki/tls/certs/your.crt;
    ssl_certificate_key /etc/pki/tls/private/your.key;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket — обязательны эти три строки
    location /ws {
        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;     # стриминг длинных ответов
    }
}
```

Фронтенд определяет протокол автоматически: на `https://` странице откроет `wss://`.

### Агент на подпути (`/ai-agent/`)

Если агент живёт не в корне, укажите подпуть в `./configure.sh`
(вопрос «ROOT_PATH агента») — он попадёт в `.env` агента и страница начнёт
строить свои ссылки от него.

```bash
ROOT_PATH="/ai-agent"      # в config.env
sudo ./scripts/install_agent.sh
```

```nginx
# без слэша на конце — иначе /ai-agent отдаст 404 мимо location ниже
location = /ai-agent { return 301 /ai-agent/; }

location /ai-agent/ {
    proxy_pass http://127.0.0.1:5001/;    # ← слэш обязателен: срезает префикс
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /ai-agent/ws {
    proxy_pass http://127.0.0.1:5001/ws;  # ← явный путь, тоже без префикса
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 300s;
}
```

Как это работает: **префикс срезает nginx**, внутри агента маршруты остаются
без него (`/clusters`, `/ws`, `/static/...`). `ROOT_PATH` нужен только для того,
чтобы `agent.py` подставил в страницу `<base href="/ai-agent/">` — от него
браузер и достраивает все относительные адреса.

Две самые частые ошибки:

| Симптом | Причина |
|---------|---------|
| `{"detail":"Not Found"}` на самой странице | `proxy_pass` **без** завершающего слэша — агент получает `/ai-agent/`, а такого маршрута у него нет |
| Страница открылась, но пустая и белая; в консоли 404 на `app.js` | `ROOT_PATH` не задан — `<base>` остался `/`, и браузер ищет статику в корне сайта |

Проверить, что подставилось:

```bash
curl -s http://localhost:5001/ | grep '<base'
#   <base href="/ai-agent/">
```

---

## Диагностика проблем

**Агент не стартует**
```bash
journalctl -u ai-alert-agent -n 30
tail -f /var/log/ai-alert-agent.log
```

**Чат отвечает `[Ошибка LLM: HTTP 401]`** — неверный токен.
Проверьте: `curl http://localhost:5001/config` → `auth_header_set` должен быть `true`.
Исправить: `./configure.sh` → `sudo ./scripts/update_llm.sh`.

**`[Ошибка: не удалось подключиться к LLM]`** — сервер мониторинга не достигает
LLM_BASE_URL. Проверьте: `curl -v https://your-llm/v1/chat/completions`.

**Стриминг не работает, ответ приходит целиком с задержкой** — ваш LLM API
не поддерживает `stream: true` или прокси буферизует SSE. Для nginx перед LLM:
`proxy_buffering off;`.

**Кластер не находится по названию города** — проверьте `label` в реестре:
`./manage_cluster.sh show <name>`. Поиск идёт по label/name/tags с усечением
последних 2 букв (падежи).

**Таргет DOWN в Prometheus** — на MySQL-сервере:
```bash
systemctl status mysqld_exporter node_exporter
curl http://localhost:9104/metrics | grep mysql_up   # должно быть 1
firewall-cmd --list-ports                             # 9100, 9104
```
`mysql_up 0` = экспортёр не может подключиться к MySQL — проверьте пользователя
`exporter` и пароль в `/etc/mysqld_exporter/.my.cnf`.

**WebSocket рвётся за прокси** — увеличьте `proxy_read_timeout` (клиент шлёт
ping каждые 25с, таймаут должен быть больше).

**После добавления кластера он не появился** — забыли `sudo ./manage_cluster.sh apply`.

---

## Безопасность

- `config.env` и `/opt/ai-alert-agent/.env` имеют права 600 (содержат токен LLM)
- `/clusters` API не отдаёт пароли exporter'ов наружу
- Агент работает от непривилегированного пользователя `aiagent`
- Пользователь MySQL `exporter` ограничен: только SELECT/PROCESS/REPLICATION CLIENT, max 3 соединения
- Веб-интерфейс не имеет аутентификации — размещайте за VPN или nginx с basic auth:
  ```nginx
  location / {
      auth_basic "DBA only";
      auth_basic_user_file /etc/nginx/.htpasswd;
      proxy_pass http://127.0.0.1:5001;
  }
  ```
