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
6. [Сборка релиза](#сборка-релиза)
7. [Переприменить все настройки](#переприменить-все-настройки)
8. [Управление кластерами](#управление-кластерами)
9. [Чат и API](#чат-и-api)
10. [WebSocket-протокол](#websocket-протокол)
11. [Алерты](#алерты)
12. [Обновление настроек LLM](#обновление-настроек-llm)
13. [HTTPS / WSS через nginx](#https--wss-через-nginx)
14. [Аутентификация](#аутентификация)
15. [Диагностика проблем](#диагностика-проблем)

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
├── grafana/
│   └── dashboards/
│       └── mysql-clusters.json   ← дашборд под метки cluster/cluster_label/role,
│                                    ставится провижинингом в папку
│                                    «MySQL AI Monitoring»
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
  Запланированное отставание реплики (MASTER_DELAY), сек.
  0 — реплика идёт в реальном времени, 7200 — отстаёт на 2 часа
  Задержка реплики, сек [7200]: 7200
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

## Сборка релиза

Версия хранится в файле `VERSION` (сейчас `1.0.0`). Сборка:

```bash
./scripts/make_release.sh                    # собрать dist/mysql-ai-monitoring-v1.0.0.zip
./scripts/make_release.sh --tag              # + создать локальный тег v1.0.0
./scripts/make_release.sh --tag --push       # + отправить тег в origin
./scripts/make_release.sh --tag --push --github   # + GitHub Release с приложенным архивом
```

По умолчанию скрипт **ничего не публикует** — только собирает архив в `dist/`.
Тег, push и Release включаются флагами явно.

### Ссылка на скачивание

После `--push` GitHub отдаёт архив тега сам, без ручной публикации:

```
https://github.com/Kertis90/monit_ai_mysql/archive/refs/tags/v1.0.0.zip
```

Скрипт печатает эту ссылку по завершении. Если нужен именно собранный нами
файл (а не автоматический архив GitHub) — используйте `--github`, тогда zip
приложится к Release как ассет:

```
https://github.com/Kertis90/monit_ai_mysql/releases/download/v1.0.0/mysql-ai-monitoring-v1.0.0.zip
```

### Почему секреты не утекут

Архив собирается через `git archive` — в него попадают **только отслеживаемые
файлы**. `config.env` (LLM-токен, пароль Grafana, хеш пароля админа,
`AUTH_SECRET`, пароль сервисной учётки LDAP) и базы `*.db` (алерты, чаты,
список доступов) перечислены в `.gitignore`, поэтому физически не могут
оказаться в архиве. После сборки скрипт дополнительно проверяет содержимое
и падает, если что-то из этого всё же обнаружилось.

Перед сборкой требуется чистое рабочее дерево — иначе версия в архиве
не соответствовала бы тегу.

### Поднять версию

```bash
echo "1.1.0" > VERSION
git add VERSION && git commit -m "Версия 1.1.0"
./scripts/make_release.sh --tag --push
```

---

## Переприменить все настройки

Изменили `config.env` или `clusters.json` — переприменить всё одной командой:

```bash
sudo ./scripts/install_all.sh
```

Скрипт идемпотентен: бинари не скачиваются заново (проверяется наличие),
но **все конфиги перегенерируются из `config.env` и `clusters.json`**, юниты
переписываются, сервисы перезапускаются.

Если конфиги «разъехались» и сервис не стартует — добавьте `--clean`:

```bash
sudo ./scripts/install_all.sh --clean
```

Тогда сгенерированные конфиги сначала удаляются, а потом создаются заново.
Данные (метрики, `grafana.db`, `alerts.db`) при этом сохраняются.

Порядок внутри: `install_monitoring.sh` → `install_agent.sh` → `manage_cluster.sh apply`.
`apply` идёт последним не случайно — он перезаписывает `prometheus.yml` целиком.

### Что перезаписывается, а что сохраняется

| Перезаписывается | Сохраняется |
|------------------|-------------|
| `/etc/prometheus/prometheus.yml` (через `apply`) | `/opt/ai-alert-agent/alerts.db` — алерты, чаты, список доступов |
| `/etc/prometheus/rules/*.yml` | `config.env` и `clusters.json` — источники правды |
| `/etc/alertmanager/alertmanager.yml` | Данные Prometheus в `/var/lib/prometheus` |
| Датасорс и дашборды Grafana | Дашборды, созданные вручную в Grafana |
| `/opt/ai-alert-agent/.env`, `agent.py`, `web/` | Пароль Grafana (сбрасывается на значение из `config.env`) |
| systemd-юниты всех сервисов | |

Учётная запись Alertmanager создаётся как `alertmanager:reguser`
(группа задаётся переменной `ALERTMANAGER_GROUP`, по умолчанию `reguser`).
Если группы нет, скрипт её создаёт; если учётка уже была в другой группе —
переводит в нужную.

Пароль локального админа, `AUTH_SECRET` и выданные доступы не теряются:
первые два лежат в `config.env`, третьи — в `alerts.db`.

### Частичное переприменение

Когда нужно быстрее и без перезапуска всего:

```bash
sudo ./manage_cluster.sh apply       # только реестр: prometheus.yml + правила,
                                     # Prometheus перечитывает конфиг без рестарта
sudo ./scripts/update_llm.sh         # только настройки LLM в .env агента
sudo ./scripts/install_agent.sh      # только агент: .env, код, веб, рестарт
sudo ./scripts/install_monitoring.sh # только Prometheus/Alertmanager/Grafana
```

### Экспортёры

В `install_all.sh` они не входят — стоят на других серверах. Переприменять
отдельно, по кластеру:

```bash
./manage_cluster.sh install-exporters kemerovo
```

Повторный запуск безопасен: бинари не перекачиваются, но `.my.cnf`, юниты
и пароль экспортёра обновляются, сервисы перезапускаются.

### Проверить результат

```bash
./scripts/verify.sh
```

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
| «Какие были алерты вчера?» | История алертов из БД за 30ч |
| «Покажи инциденты по Кемерово за неделю» | Алерты kemerovo за 170ч + метрики |
| «Были ли сбои на прошлой неделе?» | Алерты по всем кластерам за период |

Распознавание города работает с падежами: «в Кемерове», «Новосибирска» — найдётся.
Распознавание времени: «вчера», «позавчера», «за N часов», «N часов назад»,
«утром», «за сутки», «за неделю».

**Исторические данные.** Период распознаётся из фразы: «вчера», «за 3 часа»,
«за 30 минут», «за 5 дней», «за 2 недели», «за месяц», «на прошлой неделе»,
«сегодня». Если период не назван, но вопрос про историю — «покажи динамику»,
«был ли рост», «какая статистика» — берётся окно **24 часа** по умолчанию.

История собирается и когда город не назван: раньше в этом случае в контекст
уходил только текущий статус, и агент отвечал, что исторических данных нет.

**Детальная статистика по интервалам.** Если в вопросе есть «с разбивкой
по 5 минут», «детально», «поминутно», «по часам», «таблицей» — агент кладёт
в контекст не агрегаты, а **значения по каждому интервалу**: CPU, iowait,
память, load average, чтение и запись с дисков, сеть, QPS, медленные запросы,
подключения.

```
## Детальная статистика Кемерово: шаг 5 мин, период 6 ч, точек 72
  время           CPU%  iowait%     MEM%      LA1  diskR/s  diskW/s      QPS
  07.09 04:15     18.0      1.2     61.0      2.1    120.5k   3.4M      842
  07.09 04:20     74.0     22.8     63.0      9.7    980.2k  11.1M      301
```

По такой таблице видно то, чего не видно по min/avg/max: **когда именно** был
всплеск и с чем он совпал по времени.

Город называть не обязательно: если он не указан, таблицы строятся по всем
кластерам, а бюджет строк делится между ними.

Период понимается и словами, без цифр: «за последний час», «за полчаса»,
«за пару часов», «за последние сутки», «за последнюю неделю».

Шаг задаётся фразой («по 30 секунд», «по часам»), по умолчанию 5 минут. Если
точек выходит больше `SERIES_MAX_ROWS` (200), шаг увеличивается автоматически —
об этом написано в заголовке таблицы, значения не подменяются молча.

Данные **уже хранятся**: Prometheus пишет метрики с интервалом 15 с и держит
их `PROMETHEUS_RETENTION` (по умолчанию 30 дней) в `/var/lib/prometheus`.
Агент ничего не дублирует — только читает и прореживает до нужного шага.
Нужна большая глубина — увеличьте `PROMETHEUS_RETENTION` и место под данные.

Выгрузка тех же данных, в том числе в CSV для Excel:

```bash
curl -s 'http://localhost:5001/api/series/kemerovo?hours=6&step=300' | python3 -m json.tool
curl -s 'http://localhost:5001/api/series/kemerovo?hours=24&step=300&format=csv' -o stats.csv
```

**Графики в чате.** Под ответом появляется компактная строка:

```
📈 Графики за 6 ч        📄 Выгрузить PDF
```

Графики **не рисуются сами по себе** — разворачиваются по клику и встраиваются
в само сообщение, а не вываливаются отдельной стеной под ним. Десять панелей
под каждым ответом про метрики мешали читать сам ответ.

Если графики попросили явно («покажи график QPS», «нарисуй», «в картинках»),
блок разворачивается сразу. Пока не развернули, запросы в Prometheus не идут
вообще — строка предложения данных не содержит.

Панели: QPS, медленные запросы, подключения и процент от лимита, InnoDB hit
rate, CPU, iowait, память, дисковый I/O и отставание реплики (последняя —
только если реплика есть). Раскладываются в две колонки, компактно.

Рисуются инлайновым SVG в браузере: библиотека графиков не подключалась —
в закрытом контуре CDN недоступен, а тащить её ради линии с сеткой избыточно.

Данные можно взять и напрямую:

```bash
curl -s 'http://localhost:5001/api/charts/kemerovo?hours=24' | python3 -m json.tool
curl -s 'http://localhost:5001/api/charts/kemerovo?hours=6&keys=qps,cpu,iowait'
```

**Отчёт в PDF.** Ссылка **📄 Выгрузить PDF** в той же строке под ответом
(если в вопросе была просьба выгрузить или распечатать — подсвечивается).
Открывает печатную страницу `/report?cluster=<имя>&hours=<часов>`: таблица
сводки (сейчас / среднее / мин / макс по каждому показателю) и все графики,
свёрстанные под печать — карточки не разрываются между страницами, кнопки
в печать не попадают.

PDF формирует **браузер** (кнопка «Сохранить в PDF» → диалог печати). Серверного
рендера намеренно нет: он потребовал бы `weasyprint` или `reportlab` с
системными библиотеками, а у вас закрытый pip-репозиторий. Если нужен именно
файл с сервера — например, для рассылки отчётов по расписанию без участия
человека — это отдельная задача, скажите.

Страницу можно открыть и напрямую, без чата:

```
http://MONITORING_IP:5001/report?cluster=kemerovo&hours=24
```

**Суммаризация длинной переписки.** Когда история упирается в
`CHAT_CONTEXT_MESSAGES` (по умолчанию 16 сообщений), вытесняемая часть не
выбрасывается, а сжимается LLM в короткую выжимку: какие кластеры обсуждали,
что нашли, к каким выводам пришли (включая «проблемы нет»), какие значения
назывались. Выжимка сохраняется в БД с ролью `summary` и уходит в контекст
как системное сообщение, поэтому агент не «забывает» ранее разобранное —
например, что плановая задержка реплики уже признана нормой.

После рестарта агента разговор восстанавливается от последней выжимки, а не
с обрывка последних реплик. Если выжимку построить не удалось (LLM недоступна),
поведение откатывается к прежнему — простой обрезке.

**История алертов в чате.** Если в вопросе есть слова про алерты, инциденты,
сбои, аварии или «что случилось», агент дополнительно достаёт записи из
`alerts.db` и кладёт их в контекст LLM: время, severity, кластер, инстанс,
краткое описание и — для трёх последних — прошлый разбор от LLM. Работают
те же фильтры, что и в остальном чате: если назван город, выборка сузится до
него; если назван период, окно ограничится им (но не шире `ALERTS_RETENTION_DAYS`).
Без указания периода берутся последние 30 дней, не больше 20 записей.

Блок подмешивается только по ключевым словам — чтобы обычные вопросы про
текущие метрики не таскали лишнее в промпт.

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
| ReplicationLagWarning / Critical | отставание **сверх плана** > 10s / > 60s | warning / critical |
| ReplicaNotReadOnly | реплика принимает запись | critical |
| HighCPUUsage / HighMemoryUsage | > 85% / > 90% | warning |
| DiskSpaceLow / Critical | < 15% / < 5% | warning / critical |
| HighDiskIOWait | > 20% | warning |

Маршрутизация: **critical** → AI-агент + email (если настроен);
**warning** → только AI-агент. При алерте агент собирает текущие метрики +
историю за 2ч, отправляет в LLM и сохраняет диагноз — виден во вкладке
«Алерты» веб-интерфейса и через `/alerts/history`.

### Приём алертов из внешних систем (Zabbix и др.)

Кроме Alertmanager алерты можно присылать по API: агент разберёт их через LLM
и положит в ту же историю, где их потом посмотрит дежурный.

```bash
INGEST_TOKENS="<токен>"     # config.env, спрашивается в ./configure.sh
                            # несколько токенов — через запятую
```

Внешняя система не умеет логиниться cookie, поэтому у эндпоинта своя
авторизация по токену — `X-API-Key` или `Authorization: Bearer`:

```bash
curl -X POST http://MONITORING_IP:5001/api/alerts/ingest      -H 'X-API-Key: <токен>' -H 'Content-Type: application/json'      -d '{
       "alert":    "Free disk space is low",
       "severity": "critical",
       "cluster":  "kemerovo",
       "instance": "10.1.0.1",
       "summary":  "/var: свободно 8%",
       "description": "Триггер Zabbix: vfs.fs.size[/var,pfree] < 10",
       "source":   "zabbix"
     }'
```

| Поле | Обязательно | Смысл |
|------|-------------|-------|
| `alert` | да | имя события |
| `severity` | нет | `critical` / `warning` / `info`, иначе `warning` |
| `cluster` | нет | имя из `clusters.json` — если совпало, в разбор пойдут метрики и история кластера |
| `instance` | нет | хост или хост:порт |
| `summary` | нет | краткое описание |
| `description` | нет | подробности от внешней системы |
| `source` | нет | `zabbix`, `nagios`, `custom`… по умолчанию `api` |

Если `cluster` совпал с реестром, агент подложит в разбор текущие метрики
и историю за 2 часа. Не совпал — разберёт по описанию события, но алерт
всё равно сохранится.

Настройка в Zabbix: **Оповещения → Способы оповещения → Webhook**, URL
эндпоинта, заголовок `X-API-Key`, тело — JSON выше с макросами
(`{TRIGGER.NAME}`, `{HOST.CONN}`, `{TRIGGER.SEVERITY}`).

Без `INGEST_TOKENS` эндпоинт отвечает `503` — приём выключен.

### Источник алерта

В списке алертов у каждой записи есть метка источника: **Prometheus**,
**Zabbix**, **API** и т.д. Записи, созданные до появления этой колонки,
при первом запуске помечаются как `prometheus` (миграция выполняется
автоматически, данные не теряются).

### Удаление ложных срабатываний

Записи истории удаляются из вкладки «Алерты» кнопкой **✕ Удалить** — она видна
только администраторам. Или через API:

```bash
# одну запись (id виден в /alerts/history)
curl -X DELETE http://localhost:5001/api/alerts/42

# все записи одного типа — когда ошибочное правило нагенерировало пачку
curl -X DELETE 'http://localhost:5001/api/alerts?name=ReplicationLagCritical'
```

Чистить историю стоит не только ради порядка: ложные записи попадают в контекст
ИИ при вопросах про инциденты и искажают разбор следующих проблем.

Если агент недоступен, можно и напрямую в БД:

```bash
sqlite3 /opt/ai-alert-agent/alerts.db   "SELECT id, ts, alert, cluster_label FROM alerts ORDER BY ts DESC LIMIT 20;"
sqlite3 /opt/ai-alert-agent/alerts.db "DELETE FROM alerts WHERE id IN (41, 42);"
```

⚠️ Удаление записи из истории **не гасит сам алерт**, если он всё ещё активен
в Alertmanager — тогда он придёт снова. Сначала устраните причину (или
исправьте правило и выполните `sudo ./manage_cluster.sh apply`), и только
потом чистите историю.

### Реплики с намеренной задержкой (MASTER_DELAY)

Если реплика поднята как «отложенная» (`CHANGE MASTER TO MASTER_DELAY=7200`),
её `Seconds_Behind_Master` **всегда** равен этой задержке. Алертить по нему
нельзя — `ReplicationLagCritical` горел бы непрерывно, а AI-агент на каждое
срабатывание тратил бы запрос к LLM на разбор несуществующей аварии.

Задержка задаётся у каждого кластера в [clusters.json](clusters.json)
(спрашивается в `./manage_cluster.sh add`):

```json
{
  "name": "kemerovo",
  "replica_ip": "10.1.0.2",
  "replica_delay_seconds": 7200,
  ...
}
```

**Источник задержки — сама реплика.** Правило берёт `SQL_Delay` из
`SHOW SLAVE STATUS` (метрика `mysql_slave_status_sql_delay`), а
`replica_delay_seconds` из реестра применяется, только если экспортёр эту
метрику не отдаёт. Поменяли `MASTER_DELAY` на реплике — дашборд и алерты
считают по-новому сразу, править реестр не нужно.

`./manage_cluster.sh apply` генерирует
`/etc/prometheus/rules/replication_delay.yml` с двумя recording rules:

| Метрика | Смысл |
|---------|-------|
| `mysql:replica_effective_lag_seconds` | отставание **сверх** плановой задержки — по ней алерты и дашборд |
| `mysql:replica_configured_delay_seconds` | сама плановая задержка — пунктиром на графике |

Алерты и дашборд используют первую: `0` значит реплика идёт ровно по графику,
`3600` — отстала на час сверх положенного. `replica_delay_seconds: 0` (или
отсутствие поля в старом реестре) даёт прежнее поведение — алерты по сырому
отставанию.

В чате агент показывает три величины раздельно — `replication_lag_raw_s`,
`replication_planned_delay_s` и `replication_lag_over_plan_s` — и берёт их из
того же recording rule, что питает дашборд, чтобы цифры в чате и на графике
не расходились. В системном промпте есть правило судить о репликации только
по отставанию сверх плана, с разобранным примером `raw=7217, planned=7200,
over_plan=17 — это норма`.

Проверить, что задержка видна Prometheus:

```bash
curl -s 'http://localhost/prometheus/api/v1/query?query=mysql_slave_status_sql_delay'   | python3 -m json.tool
curl -s 'http://localhost/prometheus/api/v1/query?query=mysql:replica_effective_lag_seconds'   | python3 -m json.tool
```

Если первая метрика пуста — экспортёр не отдаёт `SQL_Delay`, и тогда работает
запасной путь: значение `replica_delay_seconds` из реестра, которое надо
заполнить вручную.

⚠️ Порядок важен: `install_monitoring.sh` кладёт алерты, которые ссылаются на
`mysql:replica_effective_lag_seconds`, а саму метрику создаёт `apply`. До
первого `apply` эти два алерта просто не срабатывают (пустой результат), ложных
срабатываний не будет, но и реальный лаг не поймается — не забудьте
`sudo ./manage_cluster.sh apply`.

### Сохранение чатов по пользователям

Переписка сохраняется в ту же SQLite (`/opt/ai-alert-agent/alerts.db`, таблица
`chat_messages`) и восстанавливается при следующем открытии страницы — раньше
история жила только в памяти процесса и терялась даже при F5.

**Как опознаётся пользователь.** Логина в системе нет, поэтому история привязана
к браузеру: при первом заходе `web/app.js` генерирует `crypto.randomUUID()` и
кладёт его в `localStorage` под ключом `mysql-ai-agent.client_id`. Он и уходит на
сервер с каждым сообщением.

> Чистый отпечаток браузера (canvas/шрифты/UA) для идентификации **не
> используется**: на одинаковых корпоративных машинах он совпадает, и
> пользователи видели бы переписку друг друга. Отпечаток всё же считается
> (короткий хеш UA, языка, экрана, таймзоны) и пишется в колонку `fingerprint` —
> но только как диагностическая метка, не как идентичность.

Следствия, о которых стоит знать:

| Ситуация | Что будет с историей |
|----------|----------------------|
| F5, перезапуск браузера | сохраняется |
| Другой браузер или другой профиль | отдельная история |
| Режим инкогнито | своя история, пропадёт с окном |
| Очистка данных сайта | история на сервере останется, но станет недоступна — выдастся новый `client_id` |
| Один браузер на двоих | общая история (это не аутентификация) |

```bash
CHATS_RETENTION_DAYS=30       # config.env, спрашивается в ./configure.sh
CHAT_CONTEXT_MESSAGES=16      # сколько последних сообщений уходит в LLM как контекст
```

API:

```bash
curl -s 'http://localhost:5001/chat/history?client_id=<uuid>&limit=50' | python3 -m json.tool
curl -X DELETE 'http://localhost:5001/chat/history?client_id=<uuid>'
```

В интерфейсе есть кнопка **«Очистить историю»** в шапке — она удаляет записи
этого браузера на сервере.

⚠️ Хранилище не шифруется, и любой, кто знает чужой `client_id`, может прочитать
его переписку через API. Для внутреннего инструмента это обычно приемлемо, но
если чат будет доступен снаружи — закрывайте его аутентификацией на nginx.

### Хранение истории алертов

Алерты вместе с разбором от LLM пишутся в **SQLite** — `/opt/ai-alert-agent/alerts.db`
(модуль `sqlite3` из стандартной библиотеки, дополнительных pip-пакетов не нужно).
История переживает рестарт агента; записи старше окна хранения удаляются
автоматически при следующей записи.

```bash
ALERTS_RETENTION_DAYS=30      # config.env, спрашивается в ./configure.sh
```

```bash
curl -s http://localhost:5001/alerts/history?limit=5 | python3 -m json.tool
# {
#   "total": 42,              ← всего за окно хранения
#   "items": [...],           ← последние limit, новые сверху
#   "retention_days": 30,
#   "persistent": true        ← false = БД недоступна, история только в памяти
# }
```

Если `persistent: false` — агент не смог открыть БД (обычно права на
`/opt/ai-alert-agent`) и работает на резервной копии в памяти: последние
200 записей, теряются при рестарте. Причина пишется в лог:
```bash
journalctl -u ai-alert-agent | grep -i "хранилище алертов"
```

Посмотреть напрямую:
```bash
sqlite3 /opt/ai-alert-agent/alerts.db \
  "SELECT ts, alert, cluster_label, severity FROM alerts ORDER BY ts DESC LIMIT 10;"
```

Метрики Prometheus хранятся независимо — `PROMETHEUS_RETENTION` (по умолчанию
`30d`), каталог `/var/lib/prometheus`.

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
(секция «Обратный прокси») — он попадёт в `.env` агента и страница начнёт
строить свои ссылки от него. Там же рядом спрашиваются подпути для Prometheus
и Alertmanager — все три задаются одинаково, одним путём.

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

### Prometheus и Alertmanager на подпутях

Задаются ровно так же, как подпуть агента — одним путём в той же секции
мастера:

```bash
PROMETHEUS_ROOT_PATH="/prometheus"
ALERTMANAGER_ROOT_PATH="/alertmanager"
```

Этого достаточно: сервисы начнут отдаваться под своим префиксом, а скрипты
выведут из него все внутренние адреса.

**Внешний адрес — необязательное дополнение.** Он нужен только чтобы ссылки
*в самих алертах* (`generatorURL`, ссылка на silence) вели наружу, а не на
`localhost`. Мастер спрашивает его следом, Enter — пропустить:

```bash
EXTERNAL_BASE_URL="https://monitor.company.ru"
# → PROMETHEUS_EXTERNAL_URL="https://monitor.company.ru/prometheus"
# → ALERTMANAGER_EXTERNAL_URL="https://monitor.company.ru/alertmanager"
```

`install_monitoring.sh` добавит в systemd-юниты:

```
# только подпуть:
--web.route-prefix=/prometheus/
# подпуть + внешний адрес:
--web.external-url=https://monitor.company.ru/prometheus --web.route-prefix=/prometheus/
```

**Сервисы отдают себя под своим путём**, а не в корне. Поэтому nginx префикс
**не срезает** — `proxy_pass` без завершающего слэша:

```nginx
location /prometheus/ {
    proxy_pass http://127.0.0.1:9090;       # БЕЗ слэша — путь идёт как есть
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /alertmanager/ {
    proxy_pass http://127.0.0.1:9093;       # БЕЗ слэша
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

> Это отличается от агента: тот отвечает в корне, и там `proxy_pass` **со**
> слэшем. Prometheus и Alertmanager умеют работать под префиксом сами, поэтому
> проще отдать им путь целиком.

Следствие: **все внутренние адреса тоже содержат префикс**. Скрипты выводят их
из `PROMETHEUS_ROOT_PATH` / `ALERTMANAGER_ROOT_PATH` автоматически:

| Что | Адрес при `PROMETHEUS_ROOT_PATH="/prometheus"` |
|-----|-----------------------------------------------|
| Собственный scrape-таргет | `metrics_path: '/prometheus/metrics'` в job `prometheus` |
| Датасорс Grafana | `http://localhost:9090/prometheus` |
| `PROMETHEUS_URL` агента | `http://localhost:9090/prometheus` |
| Перезагрузка конфига | `POST http://localhost:9090/prometheus/-/reload` |
| Alertmanager в `prometheus.yml` | `path_prefix: '/alertmanager/'` в блоке `alerting` |

Пустые значения дают прежнее поведение — всё в корне, без префиксов.

⚠️ `prometheus.yml` **полностью перегенерируется** командой `apply`, поэтому
править `metrics_path` в нём руками бесполезно: значение берётся из
`PROMETHEUS_ROOT_PATH` в `config.env`.

Применить к уже установленному стеку:

```bash
sudo ./scripts/install_monitoring.sh    # юниты, датасорс, базовый конфиг
sudo ./manage_cluster.sh apply          # prometheus.yml с metrics_path
sudo ./scripts/install_agent.sh         # PROMETHEUS_URL агента
```

**Внутренние обращения тоже идут через nginx — без порта.** Раз подпути уже
настроены в nginx, скрипты обращаются к сервисам по `http://localhost/prometheus`,
а не `http://localhost:9090/prometheus`. Это касается датасорса Grafana,
`PROMETHEUS_URL` агента, health-проверок, перезагрузки конфига и целей скрейпа
(`targets: ['localhost']`). Хост настраивается переменной `INTERNAL_BASE_URL`
в `config.env` (по умолчанию `http://localhost`).

Без подпутей маршрутизировать в nginx не по чему, поэтому используется прямой
адрес с портом — прежнее поведение.

⚠️ Следствие: **nginx должен работать и знать про эти location до запуска
скриптов.** Иначе health-проверки не пройдут — сервис живой, но по адресу
через nginx недоступен.

Alertmanager шлёт вебхуки агенту на `localhost:${AGENT_PORT}/webhook` — этот
адрес от префиксов не зависит. Порты 9090/9093 можно закрыть в firewalld.

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

## Аутентификация

Веб-интерфейс закрыт формой входа на `/login`. Настраивается в `./configure.sh`
(секция 10). Источники проверяются по очереди: **SSO → LDAP → локальный админ**,
любой можно выключить.

### Локальный администратор

Пароль хранится только хешем PBKDF2-SHA256 (200 000 итераций, случайная соль) —
в `config.env` и `.env` агента открытого пароля нет:

```bash
AUTH_ENABLED="true"
AUTH_ADMIN_USER="admin"
AUTH_ADMIN_PASSWORD_HASH="pbkdf2_sha256$200000$<соль>$<хеш>"
AUTH_SECRET="<64 hex>"          # подписывает сессионные cookie
AUTH_SESSION_TTL_HOURS=12
```

Сессия — подписанный HMAC cookie (`HttpOnly`, `SameSite=Lax`), состояние на
сервере не хранится. `AUTH_SECRET` генерируется один раз и сохраняется: если его
сменить, все сессии станут недействительны.

Смена пароля: `./configure.sh` → секция 10 → новый пароль → `sudo ./scripts/install_agent.sh`.

### LDAP / Active Directory

```bash
LDAP_ENABLED="true"
LDAP_URL="ldaps://dc.company.ru:636"
LDAP_BIND_TEMPLATE="{username}@company.ru"        # для AD обычно UPN
LDAP_BASE_DN="DC=company,DC=ru"                   # нужен только для проверки группы
LDAP_USER_FILTER="(sAMAccountName={username})"
LDAP_REQUIRED_GROUP="CN=DBA,OU=Groups,DC=company,DC=ru"
LDAP_TLS_VERIFY="true"
```

Проверка — обычный bind учётными данными пользователя; пароль нигде не
сохраняется. Если задан `LDAP_REQUIRED_GROUP`, после успешного bind проверяется
членство через `memberOf`.

Нужен пакет `ldap3` — `install_agent.sh` ставит его сам, но **только когда
`LDAP_ENABLED=true`**. В закрытом контуре он должен быть в вашем
`PIP_INDEX_URL`; если установка не удалась, скрипт скажет об этом явно, и вход
по LDAP работать не будет (локальный админ продолжит работать).

### SSO через обратный прокси

Рассчитано на типовую корпоративную схему: nginx с Kerberos/SAML/oauth2-proxy
аутентифицирует пользователя и передаёт имя заголовком.

```bash
SSO_ENABLED="true"
SSO_HEADER="X-Remote-User"
SSO_TRUSTED_PROXIES="127.0.0.1,::1"      # адреса, чьему заголовку верим
SSO_LOGOUT_URL="https://sso.company.ru/logout"
```

```nginx
location /ai-agent/ {
    auth_gss on;                          # или auth_request к oauth2-proxy
    proxy_pass http://127.0.0.1:5001/;
    proxy_set_header X-Remote-User $remote_user;
}
```

⚠️ **`SSO_TRUSTED_PROXIES` — не формальность.** Заголовок принимается только от
перечисленных адресов. Без этой проверки любой, кто достучится до порта агента
напрямую, поставил бы себе `X-Remote-User: admin`. Поэтому при включённом SSO
порт `5001` должен быть закрыт снаружи — доступ только через nginx.

### Список доступов

**Учётной записи в домене недостаточно.** После успешной проверки пароля
(LDAP), заголовка SSO или токена OIDC агент дополнительно смотрит, выдан ли
пользователю доступ. Не выдан — вход отклоняется с понятным сообщением, а не
«неверный пароль».

Исключение одно: **локальный администратор**. Это bootstrap-учётка, которой
список и наполняют, поэтому она в нём не нуждается.

Управление — вкладка **🔑 Доступы** (видна только администраторам):

- **Поиск по каталогу.** Введите фамилию, логин или почту — агент ищет в AD и
  показывает найденных. Кнопка «Выдать доступ» добавляет выбранного, вводить
  логин руками не нужно. Требуется сервисная учётная запись:
  ```bash
  LDAP_SEARCH_USER="CN=svc-monitor,OU=Service,DC=company,DC=ru"
  LDAP_SEARCH_PASSWORD="..."
  LDAP_BASE_DN="DC=company,DC=ru"
  ```
  Пользовательский bind тут не подходит: доступ выдают **до** того, как человек
  впервые вошёл.
- **Добавление по логину вручную** — для SSO/OIDC, когда поиска по каталогу нет.
- **Роль** `user` или `admin`. Админ дополнительно управляет доступами.
- **Отзыв** — мягкий: запись остаётся со статусом «отозван», чтобы был виден
  факт выдачи и отзыва. Кнопка «Вернуть» восстанавливает.

Логины приводятся к единому виду: `COMPANY\J.Smith`, `J.Smith` и `j.smith` —
одна и та же учётная запись.

**Отзыв действует немедленно.** Каждый запрос перепроверяет список, поэтому уже
выданная сессионная cookie перестаёт работать сразу, а не после истечения
`AUTH_SESSION_TTL_HOURS`.

```bash
curl -s http://localhost:5001/api/users                     # список (нужен админ)
curl -s 'http://localhost:5001/api/directory/search?q=смирнов'
curl -X POST http://localhost:5001/api/users      -H 'Content-Type: application/json'      -d '{"username":"j.smith","role":"user"}'
curl -X DELETE http://localhost:5001/api/users/j.smith      # отозвать
curl -X DELETE 'http://localhost:5001/api/users/j.smith?hard=true'   # удалить запись
```

> ⚠️ Пока список пуст, войти может только локальный админ — это защита от
> ситуации, когда весь домен получает доступ по умолчанию.

### OIDC (встроенный)

Authorization Code Flow с PKCE. На форме входа появляется кнопка рядом с полями
логина и пароля.

```bash
OIDC_ENABLED="true"
OIDC_ISSUER="https://sso.company.ru/realms/main"
OIDC_CLIENT_ID="mysql-ai-agent"
OIDC_CLIENT_SECRET="..."                  # пусто = публичный клиент, только PKCE
OIDC_REDIRECT_URL="https://monitor.company.ru/ai-agent/auth/oidc/callback"
OIDC_SCOPES="openid profile email"
OIDC_USERNAME_CLAIM="preferred_username"  # для Entra ID / Keycloak
OIDC_BUTTON_TEXT="Войти через SSO"
```

`OIDC_REDIRECT_URL` задавайте явно и ровно так, как он зарегистрирован у
провайдера: за nginx схему и хост автоматически не определить.

Как устроено: `/auth/oidc/login` уводит к провайдеру с `state` и PKCE-challenge,
`/auth/oidc/callback` меняет код на токены и берёт личность с **userinfo**.
Подпись ID-токена не проверяется — вместо этого userinfo запрашивается по TLS
напрямую у issuer с полученным access-токеном. Так не нужен разбор JWT и
работа с JWKS, а доверие опирается на TLS-соединение с провайдером. Если ваша
политика требует именно проверки подписи ID-токена — скажите, это отдельная
доработка.

`state` одноразовый (защита от CSRF), живёт 10 минут в памяти процесса. При
рестарте агента незавершённые входы придётся повторить.

Полученный логин проходит через список доступов на общих основаниях: нет
выданного доступа — редирект на форму с объяснением.

### Что остаётся открытым без входа

| Путь | Почему |
|------|--------|
| `/login`, `/api/login` | сама форма входа |
| `/health` | проверки `verify.sh` и мониторинга |
| `/static/*` | стили и скрипты формы |
| `/auth/oidc/login`, `/auth/oidc/callback` | иначе до входа не дойти — бесконечный редирект |
| `/webhook` | Alertmanager не умеет логиниться — вместо этого принимается **только с localhost**, с любого другого адреса 403 |

WebSocket `/ws` проверяет сессию отдельно: HTTP-middleware на него не
распространяется. При истёкшей сессии соединение закрывается кодом 4401 и
интерфейс просит войти заново.

### Отключить аутентификацию

`AUTH_ENABLED="false"` — интерфейс открыт всем, у кого есть сетевой доступ.
Допустимо только в изолированном сегменте.

Помимо встроенного OIDC остаётся вариант с oauth2-proxy перед nginx и
режимом SSO по заголовку — он не требует настройки провайдера в самом агенте.

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

**В Grafana дашборды пустые, хотя в Prometheus метрики есть**

Сначала убедитесь, что данные действительно собираются:
```bash
curl -s 'http://localhost:9090/api/v1/label/job/values' | python3 -m json.tool
# ожидаем: prometheus, mysql_<кластер>, node_<кластер>
```

Если job'ы на месте, а панели пустые — это несовпадение имён job. Community-дашборды
(1860, 7362 и другие) фильтруют по `job="node"` / `job="mysql"`, а `apply` генерирует
`job` вида `node_kemerovo` / `mysql_kemerovo`. Проверить:
```bash
curl -s 'http://localhost:9090/api/v1/query?query=up{job="node"}' \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)['data']['result']))"
# 0 -> дашборд ищет не тот job
```

Используйте дашборд **«MySQL кластеры — обзор»** (папка *MySQL AI Monitoring*) —
он лежит в [grafana/dashboards/](grafana/dashboards/) и написан под метки этого
проекта: селектор сверху переключает кластеры по метке `cluster`, в легендах
человеческие названия из `cluster_label` и роль primary/replica. Ставится
провижинингом, отдельного импорта не требует:
```bash
sudo ./scripts/install_monitoring.sh    # Prometheus/Grafana уже стоят — скрипт их пропустит
```

Community-дашборды при этом остаются: их можно донастроить, поправив переменную
`$job` вверху дашборда, либо просто не использовать.

**Панели пишут «Datasource not found» или `${DS_PROMETHEUS}`** — дашборд
импортирован без привязки датасорса. Перезалейте: `sudo ./scripts/install_monitoring.sh`.

**Grafana не стартует / `Grafana-Server Init Failed`** — быстрее всего снести
сгенерированные конфиги и создать заново:

```bash
sudo ./scripts/install_monitoring.sh --clean
```

Режим `--clean` останавливает Prometheus, Alertmanager и Grafana, удаляет
**только то, что создаёт этот скрипт** (`prometheus.yml`, правила,
`alertmanager.yml`, systemd-юниты, наш провижининг Grafana и дашборды из
`/var/lib/grafana/dashboards`) и раскладывает всё заново из `config.env`
и `clusters.json`.

Не трогаются: метрики в `/var/lib/prometheus`, `grafana.db` с пользователями
и вручную созданными дашбордами, `alerts.db` с алертами, чатами и доступами.

То же для всего стека сразу: `sudo ./scripts/install_all.sh --clean`.

**`Datasource provisioning error: data source not found`** — частный случай,
из-за которого Grafana падает на старте целиком. Возникает, если в `grafana.db`
уже есть датасорс «Prometheus» со случайным `uid` (его создал провижининг
прошлых версий, без явного uid), а новый файл задаёт `uid: prometheus`:
сопоставление идёт по uid, запись не находится, модуль провижининга падает.

Удаление файла провижининга **не помогает** — запись живёт в `grafana.db`.
Поэтому наш файл содержит блок `deleteDatasources`, который сносит старую
запись по имени перед созданием новой. Достаточно переустановить конфиги:

```bash
sudo ./scripts/install_monitoring.sh --clean
```

Если и после этого не стартует — причина не в наших файлах:

```bash
journalctl -u grafana-server -n 40 --no-pager | grep -A3 -i "init failed\|error"
ls -la /var/lib/grafana/          # права: должно быть grafana:grafana
df -h /var/lib/grafana            # место на диске
ss -tlnp | grep :3000             # порт не занят другим процессом
```

Ниже — частные случаи.

**`Grafana-Server Init Failed`** — Grafana не стартует, если провижининг-файл
невалиден, ссылается на несуществующий каталог или в этом каталоге лежит битый
JSON. Точная причина печатается сразу после `Init Failed:`:
```bash
journalctl -u grafana-server -n 40 --no-pager | grep -A3 -i "init failed\|error"
```
Быстро поднять, отключив провижининг дашбордов:
```bash
sudo mv /etc/grafana/provisioning/dashboards/mysql_monit.yml /tmp/
sudo systemctl restart grafana-server
```
`install_monitoring.sh` создаёт этот файл только после того, как в
`/var/lib/grafana/dashboards` лёг хотя бы один проверенный дашборд, поэтому
повторный прогон скрипта такую ситуацию не создаёт.

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
