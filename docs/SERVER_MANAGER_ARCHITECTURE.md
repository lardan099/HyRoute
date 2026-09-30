# HyRoute Server Manager — архитектура

Server Manager (`hyroute-server`) — controller, который разворачивает,
импортирует и обслуживает серверы Hysteria 2 по SSH и выдаёт ссылки для
клиента HyRoute. Работает на Linux VPS (основной сценарий), собирается и
на Windows. Этот документ описывает целевое устройство Phase 1 и решения,
которые не должны помешать Phase 2–4. План задач — `TODO_SERVER_MANAGER.md`.

Сверено с документацией Hysteria 2 (hysteria.network: Installation,
Server Installation Script, Full Server Config, Full Client Config, URI
Scheme, Port Hopping, Traffic Stats API, ACL) и исходниками
`apernet/hysteria` app/v2.12.3 — последней версией на момент написания.

## Аудит репозитория

Что есть и что из этого переиспользуется:

| Что | Где | Как используется в Server Manager |
|---|---|---|
| Модель клиентского профиля, парсер и сериализатор `hysteria2://` | `internal/hysteria` (`Profile`, `ParseURI`, `URI`) | P1-09 выносит модель ссылки в общий пакет `internal/hy2uri`; клиент переходит на него без изменения поведения |
| Генерация клиентского YAML | `internal/hysteria/config.go` (`BuildConfig`) | Server Manager строит клиентский конфиг своей typed-моделью (P1-08): клиентский `BuildConfig` добавляет `socks5`-режим HyRoute и не годится для выдачи пользователю |
| Серверы, подписки, группы, правила клиента | `internal/app`, `internal/rules`, `internal/groups` | Не используются: это модель клиента. Связь с клиентом — только через ссылку `hysteria2://` («Добавить в HyRoute», P1-14) |
| Проверка SHA-256 скачанных бинарников | `internal/runtimefiles`, `build/deps.json` | Тот же принцип для релей-загрузки: `hashes.txt` релиза Hysteria + SHA-256 файла |
| Маскирование секретов в журналах | `internal/logx` | Server Manager получает свой пакет `redact` (P1-03): набор секретов шире (SSH-ключи, токены, секреты API) |
| Argon2id, AES-256-GCM | резервная копия клиента (`internal/backup`) | Те же примитивы из `golang.org/x/crypto`; код не общий — у копии свой формат |
| Интерфейс | `frontend/` (Svelte 5, `style.css` с токенами тем) | Админка `web/admin` — отдельное приложение с тем же визуальным языком (копия токенов, не общий код) |
| YAML | `gopkg.in/yaml.v3` уже в зависимостях | Typed-модель конфига поверх `yaml.Node` (сохранение неизвестных полей) |
| SSH | `golang.org/x/crypto` уже в зависимостях (пакет `ssh`) | `RemoteExecutor`; SFTP — `github.com/pkg/sftp` (новая зависимость) |

Новые зависимости: `modernc.org/sqlite` (SQLite без CGO) и
`github.com/pkg/sftp`. Обе собираются на Linux и Windows.

Правило разделения: пакеты Server Manager лежат в `internal/srvmgr/...`
и не импортируют пакеты клиента, кроме общих `internal/hy2uri` и
`internal/hyconfig`. Клиент не импортирует ничего из `internal/srvmgr`.
Поведение Windows-клиента не меняется (единственное исключение —
переход на общий пакет ссылок в P1-09 с сохранением всех тестов).

## Обязательное поведение

Поведение старого прототипа-установщика, которое должно быть в новой
системе, и задача, в которой оно появляется.

| # | Поведение | Задача | Как |
|---|---|---|---|
| 1 | Развёртывание одного сервера | P1-10 | Job Quick Deploy: preflight → бинарник → unit → TLS → конфиг → firewall → запуск → проверка |
| 2 | Каскад Entry → Exit | модель — P1-00/P1-04 (роль сервера, topology), работа — Phase 3 | Topology из N узлов; в Phase 1 цепочка из одного узла |
| 3 | Импорт уже настроенного сервера без изменений | P1-11 | Только читающие операции; результат — typed-модель и предупреждения |
| 4 | Развёртывание по SSH/SFTP | P1-05, P1-10 | `RemoteExecutor` на `x/crypto/ssh` + SFTP, TOFU host key |
| 5 | Генерация серверного и клиентского конфига | P1-08, P1-10, P1-14 | Typed-модель `internal/hyconfig`, сериализация через `yaml.v3` |
| 6 | Obfs Salamander | P1-08, P1-09, P1-10 | Поле модели, параметр ссылки `obfs=salamander&obfs-password=` |
| 7 | Сертификаты и pinning | P1-10, P1-09 | Самоподписанный (ECDSA P-256, pin = SHA-256 DER сертификата) или ACME (http/tls) |
| 8 | Port hopping | P1-10 (развёртывание), P1-09 (ссылка), Phase 2 (UI диапазонов) | Встроенный диапазон Hysteria на Linux (`listen: :20000-50000`), firewall — только открыть диапазон |
| 9 | geosite/geoip | P1-08 (модель `acl.geoip/geosite`), Phase 3 (управление) | Поля ACL сохраняются и редактируются как данные |
| 10 | ACL routing | P1-08 (модель `acl`, `outbounds`), P1-13 (raw-редактор), Phase 3 (редактор правил) | `acl.inline` — список строк правил Hysteria |
| 11 | Генерация `hysteria2://` | P1-09, P1-14 | `internal/hy2uri` |
| 12 | Параметры для HApp/Incy/Shadowrocket | P1-09 | Только параметры официальной схемы (`obfs`, `obfs-password`, `sni`, `insecure`, `pinSHA256`), `hysteria2://`, multi-port в хосте, имя во фрагменте |
| 13 | Релей-загрузка, если у сервера нет доступа к GitHub | P1-10 (через controller), Phase 3 (через другой узел) | Интерфейс `download.Source` |
| 14 | Управление правилами | P1-13 (raw), Phase 3 (структурный редактор, «Проверить правило») | Через typed-модель, не regex |

## Снимок сервера

`reference/server-snapshot/` в репозитории нет. Импорт (P1-11) и
предупреждения «Needs attention» проверяются на синтетических фикстурах,
построенных по официальному установщику (`get.hy2.sh`) и документации.
Когда снимок появится, он становится фикстурой импорта, а каждая проблема
из его README — проверкой в `importer` с тестом.

## Пакеты

```
cmd/hyroute-server            main: флаги/env, сборка зависимостей, graceful shutdown
web/admin                     Svelte 5; web/admin/embed.go — go:embed dist
internal/hy2uri               модель, парсер и сериализатор hysteria2:// (общий с клиентом)
internal/hyconfig             typed-модель серверного и клиентского YAML с неизвестными полями
internal/srvmgr/
  config                      конфигурация controller (флаги + env)
  model                       сущности домена, без зависимостей
  store                       интерфейсы репозиториев и ошибки (ErrNotFound, ErrConflict)
  store/sqlite                реализация на modernc.org/sqlite, миграции (embed *.sql)
  secrets                     master key, envelope encryption (AES-256-GCM)
  redact                      вычистка секретов из строк, YAML, ссылок
  auth                        пользователи, argon2id, сессии, CSRF, rate limit, роли
  remote                      интерфейс Executor, typed operations, ошибки
  remote/sshexec              реализация на x/crypto/ssh + pkg/sftp, TOFU host key
  remote/fake                 fake executor для тестов (скриптуемые ответы, журнал вызовов)
  jobs                        job engine: state machine, steps, retry, recovery, журнал, SSE-брокер
  preflight                   проверки сервера перед развёртыванием
  download                    источники бинарника Hysteria: direct, relay через controller
  deploy                      Quick Deploy (шаги job)
  importer                    импорт установленного сервера (только чтение)
  service                     статус, start/stop/restart, journal
  apply                       безопасное применение конфига с откатом
  topology                    цепочки узлов (N-hop-ready), в Phase 1 — один узел
  api                         HTTP /api/v1: handlers, middleware, ошибки
```

Зависимости направлены сверху вниз: `api` → сервисы (`deploy`, `importer`,
`service`, `apply`, `auth`, `preflight`) → `jobs`, `remote`, `hyconfig`,
`secrets`, `redact` → `store` (интерфейсы) → `model`. `store/sqlite`
подключается только в `cmd/hyroute-server` и тестах. Бизнес-логика не
знает про HTTP и SQL; `api` не содержит логики, кроме разбора запроса и
проверки прав.

## Данные

Каталог данных: `--data-dir` / `HYROUTE_SERVER_DATA_DIR`, по умолчанию
`/var/lib/hyroute-server` (Linux) и `%ProgramData%\HyRoute Server`
(Windows). В нём `hyroute-server.db`, `master.key` (если ключ не задан в
env), `setup-token` на время первого запуска.

### Сущности (SQLite)

| Таблица | Поля (основные) | Заметки |
|---|---|---|
| `schema_migrations` | version, applied_at | миграции только вперёд, в транзакции |
| `users` | id, username (unique), password_hash (PHC argon2id), role, disabled, created_at | роли: owner, admin, operator, readonly |
| `sessions` | id_hash (SHA-256 токена), user_id, csrf_hash, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent | в БД только хеши токенов |
| `servers` | id, name, tags (json), location, host, ssh_port, ssh_user, auth_type (password/key), role (standalone/entry/relay/exit), notes, state, created_at, updated_at | state: new, deploying, healthy, degraded, offline, needs_attention |
| `server_credentials` | server_id, kind (ssh_password/ssh_key/ssh_key_passphrase), secret (envelope) | никогда не возвращаются в API |
| `host_keys` | server_id, key_type, key (raw), fingerprint_sha256, trusted_at, trusted_by | TOFU; смена ключа — только явный re-trust |
| `installations` | server_id, binary_path, config_path, unit_name, service_user, hysteria_version, managed (bool), imported_at | managed = установлено нами; imported — чужая установка |
| `config_revisions` | id, server_id, seq, yaml (envelope), sha256, source (deploy/import/edit/rollback), status (candidate/applied/failed/rolled_back), created_by, created_at, applied_at | YAML содержит пароли → хранится зашифрованным |
| `client_profiles` | server_id, uri (envelope), name, created_at | ссылки выдаются по явному действию |
| `jobs` | id, kind, server_id, state, current_step, params (json без секретов), secret_params (envelope), attempt, error_message, error_details, created_by, created_at, started_at, finished_at, lease_owner, lease_until | |
| `job_steps` | job_id, idx, name, state, attempt, started_at, finished_at, error | |
| `job_logs` | job_id, seq, ts, level, step, message | message уже прошёл redaction |
| `chains`, `chain_hops` | id, name; chain_id, position, server_id, role | topology, N узлов; в Phase 1 создаётся цепочка из одного узла |
| `audit_log` | id, ts, user_id, action, target, details | кто что сделал (логин, развёртывание, re-trust, показ секретов) |

Секреты — только в колонках-envelope (`secrets.Sealed`, BLOB). Тест
P1-04 сканирует файл БД на открытые значения тестовых секретов.

## Секреты

- **Master key** — 32 байта, base64: `HYROUTE_MASTER_KEY` или файл
  (`--master-key-file`, по умолчанию `<data-dir>/master.key`). Файл должен
  иметь права 0600 и принадлежать пользователю controller, иначе запуск
  отказывается (на Windows права не проверяются: документируется). Если
  ни ключа, ни файла нет, первый запуск создаёт файл и пишет в журнал, что
  его нужно сохранить. Потеря ключа = потеря всех сохранённых credentials
  и конфигов в БД; серверы продолжают работать, их можно импортировать
  заново.
- **Envelope encryption.** Для каждого значения — случайный DEK (32
  байта); значение шифруется DEK (AES-256-GCM), DEK шифруется ключом
  версии N (AES-256-GCM). Хранится `{kek_version, wrapped_dek, nonce, ct}`.
  AAD — контекст значения (`server/<id>/ssh_password`), поэтому шифротекст
  нельзя переставить в другую строку. Ротация: keyring с версиями, новые
  значения — текущей версией, перешифровка DEK — отдельная операция
  (Phase 4).
- Секреты не попадают в журналы, ответы API (кроме явного «показать» с
  записью в audit log), frontend bundle, JSON-параметры jobs, тестовые
  фикстуры (только явно фейковые значения).

## Аутентификация

- **Первый запуск.** Если пользователей нет, controller кладёт одноразовый
  setup token в `<data-dir>/setup-token` (0600) и пишет в журнал путь к
  файлу (сам токен в журнал не попадает).
  `POST /api/v1/setup` принимает токен, имя и пароль и создаёт owner в
  транзакции, только если пользователей нет. Без токена занять админку
  нельзя, даже если порт случайно открыт наружу.
- Пароли — argon2id (m=64 MiB, t=3, p=2 по умолчанию, параметры в PHC-строке).
- Сессия: случайный токен 32 байта в cookie `hyroute_session` (HttpOnly,
  SameSite=Strict, Secure — если запрос пришёл по TLS или от доверенного
  reverse proxy с `X-Forwarded-Proto: https`; на `127.0.0.1` по HTTP —
  без Secure). В БД — SHA-256 токена. Idle timeout 12 ч, абсолютный — 7 дней.
- CSRF: токен сессии, выдаётся в ответе логина и `GET /api/v1/session`;
  все изменяющие запросы требуют `X-CSRF-Token` и проверку
  `Origin`/`Sec-Fetch-Site`.
- Rate limit логина: по IP и по имени пользователя (token bucket в
  памяти, 5 попыток в минуту, затем растущая задержка).
- Роли: owner/admin — всё; operator — развёртывание и управление
  сервисом, без пользователей и настроек; readonly — только чтение
  (Phase 1 гарантирует: readonly получает 403 на любой изменяющий
  запрос). Полный RBAC — Phase 4.

## Удалённое выполнение

- `remote.Executor` — низкоуровневый интерфейс: запуск argv (не строки
  shell) с опциональным sudo, чтение файла, атомарная запись файла
  (временный файл + `rename`, владелец и права), stat, потоковый вывод.
  Он внутренний: API и UI до него не доходят.
- Над ним — **typed operations** (`remote.OSRelease`, `remote.Arch`,
  `remote.UnitStatus(unit)`, `remote.JournalTail(unit, n)`,
  `remote.ListeningPorts()`, `remote.InstallFile(...)`, …). Каждый
  аргумент проверяется (имя unit — `^[a-zA-Z0-9@._-]+\.service$`, путь —
  абсолютный, без `..`), argv экранируется для shell на стороне SSH
  (`remote.Quote`). Произвольную команду из API выполнить нельзя.
- Привилегии: пользователь SSH — root или пользователь с `sudo -n`
  (NOPASSWD). Sudo с паролем в Phase 1 не поддерживается (preflight
  сообщает об этом понятной ошибкой).
- **Host key — TOFU.** Нет сохранённого ключа → операция возвращает
  `host_key_unknown` с отпечатком SHA-256; UI показывает его и ждёт
  подтверждения (`POST /servers/{id}/host-key` с тем же отпечатком).
  Подтверждение заново читает ключ сервера (`sshexec.FetchHostKey`:
  рукопожатие обрывается на проверке ключа, учётные данные не
  отправляются) и сохраняет его, только если отпечаток совпал с
  подтверждённым. Ключ изменился → `host_key_changed` со старым и новым
  отпечатком; подключение запрещено, пока пользователь явно не выполнит
  re-trust (`replace: true`). Проверка ключа идёт до аутентификации:
  непроверенный сервер не видит ни пароля, ни ключа. Смена адреса или
  порта сервера забывает доверенный ключ. `InsecureIgnoreHostKey` не
  используется нигде.
- Тесты: `remote/fake` (сценарии ответов, журнал вызовов, запрет записи
  для импорта) и in-process SSH-сервер на `x/crypto/ssh` для sshexec.
  Docker-тесты — только за build tag `integration`.

## Jobs

State machine:

```
queued → connecting → preflight → downloading → installing → configuring
       → firewall → starting → verifying → completed
любое → failed;  starting/verifying (ошибка) → rolling_back → failed
незавершённый после рестарта → recovering → (checked) → failed | queued (retry)
```

- Job — упорядоченный список шагов. Каждый шаг идемпотентен: сначала
  проверяет, сделано ли уже (`Check`), затем делает (`Run`). Шаг
  объявляет, безопасно ли повторять с него; retry начинается с первого
  незавершённого шага или с ближайшего безопасного шага перед ним.
- Выполнение: пул воркеров, аренда job (`lease_owner`, `lease_until`),
  один активный job на сервер.
- **Recovery.** При старте controller все job в незавершённых состояниях
  переходят в `recovering`: шаг проверки фактического состояния сервера
  (что установлено, какой конфиг, активен ли сервис) определяет, завершён
  ли job фактически, нужен ли откат или retry. Слепого продолжения нет.
- Журнал шагов пишется через `redact` в `job_logs`; live-поток — SSE
  (`GET /api/v1/jobs/{id}/events`): сначала сохранённые строки, затем новые.

## Модель конфига Hysteria

`internal/hyconfig`:

- Typed-структуры серверного конфига по Full Server Config: `listen`,
  `tls`, `acme`, `obfs` (salamander, gecko), `quic`, `bandwidth`,
  `ignoreClientBandwidth`, `speedTest`, `disableUDP`, `udpIdleTimeout`,
  `auth` (password, userpass, http, command), `resolver`, `sniff`, `acl`,
  `outbounds`, `trafficStats`, `masquerade`; и клиентского (для выдачи
  пользователю): `server`, `auth`, `tls`, `obfs`, `transport`, `quic`,
  `bandwidth`, `fastOpen`, `lazy`, режимы `socks5`/`http`.
- **Неизвестные поля.** Каждая структура хранит нераспознанные ключи
  своего уровня (`Unknown` — упорядоченный список пар `yaml.Node`).
  Разбор идёт через `yaml.Node`, сериализация — известные поля в
  каноническом порядке, затем неизвестные как были. Новые поля Hysteria не
  теряются при правке. Комментарии YAML при правке через модель не
  сохраняются (raw-редактор P1-13 показывает diff до применения).
- Валидация на стороне controller: обязательные поля, взаимоисключающие
  (`tls` и `acme`, `hopInterval` и `min/maxHopInterval`), формат портов и
  диапазонов, длительности, пароли obfs и auth не пустые. Проверка
  самой Hysteria (`hysteria server --config … --check`, если версия её
  умеет; иначе — запуск с таймаутом) — в P1-13.
- Никаких regex-замен в YAML.

## Ссылки для клиента

`internal/hy2uri` (P1-09): `hysteria2://auth@host:ports/?obfs=…&obfs-password=…&sni=…&insecure=1&pinSHA256=…#name`.
Multi-port (`443,20000-50000`) — в части порта. Самоподписанный
сертификат: `insecure=1` + `pinSHA256` (Hysteria проверяет pin после
пропуска цепочки; клиенты без поддержки pin подключатся без проверки —
предупреждение в UI). Параметры сверх официальной схемы (bandwidth,
режимы клиента) в ссылку не пишутся — так требует документация URI Scheme.

## Развёртывание (P1-10)

- Пути и имена — как у официального установщика: `/usr/local/bin/hysteria`,
  `/etc/hysteria/config.yaml`, `hysteria-server.service`, системный
  пользователь `hysteria`, capabilities `CAP_NET_ADMIN CAP_NET_BIND_SERVICE
  CAP_NET_RAW`, `NoNewPrivileges=true`. Такую установку потом понимает и
  импорт, и официальный скрипт.
- Бинарник: `hysteria-linux-<arch>` из релиза GitHub выбранной версии,
  SHA-256 сверяется с `hashes.txt` того же релиза. Источник
  (`download.Source`): **direct** — сервер скачивает сам, controller
  сверяет хеш на сервере; **relay** — controller скачивает и сверяет
  сам, заливает по SFTP. Phase 3 добавит источник «через другой узел».
- TLS: самоподписанный сертификат генерирует controller (ключ уходит на
  сервер по SFTP, 0600, владелец `hysteria`) — клиенту выдаётся pin; или
  ACME (`acme.domains`, тип http/tls) — нужен домен и открытый TCP 80/443.
- Port hopping: встроенный диапазон Hysteria на Linux (`listen:
  :20000-50000`) — сервер сам ставит перенаправление через nftables или
  iptables для IPv4 и IPv6 и снимает его при остановке. Controller только
  открывает диапазон в firewall, если firewall активен.
- Firewall: если активен ufw или firewalld — открыть нужные UDP-порты (и
  TCP для ACME) их средствами и запомнить, что открыто. Голые
  nftables/iptables с политикой ACCEPT — ничего не трогать; с политикой
  DROP — предупреждение в preflight и правило только по явному согласию
  (ручные persistent-правила iptables не пишутся).
- Повторный развёртывание: каждый шаг сверяет фактическое состояние;
  одинаковый конфиг и версия → ничего не меняется и сервис не
  перезапускается.

## Импорт (P1-11)

Только читающие операции (fake executor в тесте запрещает запись):
найти unit `hysteria-server*.service` и его `ExecStart`, путь конфига,
бинарник и версию (`hysteria version`), прочитать конфиг, разобрать в
typed-модель. Предупреждения «Needs attention»: неизвестные поля,
нестандартные пути, сервис от root, конфиг читается всеми, `insecure`-
настройки outbounds, Traffic Stats API без secret или на внешнем адресе,
пароль auth слабый, masquerade отсутствует, версия старше поддерживаемой.

## Применение конфига (P1-13)

read current → backup (ревизия) → candidate → validate (модель + сама
Hysteria) → diff → атомарная установка → restart → health check → commit
ревизии. Ошибка после установки → rollback (прежний файл) → restart →
отчёт. Desired state — последняя применённая ревизия; actual state —
SHA-256 файла на сервере и статус сервиса; расхождение (правка вручную) —
«Needs attention». Регулярная reconciliation — Phase 4.

## Topology

`chains` и `chain_hops`: цепочка из N узлов с ролями entry/relay/exit.
Phase 1 создаёт цепочку из одного узла (standalone) и хранит роль
сервера. Каскад Entry → Exit (Phase 3): на entry работает сервер
Hysteria и клиент Hysteria до exit (outbound `socks5` на локальный
клиент), промежуточные credentials генерируются. Модель не ограничивает
число узлов, поэтому N-hop (Phase 4) не требует миграции схемы.

## REST API v1

Ошибки: `{"error": {"code": "host_key_unknown", "message": "понятный текст",
"details": "технические подробности"}}` с HTTP-статусом по смыслу.

| Метод | Путь | Роль | Что |
|---|---|---|---|
| GET | `/api/v1/health` | — | жив ли controller, версия схемы БД |
| GET | `/api/v1/setup` | — | нужен ли первый запуск |
| POST | `/api/v1/setup` | — | создать owner (setup token) |
| POST | `/api/v1/session` | — | логин |
| GET | `/api/v1/session` | любая | текущий пользователь, CSRF-токен |
| DELETE | `/api/v1/session` | любая | выход |
| GET/DELETE | `/api/v1/sessions[/{id}]` | owner/admin | список и отзыв сессий |
| GET/POST | `/api/v1/servers` | читать: любая; создать: operator+ | инвентарь |
| GET/PATCH/DELETE | `/api/v1/servers/{id}` | | |
| POST | `/api/v1/servers/{id}/check` | operator+ | подключение и проверка прав (ничего не меняет) |
| POST | `/api/v1/servers/{id}/host-key` | operator+ | TOFU / re-trust с отпечатком (`replace`) |
| POST | `/api/v1/servers/{id}/preflight` | operator+ | job preflight |
| POST | `/api/v1/servers/{id}/deploy` | operator+ | job Quick Deploy |
| POST | `/api/v1/servers/{id}/import` | operator+ | job импорта |
| GET | `/api/v1/servers/{id}/status` | любая | статус сервиса |
| POST | `/api/v1/servers/{id}/service/{start,stop,restart}` | operator+ | с подтверждением в UI |
| GET | `/api/v1/servers/{id}/journal` (SSE) | любая | журнал Hysteria через redaction |
| GET/POST | `/api/v1/servers/{id}/config` | читать: любая; применить: operator+ | текущий конфиг (секреты скрыты), diff, apply |
| GET | `/api/v1/servers/{id}/client` | любая | ссылка/QR/конфиг без секретов; `?reveal=1` — operator+, пишется в audit log |
| GET | `/api/v1/jobs`, `/api/v1/jobs/{id}` | любая | список (`?server=`, `?before=`), детали с шагами |
| GET | `/api/v1/jobs/{id}/logs` | любая | строки журнала после `?after=` |
| GET | `/api/v1/jobs/{id}/events` (SSE) | любая | сохранённый журнал после `Last-Event-ID`, затем события `log`/`step`/`job` до конца задания, `end` |
| POST | `/api/v1/jobs/{id}/retry` | operator+ | повтор с безопасного шага |
| GET | `/api/v1/logs` | любая | журнал controller и jobs с фильтрами |

## Модель угроз

| Типичная ошибка самодельных установщиков | Как закрыто |
|---|---|
| SSH без проверки ключа хоста (AutoAddPolicy, `InsecureIgnoreHostKey`) | TOFU с подтверждением отпечатка, отказ при смене ключа, re-trust только явно |
| Секреты в коде, логах, чатах | Envelope encryption в БД, `redact` на журналы controller, jobs и journal сервера, ответы API без секретов, фейковые значения в тестах |
| Открытый management API | Bind `127.0.0.1` по умолчанию; setup token для первого пользователя; сессии + CSRF + rate limit; доступ извне — SSH-туннель или reverse proxy с TLS (документируется) |
| Произвольные shell-команды | Только typed operations с проверкой аргументов и экранированием; в API нет «выполнить команду» |
| Правка YAML через sed/regex | Typed-модель + сериализация, diff перед применением, откат |
| Persistent iptables руками | Port hopping встроенный в Hysteria (снимается вместе с сервисом); firewall — через ufw/firewalld, если они активны |
| Бинарник без проверки | SHA-256 из `hashes.txt` релиза; relay-загрузка проверяется на controller |
| Сервис от root, ключи читаемы всеми | Пользователь `hysteria`, capabilities вместо root, ключ и конфиг 0600/0640 |
| Traffic Stats API наружу без секрета | Phase 2: только `127.0.0.1`, секрет всегда; импорт предупреждает о чужой такой настройке |
| Потеря контроля после сбоя | Jobs с recovery через проверку фактического состояния; откат конфига |
| Кража БД | Без master key секреты в БД бесполезны; master key хранится отдельно (env или файл 0600) |

## Решения и допущения

- Целевая версия Hysteria — v2.12.3 (последняя на момент написания);
  список поддерживаемых версий и минимальная — в `deploy`, обновляется
  вместе с документацией.
- Встроенный диапазон портов в `listen` работает только на Linux —
  развёртывание поддерживает только Linux-серверы с systemd.
- Поддерживаемые ОС сервера в Phase 1: Debian 11+, Ubuntu 22.04+ (как
  рекомендует официальный установщик); Rocky/Alma/Fedora — best effort с
  предупреждением; Alpine, OpenWrt, NixOS — не поддерживаются.
- Строки UI — в словаре `web/admin/src/i18n/ru.ts`, чтобы позже добавить
  другие языки.
