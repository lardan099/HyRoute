# HyRoute Server Manager — архитектура

Server Manager (`hyroute-server`) — controller, который разворачивает,
импортирует и обслуживает серверы Hysteria 2 по SSH и выдаёт ссылки для
клиента HyRoute. Работает на Linux VPS (основной сценарий), собирается и
на Windows. Этот документ описывает устройство Phase 1 в том виде, как
она сделана, и решения, которые не должны помешать Phase 2–4. План задач —
`TODO_SERVER_MANAGER.md`, инструкция для пользователя — `SERVER_MANAGER.md`.

Сверено с документацией Hysteria 2 (hysteria.network: Installation,
Server Installation Script, Full Server Config, Full Client Config, URI
Scheme, Port Hopping, Traffic Stats API, ACL) и исходниками
`apernet/hysteria` app/v2.12.3 — последней версией на момент написания.

## Аудит репозитория

Что есть и что из этого переиспользуется:

| Что | Где | Как используется в Server Manager |
|---|---|---|
| Модель клиентского профиля, парсер и сериализатор `hysteria2://` | `internal/hysteria` (`Profile`, `ParseURI`, `URI`) | P1-09 вынес модель ссылки в общий пакет `internal/hy2uri`; клиент перешёл на него, все его тесты прежние (добавилось чтение `ports` и `mportHopInt`) |
| Генерация клиентского YAML | `internal/hysteria/config.go` (`BuildConfig`) | Server Manager строит клиентский конфиг своей typed-моделью (P1-08): клиентский `BuildConfig` добавляет `socks5`-режим HyRoute и не годится для выдачи пользователю |
| Серверы, подписки, группы, правила клиента | `internal/app`, `internal/rules`, `internal/groups` | Не используются: это модель клиента. Связь с клиентом — только через ссылку `hysteria2://` («Добавить в HyRoute», P1-14) |
| Проверка SHA-256 скачанных бинарников | `internal/runtimefiles`, `build/deps.json` | Тот же принцип для релей-загрузки: `hashes.txt` релиза Hysteria + SHA-256 файла |
| Маскирование секретов в журналах | `internal/logx` | Server Manager получает свой пакет `redact` (P1-03): набор секретов шире (SSH-ключи, токены, секреты API) |
| Argon2id, AES-256-GCM | резервная копия клиента (`internal/backup`) | Те же примитивы из `golang.org/x/crypto`; код не общий — у копии свой формат |
| Интерфейс | `frontend/` (Svelte 5, `style.css` с токенами тем) | Админка `web/admin` — отдельное приложение с тем же визуальным языком (копия токенов, не общий код) |
| YAML | `gopkg.in/yaml.v3` уже в зависимостях | Typed-модель конфига поверх `yaml.Node` (сохранение неизвестных полей) |
| SSH | `golang.org/x/crypto` уже в зависимостях (пакет `ssh`) | `RemoteExecutor`; SFTP — `github.com/pkg/sftp` (новая зависимость) |

Новые зависимости: `modernc.org/sqlite` (SQLite без CGO),
`github.com/pkg/sftp` и `rsc.io/qr` (QR-коды ссылок, P1-14). Все
собираются на Linux и Windows.

Правило разделения: пакеты Server Manager лежат в `internal/srvmgr/...`
и не импортируют пакеты клиента, кроме общих `internal/hy2uri` и
`internal/hyconfig`. Клиент не импортирует ничего из `internal/srvmgr`.
Поведение Windows-клиента не меняется (единственное исключение —
переход на общий пакет ссылок в P1-09 с сохранением всех тестов: клиент
теперь понимает ещё `ports` и `mportHopInt`).

## Обязательное поведение

Поведение старого прототипа-установщика, которое должно быть в новой
системе, и задача, в которой оно появляется.

| # | Поведение | Задача | Как |
|---|---|---|---|
| 1 | Развёртывание одного сервера | P1-10 | Job Quick Deploy: preflight → бинарник → unit → TLS → конфиг → firewall → запуск → проверка |
| 2 | Каскад Entry → Exit | роль сервера — P1-04, работа — Phase 3 | Topology из N узлов — Phase 3; в Phase 1 у сервера только роль |
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
| 13 | Релей-загрузка, если у сервера нет доступа к GitHub | P1-10 (через controller), Phase 3 (через другой узел) | Интерфейс `hyrelease.Source` |
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
  logbuf                      буфер последних записей журнала controller (страница «Журнал»)
  servers                     инвентарь серверов, учётные данные SSH (шифруются)
  connect                     подключение по SSH к серверу из инвентаря, TOFU, проверка
  remote                      интерфейс Executor, typed operations, ReadOnly, ошибки
  remote/sshexec              реализация на x/crypto/ssh + pkg/sftp
  remote/fake, remote/sshtest fake executor и in-process SSH-сервер для тестов
  jobs                        job engine: шаги, Done/Run/Undo, откат, recovery, журнал, SSE
  preflight                   проверки сервера перед развёртыванием (задание preflight)
  hyrelease                   релизы Hysteria: ассет, SHA-256, источники direct и relay
  deploy                      Quick Deploy (задание deploy) и запуск с секретами
  importer                    импорт установленного сервера (задание import, только чтение)
  service                     статус, start/stop/restart (задание service), journal
  apply                       редактор конфига: маскирование, поля, diff; задание apply
  firewall                    порты конфига, открытие/закрытие в ufw/firewalld и учёт правил HyRoute
  monitor                     сбор метрик серверов по расписанию (вне движка заданий)
  profile                     ссылки, клиентский конфиг и QR для клиентов
  api                         HTTP /api/v1: handlers, middleware, ошибки
```

Цепочки узлов (`topology`) появятся в Phase 3; в Phase 1 у сервера есть
только поле роли.

Зависимости направлены сверху вниз: `api` → сервисы (`deploy`, `importer`,
`service`, `apply`, `profile`, `auth`, `preflight`) → `firewall` → `jobs`, `remote`, `hyconfig`,
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
| `installations` | server_id, binary_path, config_path, unit, service_user, version, managed (bool), updated_at | managed = установлено HyRoute (deploy); импорт записывает найденную установку с managed = 0 |
| `server_configs` | id, server_id, revision, config (envelope, контекст `server/<id>/config/<rev>`), sha256, meta (json: версия, listen, порты, TLS, pin, SNI, obfs, auth), source (deploy/import/edit), job_id, created_by, created_at | ревизия появляется только после успешного применения; YAML с паролями — зашифрован |
| `jobs` | id, kind, server_id, state, current_step, params (json без секретов), secret_params (envelope), attempt, error_message, error_details, created_by, created_at, started_at, finished_at, lease_owner, lease_until | |
| `job_steps` | job_id, idx, name, state, attempt, started_at, finished_at, error | |
| `job_logs` | job_id, seq, ts, level, step, message | message уже прошёл redaction |
| `audit_log` | id, ts, user_id, action, target, details | кто что сделал (вход, выход, пользователи, подтверждение ключа, показ ссылок) |

Ссылки для клиентов не хранятся: они собираются из текущей ревизии по
запросу (`profile`). Таблицы топологии (`chains`, `chain_hops`) — Phase 3.

Секреты — только в колонках-envelope (`secrets.Sealed`, BLOB). Тест
P1-04 сканирует файл БД на открытые значения тестовых секретов.

## Секреты

- **Master key** — 32 байта, base64: `HYROUTE_MASTER_KEY` или файл
  (`--master-key-file`, по умолчанию `<data-dir>/master.key`). Файл должен
  иметь права 0600 и принадлежать пользователю controller, иначе запуск
  отказывается. То же для каталога данных (0700) и файлов БД (0600, с
  `-wal` и `-shm`) — пакет `datadir`, проверка до чтения чего-либо и с
  командой исправления в ошибке. На Windows права не проверяются, а
  ставятся: защищённый ACL только для SYSTEM, Administrators и
  пользователя controller (у каталога — наследуемый). Если
  ни ключа, ни файла нет, файл создаётся, только пока в БД нет ничего
  зашифрованного, и в журнал пишется, что его нужно сохранить. БД помнит
  свой ключ: в `settings` (`master_key_check`) лежит проверочное значение,
  зашифрованное им (после ротации — текущей версией). Без ключа или с
  другим ключом controller не стартует (`secrets.Open`) до первой записи
  зашифрованного и не создаёт новый ключ рядом со старыми данными. Потеря
  ключа = потеря всех сохранённых credentials и конфигов в БД; серверы
  продолжают работать, их можно импортировать заново.
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
  Файл больше 32 МБ не читается: `remote.ErrFileTooLarge`, а не
  обрезанные данные. Он внутренний: API и UI до него не доходят.
- Над ним — **typed operations**: `RunProbe`, `ReadOSRelease`, `Memory`,
  `DiskFree`, `Uptime`, `LoadAverage`, `Listeners`, `ReadFirewall`,
  `Unit`, `ServiceUnits`, `UnitOfPID`, `ActiveState`, `Systemctl`,
  `DaemonReload`, `JournalTail`, `JournalEntries`, `JournalFollow`,
  `HysteriaVersion`, `Stat`, `FileSHA256`, `Download`, `InstallFile`,
  `CopyFile`, `Rename`, `RemoveFile`, `MakeDir`, `TempDir`,
  `CreateSystemUser`, `UserHome`, `UFWAllow`, `FirewalldAllow`,
  `PortAllowed`, `OpenPort`, `ClosePort`. Каждый
  аргумент проверяется (имя unit — `^[a-zA-Z0-9@._-]+\.service$`, путь —
  абсолютный, без `..`), argv экранируется для shell на стороне SSH
  (`remote.Quote`). Произвольную команду из API выполнить нельзя.
- `remote.ReadOnly(ex)` — исполнитель для работы, которая не должна
  ничего менять (импорт, статус, журнал, сводка конфига после apply):
  запись файлов отклоняется, команды — только читающие typed-операции с
  их читающими флагами.
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
  проверяет фактическое состояние (`Done`), затем делает (`Run`); `Undo`
  откатывает сделанное. При ошибке шага откатываются он сам и все
  выполненные и пропущенные шаги перед ним, в обратном порядке
  (`ErrNothingToUndo` — откатывать нечего).
- **Запись до изменения.** `Env.Set` пишет данные задания в БД до
  возврата, и шаг записывает, что собирается изменить, до изменения:
  копии файлов хранят SHA-256 исходного файла (или `absent`). `Undo`
  действует только по этим записям: восстанавливает копию, если её хеш
  совпадает с записанным, удаляет файл, которого не было, и ничего не
  трогает без записи. Поэтому откат задания, прерванного падением
  controller посреди шага, возвращает прежний файл, а не удаляет новый.
  Ошибка записи — ошибка шага. Шаг
  объявляет, безопасно ли повторять с него; retry начинается с первого
  незавершённого шага или с ближайшего безопасного шага перед ним.
  Хук `Finished` выставляет состояние сервера.
- Выполнение: пул воркеров, аренда job (`lease_owner`, `lease_until`),
  один активный job на сервер.
- **Recovery.** При старте controller все job в незавершённых состояниях
  переходят в `recovering`, и вид задания решает (`Recover`): deploy,
  import и apply продолжают с ближайшего безопасного шага (каждый шаг
  сначала сверяет сервер), service помечается ошибкой — недоделанный
  start/stop/restart сам не повторяется. Слепого продолжения нет.
- Журнал шагов пишется через `redact` в `job_logs`; live-поток — SSE
  (`GET /api/v1/jobs/{id}/events`): сначала сохранённые строки, затем новые.

## Модель конфига Hysteria

`internal/hyconfig`:

- Typed-структуры серверного конфига по Full Server Config (app
  v2.12.3): `listen`, `tls`, `acme`, `ech`, `obfs` (salamander, gecko),
  `quic`, `mimic`, `congestion`, `bandwidth`, `ignoreClientBandwidth`,
  `speedTest`, `disableUDP`, `udpIdleTimeout`, `auth` (password,
  userpass, http, command), `resolver`, `sniff`, `acl`, `outbounds`,
  `trafficStats`, `masquerade`, `realm`; и клиентского (для выдачи
  пользователю): `server`, `auth`, `tls`, `obfs`, `transport`, `quic`,
  `congestion`, `bandwidth`, `fastOpen`, `lazy`, `mimic`, `realm`, режимы
  `socks5`/`http` (остальные режимы — неизвестные поля).
- **Неизвестные поля.** Каждая структура хранит нераспознанные ключи
  своего уровня (`Unknown` — упорядоченный список пар `yaml.Node`).
  Разбор идёт через `yaml.Node`, сериализация — известные поля в
  каноническом порядке, затем неизвестные как были. Ключи сопоставляются
  без учёта регистра, как в Hysteria. Новые поля Hysteria не теряются при
  правке; `UnknownFields` перечисляет их пути для предупреждений импорта.
  Комментарии YAML при правке через модель не сохраняются (raw-редактор
  P1-13 показывает diff до применения).
- `ParseListen` разбирает `listen` (порт, диапазон, первый порт, который
  слушает сервер); `ClientFor(server, ClientOptions)` строит клиентский
  конфиг из серверного и того, что знает только controller (публичный
  адрес, pin самоподписанного сертификата, выбранный пользователь,
  hopInterval, скорости).
- Валидация на стороне controller (`Validate` → список `Problem`: поле,
  текст, ошибка или предупреждение): обязательные поля по выбранному типу,
  взаимоисключающие (`tls` и `acme`, `acl.file` и `acl.inline`,
  `hopInterval` и `min/maxHopInterval`), формат портов и диапазонов,
  длительности и их допустимые границы, скорости, пароли obfs и auth.
  Команды «проверить конфиг без запуска» у Hysteria v2 нет: проверкой
  служит перезапуск с откатом (P1-13).
- Никаких regex-замен в YAML.

## Ссылки для клиента

`internal/hy2uri` (P1-09): модель `Link`, разбор и два вида записи.

- `String()` — официальная схема URI Scheme:
  `hysteria2://auth@host:443,20000-50000/?obfs=…&obfs-password=…&sni=…&insecure=1&pinSHA256=…#name`.
  Multi-port — в части порта; так ссылки принимают Hysteria, HApp и Incy
  (по их документации). Параметры сверх официальной схемы (скорость,
  интервал hopping) в неё не пишутся.
- `Compat()` — для импортёров, которые разбирают адрес URL-библиотекой
  (v2rayN и клиенты на System.Uri): в адресе первый порт, весь список — в
  `mport`, интервал — `mportHopInt` в секундах (его читает Incy). Для
  одного порта совпадает с `String()`. Shadowrocket по первоисточникам
  проверить не удалось — UI P1-14 предлагает обе ссылки.
- `Parse` принимает обе формы и варианты панелей и клиентов: `hy2://`,
  `mport`/`ports`, `mportHopInt`, `up`/`down`, `allowInsecure`, `peer`,
  `pcs`, `fm` (Xray finalmask), `obfs-password` без `obfs`; догадки и
  лишние параметры — в предупреждениях.
- Самоподписанный сертификат: `insecure=1` + `pinSHA256` (Hysteria
  проверяет pin после пропуска цепочки; клиенты без поддержки pin
  подключатся без проверки — предупреждение в UI).

## Развёртывание (P1-10)

- Пути и имена — как у официального установщика: `/usr/local/bin/hysteria`,
  `/etc/hysteria/config.yaml`, `hysteria-server.service`, системный
  пользователь `hysteria`, capabilities `CAP_NET_ADMIN CAP_NET_BIND_SERVICE
  CAP_NET_RAW`, `NoNewPrivileges=true`. Такую установку потом понимает и
  импорт, и официальный скрипт.
- Бинарник: `hysteria-linux-<arch>` из релиза GitHub выбранной версии,
  SHA-256 сверяется с `hashes.txt` того же релиза. Источник
  (`hyrelease.Source`): **direct** — сервер скачивает сам, controller
  сверяет хеш на сервере; **relay** — controller скачивает и сверяет
  сам, заливает по SFTP. Phase 3 добавит источник «через другой узел».
- TLS: самоподписанный сертификат (ECDSA P-256, 10 лет) генерирует
  controller; ключ и конфиг на сервере — 0640 root:hysteria (служба
  читает, остальные нет), клиенту выдаётся pin; или
  ACME (`acme.domains`, тип http/tls) — нужен домен и открытый TCP 80/443.
- Port hopping: встроенный диапазон Hysteria на Linux (`listen:
  :20000-50000`) — сервер сам ставит перенаправление через nftables или
  iptables для IPv4 и IPv6 и снимает его при остановке. Controller только
  открывает диапазон в firewall, если firewall активен.
- Firewall: если активен ufw или firewalld — открыть нужные UDP-порты (и
  TCP для ACME) их средствами. Открывается только то, чего нет: порт
  сначала записывается в данные задания (`fwAdded`), потом добавляется
  правило, и `Undo` шага закрывает ровно эти правила (правила, которые
  были до задания, не трогаются). После успешной проверки commit
  записывает в `installations` (`firewall_tool`, `firewall_ports`)
  прежние правила HyRoute плюс открытые заданием, и последний шаг
  `cleanup` закрывает записанные правила HyRoute для портов, которых в
  новом конфиге нет. `cleanup` не валит задание: незакрытое правило
  остаётся в записи с предупреждением. «Брандмауэр не трогать» при
  развёртывании запоминается (`firewall_keep`) и соблюдается apply. Голые
  nftables/iptables с политикой ACCEPT — ничего не трогать; с политикой
  DROP — только предупреждение: порты открывает администратор
  (persistent-правила iptables HyRoute не пишет).
- Повторный развёртывание: каждый шаг сверяет фактическое состояние;
  одинаковый конфиг и версия → ничего не меняется и сервис не
  перезапускается.

## Импорт (P1-11)

Все команды — через `remote.ReadOnly`. Служба ищется среди стандартной
`hysteria-server.service`, `hysteria*` (в том числе экземпляров шаблона) и
служб процессов `hysteria*` на слушающих портах (`ps -o unit=`); из
нескольких берётся работающая. Из `ExecStart` — программа и `-c/--config`
(относительный путь — от WorkingDirectory; без флага — места, где
Hysteria ищет `config.yaml`). Версия — `hysteria version` (только у
программы с именем `hysteria*`). Конфиг разбирается typed-моделью,
сертификат читается (ключ — никогда): у самоподписанного — pin, у
выданного CA — срок. Находки (warn — «Требует внимания», info — к
сведению): конфиг читается или пишется всеми, служба от root, не
работает или не в автозапуске, нет Restart, ошибки валидации, неизвестные
поля, короткие пароли auth и obfs, сертификат нет / истёк / истекает,
Traffic Stats API не на localhost или без секрета, `insecure` в
auth.http, outbounds и resolver, нестандартные пути, другие службы
Hysteria, старая версия, userpass и внешняя проверка паролей, нет
маскировки. Сохранение: ревизия `import` (конфиг читается повторно и
должен совпасть по SHA-256) и запись `installations` с managed = 0.
Deploy не считает такую установку своей: без замены — отказ, в
нестандартных местах — не заменяет вовсе.

## Применение конфига (P1-13)

Редактор получает конфиг с `[REDACTED]` вместо секретов (на уровне
`yaml.Node`: порядок и комментарии остаются); кандидат получает текущие
секреты обратно по пути поля (элементы списков — по `name`), новые
секреты остаются видимыми. Основные поля ⇄ typed-модель. Проверка: разбор,
`Validate`, diff с текущей ревизией без секретов, список меняющихся
секретов. Задание `apply`: файл на сервере должен совпадать с базовой
ревизией (правка вручную — отказ с предложением импорта) → копия
`.hyroute-prev` → атомарная запись с правами прежнего файла → firewall
(порты, которых не было в прежнем конфиге, открываются в ufw/firewalld;
откат их закрывает) → restart → служба active и UDP-порт слушает
hysteria → ревизия `edit` → cleanup (закрыть правила HyRoute для
ушедших портов).

История (P2-01): ревизии не меняются и не удаляются. Возврат к ревизии N
— то же задание `apply` с конфигом ревизии N как кандидатом (`Params.From
= N`): базой должна оставаться текущая ревизия, кандидат проходит
`Validate`, а результат сохраняется как новая ревизия с источником
`rollback` и `from_revision = N` (миграция 0009 пересобирает таблицу:
SQLite не меняет CHECK). Неудачный возврат откатывается как любое
применение, ревизия не добавляется. Текст ревизий и diff открыты только
ролям с правом записи, как и редактор: маскирование не знает секретов под
неизвестными ключами. Ошибка после
записи → прежний файл → restart → отчёт с журналом (редакция паролями
обоих конфигов). Регулярная сверка desired/actual (reconciliation) —
Phase 4.

## Мониторинг (P2-02)

`monitor.Collector` раз в `-monitor-interval` (по умолчанию минута, 0 —
выключен) обходит серверы с доверенным ключом хоста: не больше 4
подключений сразу, 20 с на сервер, исполнитель `remote.ReadOnly`, без
sudo. Замер — `remote.ReadSample`: один `head -n 200 -- /proc/stat
/proc/meminfo /proc/loadavg /proc/net/dev /proc/uptime` (заголовки `==>
файл <==` разделяют части) и `df -Pk /`. CPU (всё, кроме idle и iowait)
и скорости сети — разница с прошлым замером того же сервера, который
хранится в памяти; первый замер после запуска controller и замер после
перезагрузки сервера (uptime уменьшился) скоростей не имеют. Сеть —
сумма интерфейсов, кроме `lo` и виртуальных (`veth*`, `docker*`, `br-*`,
`virbr*`, `cni*`, `flannel*`): их трафик идёт и через настоящий.

Таблица `metrics` (миграция 0010): замеры (`step` 0) хранятся 48 ч,
15-минутные средние (`step` 900) — 30 дней. Раз в 10 минут
`CompactMetrics` усредняет завершённые периоды, пересчитывая только те,
чьи замеры ещё все на месте, и удаляет старое.

Состояние сервера сборщик меняет только атомарно (`SwapServerState`):
Healthy/Degraded → Offline, если SSH недоступен (`UnreachableError`;
отказ в доступе или смена ключа хоста — только запись в журнал), и
Offline → Healthy, когда замер снова удался. Состояния заданий
(Deploying, Needs attention) он не трогает.

Здоровье (P2-03). У серверов с установленной Hysteria тот же круг
делает проверку: служба (`systemctl is-active`), слушает ли Hysteria
UDP-порт конфига (`ss`), адрес исходящего интерфейса (`ip -o route get
1.1.1.1` — только поиск маршрута, без трафика; за NAT это частный
адрес), время SSH-подключения и UDP снаружи. UDP проверяет
`quicprobe`: controller шлёт на порт QUIC-пакет зарезервированной версии
`0x1a2a3a4a`, дополненный до 1200 байт; QUIC-сервер обязан ответить
Version Negotiation с нашими connection ID (RFC 9000 §6, §15, §17.2.1).
Пароль клиентов не нужен и сервер ничего не принимает от нашего имени.
С Salamander пакет обфусцируется паролем obfs так же, как это делает
Hysteria (соль 8 байт, XOR с BLAKE2b-256(пароль‖соль)); с другой
обфускацией UDP не проверяется. Проба идёт параллельно с SSH, 3 с, пакет
повторяется через 300 мс. Допущение: Hysteria не выключает Version
Negotiation в quic-go (по умолчанию включено) — проверить на живом
сервере.

Статус: SSH и UDP молчат → Offline; SSH нет, UDP отвечает → Degraded;
служба не active, не слушает порт, UDP не отвечает или проба упала →
Degraded с причиной; иначе Healthy. Статус пишется в историю
(`health_checks`, миграция 0011, 7 дней) и переносится на сервер
`SwapServerState` только между Healthy/Degraded/Offline. Серверы с
незавершённым заданием в этом круге не проверяются: задание само
перезапускает службу и меняет порты.

UI: карточка «Нагрузка сервера» — пять небольших графиков (свой SVG, без
библиотек): процессор, память (ось до установленной), сеть (приём и
отдача в бит/с, два ряда с легендой), load, диск; перекрестье с
подсказкой по мыши и стрелкам, разрыв линии на пропусках, табличный вид.
Цвета рядов — токены `--viz-1`/`--viz-2` в каждой теме, проверены
валидатором палитры (различимость при дальтонизме, контраст с фоном).

## Topology

План (Phase 3): `chains` и `chain_hops` — цепочка из N узлов с ролями
entry/relay/exit. В Phase 1 у сервера есть только поле роли. Каскад
Entry → Exit (Phase 3): на entry работает сервер
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
| POST | `/api/v1/servers/{id}/deploy` | operator+ | job Quick Deploy; нужен подтверждённый ключ SSH; пароли прежней ревизии (любой `auth`) сохраняются; текущий конфиг не из развёртывания (правка, возврат, импорт) заменяется только с `"overwrite": true`, иначе 409 `config_changed` |
| POST | `/api/v1/servers/{id}/import` | operator+ | job импорта |
| GET | `/api/v1/servers/{id}/status` | любая | статус сервиса |
| POST | `/api/v1/servers/{id}/service/{start,stop,restart}` | operator+ | с подтверждением в UI |
| GET | `/api/v1/servers/{id}/journal` | любая | журнал Hysteria через redaction (шаблоны + пароли текущего конфига): JSON последних записей или SSE с `?follow=1` |
| GET | `/api/v1/servers/{id}/config` | любая | сводка текущей ревизии (версия, порты, TLS, pin, obfs; без конфига и паролей) |
| GET | `/api/v1/servers/{id}/config/edit` | operator+ | конфиг для редактора: секреты `[REDACTED]` (под секретными ключами, за alias, пароли в URL, шаблоны redactor, комментарии), основные поля |
| POST | `/api/v1/servers/{id}/config/render` | operator+ | кандидат из текста и полей: проверка, diff, меняющиеся секреты (ничего не сохраняет) |
| POST | `/api/v1/servers/{id}/config/apply` | operator+ | задание `apply` с откатом |
| GET | `/api/v1/servers/{id}/metrics?period=` | любая роль | ряд метрик: 1h/6h/24h/48h — замеры, 7d/30d — средние по 15 мин |
| GET | `/api/v1/metrics/latest` | любая роль | последний замер каждого сервера за 5 минут (Overview) |
| GET | `/api/v1/servers/{id}/health` | любая роль | последняя проверка и смены статуса или причины за неделю (до 50) |
| GET | `/api/v1/servers/{id}/config/revisions` | любая роль | история ревизий без текста конфига |
| GET | `/api/v1/servers/{id}/config/revisions/{rev}` | operator+ | конфиг ревизии, секреты замаскированы |
| GET | `/api/v1/servers/{id}/config/compare?from=&to=` | operator+ | diff двух ревизий без секретов, изменённые секреты — путями |
| POST | `/api/v1/servers/{id}/config/rollback` | operator+ | `{base, revision}`: задание `apply` с конфигом ревизии |
| GET | `/api/v1/servers/{id}/client` | любая | сводка для клиентов без секретов |
| POST | `/api/v1/servers/{id}/client/reveal` | operator+ | `{user}` → ссылки (официальная и совместимая), `config.yaml`, QR; CSRF, `no-store`, пишется в audit log |
| GET | `/api/v1/jobs`, `/api/v1/jobs/{id}` | любая | список (`?server=`, `?before=`), детали с шагами |
| GET | `/api/v1/jobs/{id}/logs` | любая | строки журнала после `?after=` |
| GET | `/api/v1/jobs/{id}/events` (SSE) | любая | сохранённый журнал после `Last-Event-ID`, затем события `log`/`step`/`job` до конца задания, `end` |
| POST | `/api/v1/jobs/{id}/retry` | operator+ | повтор с безопасного шага |
| GET | `/api/v1/logs` | любая | `source=controller` (буфер последних записей процесса) или `jobs` (журналы заданий), фильтры `server`, `level`, `q`; всё уже отредактировано |

## Модель угроз

| Типичная ошибка самодельных установщиков | Как закрыто |
|---|---|
| SSH без проверки ключа хоста (AutoAddPolicy, `InsecureIgnoreHostKey`) | TOFU с подтверждением отпечатка, отказ при смене ключа, re-trust только явно |
| Секреты в коде, логах, чатах | Envelope encryption в БД, `redact` на журналы controller, jobs и journal сервера, ответы API без секретов, фейковые значения в тестах |
| Открытый management API | Bind `127.0.0.1` по умолчанию; setup token для первого пользователя; сессии + CSRF + rate limit; доступ извне — SSH-туннель, reverse proxy с TLS или встроенный TLS (`-tls-cert`/`-tls-key`); plaintext HTTP на не-loopback адресе — только с явным `-insecure-http` |
| Произвольные shell-команды | Только typed operations с проверкой аргументов и экранированием; в API нет «выполнить команду» |
| Правка YAML через sed/regex | Typed-модель + сериализация, diff перед применением, откат |
| Persistent iptables руками | Port hopping встроенный в Hysteria (снимается вместе с сервисом); firewall — через ufw/firewalld, если они активны |
| Бинарник без проверки | SHA-256 из `hashes.txt` релиза; relay-загрузка проверяется на controller |
| Сервис от root, ключи читаемы всеми | Пользователь `hysteria`, capabilities вместо root, ключ и конфиг 0600/0640 |
| Traffic Stats API наружу без секрета | Импорт предупреждает (не localhost, нет секрета); настройка из панели — Phase 2: только `127.0.0.1`, секрет всегда |
| Потеря контроля после сбоя | Jobs с recovery через проверку фактического состояния; откат конфига |
| Кража БД | Без master key секреты в БД бесполезны; master key хранится отдельно (env или файл 0600) |

## Решения и допущения

- Версия Hysteria по умолчанию — v2.12.3 (`hyrelease.DefaultVersion`, её
  хеши встроены); другую версию можно указать при развёртывании, её хеши
  берутся из `hashes.txt` релиза.
- Встроенный диапазон портов в `listen` работает только на Linux —
  развёртывание поддерживает только Linux-серверы с systemd.
- Поддерживаемые ОС сервера в Phase 1: Debian 11+, Ubuntu 22.04+ (как
  рекомендует официальный установщик); Rocky/Alma/Fedora — best effort с
  предупреждением; Alpine, OpenWrt, NixOS — не поддерживаются.
- Строки UI — в словаре `web/admin/src/i18n/ru.ts`, чтобы позже добавить
  другие языки.
