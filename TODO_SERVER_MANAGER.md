# HyRoute Server Manager — TODO

> Этот файл — рабочий план и спецификация для Claude Code. Лежит в корне репозитория.
> Журнал работы — `docs/SERVER_MANAGER_PROGRESS.md`, архитектура — `docs/SERVER_MANAGER_ARCHITECTURE.md`. Оба файла Claude создаёт сам.

---

## 🤖 Инструкция для Claude (читать в начале КАЖДОЙ сессии)

1. Прочитай `CLAUDE.md` и этот файл. Затем прочитай те из файлов ниже, которые уже существуют:
   - `docs/SERVER_MANAGER_PROGRESS.md` — журнал работы. **Если его нет, создай** с заголовком и пустым журналом, это значит, что работа только начинается;
   - `docs/SERVER_MANAGER_ARCHITECTURE.md` — появится после задачи P1-00;
   - `reference/server-snapshot/` — необязательный снимок реального сервера владельца (см. раздел «Снимок сервера»).
2. Возьми **первую невыполненную задачу** `[ ]` сверху вниз. Задачи со статусом `[!]` (blocked) пропускай.
3. Если задача слишком большая для одного прохода, **сначала разбей её в этом файле** на подзадачи `P1-XXa`, `P1-XXb` и только потом начинай.
4. Выполни задачу. Соблюдай conventions проекта и ограничения из раздела «Зафиксированные решения».
5. Перед тем как отметить задачу выполненной:
   - выполнены все пункты **Done**;
   - прогнаны проверки из `CLAUDE.md` (Go: `gofmt`, `go vet`, `go test ./...`; UI: `svelte-check`, build);
   - все существующие тесты проходят.
6. Отметь задачу `[x]`, сделай коммит с сообщением `server-manager: P1-XX <кратко>`.
7. Добавь запись в `docs/SERVER_MANAGER_PROGRESS.md`: что сделано, принятые решения, известные проблемы.
8. Переходи к следующей задаче. **Не спрашивай подтверждения по мелочам.** Неоднозначность решай в пользу самого простого, безопасного и расширяемого варианта и записывай решение в PROGRESS.
9. Если задача заблокирована (нет доступа к сети, нужна информация от владельца), пометь её `[!]`, опиши причину в PROGRESS и переходи к следующей независимой задаче.
10. Если чувствуешь, что контекст заканчивается, **остановись на границе задачи**: закоммить завершённое, обнови PROGRESS с точным описанием, где остановился.

### Статусы
- `[ ]` — не начата
- `[~]` — в работе (частично сделана, детали в PROGRESS)
- `[x]` — выполнена, проверки прошли, закоммичено
- `[!]` — заблокирована (причина в PROGRESS)

### Жёсткие правила (нарушать нельзя)
- Не менять поведение Windows-клиента HyRoute, кроме явно разрешённого в задаче P1-09.
- Никаких секретов в репозитории, frontend bundle, логах, plain JSON и тестовых фикстурах (только явно фейковые значения).
- Никакого `InsecureIgnoreHostKey` / аналога AutoAddPolicy для SSH.
- Никакого generic «выполнить произвольную команду» в API или UI. Только typed operations.
- Не редактировать YAML regex-заменами — только через typed model + сериализацию.
- Не реализовывать Phase 2–4 заранее. Они описаны только для того, чтобы не принять решений, которые их заблокируют.
- Не делать один гигантский пакет. Business logic не зависит от HTTP handlers и UI.
- Репозиторий **публичный**. Всё, что коммитится, видно всем: никаких реальных IP, паролей, ключей и ссылок даже в тестах и документации.
- `reference/server-snapshot/` — пример реальной установки «как есть», а не образец. Не копировать из него решения, помеченные владельцем как неправильные.

---

## 📌 Зафиксированные решения

> Владелец может поменять любой пункт. Если пункт изменён — следуй новой версии.

| Тема | Решение |
|---|---|
| Где работает controller | Linux VPS (основной сценарий). Запуск на Windows желателен, но не обязателен |
| Бинарник | `cmd/hyroute-server` в том же Go-модуле |
| БД | SQLite через `modernc.org/sqlite` (без CGO), миграции, repository interfaces |
| Web-admin | Svelte 5 в `web/admin`, встраивается через `go:embed`, визуальный язык существующего frontend |
| Язык UI | Русский — основной, строки вынесены так, чтобы позже можно было добавить i18n |
| Bind по умолчанию | `127.0.0.1:<port>`; доступ извне — через SSH-туннель или reverse proxy с TLS (документировать) |
| Master key | env `HYROUTE_MASTER_KEY` или файл с правами 0600; потеря ключа = потеря сохранённых credentials (документировать) |
| Шифрование секретов | AES-256-GCM, envelope encryption, версия ключа хранится рядом с шифротекстом |
| Хеширование паролей | argon2id |
| Live-логи | SSE (проще WebSocket для однонаправленного потока) |
| Тесты remote-операций | fake `RemoteExecutor` + in-process SSH-сервер на `golang.org/x/crypto/ssh`; Docker-тесты только за build tag `integration` |
| Версия Hysteria | Проверить актуальную официальную документацию. Если сеть недоступна — зафиксировать целевую версию и пометить допущения в ARCHITECTURE |
| Ветка | Не коммитить в `main`. Если текущая ветка — `main`, создай `feature/server-manager`. Маленькие коммиты, без force-push |

---

## Снимок сервера (необязательно)

Владелец может положить в `reference/server-snapshot/` снимок своего сервера: конфиги Hysteria, systemd unit, правила firewall, sysctl, версию, ОС, список слушающих портов. Секреты и IP в нём заменены заглушками. В `reference/server-snapshot/README.md` владелец описывает, что в этой установке сделано не так, как надо.

Как использовать снимок:
- как тестовую фикстуру для импорта (P1-11): импорт должен распознавать такую установку, ничего на ней не меняя;
- как источник предупреждений «Needs attention»: каждая проблема из README владельца должна находиться автоматически и сопровождаться понятным объяснением и предложением исправить;
- **не** как образец для генерации новых конфигов.

Если снимка нет, работай по официальной документации Hysteria 2 и пометь в PROGRESS, что импорт проверен только на синтетических фикстурах.

---

## Phase 0 — подготовка (делает ВЛАДЕЛЕЦ, не Claude)

- [ ] Если в старом боте были реальные токены или пароли и файл где-то публиковался или пересылался — отозвать их.
- [ ] (Необязательно) Положить снимок сервера в `reference/server-snapshot/`, **вручную** проверив, что в нём нет секретов и реальных IP.
- [x] Положить этот файл в корень репозитория.

---

## Phase 1 — Foundation

### P1-00 Аудит и архитектура
- [x] Аудит репозитория: README, CLAUDE.md, docs/, cmd/, internal/, frontend/, модели servers/rules/subscriptions/groups/stats, работа с конфигом Hysteria, существующий URI parser.
- [x] Список обязательного поведения (оно было в старом прототипе-установщике и должно быть в новой системе): single-server deploy, cascade Entry → Exit, импорт уже настроенного сервера без изменений, SSH/SFTP deploy, генерация server/client configs, Salamander obfs, сертификаты и fingerprint pinning, port hopping, geosite/geoip, ACL routing, генерация `hysteria2://`, параметры, совместимые с HApp/Incy/Shadowrocket, relay-загрузка, когда у сервера нет доступа к GitHub, управление правилами. Для каждого пункта — в какой задаче он реализуется.
- [x] Если есть `reference/server-snapshot/` — разбор снимка: что распознаётся, какие проблемы из README владельца и как их обнаруживать автоматически.
- [x] Threat model: типичные небезопасные решения самодельных установщиков (AutoAddPolicy для SSH, секреты в коде и логах, открытые management API, произвольные shell-команды, persistent iptables руками) и как каждое закрывается в новой системе.
- [x] Проверка официальной документации Hysteria 2: server/client config, URI scheme, port hopping, Traffic Stats API, ACL/outbounds, congestion control.
- [x] Создать `docs/SERVER_MANAGER_ARCHITECTURE.md`: пакеты и зависимости между ними, DB entities, REST API v1, job state machine, модель desired/actual state и reconciliation, модель Hysteria config с unknown fields, модель topology (N-hop-ready), threat model, решения по секретам.

**Done:** документ создан и покрывает все пункты выше; в нём есть раздел «Обязательное поведение» с чек-листом и привязкой к задачам.

### P1-01 Каркас controller
- [x] `cmd/hyroute-server` с конфигурацией (флаги + env), graceful shutdown.
- [x] SQLite, система миграций, repository interfaces (бизнес-логика не знает про SQL).
- [x] HTTP-роутер `/api/v1`, endpoint `/api/v1/health`, структурированные ошибки (human-readable message + technical details).
- [x] Каркас `web/admin` на Svelte 5 со встраиванием через `go:embed`, навигация: Overview, Servers, Cascades, Rules, Presets, Deployments, Logs, Settings (пока пустые страницы, где не реализовано).

**Done:** `hyroute-server` запускается, отдаёт UI и `/api/v1/health`; миграции применяются на чистой БД; тесты на миграции.

### P1-02 Аутентификация админки
- [x] First-run создание администратора (только если пользователей нет).
- [x] argon2id, сессии в БД, secure/HttpOnly/SameSite cookies, CSRF-защита.
- [x] Rate limiting логина, logout, отзыв сессий.
- [x] Роли в data model: Owner/Admin, Operator, Read-only (enforcement минимальный: Read-only не может менять).
- [x] Все API, кроме login/first-run/health, требуют сессию.

**Done:** тесты: first-run нельзя повторить, неверный пароль, rate limit, истёкшая/отозванная сессия, CSRF, Read-only получает 403 на изменение.

### P1-03 Секреты и redaction
- [x] Пакет secrets: envelope encryption, загрузка master key, ротация версии ключа в модели.
- [x] Пакет redaction: пароли, auth, obfs password, API secret, private key, SSH password/key, Telegram token, полные `hysteria2://` / `hy2://` ссылки. Применяется к логам controller, логам jobs и ответам API.

**Done:** тесты: шифрование round-trip, неверный ключ даёт ошибку, redaction всех перечисленных типов (включая секреты внутри YAML и URI).

### P1-04 Инвентарь серверов
- [x] Entity Server: name, tags, country/location label, host, SSH port/user, auth type, role, заметки, состояние.
- [x] CRUD API, credentials хранятся только зашифрованными и никогда не возвращаются в API.
- [x] Страница Servers: список, добавление, редактирование, удаление с подтверждением.

**Done:** из UI можно добавить/изменить/удалить сервер; в БД нет открытых секретов (тест).

### P1-05 Безопасный SSH-слой
- [x] Интерфейс `RemoteExecutor` + typed operations (не произвольные команды из API).
- [x] Реализация на `golang.org/x/crypto/ssh` + SFTP.
- [x] TOFU: при первом подключении показать fingerprint в UI и ждать подтверждения; сохранить host key; при смене ключа — отказ и понятное предупреждение с возможностью явного re-trust.
- [x] Fake executor для тестов.

**Done:** тесты с in-process SSH-сервером: первый connect требует подтверждения, смена host key блокирует подключение, неверные credentials дают понятную ошибку.

### P1-06 Job engine
- [ ] Jobs и steps в БД, state machine: `queued → connecting → preflight → downloading → installing → configuring → firewall → starting → verifying → completed | failed | rolling_back`.
- [ ] Idempotent steps, retry с безопасного шага.
- [ ] Recovery после рестарта controller: незавершённые jobs переходят в состояние, которое проверяет фактическое состояние сервера, а не слепо продолжает.
- [ ] Лог шагов (через redaction), live-стрим через SSE.
- [ ] Страница Deployments: список jobs, детальный вид с текущим шагом и live-логом, retry.

**Done:** тесты: успешный job, падение на шаге, retry, recovery после «убитого» процесса (симуляция), секреты не попадают в лог job.

### P1-07 Preflight
- [ ] Job preflight: ОС/дистрибутив, архитектура, systemd, ресурсы (CPU/RAM/disk), firewall (ufw/firewalld/nftables/iptables), DNS, занятость нужных портов, доступ к источникам загрузки (GitHub), наличие уже установленной Hysteria.
- [ ] Результат — структурированный отчёт с предупреждениями, показывается в UI.

**Done:** тесты на fake executor для Debian/Ubuntu, неподдерживаемой ОС, занятого порта, отсутствия доступа к GitHub.

### P1-08 Typed model конфига Hysteria
- [ ] Typed-структуры server config (listen, tls, acme, auth, obfs, masquerade, resolver, sniff, bandwidth, quic, outbounds, acl, trafficStats, и т.д. по актуальной документации).
- [ ] Сохранение unknown fields при round-trip (новые поля Hysteria не теряются).
- [ ] Генератор client config.
- [ ] Валидация на стороне controller.

**Done:** round-trip тесты (включая unknown fields и конфиги из `reference/server-snapshot/`, если он есть); тесты валидации.

### P1-09 Общая модель Hysteria URI
- [ ] Вынести typed model + parser/serializer `hysteria2://` в общий пакет. **Разрешено** перевести на него существующий клиент HyRoute, если все старые тесты проходят.
- [ ] Поддержка obfs/Salamander, SNI, insecure, pinSHA256, port hopping (multi-port), параметров, совместимых с HApp/Incy/Shadowrocket.

**Done:** round-trip тесты; тесты на URI с obfs, pinSHA256 и multi-port в форматах, которые принимают HApp/Incy/Shadowrocket; все существующие тесты клиента проходят.

### P1-10 Quick Deploy (single server)
- [ ] Job: preflight → загрузка бинарника Hysteria с проверкой checksum → установка → systemd unit → TLS (self-signed с pinning или ACME) → auth → Salamander obfs (опционально) → masquerade → port hopping (native port range, firewall fallback только где действительно нужен, IPv4 и IPv6) → firewall → запуск → verify.
- [ ] Абстракция источника загрузки: прямая загрузка **или** relay через controller (controller скачивает, проверяет checksum, заливает по SFTP). Интерфейс должен позволять позже добавить relay через другой managed node.
- [ ] Повторный deploy не ломает работающий сервер.
- [ ] UI: форма «имя, страна, host, SSH credentials → Развернуть», live-прогресс.

**Done:** тесты на fake executor: успешный deploy, падение install, падение старта сервиса (с откатом), повторный deploy без изменений ничего не ломает, relay-загрузка.

### P1-11 Импорт существующего сервера
- [ ] Подключиться, найти установленную Hysteria и её конфиг, распарсить в typed model, **ничего не меняя на сервере**.
- [ ] Показать результат импорта и предупреждения (неизвестные поля, нестандартные пути).

**Done:** тесты: импорт стандартной установки, установки из `reference/server-snapshot/` (если есть) с проверкой, что все проблемы из README владельца попали в предупреждения, нестандартного конфига; проверка, что никаких записывающих операций не выполнялось.

### P1-12 Статус сервиса, управление, логи
- [ ] Статус сервиса, uptime, версия Hysteria, базовые метрики системы.
- [ ] Действия: start, stop, restart (с подтверждением для destructive).
- [ ] Tail systemd journal через typed operation, стрим в UI через SSE.
- [ ] Страница Logs: источники (controller, jobs, Hysteria journal), фильтр по серверу, severity, тексту; всё через redaction.

**Done:** из UI видно состояние сервера, работают restart и live-логи; тест, что секреты из journal редактируются.

### P1-13 Базовый редактор конфига с безопасным применением
- [ ] Structured editor для основных полей + Raw YAML editor, синхронизация через typed model.
- [ ] Pipeline apply: read current → backup → candidate → validate (включая проверку самой Hysteria, если возможно) → diff → atomic install → restart → health check → commit revision; при ошибке — rollback → restart предыдущей версии → понятный отчёт.
- [ ] Diff viewer в UI перед применением.

**Done:** тесты: успешное применение, невалидный конфиг отклонён до установки, сервис не стартовал → автоматический rollback.

### P1-14 Профиль для клиента
- [ ] После deploy/import: URI, QR code, скачать config, кнопка «Добавить в HyRoute» (через стабильный формат/URI, без чтения файлов друг друга).
- [ ] Секреты показываются только по явному действию пользователя.

**Done:** сгенерированный URI парсится клиентом HyRoute (тест через общий пакет из P1-09).

### P1-15 Завершение Phase 1
- [ ] Минимальная страница Overview: список серверов со статусами Healthy / Degraded / Offline / Deploying / Needs attention, последние jobs.
- [ ] Документация пользователя: установка controller, первый запуск, доступ через SSH-туннель/reverse proxy, резервное копирование master key.
- [ ] Обновить ARCHITECTURE по фактической реализации.
- [ ] Прогнать полный набор проверок, обновить PROGRESS итогом фазы.

**Done:** чистый VPS (или fake) → Quick Deploy → работающий сервер в Servers → URI для HyRoute, без ручного SSH.

---

## Phase 2 — Full management
> Перед началом фазы разбить на задачи P2-XX в этом же формате (с Done-критериями).

- [ ] Monitoring: CPU/RAM/disk/load/network, история, графики
- [ ] Traffic Stats API Hysteria (bind на localhost/private path, всегда secret): online clients, traffic, connections, streams (streams только live, без долговременной истории)
- [ ] История ревизий конфигов, diff, rollback к любой ревизии
- [ ] Presets: create from server, clone, rename, export/import, apply to new, apply sections to existing с diff
- [ ] Advanced Deploy: все разумные параметры до установки
- [ ] System tuning: проверка поддержки kernel, current vs desired, idempotent sysctl с backup/rollback; чёткое разделение Linux TCP CC, QUIC CC и Brutal
- [ ] Port hopping UI: диапазоны/списки, hop interval, валидация пересечений и занятых портов, IPv4/IPv6
- [ ] Update Hysteria, reinstall, rotate credentials/certificate, regenerate links
- [ ] Health checks: connectivity, UDP, outbound IP, latency, история

## Phase 3 — Cascades
- [ ] Topology model (N-hop-ready), Entry → Exit в production-качестве
- [ ] Visual chain builder: roles, health связей, latency, статусы client/server сервисов, итоговый egress IP
- [ ] Автогенерация промежуточных credentials и configs, секреты не в логах
- [ ] Relay-загрузка через другой managed node
- [ ] Health checks между nodes
- [ ] Routing/outbounds management, редактор ACL: domain/suffix, IP/CIDR, port, protocol, geosite/geoip, direct/block/outbound; drag-and-drop, enable/disable, bulk, import/export, search, comments, groups, presets, duplicate, dry-run
- [ ] «Проверить правило»: какое правило совпадёт первым и куда уйдёт трафик
- [ ] Topology presets

## Phase 4 — Ultra
- [ ] N-hop cascades в production
- [ ] Advanced ACL builder
- [ ] Bulk operations
- [ ] Полный RBAC enforcement
- [ ] Alerts
- [ ] Diagnostic bundle с автоматической санитизацией
- [ ] Backup/restore controller
- [ ] Reconciliation desired vs actual state по расписанию
