# HyRoute Server Manager — журнал работы

План и статусы задач — `TODO_SERVER_MANAGER.md`, архитектура —
`docs/SERVER_MANAGER_ARCHITECTURE.md`. Новые записи — внизу.

## Журнал

### P1-00 Аудит и архитектура — выполнено

- Создан `docs/SERVER_MANAGER_ARCHITECTURE.md`: аудит репозитория (что
  переиспользуется), чек-лист обязательного поведения с привязкой к
  задачам, пакеты и зависимости, сущности БД, секреты, аутентификация,
  удалённое выполнение и TOFU, state machine jobs и recovery, модель
  конфига с неизвестными полями, ссылки, развёртывание, импорт,
  применение конфига, topology, REST API v1, модель угроз.
- Сверено с документацией hysteria.network (Installation, Server
  Installation Script, Full Server/Client Config, URI Scheme, Port Hopping,
  Traffic Stats API, ACL) и исходниками apernet/hysteria app/v2.12.3.
  Сначала сайт был закрыт сетевой политикой окружения; владелец открыл
  доступ, документация прочитана.
- `reference/server-snapshot/` нет: импорт будет проверяться на
  синтетических фикстурах по официальному установщику.
- Решения: пакеты Server Manager — `internal/srvmgr/...`, общие с клиентом —
  `internal/hy2uri`, `internal/hyconfig`; пути и unit как у официального
  установщика; port hopping — встроенный диапазон Hysteria (только
  Linux); SSH-пользователь — root или `sudo -n`; первый администратор —
  только с setup token из журнала/файла (защита от занятия админки,
  если порт открыт наружу).
- Ветка: работа идёт в `claude/laughing-keller-wax6iy` (текущая ветка
  сессии, не `main`); в `main` не коммитится.

### P1-01 Каркас controller — выполнено

- `cmd/hyroute-server`: флаги + env `HYROUTE_SERVER_*` (`internal/srvmgr/config`),
  bind по умолчанию `127.0.0.1:8480`, предупреждение в журнале, если
  адрес не loopback; graceful shutdown по SIGINT/SIGTERM (10 с).
- SQLite (`modernc.org/sqlite`, без CGO): `internal/srvmgr/store` —
  интерфейсы, `store/sqlite` — реализация. Файл БД создаётся с правами
  0600, каталог данных 0700; WAL, foreign keys, busy timeout.
  Миграции `migrations/NNNN_name.sql` (embed), каждая в своей транзакции,
  без пропусков номеров; БД более новой схемы не открывается.
  Первая миграция — `settings` и `audit_log`; таблицы остальных сущностей
  добавляют задачи, которым они нужны.
- `/api/v1/health`; структурированные ошибки `{"error": {code, message,
  details}}`; неизвестный `/api/...` — JSON 404, а не страница UI;
  заголовки безопасности (CSP без внешних источников, запрет фреймов,
  nosniff, no-referrer); ограничение тела запроса 1 МБ; паника в handler —
  500 без текста паники в ответе.
- `web/admin`: Svelte 5 + Vite, стили и темы скопированы из клиента,
  строки — в `src/i18n/ru.ts`, навигация Overview/Servers/Cascades/Rules/
  Presets/Deployments/Logs/Settings (history-роутер, controller отдаёт
  `index.html` для не-API путей), Overview показывает health.
  `web/admin/dist` коммитится и встраивается (`web/admin/embed.go`).
- CI: проверка типов, сборка админки и сверка `web/admin/dist` с исходниками.
  CLAUDE.md: проверки для `web/admin`.
- Тесты: конфигурация, миграции (чистая БД, повторное открытие,
  инкрементальная, откат упавшей миграции, отказ на более новой схеме,
  проверка имён), HTTP-слой, запуск и остановка controller целиком.
- Известное: `go get modernc.org/sqlite` поднял косвенную зависимость
  `github.com/mattn/go-isatty` 0.0.20 → 0.0.24 (её использует и клиент
  через Wails); на поведение клиента не влияет.
- Без `ReadTimeout`/`WriteTimeout` у HTTP-сервера: SSE-потоки живут долго;
  тела запросов ограничены размером.
