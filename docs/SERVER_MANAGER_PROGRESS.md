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
