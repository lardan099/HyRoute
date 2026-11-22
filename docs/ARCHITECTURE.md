# Архитектура HyRoute

HyRoute — клиент Hysteria 2, VLESS и AmneziaWG для Windows и macOS, который решает, какой
трафик идёт через VPN, а какой напрямую, по программам, сайтам, адресам и
портам. Этот документ — обзор: из чего состоит программа, как через неё идёт
трафик и какие правила она соблюдает. Ниже описан Windows; macOS использует всё
то же выше уровня пакетов, а перехват (utun вместо WinDivert), процессы и kill
switch (pf) у него свои — [macos.md](architecture/macos.md). Подробности по
каждой части — в [`docs/architecture/`](architecture/).

Проверено по документации Hysteria 2 (Full Client Config, URI Scheme), исходникам
`apernet/hysteria` app/v2.12.3 и `basil00/WinDivert` v2.2.2.

## Как идёт трафик

```
программа ── исходящий пакет ──► WinDivert H1 (движок HyRoute)
                                   │  чей пакет: SOCKET/FLOW-события, IP Helper
                                   │  куда: IP, порт, имя из DNS-кэша или SNI/Host
                                   │  правила сверху вниз, первое совпадение
                                   ├─ Напрямую ─► пакет уходит в сеть как есть
                                   ├─ Блок ─────► RST программе / пакет отброшен
                                   └─ VPN ──────► отражается в локальный relay
                                                    └─► SOCKS5 hysteria.exe (VLESS: xray.exe,
                                                         AmneziaWG: HyRoute.exe --awg) ─► сервер
```

- **Перехват.** WinDivert ловит только исходящие пакеты; входящие прямых
  соединений в программу не попадают, поэтому прямой трафик не замедляется.
  Отдельные хэндлы пассивно читают DNS-ответы и события сокетов, чтобы знать
  имя сайта и программу раньше первого пакета.
- **Решение** принимается один раз на поток, по пакету. Если маршрут зависит
  от ещё неизвестного имени сайта, TCP-соединение принимает relay и читает
  имя из TLS ClientHello или HTTP Host.
- **VPN.** Для каждого используемого сервера запускается свой `hysteria.exe`
  в режиме SOCKS5 (для VLESS — `xray.exe`, для AmneziaWG — сам HyRoute). TCP идёт в relay через reflect-NAT (пакет разворачивается
  во входящий к локальному порту), UDP — на уровне пакетов через SOCKS5 UDP
  ASSOCIATE.
- **DNS.** По умолчанию HyRoute только читает DNS-ответы. «DNS по правилам»
  дополнительно отвечает на запросы сам и разрешает имена «через VPN» через
  тот же сервер.

## Правила, которые не нарушаются

- **VPN-трафик никогда не уходит напрямую.** Сервер недоступен, группа пуста,
  relay упал, DNS через VPN не отвечает — соединение отклоняется или идёт через
  запасной сервер, но не мимо туннеля.
- **Прямой трафик не зависит от VPN.** Direct и Block не проходят через relay
  и Hysteria, их поломка прямой трафик не задевает.
- **Упавший HyRoute не оставляет сеть сломанной.** Фильтры WinDivert живут,
  пока открыт хэндл: при выходе, крэше или зависании packet loop (его снимает
  сторож внутри процесса) трафик идёт напрямую. Kill switch на WFP, если
  включён, в этом случае закрывает интернет. Замёрзший целиком процесс
  (приостановка, отладчик) держит фильтры, пока его не завершат.
- **Процесс с правами администратора не доверяет файлам пользователя.**
  Файлы данных читаются строго и без перехода по ссылкам, исполняемые файлы
  запускаются только из защищённых папок, обновления сверяются по SHA-256.
- **Секреты не попадают в журналы** (пароли, obfs, ссылки подписок), а
  **статистика не хранит сайты** — только программы, серверы и группы.

## Процессы

| Процесс | Права | Что делает |
|---|---|---|
| `HyRoute.exe` | администратор | трей, движок WinDivert, relay, kill switch, контроллер |
| `HyRoute.exe --window` | как у HyRoute | окно (Wails + WebView2): живёт, пока окно открыто; вызовы страницы передаёт основному процессу ([app](architecture/app.md)) |
| `hysteria.exe` | как у HyRoute | по одному на используемый сервер Hysteria 2, в Job Object с `KILL_ON_JOB_CLOSE` |
| `xray.exe` | как у HyRoute | то же для сервера VLESS (Xray-core): SOCKS5 → VLESS ([servers](architecture/servers.md#vless-профиль-конфиг-xray-проверка)) |
| `HyRoute.exe --awg` | как у HyRoute | то же для сервера AmneziaWG или WireGuard: amneziawg-go и сетевой стек gVisor внутри процесса, SOCKS5 → AmneziaWG, без драйвера и адаптера ([servers](architecture/servers.md#amneziawg-профиль-процесс-проверка)) |
| `hyroute-updater.exe` | администратор | заменяет файлы при обновлении и откатывает их, если новая версия не запустилась |
| `hyroutectl.exe` | пользователь | командная строка, говорит с HyRoute через именованный канал |
| `hyroute-server.exe` | пользователь | [HyRoute Server](SERVER_MANAGER.md) по кнопке «Открыть панель»: HyRoute сверяет его с SHA-256, зашитым при сборке, и запускает через Explorer (как браузер), в свёрнутом консольном окне; живёт, пока открыто это окно |

Задачи Планировщика: автозапуск при входе и проверка оставшейся блокировки
kill switch при входе.

## Данные

`%APPDATA%\HyRoute` (папки проверяет `store.Guard`: обычные папки без ссылок):

| Файл | Что |
|---|---|
| `settings.json` | правила включённого профиля правил и опции движка |
| `rulesets.json` | профили правил, появляется со вторым профилем |
| `profiles.json` | серверы; пароли, obfs, UUID VLESS и ключи AmneziaWG зашифрованы DPAPI |
| `subscriptions.json`, `subs\` | подписки и снимки их содержимого (DPAPI) |
| `groups.json`, `proxies.json`, `dns.json`, `networks.json` | группы серверов, локальные прокси, DNS, правила сетей |
| `prefs.json` | журналы, обновления, базы правил, запуск и трей, доступ командной строки |
| `geo\` | базы geosite/geoip |
| `stats\` | статистика по дням и месяцам |
| `logs\`, `run\` | журналы; временные конфиги Hysteria, Xray и AmneziaWG с закрытым DACL |

`%ProgramData%\HyRoute` (SYSTEM и Administrators — запись, Users — чтение):
`runtime\` — проверенные копии `hysteria.exe`, `xray.exe` и WinDivert, `core\` —
обновлённые ядра Hysteria, `updates\` и `update-journal.json` — обновление
HyRoute. Данные WebView2 лежат не здесь, а в `%LOCALAPPDATA%\HyRoute\webview`
пользователя: WebView2 работает без прав администратора.

## Пакеты

| Пакет | Назначение |
|---|---|
| `cmd/hyroute` | `HyRoute.exe`: Wails-привязки (`gui_*.go`), трей, один экземпляр, порядок запуска (`startgate.go`), канал hyroutectl |
| `cmd/hyroute-updater`, `cmd/hyroutectl` | программа обновления; командная строка |
| `build`, `frontend` | встроенные в exe `build/deps.json` и иконка; собранный интерфейс |
| `internal/app` | контроллер: серверы, подписки, группы, правила, подключение, статус, проверки, DNS, «Сети», статистика, обновления, резервная копия |
| `internal/session` | одно подключение: relay, движок и Hysteria вместе |
| `internal/engine`, `engine/nat` | решения по пакетам, NAT, UDP-сессии, DNS-политики в движке; хэндлы WinDivert, горячая замена, watchdog; на macOS — устройство utun и прямой UDP |
| `internal/divert`, `internal/packet` | биндинги WinDivert без cgo, фильтры; разбор, переписывание и сборка пакетов |
| `internal/attrib`, `internal/procinfo` | чей пакет: таблица сокетов, IP Helper; PID → путь, дерево процессов |
| `internal/relay`, `internal/sniff`, `internal/socks5` | relay TCP; SNI и HTTP Host; клиент SOCKS5 |
| `internal/rules`, `internal/geodata`, `internal/ruleconv` | модель правил, компиляция, трёхзначная оценка, место правила из соединения; базы geosite/geoip; правила других программ (SwitchyOmega, v2rayN, sing-box, Clash…) |
| `internal/dnscache`, `internal/dnspolicy`, `internal/dnsproxy`, `internal/sysdns` | DNS-кэш из ответов; DNS-политики; резолвер DoH/DoT; DNS-серверы адаптеров |
| `internal/hysteria`, `internal/tunnels`, `internal/groups` | ссылки, конфиг и процесс Hysteria; запущенные серверы; группы серверов |
| `internal/hy2uri` | модель, разбор и запись ссылок `hysteria2://` (общий с менеджером серверов) |
| `internal/vless`, `internal/subfmt` | VLESS: настройки, ссылки `vless://`, конфиг Xray; подписки в виде конфигов Clash, sing-box и Xray |
| `internal/awg` | AmneziaWG: настройки, конфиги `.conf` и ключи `vpn://` приложения Amnezia, процесс сервера (amneziawg-go в сетевом стеке gVisor за SOCKS5) |
| `internal/localproxy`, `internal/fwrule` | локальные SOCKS5/HTTP-прокси; правила брандмауэра Windows |
| `internal/killswitch` | kill switch: WFP на Windows, pf на macOS |
| `internal/uirpc` | протокол между окном и основным процессом (на macOS — службой) |
| `internal/flows`, `internal/stats`, `internal/logx` | «Соединения»; статистика; журналы, маскирование секретов, Privacy mode |
| `internal/store`, `internal/settings`, `internal/backup` | файлы данных; файл правил; формат резервной копии |
| `internal/netmode`, `internal/netwatch` | правила сетей; чтение сетей Windows |
| `internal/release`, `internal/core`, `internal/update`, `internal/runtimefiles`, `internal/autostart` | релизы GitHub; ядро Hysteria; обновление HyRoute; защищённые копии бинарников; автозапуск |
| `internal/ctl` | протокол и канал hyroutectl, клиент и сервер команд, хост расширения браузера |
| `browser/` | расширение для браузеров на Chromium (`browser/extension`) и его установка: файлы рядом с HyRoute, манифест хоста |
| `frontend/` | интерфейс на Svelte 5 + TypeScript; собранный `frontend/dist` лежит в репозитории |
| `tools/` | `genicon` (иконка), `wdfilter` (компилятор фильтров WinDivert для тестов), `udpprobe` (ручная проверка больших UDP-датаграмм) |

## Сборка и зависимости

- `build/deps.json` — версии и SHA-256 Hysteria, WinDivert и Xray. `scripts/fetch-deps.ps1`
  скачивает их в `bin\` и сверяет: хэш Hysteria ещё и с `hashes.txt` её
  релиза, у WinDivert — хэш архива и извлечённых файлов. Бинарники в
  репозиторий не коммитятся.
- `scripts/build.ps1` собирает без wails CLI: `go build -tags desktop,production`,
  ресурсы (манифест `requireAdministrator`, иконка, версия) — `go-winres`.
  Репозиторий обновлений — `main.updateRepo` в `cmd/hyroute` (по умолчанию этот), другой
  задаётся при сборке: `-X main.updateRepo=owner/repo`.
- Релиз собирает `.github/workflows/release.yml` по тегу `v*`:
  `HyRoute-<версия>-windows-amd64.zip`, `HyRoute-<версия>-macos-universal.zip`
  (`scripts/build-macos.sh`) и `SHA256SUMS`, а также пакеты HyRoute Server
  (`scripts/build-server.sh`) и `install-server.sh`; их суммы — в том же `SHA256SUMS`.
- Тесты не требуют драйвера и идут на Linux, Windows и macOS: `go test ./...`
  ([что покрыто](architecture/testing.md)).

## Подробно

| Документ | О чём |
|---|---|
| [interception.md](architecture/interception.md) | почему WinDivert, хэндлы и фильтры, соседство с zapret и GoodbyeDPI, атрибуция процесса, обязательные исключения |
| [routing.md](architecture/routing.md) | где принимается решение, reflect-NAT, режимы relay, UDP, IP-фрагменты |
| [dns.md](architecture/dns.md) | DNS-кэш и приоритет источников имени, DNS-политики |
| [rules.md](architecture/rules.md) | модель правил, порты, текст правил, geosite/geoip, профили правил, ревизии, правило из соединения, объяснение и линтер |
| [failure.md](architecture/failure.md) | поведение при отказах, kill switch на WFP |
| [servers.md](architecture/servers.md) | Hysteria, несколько серверов, запасные, подписки, проверка сервера, группы, локальные прокси |
| [app.md](architecture/app.md) | «Соединения», статистика, журналы и Privacy mode, интерфейс и система |
| [updates.md](architecture/updates.md) | обновление ядра Hysteria и HyRoute, журнал и откат |
| [backup.md](architecture/backup.md) | резервная копия: формат, разделы, план, применение, отмена |
| [networks.md](architecture/networks.md) | «Сети»: чтение сети, идентичность, асимметричное решение |
| [zapret.md](architecture/zapret.md) | «Обход DPI»: winws2 рядом с движком, правила, безопасная командная строка, методы, подбор |
| [cli.md](architecture/cli.md) | hyroutectl: канал, права, протокол, режимы; расширение для браузера |
| [macos.md](architecture/macos.md) | macOS: utun, атрибуция, служба и окно, kill switch на pf, обновления |
| [testing.md](architecture/testing.md) | что покрыто тестами |
