<p align="center">
  <img src="build/windows/icon.png" width="96" alt="Логотип HyRoute">
</p>

<h1 align="center">HyRoute</h1>

<p align="center">
  VPN-клиент для Windows и macOS с раздельной маршрутизацией по приложениям и сайтам.<br>
  Hysteria 2, VLESS, AmneziaWG и WireGuard.
</p>

<p align="center">
  <a href="https://github.com/lardan099/HyRoute/releases/latest">Скачать HyRoute</a> ·
  <a href="#hyroute-mobile">Android и iOS</a> ·
  <a href="#hyroute-server">Панель серверов</a> ·
  <a href="docs/GUIDE.md">Руководство</a>
</p>

<p align="center">
  <img src="docs/screenshots/home.png" width="860" alt="Главное окно HyRoute для Windows">
</p>

HyRoute направляет нужные приложения и сайты через выбранные VPN-серверы. Остальной трафик можно пропускать напрямую или блокировать. Например, браузер может работать через один сервер, игра через другой, а локальная сеть напрямую. Системный перехват работает через WinDivert на Windows и через `utun` на macOS.

## Установка

Текущий настольный релиз **v1.3.43**. Для подключения нужен свой сервер либо конфигурация от VPN-провайдера. [Все релизы](https://github.com/lardan099/HyRoute/releases)

| Платформа | Сборка | Первый запуск |
| --- | --- | --- |
| Windows 10 и 11, x64 | [Скачать ZIP](https://github.com/lardan099/HyRoute/releases/download/v1.3.43/HyRoute-1.3.43-windows-amd64.zip) | Распакуйте архив и запустите `HyRoute.exe` с правами администратора. Кнопка **Перенести** устанавливает клиент в `C:\Program Files\HyRoute`. [Установка на Windows](docs/GUIDE.md#установка-и-защищённая-папка) |
| macOS, Apple Silicon и Intel | [Скачать универсальный ZIP](https://github.com/lardan099/HyRoute/releases/download/v1.3.43/HyRoute-1.3.43-macos-universal.zip) | Это тестовая сборка. Перенесите `HyRoute.app` в «Программы», разрешите запуск и введите пароль администратора для установки службы. [Установка на macOS](docs/MACOS.md#установка) |

При первом запуске мастер предложит добавить и проверить сервер, выбрать схему маршрутизации и подключиться. Вручную сервер или конфигурацию можно добавить в **Серверах**, а HTTPS-подписку в **Подписках**. Чтобы проверить маршрут, откройте **Проверить адрес** в разделе **Правила**. [Пошаговая настройка](docs/GUIDE.md#простой-режим-и-пошаговая-настройка)

### Что нового в v1.3.43

Если UDP в цепочке VPN зависает, HyRoute переподключает выходной сервер Hysteria 2. В выпусках v1.3.40–v1.3.42 также появились AmneziaWG и WireGuard, цепочки из двух VPN-профилей и выбор группы серверов в качестве первого звена. [Заметки к выпуску](https://github.com/lardan099/HyRoute/releases/tag/v1.3.43)

## Возможности клиента

### Серверы и подписки

- **Импорт.** Ссылки `hysteria2://`, `hy2://` и `vless://`, а для AmneziaWG и WireGuard конфиги `.conf` и ключи `vpn://` с параметрами подключения из Amnezia. HTTPS-подписки поддерживают Hysteria 2 и VLESS.
- **Подписки.** Автообновление, срок действия и трафик при наличии этих данных от провайдера. Профили VLESS с балансировщиком Xray `leastLoad` могут импортироваться как **Автовыбор**.
- **Группы и резерв.** Группа выбирает сервер по заданной стратегии. В неё можно добавить подписку целиком и исключить отдельные серверы. В правилах можно задать резервные профили.
- **VPN через VPN.** В редакторе выходного сервера выберите входной профиль или группу в поле **Подключаться через**. HyRoute запускает оба звена. Выход Hysteria 2 требует одного порта и поддержки UDP первым звеном. [Серверы, подписки и ограничения цепочек](docs/GUIDE.md#серверы-и-подписки)

### Маршрутизация и диагностика

- **Правила.** Приложения, домены, IP, подсети, порты, протоколы и списки GeoSite или GeoIP. Для совпавших соединений можно выбрать VPN-профиль, прямой маршрут или блокировку. Правила проверяются сверху вниз.
- **Редактор и импорт.** Правила можно набрать текстом или перенести из SwitchyOmega, ZeroOmega, v2rayN, Xray, Throne, sing-box, FoxyProxy, Clash и PAC. [Синтаксис и форматы](docs/GUIDE.md#импорт-правил-из-других-программ)
- **Профили и сети.** Переключайте наборы правил вручную или привяжите их к сетям. DNS по правилам позволяет разрешать имена через назначенный VPN-сервер. [Профили](docs/GUIDE.md#профили-правил) · [Сети](docs/GUIDE.md#сети) · [DNS](docs/GUIDE.md#dns)
- **Проверки.** **Проверить адрес** объясняет выбор правила. **Соединения** показывают, куда пошёл трафик. Проверка сервера показывает внешний IP, задержку и доступность UDP. Статистика группируется по приложениям, серверам и группам.
- **Инструменты.** Локальные HTTP и SOCKS5-прокси, расширение для Chromium, команда `hyroutectl`, резервная копия настроек, обновления с откатом и kill switch. [Ограничения](docs/GUIDE.md#ограничения)

### Обход DPI на Windows

В отдельном разделе можно включить обход DPI через zapret2 для YouTube, Discord и своих сайтов или использовать режим для Telegram Desktop через WebSocket. HyRoute умеет подобрать стратегию для сети и сохранить её. [Как работает обход DPI](docs/GUIDE.md#обход-dpi)

## HyRoute Mobile

Отдельный клиент для **Android 7.0+ и iOS 16+** с поддержкой **Hysteria 2 и VLESS**. В нём есть импорт подписок и конфигов, замеры задержки в списке серверов, профили правил, цепочки VPN, раздельный DNS и журнал VPN.

На Android можно выбирать приложения для VPN и задавать правила по приложениям. На iOS доступны автовосстановление VPN, журнал подключений и управление через «Команды».

<p>
  <a href="https://github.com/lardan099/HyRoute-Mobile#скриншоты"><img src="https://raw.githubusercontent.com/lardan099/HyRoute-Mobile/9f2e68ddef93a3c7e7c771cf84447a154ba02dbb/docs/screenshots/android-home.png" width="190" alt="Главная HyRoute Mobile на Android"></a>
  <a href="https://github.com/lardan099/HyRoute-Mobile#скриншоты"><img src="https://raw.githubusercontent.com/lardan099/HyRoute-Mobile/9f2e68ddef93a3c7e7c771cf84447a154ba02dbb/docs/screenshots/ios-home.png" width="190" alt="Главная HyRoute Mobile на iOS"></a>
</p>

На снимках тестовая сборка **0.3.32**. APK для Android, IPA для iOS, требования к подписи и остальные скриншоты собраны в [README HyRoute Mobile](https://github.com/lardan099/HyRoute-Mobile#readme).

## HyRoute Server

Веб-панель для собственных серверов **Hysteria 2**. Она разворачивает серверы на Linux по SSH или берёт под управление уже работающие установки. В панели можно редактировать конфигурацию с откатом, смотреть журналы и трафик, управлять пользователями, выпускать ссылки и QR-коды и настраивать каскады.

На Windows панель запускается кнопкой **Открыть панель** в разделе **Серверы**. Для постоянной работы есть отдельная сборка и скрипт установки на Linux с systemd. [Установка, доступ и эксплуатация панели](docs/SERVER_MANAGER.md)

## Документация и сборка

- [Руководство пользователя](docs/GUIDE.md), [особенности macOS](docs/MACOS.md), [архитектура клиента](docs/ARCHITECTURE.md) и [архитектура панели](docs/SERVER_MANAGER_ARCHITECTURE.md).
- [Лицензия MIT](LICENSE), [лицензии компонентов](THIRD-PARTY-NOTICES.txt) и [сообщения об уязвимостях](SECURITY.md). Ошибки и предложения можно оставить в [Issues](https://github.com/lardan099/HyRoute/issues).

Для сборки Windows используются Go 1.27 и PowerShell. Флаг `-Frontend` пересобирает интерфейсы и требует Node.js. На macOS нужны Go и Xcode Command Line Tools.

```powershell
.\scripts\build.ps1
.\bin\HyRoute.exe
```

На macOS запустите `bash scripts/build-macos.sh` из корня репозитория. Тесты Go запускаются командой `go test ./...`.

<p>
  <a href="https://pay.cloudtips.ru/p/067a1ae1">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/support-dark.svg">
      <img src="docs/support-light.svg" width="278" height="46" alt="Поддержать разработчика">
    </picture>
  </a>
</p>
