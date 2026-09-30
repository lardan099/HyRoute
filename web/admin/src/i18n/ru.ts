// Russian UI strings. Every visible string of the admin comes from here, so
// another language is one more file of the same shape.
export const ru = {
  'app.name': 'HyRoute Server',

  'nav.overview': 'Обзор',
  'nav.servers': 'Серверы',
  'nav.cascades': 'Каскады',
  'nav.rules': 'Правила',
  'nav.presets': 'Пресеты',
  'nav.deployments': 'Развёртывания',
  'nav.logs': 'Журнал',
  'nav.settings': 'Настройки',

  'overview.title': 'Обзор',
  'overview.controller': 'Controller',
  'overview.version': 'Версия',
  'overview.schema': 'Версия схемы БД',
  'overview.status': 'Состояние',
  'overview.ok': 'Работает',
  'overview.checking': 'Проверка…',
  'overview.servers': 'Серверы',
  'overview.serversEmpty': 'Серверов пока нет. Добавить сервер можно будет на странице «Серверы».',

  'soon.title': 'Раздел в разработке',
  'soon.servers': 'Инвентарь серверов: добавление по SSH, развёртывание Hysteria 2, импорт уже настроенного сервера, статус и управление сервисом.',
  'soon.cascades': 'Цепочки серверов Entry → Exit: схема, состояние связей, итоговый выходной IP.',
  'soon.rules': 'Правила маршрутизации на сервере (ACL Hysteria): сайты, адреса, geosite и geoip, направление напрямую, в блок или через другой сервер.',
  'soon.presets': 'Готовые наборы настроек: создать из сервера, применить к новому или к части существующего.',
  'soon.deployments': 'Задания развёртывания: шаги, живой журнал, повтор после ошибки.',
  'soon.logs': 'Журналы controller, заданий и Hysteria на серверах — с фильтрами и без секретов.',
  'soon.settings': 'Пользователи, сессии, ключ шифрования и параметры controller.',

  'error.network': 'Нет связи с controller.',
  'error.unknown': 'Неизвестная ошибка.',
} as const;

export type Key = keyof typeof ru;
