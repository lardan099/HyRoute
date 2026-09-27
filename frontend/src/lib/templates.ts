// Ready-made rules. Services use lists from the rule database
// (geosite:/geoip:), which are maintained upstream and updated by HyRoute,
// so a template never goes stale when a service adds a new CDN domain.
// Apps are exe names. A template names programs or sites, never both: a
// rule with both matches only when those programs open those sites, and a
// program such as Discord (voice by IP) or Telegram needs all its traffic
// through the VPN.
import type { Action, Rule, Settings } from '../api';

export interface Template {
  id: string;
  name: string;
  hint: string;
  apps?: string[];
  domains: string[];
  action?: Action; // default: tunnel
  group: 'Сервисы' | 'Россия' | 'Полезное';
}

export const templates: Template[] = [
  { id: 'youtube', name: 'YouTube', hint: 'сайт, видео, превью, приложение', domains: ['geosite:youtube'], group: 'Сервисы' },
  { id: 'discord-app', name: 'Discord — программа', hint: 'весь трафик Discord.exe, включая голос', apps: ['Discord.exe'], domains: [], group: 'Сервисы' },
  { id: 'discord', name: 'Discord — сайт', hint: 'discord.com в браузере', domains: ['geosite:discord'], group: 'Сервисы' },
  { id: 'telegram-app', name: 'Telegram — программа', hint: 'весь трафик Telegram.exe', apps: ['Telegram.exe'], domains: [], group: 'Сервисы' },
  { id: 'telegram', name: 'Telegram — сайт и серверы', hint: 'веб-версия и IP-адреса Telegram для любых программ', domains: ['geosite:telegram', 'geoip:telegram'], group: 'Сервисы' },
  { id: 'chatgpt-app', name: 'ChatGPT — программа', hint: 'весь трафик ChatGPT.exe', apps: ['ChatGPT.exe'], domains: [], group: 'Сервисы' },
  { id: 'chatgpt', name: 'ChatGPT — сайт', hint: 'chatgpt.com и OpenAI', domains: ['geosite:openai'], group: 'Сервисы' },
  { id: 'claude-app', name: 'Claude — программа', hint: 'весь трафик claude.exe', apps: ['claude.exe'], domains: [], group: 'Сервисы' },
  { id: 'claude', name: 'Claude — сайт', hint: 'claude.ai и Anthropic', domains: ['geosite:anthropic'], group: 'Сервисы' },
  { id: 'ai', name: 'Все ИИ-сервисы', hint: 'ChatGPT, Claude, Gemini, Copilot…', domains: ['geosite:category-ai-!cn'], group: 'Сервисы' },
  { id: 'instagram', name: 'Instagram', hint: 'сайт и медиа', domains: ['geosite:instagram'], group: 'Сервисы' },
  { id: 'meta', name: 'Facebook, Instagram, WhatsApp', hint: 'все сервисы Meta', domains: ['geosite:meta'], group: 'Сервисы' },
  { id: 'x', name: 'X (Twitter)', hint: 'x.com и медиа', domains: ['geosite:twitter'], group: 'Сервисы' },
  { id: 'spotify-app', name: 'Spotify — программа', hint: 'весь трафик Spotify.exe', apps: ['Spotify.exe'], domains: [], group: 'Сервисы' },
  { id: 'spotify', name: 'Spotify — сайт', hint: 'open.spotify.com в браузере', domains: ['geosite:spotify'], group: 'Сервисы' },
  { id: 'netflix', name: 'Netflix', hint: 'сайт и видео', domains: ['geosite:netflix'], group: 'Сервисы' },
  { id: 'twitch', name: 'Twitch', hint: 'сайт и трансляции', domains: ['geosite:twitch'], group: 'Сервисы' },
  { id: 'linkedin', name: 'LinkedIn', hint: 'сайт и медиа', domains: ['geosite:linkedin'], group: 'Сервисы' },

  {
    id: 'ru-blocked',
    name: 'Заблокированное в России',
    hint: 'сайты и IP из реестра блокировок → VPN',
    domains: ['geosite:ru-blocked', 'geoip:ru-blocked'],
    group: 'Россия',
  },
  {
    id: 'ru-inside',
    name: 'Работает только из России',
    hint: 'Госуслуги, банки и т. п. → напрямую',
    domains: ['geosite:ru-available-only-inside', 'geosite:category-gov-ru', 'geosite:category-bank-ru'],
    action: 'direct',
    group: 'Россия',
  },
  {
    id: 'ru-all',
    name: 'Российские сайты и IP',
    hint: 'зона .ru, Яндекс, VK, российские сети → напрямую',
    domains: ['geosite:category-ru', 'geoip:ru'],
    action: 'direct',
    group: 'Россия',
  },

  { id: 'lan', name: 'Локальная сеть', hint: 'роутер, принтер, NAS → напрямую', domains: ['geoip:private'], action: 'direct', group: 'Полезное' },
  { id: 'ads', name: 'Реклама', hint: 'рекламные сети → блок', domains: ['geosite:category-ads-all'], action: 'block', group: 'Полезное' },
  { id: 'telemetry', name: 'Телеметрия Windows', hint: 'сбор данных Microsoft → блок', domains: ['geosite:win-spy'], action: 'block', group: 'Полезное' },
];

export function ruleFromTemplate(t: Template): Rule {
  return {
    name: t.name,
    apps: (t.apps ?? []).map((a) => ({ pattern: a, inheritChildren: true })),
    domains: [...t.domains],
    action: t.action ?? 'tunnel',
    profile: '',
    protocol: '',
  };
}

// A scheme is a whole setup: several rules plus "everything else".
export interface Scheme {
  id: string;
  name: string;
  hint: string;
  rules: (string | Template)[]; // template IDs or inline rules, top to bottom
  rest: Action;
  source?: string; // the rule database the scheme is made for
}

export const schemes: Scheme[] = [
  {
    id: 'ru-blocked-only',
    name: 'Через VPN только заблокированное',
    hint: 'Всё, что заблокировано в России, — через VPN, остальное напрямую. Быстро и экономит трафик.',
    rules: ['lan', 'ru-inside', 'ru-blocked'],
    rest: 'direct',
  },
  {
    id: 'all-but-ru',
    name: 'Всё через VPN, кроме российского',
    hint: 'Российские сайты, банки и Госуслуги — напрямую, всё остальное — через VPN.',
    rules: ['lan', 'ru-inside', 'ru-all'],
    rest: 'tunnel',
  },
  {
    // hydraponique/roscomvpn-routing, DEFAULT: block, then proxy, then
    // direct, everything else through the VPN. Torrents go direct instead
    // of being blocked: on a desktop a block would break the torrent client,
    // and direct keeps them off the VPN server just the same.
    id: 'roscomvpn',
    name: 'RoscomVPN',
    hint: 'Маршрутизация RoscomVPN: реклама и телеметрия — блок; YouTube, Telegram, GitHub, Google Play — через VPN; российское, Microsoft, Apple, игры и торренты — напрямую; остальное — через VPN.',
    source: 'hysteria-geodata',
    rules: [
      'lan',
      { id: 'rc-block', name: 'Реклама и телеметрия', hint: '', domains: ['geosite:win-spy', 'geosite:category-ads-all'], action: 'block', group: 'Полезное' },
      { id: 'rc-proxy', name: 'Через VPN (RoscomVPN)', hint: '', domains: ['geosite:google-play', 'geosite:github', 'geosite:twitch-ads', 'geosite:youtube', 'geosite:telegram'], group: 'Сервисы' },
      {
        id: 'rc-direct',
        name: 'Напрямую (RoscomVPN)',
        hint: '',
        domains: [
          'geosite:whitelist', 'geosite:category-ru', 'geoip:direct', 'geosite:microsoft', 'geosite:apple', 'geosite:epicgames', 'geosite:riot',
          'geosite:escapefromtarkov', 'geosite:steam', 'geosite:twitch', 'geosite:pinterest', 'geosite:faceit', 'geosite:torrent',
        ],
        action: 'direct',
        group: 'Россия',
      },
    ],
    rest: 'tunnel',
  },
];

export function schemeTemplates(sc: Scheme): Template[] {
  return sc.rules.map((r) => (typeof r === 'string' ? templates.find((t) => t.id === r)! : r));
}

// applyScheme puts the scheme's rules on top (skipping ones already
// present) and sets "everything else". Only a rule that works the same
// way counts as present: enabled, for every program and protocol, and not
// cut off by an enabled rule above it that sends some of the same traffic
// elsewhere: one with another action and a common item or no sites at all
// (a program's rule). A turned off, narrowed (chrome.exe + geoip:private)
// or cut off copy stays as it is, and the scheme's rule goes on top. The
// scheme's own rules share no items, so the ones added on top cut off
// nothing.
export function applyScheme(s: Settings, sc: Scheme): Settings {
  const next: Settings = JSON.parse(JSON.stringify(s));
  const sites = (r: Rule) => [...(r.domains ?? []), ...(r.domain?.pattern ? [r.domain.pattern] : [])];
  const key = (r: Rule) => JSON.stringify(sites(r).sort()) + r.action;
  const general = (r: Rule) => r.enabled !== false && !r.apps?.length && !r.app?.pattern && !r.protocol;
  const cuts = (above: Rule, r: Rule) =>
    above.enabled !== false && above.action !== r.action && (!sites(above).length || sites(above).some((d) => sites(r).includes(d)));
  const present = (r: Rule) => next.rules.some((x, i) => general(x) && key(x) === key(r) && !next.rules.slice(0, i).some((a) => cuts(a, r)));
  const add = schemeTemplates(sc)
    .map(ruleFromTemplate)
    .filter((r) => !present(r));
  next.rules = [...add, ...next.rules];
  next.defaultAction = sc.rest;
  if (sc.rest !== 'tunnel') next.defaultProfile = '';
  return next;
}
