// Rule destinations beyond plain sites: geosite:/geoip: categories, IPs,
// networks, keyword:/regexp:. Every list says which database it comes
// from (runetfreedom, Loyalsoldier, v2fly…): the same name can exist in
// one and be missing from another.
import { api, type GeoCategory, type GeoSource } from './api';

export const geo = $state({
  popular: [] as GeoCategory[],
  sources: [] as GeoSource[],
  sourceName: '', // database in use, e.g. "runetfreedom"
  loaded: false,
});

export async function loadGeo(force = false) {
  if (geo.loaded && !force) return;
  try {
    const i = await api.GeoInfo();
    geo.popular = i.popular ?? [];
    geo.sources = i.sources ?? [];
    geo.sourceName = i.sourceName;
    geo.loaded = true;
  } catch {}
}

const typed = /^(geosite|geoip|keyword|regexp|full|domain):/i;
const ipv4 = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/;
const ipv6 = /^\[?[0-9a-f]*:[0-9a-f:.]*\]?(\/\d{1,3})?$/i;

// isSpecial: kept as typed (no "." prefix, no URL cleanup).
export function isSpecial(s: string): boolean {
  return typed.test(s) || ipv4.test(s) || ipv6.test(s);
}

export function isAddress(s: string): boolean {
  return /^geoip:/i.test(s) || ipv4.test(s) || ipv6.test(s);
}

export interface ItemLabel {
  text: string; // what to show
  kind: string; // small badge: "runetfreedom", "IP", "сеть", "слово"…
  tip: string;
  geo: boolean; // from a database
  missing: string; // non-empty: not in the database in use, and why
}

export function category(kind: 'site' | 'ip', name: string): GeoCategory | undefined {
  const n = name.toLowerCase();
  return geo.popular.find((c) => c.kind === kind && c.name === n);
}

// sourceNames turns preset IDs into their short names.
export function sourceNames(ids: string[]): string {
  return ids.map((id) => geo.sources.find((s) => s.id === id)?.short ?? id).join(', ');
}

// missingText explains a well-known category the database in use lacks.
export function missingText(c: GeoCategory | undefined): string {
  if (!c || c.inSource !== false) return '';
  return `нет в базе ${geo.sourceName || 'правил'}, есть в: ${sourceNames(c.sources)}`;
}

function base(): string {
  return geo.sourceName ? `из базы ${geo.sourceName}` : 'из базы правил';
}

// itemLabel describes a typed destination item; null for a plain site.
export function itemLabel(d: string): ItemLabel | null {
  const m = /^(geosite|geoip|keyword|regexp|full|domain):(.*)$/i.exec(d);
  if (m) {
    const t = m[1].toLowerCase();
    const v = m[2];
    if (t === 'geosite' || t === 'geoip') {
      const ip = t === 'geoip';
      const c = category(ip ? 'ip' : 'site', v.split('@')[0]);
      const miss = missingText(c);
      const what = ip ? 'адреса' : 'сайты';
      return {
        text: c?.title ?? (ip ? v.toUpperCase() : v),
        kind: geo.sourceName || (ip ? 'geoip' : 'geosite'),
        tip: `${t}:${v} — ${what} ${base()}${c?.hint ? '. ' + c.hint : ''}${miss ? '. Внимание: ' + miss + ' (Настройки → Базы правил)' : ''}`,
        geo: true,
        missing: miss,
      };
    }
    const plain = { geo: false, missing: '' };
    if (t === 'keyword') return { text: v, kind: 'слово', tip: `Любой сайт, в имени которого есть «${v}»`, ...plain };
    if (t === 'regexp') return { text: v, kind: 'regexp', tip: 'Имя сайта по регулярному выражению', ...plain };
    if (t === 'full') return { text: v, kind: 'только этот адрес', tip: `Только ${v}, без поддоменов`, ...plain };
    return { text: v, kind: '+ поддомены', tip: `${v} и все поддомены`, ...plain };
  }
  if (ipv4.test(d) || ipv6.test(d)) {
    const net = d.includes('/') && !/\/(32|128)$/.test(d);
    return { text: d, kind: net ? 'сеть' : 'IP', tip: net ? `Все адреса сети ${d}` : `Адрес ${d}`, geo: false, missing: '' };
  }
  return null;
}

// shortLabel is the compact text for rule cards.
export function shortLabel(d: string): string {
  const l = itemLabel(d);
  if (l) return l.geo ? l.text : d;
  return d.startsWith('*.') ? d : d.replace(/^\./, '');
}
