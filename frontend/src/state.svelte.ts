// Shared UI state: status, profiles, Privacy mode, theme.
import { maskDomains, maskHosts, maskIPs, maskURLs } from './privacy';
import { isGroupId, type GroupView, type ProfileSummary, type Status, type SubAlert } from './api';
import { netUnknownName, type NetState } from './api'; // netmodes

function get(k: string): string | null {
  try {
    return localStorage.getItem('hyroute.' + k);
  } catch {
    return null;
  }
}

function set(k: string, v: string) {
  try {
    localStorage.setItem('hyroute.' + k, v);
  } catch {}
}

export type Theme = 'system' | 'light' | 'dark' | 'midnight';
export type Accent = 'blue' | 'violet' | 'teal' | 'orange' | 'pink' | 'rainbow';

export const ui = $state({
  privacy: get('privacy') === '1',
  profiles: [] as ProfileSummary[],
  status: null as Status | null,
  theme: (get('theme') ?? 'system') as Theme,
  accent: (get('accent') ?? 'blue') as Accent,
  // foundation: the highest settings revision seen (status and the
  // "settings" event); pages holding a copy of the rules reload when it
  // passes theirs.
  settingsRev: 0,
  // The full interface (Настройки → Режим интерфейса). Off: fewer pages,
  // plain-words hints and the step-by-step setup. null until decided: a
  // copy that already has servers from before the mode existed opens in
  // the full one (App.svelte).
  expert: (get('expert') === null ? null : get('expert') === '1') as boolean | null,
  // groups: the server groups (App reloads them with the servers)
  groups: [] as GroupView[],
  // subinfo: dismissed subscription alerts, subscription ID -> alert key
  // (WebView memory only; not part of a backup).
  subAck: loadSubAcks(),
  // dns: an element id a page scrolls to once it is shown (Home → «Настройки DNS»)
  scrollTo: '',
});

export function setExpert(on: boolean) {
  ui.expert = on;
  set('expert', on ? '1' : '0');
}

// The step-by-step setup: the step it stopped at ('' = not started) and
// whether it was finished or skipped. The step survives the restart after
// «Установить» (moving to Program Files): the WebView data does not depend
// on where HyRoute.exe is.
export function setupStep(): string {
  return get('setup.step') ?? '';
}

export function setSetupStep(s: string) {
  set('setup.step', s);
}

export function setupDone(): boolean {
  return get('setup.done') === '1';
}

export function finishSetup() {
  set('setup.done', '1');
  set('setup.step', '');
}

// Hints (lib/Help.svelte) the user closed.
export function helpClosed(id: string): boolean {
  return get('help.' + id) === '1';
}

export function closeHelp(id: string) {
  set('help.' + id, '1');
}

export function resetHelp() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith('hyroute.help.')) localStorage.removeItem(k);
  } catch {}
}

// noteSettingsRev raises ui.settingsRev, never lowers it.
export function noteSettingsRev(r: unknown) {
  if (typeof r === 'number' && r > ui.settingsRev) ui.settingsRev = r;
}

export function applyTheme() {
  const r = document.documentElement;
  if (ui.theme === 'system') r.removeAttribute('data-theme');
  else r.setAttribute('data-theme', ui.theme);
  r.setAttribute('data-accent', ui.accent);
}

export function setTheme(t: Theme) {
  ui.theme = t;
  set('theme', t);
  applyTheme();
}

export function setAccent(a: Accent) {
  ui.accent = a;
  set('accent', a);
  applyTheme();
}

export function setPrivacy(on: boolean) {
  ui.privacy = on;
  set('privacy', on ? '1' : '0');
}

// hide masks IPs, domains (SNI, Host, DNS names), server hosts and URLs
// when Privacy mode is on. Server and subscription names and error texts go
// through it too: a link without a #name is named after its host.
export function hide(s: string | undefined | null): string {
  if (!s) return s ?? '';
  if (!ui.privacy) return s;
  const hosts = ui.profiles.flatMap((p) => [p.host, p.sni]);
  return maskIPs(maskDomains(maskURLs(maskHosts(s, hosts))));
}

// profileName is a server's or a group's name for display, masked in
// Privacy mode.
export function profileName(id: string): string {
  if (!id) return '';
  if (isGroupId(id)) return hide(ui.groups.find((g) => g.id === id)?.name ?? 'удалённая группа');
  return hide(ui.profiles.find((p) => p.id === id)?.name ?? 'удалённый сервер');
}

export function mainProfile(): ProfileSummary | undefined {
  return ui.profiles.find((p) => p.main);
}

// MainTarget is the main server or group (★): what rules without an
// explicit server use.
export interface MainTarget {
  id: string;
  name: string; // for display (masked)
  group: boolean;
  unloaded: boolean; // a group groups.json could not load
}

// mainTarget comes from Go (Status.mainId), not from ui.groups: while
// groups.json is broken the main may be a group nobody can list, and its
// ID must still count as the main one.
export function mainTarget(): MainTarget | undefined {
  const id = ui.status?.mainId;
  if (!id) return undefined;
  const unloaded = !!ui.status?.mainUnloaded;
  return { id, group: isGroupId(id), unloaded, name: unloaded ? 'основная группа не загружена' : profileName(id) };
}

// targetText names a server as is and a group as «группа «X»».
export function targetText(id: string): string {
  return isGroupId(id) ? `группа «${profileName(id)}»` : profileName(id);
}

// settle runs the save behind a checkbox, radio, select or number field and
// then shows what saved() reads after it. Svelte writes a one-way
// checked={…} or value={…} to the DOM only when the value changes, so after
// a failed save the control would keep the user's click (a kill switch
// shown on while it is off).
export async function settle(e: Event, save: (el: HTMLInputElement) => Promise<unknown>, saved: () => unknown) {
  const el = e.currentTarget as HTMLInputElement; // a <select> has the same value
  await save(el);
  const v = saved();
  if (el.type === 'checkbox') el.checked = v === true;
  else if (el.type === 'radio') for (const r of document.getElementsByName(el.name) as NodeListOf<HTMLInputElement>) r.checked = r.value === v;
  else el.value = String(v);
}

// mainText is the main target for display: a server's name, «группа «X»»,
// or the note that the main group did not load.
export function mainText(m = mainTarget()): string {
  if (!m) return '';
  return m.unloaded ? m.name : targetText(m.id);
}

// ==== subinfo ====

// loadSubAcks reads hyroute.subAck: an object of strings, else {}.
function loadSubAcks(): Record<string, string> {
  try {
    const v: unknown = JSON.parse(get('subAck') ?? '{}');
    if (!v || typeof v !== 'object' || Array.isArray(v)) return {};
    return Object.fromEntries(Object.entries(v).filter(([, k]) => typeof k === 'string')) as Record<string, string>;
  } catch {
    return {};
  }
}

function saveSubAcks(acks: Record<string, string>) {
  ui.subAck = acks;
  set('subAck', JSON.stringify(acks));
}

// subAlerts are the subscription alerts the user has not dismissed.
export function subAlerts(): SubAlert[] {
  return (ui.status?.subAlerts ?? []).filter((a) => ui.subAck[a.id] !== a.key);
}

// ackSubAlert hides a until its situation changes (its key).
export function ackSubAlert(a: SubAlert) {
  saveSubAcks({ ...ui.subAck, [a.id]: a.key });
}

// pruneSubAcks forgets dismissals of subscriptions that have no alert now,
// so a later alert with the same key (the next month of a plan) shows
// again. Only from a status whose subscription list is authoritative: a
// subscriptions.json that did not load never clears them.
export function pruneSubAcks(st: Status) {
  if (!st.subsOK) return;
  const ids = new Set((st.subAlerts ?? []).map((a) => a.id));
  const keep = Object.fromEntries(Object.entries(ui.subAck).filter(([id]) => ids.has(id)));
  if (Object.keys(keep).length !== Object.keys(ui.subAck).length) saveSubAcks(keep);
}

// ==== netmodes ====

// hideNet masks a network name, a Wi-Fi name or a network rule's name (free
// text, often the Wi-Fi name) in Privacy mode: they are not domain-shaped,
// so hide() would not. «Неизвестная сеть» is not a secret.
export function hideNet(s: string | undefined | null): string {
  if (!s) return s ?? '';
  return ui.privacy && s !== netUnknownName ? '***' : s;
}

// netText is a network rule's state text or error for display: in Privacy
// mode the rule names in it (of st and names, longest first, and any name
// quoted after «правило сети» — load errors of networks.json name rules
// the page does not know) become «***», then hide() masks hosts, IPs,
// domains and URLs.
export function netText(s: string | undefined | null, st?: NetState | null, names: string[] = []): string {
  if (!s) return s ?? '';
  if (!ui.privacy) return s;
  const all = [st?.rule, st?.offBy, ...names].filter((n): n is string => !!n && n !== netUnknownName);
  all.sort((a, b) => b.length - a.length);
  for (const n of all) s = s.split(`«${n}»`).join('«***»');
  s = s.replace(netRuleQuote, (m, pre: string, n: string) => (n === netUnknownName ? m : `${pre}***»`));
  return hide(s);
}

const netRuleQuote = /([Пп]равил[а-я]* сет(?:и|ей) «)([^»]*)»/g;
