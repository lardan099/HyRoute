// Shared UI state: status, profiles, Privacy mode, theme.
import { maskDomains, maskHosts, maskIPs, maskURLs } from './privacy';
import type { ProfileSummary, Status } from './api';

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
});

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

// profileName is a server's name for display, masked in Privacy mode.
export function profileName(id: string): string {
  if (!id) return '';
  return hide(ui.profiles.find((p) => p.id === id)?.name ?? 'удалённый сервер');
}

export function mainProfile(): ProfileSummary | undefined {
  return ui.profiles.find((p) => p.main);
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
