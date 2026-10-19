// The rule builder by services (the «По сервисам» tab): what a service's
// switch offers and which of the group's choices the tab keeps. The
// controller builds the group and reads it back (routing/services); this
// is what the tab decides on its own.
import type { CatalogService, ServicesView } from '../api';
import { t } from '../i18n';

// SERVICES_GROUP is the rule group the builder owns (routing.ServicesGroup).
export const SERVICES_GROUP = 'По сервисам';

// Action is a position of a service's switch: '' leaves the service alone
// (no rules), otherwise the outbound its rules name.
export interface Action {
  value: string;
  label: string;
  // own: an outbound of the server's config.
  own?: boolean;
}

// reserved are the names the switch offers by meaning or not at all.
const reserved = ['cascade', 'direct', 'reject', 'default'];

// offered are the positions of a switch: leave alone, direct, through the
// exit (the cascade outbound, on the entry of a cascade only), each other
// outbound of the draft, block.
export function offered(outbounds: string[], entry: boolean): Action[] {
  const out: Action[] = [
    { value: '', label: t('svc.none') },
    { value: 'direct', label: t('svc.direct') },
  ];
  if (entry) out.push({ value: 'cascade', label: t('svc.exit') });
  for (const o of outbounds) if (!reserved.includes(o.toLowerCase())) out.push({ value: o, label: o, own: true });
  out.push({ value: 'reject', label: t('svc.block') });
  return out;
}

// Dropped is a service the group has rules of that the tab cannot show:
// its categories are not in the databases, or its outbound is not one the
// switch offers. The next build leaves its rules out.
export interface Dropped {
  name: string;
  outbound: string;
}

// split takes the choices read back from the group: those the switches
// show (as the switch names the outbound, matched without case) and the
// dropped ones.
export function split(view: ServicesView, acts: Action[]): { choices: Record<string, string>; dropped: Dropped[] } {
  const shown = new Map<string, CatalogService>();
  for (const s of view.sections) for (const c of s.services) shown.set(c.id, c);
  const choices: Record<string, string> = {};
  const dropped: Dropped[] = [];
  for (const [id, o] of Object.entries(view.state.choices ?? {})) {
    const c = shown.get(id);
    const a = acts.find((x) => x.value && x.value.toLowerCase() === o.toLowerCase());
    if (c && a) choices[id] = a.value;
    else dropped.push({ name: c?.name ?? view.hidden.find((h) => h.id === id)?.name ?? id, outbound: o });
  }
  return { choices, dropped };
}

// withChoice is choices with service id set to value ('' removes it).
export function withChoice(choices: Record<string, string>, id: string, value: string): Record<string, string> {
  const next = { ...choices };
  if (value) next[id] = value;
  else delete next[id];
  return next;
}

// categories are a service's categories as the rules name them.
export function categories(c: CatalogService): string {
  return [...(c.sites ?? []).map((s) => 'geosite:' + s), ...(c.domains ?? []).map((d) => 'suffix:' + d), ...(c.ips ?? []).map((i) => 'geoip:' + i)].join(', ');
}
