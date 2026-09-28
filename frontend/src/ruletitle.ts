// Rule titles as the Rules page shows them, for every surface that names a
// rule (Rules, toasts). A title can contain sites: callers outside the
// Rules page pass it through hide().
import type { Rule } from './api';
import { hide } from './state.svelte';
import { itemLabel, shortLabel } from './geo.svelte';

// appLabel is a program's file name; a glob pattern is shown as is.
export function appLabel(p: string): string {
  return /[*?]/.test(p) ? p : (p.split('\\').pop() ?? p);
}

export function siteLabel(d: string): string {
  return shortLabel(d);
}

// ruleTitle of a rule without a name is made of its items: sites are
// masked in Privacy mode as in the Rules page's tags (lists from the
// database are not).
export function ruleTitle(r: Rule): string {
  if (r.name) return r.name;
  const a = (r.apps ?? []).map((x) => appLabel(x.pattern));
  const d = (r.domains ?? []).map((x) => (itemLabel(x)?.geo ? siteLabel(x) : hide(siteLabel(x))));
  const what = [...a, ...d].slice(0, 2).join(', ') + (a.length + d.length > 2 ? '…' : '');
  if (!what && r.ports?.trim()) return `Порт ${r.ports.split(/[\s,;]+/).filter(Boolean).join(', ')}`;
  return what || 'Правило';
}
