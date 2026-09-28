// Rule titles as the Rules page shows them, for every surface that names a
// rule (Rules, toasts). A title can contain sites: callers outside the
// Rules page pass it through hide().
import { cleanRule, portsText, type Rule } from './api';
import { hide, ui, mainTarget } from './state.svelte';
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
// database are not). A rule with ports only is named by them («TCP 22»),
// as Go's ruleName names it (Connections, the log, Explain).
export function ruleTitle(r: Rule): string {
  if (r.name) return r.name;
  const a = (r.apps ?? []).map((x) => appLabel(x.pattern));
  const d = (r.domains ?? []).map((x) => (itemLabel(x)?.geo ? siteLabel(x) : hide(siteLabel(x))));
  return [...a, ...d].slice(0, 2).join(', ') + (a.length + d.length > 2 ? '…' : '') || (r.ports ? portsText(r) : '') || 'Правило';
}

// ==== conn-rules ====

// sortedJSON is JSON with object keys sorted (a stable form to compare).
function sortedJSON(v: unknown): string {
  return JSON.stringify(v, (_k, x) =>
    x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x,
  );
}

// sameRule compares two rules as they are saved (cleanRule), key order aside.
export function sameRule(a: Rule, b: Rule): boolean {
  const main = mainTarget()?.id;
  return sortedJSON(cleanRule(a, main)) === sortedJSON(cleanRule(b, main));
}

// RuleRef names a rule of a list that may have changed since it was read:
// its ID, its index then, the rule itself and the settings revision then.
export interface RuleRef {
  id: string;
  index: number;
  rule: Rule;
  rev?: number;
}

// locateRule finds want in list: by ID when it has one; else at its index
// while nothing changed since (the revision) and the rule there is the same;
// else the only rule equal to it. -1 when none or several match.
export function locateRule(list: Rule[], want: RuleRef): number {
  if (want.id !== '') return list.findIndex((r) => r.id === want.id);
  if (want.rev !== undefined && want.rev === ui.settingsRev && list[want.index] && sameRule(list[want.index], want.rule)) return want.index;
  const hits = list.flatMap((r, i) => (sameRule(r, want.rule) ? [i] : []));
  return hits.length === 1 ? hits[0] : -1;
}
