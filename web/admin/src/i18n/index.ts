import { ru, type Key } from './ru';

export type { Key };

const dict: Record<Key, string> = ru;

// t returns the string for key; {name} placeholders are replaced from params.
export function t(key: Key, params?: Record<string, string | number>): string {
  let s: string = dict[key] ?? key;
  if (params) {
    for (const [k, v] of Object.entries(params)) s = s.replaceAll(`{${k}}`, String(v));
  }
  return s;
}

// tOr is t for keys built at run time (job kinds, step names): unknown keys
// give fallback instead of the key itself.
export function tOr(key: string, fallback: string): string {
  return (dict as Record<string, string>)[key] ?? fallback;
}
