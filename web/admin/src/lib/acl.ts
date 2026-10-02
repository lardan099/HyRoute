// Routing rule helpers: the kinds of addresses as Hysteria's compiler
// tells them apart (acl.KindOf on the controller), an address from a kind
// and a value, and the checks the rule dialog makes before the controller
// does.
import type { AclRule, RoutingOutbound, RoutingTemplate } from '../api';

export type AddrKind = 'all' | 'domain' | 'suffix' | 'wildcard' | 'geosite' | 'ip' | 'cidr' | 'geoip';

// kinds in the order the rule dialog offers them.
export const kinds: AddrKind[] = ['domain', 'suffix', 'wildcard', 'geosite', 'ip', 'cidr', 'geoip', 'all'];

// builtIn are the outbounds every server has unless the config names its
// own so.
export const builtIn = ['direct', 'reject', 'default'];

const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const ipv6 = /^[0-9a-f:.]+$/i;

export function isIP(s: string): boolean {
  if (ipv4.test(s)) return s.split('.').every((p) => Number(p) <= 255);
  return (s.match(/:/g)?.length ?? 0) >= 2 && ipv6.test(s);
}

// norm is an address as the compiler sees it: lower case, no trailing dot.
export function norm(a: string): string {
  return a.trim().toLowerCase().replace(/\.+$/, '');
}

export function kindOf(address: string): AddrKind {
  const a = norm(address);
  if (a === '*' || a === 'all') return 'all';
  if (a.startsWith('geoip:')) return 'geoip';
  if (a.startsWith('geosite:')) return 'geosite';
  if (a.startsWith('suffix:')) return 'suffix';
  if (a.includes('/')) return 'cidr';
  if (isIP(a)) return 'ip';
  if (a.includes('*')) return 'wildcard';
  return 'domain';
}

// valueOf is the address without its kind's prefix.
export function valueOf(address: string): string {
  const a = address.trim();
  switch (kindOf(a)) {
    case 'all':
      return '';
    case 'geoip':
    case 'geosite':
    case 'suffix':
      return a.slice(a.indexOf(':') + 1);
  }
  return a;
}

export function addressOf(kind: AddrKind, value: string): string {
  const v = value.trim();
  switch (kind) {
    case 'all':
      return 'all';
    case 'geoip':
    case 'geosite':
    case 'suffix':
      return `${kind}:${v}`;
  }
  return v;
}

// protoPort is proto/port as the rule line has it ("": every protocol
// and port).
export function protoPort(r: AclRule): string {
  const p = r.proto || '';
  const port = r.port || '';
  if (!port) return p;
  return (p || '*') + '/' + port;
}

// bad: a line Hysteria cannot read (it has only text).
export const bad = (r: AclRule) => !r.outbound && !r.address && !!r.text;

// badChars are what a field of a rule line cannot hold.
export const badChars = /[,#()\r\n]/;

// portOK: empty, a port, or a range lo-hi.
export function portOK(s: string): boolean {
  if (!s.trim()) return true;
  const m = s.trim().match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
  if (!m) return false;
  const lo = Number(m[1]);
  const hi = m[2] ? Number(m[2]) : lo;
  return lo >= 1 && hi <= 65535 && lo <= hi;
}

export const outboundOK = (s: string) => /^\w+$/.test(s);

// TemplateMode is where a template's rules go.
export type TemplateMode = 'top' | 'bottom' | 'replace';

// merge puts a template into rules and outbounds: its rules at the top,
// at the end or instead; its outbounds the list lacks (by name, without
// passwords) at the end.
export function merge(rules: AclRule[], obs: RoutingOutbound[], tpl: RoutingTemplate, mode: TemplateMode, withOutbounds: boolean) {
  const add = (tpl.acl.rules ?? []).map((r) => ({ ...r }));
  const out = mode === 'top' ? [...add, ...rules] : mode === 'bottom' ? [...rules, ...add] : add;
  const outbounds = [...obs];
  if (withOutbounds) {
    for (const o of tpl.outbounds ?? []) {
      if (!outbounds.some((x) => x.name.toLowerCase() === o.name.toLowerCase())) outbounds.push({ ...o, from: undefined, locked: undefined });
    }
  }
  return { rules: out, outbounds, resolver: tpl.resolver ? { ...tpl.resolver } : undefined };
}
