import type { ServerState } from '../api';

// flag turns an ISO country code ("DE") into its flag emoji.
export function flag(country: string): string {
  if (!/^[A-Z]{2}$/.test(country)) return '';
  return String.fromCodePoint(...[...country].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// stateTone is the dot color class of a server state.
export function stateTone(s: ServerState): string {
  switch (s) {
    case 'healthy':
      return 'ok';
    case 'deploying':
    case 'degraded':
    case 'needs_attention':
      return 'wait';
    case 'offline':
      return 'bad';
  }
  return '';
}
