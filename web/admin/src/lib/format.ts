import type { JobState, ServerState, StepState } from '../api';

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

// jobTone is the dot color class of a job state.
export function jobTone(s: JobState): string {
  if (s === 'completed') return 'ok';
  if (s === 'failed') return 'bad';
  return 'wait';
}

export function stepTone(s: StepState): string {
  switch (s) {
    case 'done':
    case 'skipped':
      return 'ok';
    case 'running':
    case 'rolled_back':
      return 'wait';
    case 'failed':
      return 'bad';
  }
  return '';
}

export function when(s: string | null): string {
  return s ? new Date(s).toLocaleString('ru-RU') : '—';
}

// duration between two times, "1 мин 5 с".
export function duration(from: string | null, to: string | null): string {
  if (!from) return '—';
  const ms = (to ? new Date(to) : new Date()).getTime() - new Date(from).getTime();
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s} с` : `${Math.floor(s / 60)} мин ${s % 60} с`;
}
