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

// uptime in seconds as "3 д 4 ч", "5 ч 12 мин", "7 мин".
export function uptime(sec: number): string {
  if (!sec || sec < 0) return '—';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d} д ${h} ч`;
  if (h > 0) return `${h} ч ${m} мин`;
  return `${Math.max(m, 1)} мин`;
}

export function clock(s: string): string {
  return new Date(s).toLocaleTimeString('ru-RU');
}

// pct is a percentage without needless decimals.
export function pct(v: number): string {
  return `${v < 10 && v > 0 ? v.toFixed(1) : Math.round(v)}%`;
}

// mib is a size given in MiB, in MiB or GiB.
export function mib(v: number): string {
  if (v >= 1024) return `${(v / 1024).toFixed(v >= 10240 ? 0 : 1)} ГБ`;
  return `${Math.round(v)} МБ`;
}

// bits is a rate given in bits per second.
export function bits(v: number): string {
  const units = ['бит/с', 'Кбит/с', 'Мбит/с', 'Гбит/с'];
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

// bytes is an amount of data in bytes (binary units, as the client shows).
export function bytes(v: number): string {
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
