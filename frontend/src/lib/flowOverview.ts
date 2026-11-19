import type { Flow } from '../api';

export function flowFailed(f: Flow): boolean {
  if (f.stage === 'dns') return f.outcome.startsWith('dns: SERVFAIL');
  return (f.route === 'direct' || f.route === 'tunnel') && /^(rst:|dropped:)/.test(f.outcome);
}

export function usedTunnel(f: Flow): boolean {
  return f.route === 'tunnel' && f.stage !== 'dns' &&
    (f.outcome === 'relayed' || (f.outcome === 'tunneled' && (f.sent > 0 || f.recv > 0)));
}

export function flowState(f: Flow): string {
  if (f.stage === 'dns') {
    if (flowFailed(f)) return 'Не удалось узнать IP';
    if (f.outcome.includes('NXDOMAIN')) return 'Запрос заблокирован';
    if (f.outcome.includes('NODATA')) return 'Ответ без данных';
    return 'DNS-запрос обработан';
  }
  if (f.tooBig && !f.sent) return 'Пакет слишком большой';
  if (flowFailed(f)) return 'Не удалось подключиться';
  if (f.route === 'block') return 'Заблокировано';
  if (f.outcome.startsWith('aborted')) return 'Попытка прервана';
  if (f.closed) return 'Соединение закрыто';
  if (usedTunnel(f) || f.outcome === 'relayed') return 'Подключено';
  if (f.outcome === 'passed') return 'Трафик разрешён';
  return 'Подключается…';
}

// Domainless connections retain their full endpoint. A failure, a fallback
// or a different deciding rule always gets its own row.
export function overviewKey(f: Flow): string {
  return JSON.stringify([f.path || f.process || f.pid, f.domain || f.dst, f.proto, f.dst.split(':').pop(),
    f.stage === 'dns', f.route, f.rule, f.profile, f.group, !!f.failover, f.outcome, flowState(f), usedTunnel(f), !!f.closed]);
}

export function overviewGroups(flows: Flow[]) {
  const groups = new Map<string, { flow: Flow; count: number }>();
  for (const flow of flows) {
    const key = overviewKey(flow);
    const group = groups.get(key);
    if (group) group.count++;
    else groups.set(key, { flow, count: 1 });
  }
  return groups;
}
