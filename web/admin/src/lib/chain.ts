import type { Chain, LinkState, RoutingTemplate } from '../api';
import { t, type Key } from '../i18n';

// deployed: some link may be in effect on the servers, so the chain is
// removed by a job that takes it off first.
export function deployed(c: Chain): boolean {
  return c.links.some((l) => l.state !== 'new' && l.state !== 'failed');
}

// busy: a job is deploying or removing a link.
export function busy(c: Chain): boolean {
  return c.state === 'linking' || c.state === 'unlinking';
}

export function linkStateText(s: LinkState): string {
  return t(`linkstate.${s}` as Key);
}

// linkTone is the dot color of a link state.
export function linkTone(s: LinkState): string {
  switch (s) {
    case 'active':
      return 'ok';
    case 'failed':
      return 'bad';
    case 'new':
      return '';
  }
  return 'wait';
}

// pendingEntry are the entry rules of the template a cascade was just
// made from (by cascade ID), offered on its page for this session.
export const pendingEntry = new Map<number, RoutingTemplate>();
