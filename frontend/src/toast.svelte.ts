// Transient messages at the bottom right (lib/Toasts.svelte shows them),
// shared by every feature. Text, detail and labels are thunks, so hide()
// re-evaluates when Privacy mode is toggled while a toast is visible.

export interface ToastAction {
  label: () => string;
  run: () => void | Promise<void>;
  // undo: removed by expireUndo once Go no longer keeps the operation.
  undo?: boolean;
}

export interface Toast {
  id: number;
  text: () => string;
  detail?: () => string;
  tone: 'ok' | 'info' | 'error';
  actions: ToastAction[];
  ms: number;
  // group: toasts of one kind (e.g. 'connrule'), for expireUndo and folding.
  group?: string;
  // seq: the operation's sequence number in its group (expireUndo).
  seq?: number;
  // expired: its «Отменить» was removed (the host says so).
  expired?: boolean;
  // folded: this is a group's summary toast standing for n folded ones.
  folded?: number;
}

export interface ToastInput {
  text: () => string;
  detail?: () => string;
  tone?: Toast['tone'];
  actions?: ToastAction[];
  ms?: number;
  group?: string;
  seq?: number;
}

// A group's summary for folded toasts: text and actions for n of them.
export type Fold = (n: () => number) => { text: () => string; detail?: () => string; actions: ToastAction[] };

// At most maxShown toasts are visible; the others wait in order.
const maxShown = 3;
// Beyond maxQueued waiting toasts, the oldest one without actions goes.
const maxQueued = 10;
// Beyond maxQueuedActions waiting toasts with actions, the oldest of a
// group with a fold are folded into its summary (else dropped).
const maxQueuedActions = 20;
// undoCapacity mirrors the number of undo entries Go keeps (conn-rules'
// connUndo); a change of one must change the other.
export const undoCapacity = 20;

export const toasts: { shown: Toast[]; queued: Toast[] } = $state({ shown: [], queued: [] });

const folds = new Map<string, Fold>();
let nextID = 1;

// setFold registers how waiting toasts of group are summarised when too
// many of them wait (the feature that owns the group provides the text).
export function setFold(group: string, fold: Fold) {
  folds.set(group, fold);
}

// toast shows a message (or queues it while maxShown are visible) and
// returns its ID. Default duration 8 s, errors 12 s.
export function toast(t: ToastInput): number {
  const tone = t.tone ?? 'info';
  const item: Toast = {
    id: nextID++,
    text: t.text,
    detail: t.detail,
    tone,
    actions: t.actions ?? [],
    ms: t.ms ?? (tone === 'error' ? 12000 : 8000),
    group: t.group,
    seq: t.seq,
  };
  if (toasts.shown.length < maxShown) toasts.shown.push(item);
  else {
    toasts.queued.push(item);
    trim();
  }
  return item.id;
}

// trim keeps the queue bounded: toasts without actions go first, then
// toasts with actions are folded into their group's summary.
function trim() {
  const q = toasts.queued;
  while (q.length > maxQueued) {
    const i = q.findIndex((x) => x.actions.length === 0 && !x.folded);
    if (i < 0) break;
    q.splice(i, 1);
  }
  while (q.filter((x) => x.actions.length > 0 && !x.folded).length > maxQueuedActions) {
    const i = q.findIndex((x) => x.actions.length > 0 && !x.folded);
    const old = q[i];
    q.splice(i, 1);
    const fold = old.group ? folds.get(old.group) : undefined;
    if (!fold) continue; // no summary for this kind: the oldest goes
    const sum = q.find((x) => x.folded && x.group === old.group);
    if (sum) {
      sum.folded!++;
      continue;
    }
    q.splice(i, 0, { id: nextID++, tone: 'info', ms: 12000, group: old.group, folded: 1, text: () => '', actions: [] });
    const item = q[i]; // the reactive copy: its count is read by the text
    const made = fold(() => item.folded ?? 0);
    item.text = made.text;
    item.detail = made.detail;
    item.actions = made.actions;
  }
}

// dismiss removes a toast and shows the next waiting one.
export function dismiss(id: number) {
  const i = toasts.shown.findIndex((x) => x.id === id);
  if (i >= 0) {
    toasts.shown.splice(i, 1);
    const next = toasts.queued.shift();
    if (next) toasts.shown.push(next);
    return;
  }
  const j = toasts.queued.findIndex((x) => x.id === id);
  if (j >= 0) toasts.queued.splice(j, 1);
}

// expireUndo removes the undo actions of every toast of group whose seq is
// keep or more below newestSeq (Go no longer keeps those operations) and
// marks them expired.
export function expireUndo(group: string, newestSeq: number, keep = undoCapacity) {
  for (const t of [...toasts.shown, ...toasts.queued]) {
    if (t.group !== group || t.seq === undefined || t.seq > newestSeq - keep) continue;
    if (!t.actions.some((a) => a.undo)) continue;
    t.actions = t.actions.filter((a) => !a.undo);
    t.expired = true;
  }
}
