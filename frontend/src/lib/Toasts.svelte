<script lang="ts">
  // The toast host (toast.svelte.ts): bottom right, above dialogs. It sits
  // right after <main>, so its buttons follow the page in the tab order.
  // A toast's timer starts when it is shown and pauses while the pointer
  // or the focus is on it.
  //
  // Screen readers announce only changes inside a live region that is
  // already in the page, so both regions are always rendered, empty or
  // not: errors in a role="alert" one (above), the rest in a polite
  // role="status" one.
  import { tick } from 'svelte';
  import { errText } from '../api';
  import { hide } from '../state.svelte';
  import { toasts, toast, dismiss, type Toast, type ToastAction } from '../toast.svelte';
  import Icon from './Icon.svelte';

  let host = $state<HTMLElement>();
  const errors = $derived(toasts.shown.filter((t) => t.tone === 'error'));
  const others = $derived(toasts.shown.filter((t) => t.tone !== 'error'));

  function timer(el: HTMLElement, t: Toast) {
    let left = t.ms;
    let since = 0;
    let handle: ReturnType<typeof setTimeout> | undefined;
    let hover = false;
    let focus = false;
    const start = () => {
      if (handle !== undefined || hover || focus) return;
      since = Date.now();
      handle = setTimeout(() => dismiss(t.id), left);
    };
    const pause = () => {
      if (handle === undefined) return;
      clearTimeout(handle);
      handle = undefined;
      left = Math.max(1000, left - (Date.now() - since));
    };
    const on = (e: Event) => {
      if (e.type === 'mouseenter') hover = true;
      if (e.type === 'mouseleave') hover = false;
      if (e.type === 'focusin') focus = true;
      if (e.type === 'focusout') focus = el.contains((e as FocusEvent).relatedTarget as Node | null);
      if (hover || focus) pause();
      else start();
    };
    const events = ['mouseenter', 'mouseleave', 'focusin', 'focusout'];
    for (const n of events) el.addEventListener(n, on);
    start();
    return {
      destroy() {
        for (const n of events) el.removeEventListener(n, on);
        clearTimeout(handle);
      },
    };
  }

  // close dismisses t. If the focus was on it, it moves to the toast now
  // in its place (or the last one), else back to the page: it must not
  // fall to <body>.
  async function close(t: Toast) {
    const els = () => [...(host?.querySelectorAll<HTMLElement>('.toast') ?? [])];
    const at = els().findIndex((el) => el.dataset.id === String(t.id) && el.contains(document.activeElement));
    dismiss(t.id);
    if (at < 0) return;
    await tick();
    const list = els();
    const next = list[Math.min(at, list.length - 1)]?.querySelector<HTMLElement>('button');
    (next ?? document.querySelector<HTMLElement>('main'))?.focus();
  }

  async function act(t: Toast, a: ToastAction) {
    await close(t);
    try {
      await a.run();
    } catch (e) {
      toast({ text: () => hide(errText(e)), tone: 'error' });
    }
  }
</script>

{#snippet item(t: Toast)}
  <div class="toast {t.tone}" data-id={t.id} use:timer={t}>
    <div class="grow">
      <div class="t">{t.text()}</div>
      {#if t.detail}<div class="d">{t.detail()}</div>{/if}
      {#if t.expired}<div class="d">Отменить уже нельзя — измените правило на странице «Правила».</div>{/if}
      {#if t.actions.length}
        <div class="acts">
          {#each t.actions as a}<button class="link" onclick={() => act(t, a)}>{a.label()}</button>{/each}
        </div>
      {/if}
    </div>
    <button class="icon" aria-label="Закрыть" title="Закрыть" onclick={() => close(t)}><Icon name="x" size={16} /></button>
  </div>
{/snippet}

<div class="toasts" bind:this={host}>
  <div class="region" role="alert" aria-atomic="false">
    {#each errors as t (t.id)}{@render item(t)}{/each}
  </div>
  <div class="region" role="status" aria-live="polite" aria-atomic="false">
    {#each others as t (t.id)}{@render item(t)}{/each}
  </div>
  {#if toasts.queued.length}<div class="more">ещё {toasts.queued.length}</div>{/if}
</div>
