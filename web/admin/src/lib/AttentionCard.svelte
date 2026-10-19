<script lang="ts">
  // «Требует внимания» of the overview: what wants a look now, with a way
  // to the page of each, the banner of a controller without network, and
  // the events of the last days. Refreshed every 30 s while the tab is
  // visible.
  import { onDestroy, onMount } from 'svelte';
  import { api, type Attention, type AttentionItem, type EventInfo, type Severity } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import { when } from './format';

  let data = $state<Attention | null>(null);
  let recent = $state<EventInfo[]>([]);
  let all = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let gone = false;

  const shown = 8;

  async function load() {
    clearTimeout(timer);
    if (document.visibilityState === 'visible') {
      try {
        [data, recent] = await Promise.all([api.attention(), api.events(20)]);
      } catch {} // the summary is optional; the next round tries again
    }
    if (!gone) timer = setTimeout(load, 30e3);
  }

  function visible() {
    if (document.visibilityState === 'visible') load();
  }

  onMount(() => {
    load();
    document.addEventListener('visibilitychange', visible);
  });
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
    document.removeEventListener('visibilitychange', visible);
  });

  const tone = (s: Severity) => (s === 'critical' ? 'bad' : s === 'warning' ? 'wait' : '');

  // open goes to the page of what an item or event is about.
  function open(subject: string, id?: number) {
    if (!id) return;
    if (subject === 'server') go('servers', id);
    else if (subject === 'chain') go('cascades', id);
    else if (subject === 'job') go('deployments', id);
  }

  let items = $derived(data ? (all ? data.items : data.items.slice(0, shown)) : []);
</script>

{#if data?.network}
  <div class="note error banner">{t('attention.network', { at: when(data.network.openedAt) })}</div>
{/if}

{#if data}
  <section class="card attention">
    <h2>{t('attention.title')}</h2>
    {#if data.items.length === 0}
      <p class="muted">{t('attention.none')}</p>
    {:else}
      <ul>
        {#each items as it, i (i + it.kind + it.subject + (it.subjectId ?? 0))}
          {@render item(it)}
        {/each}
      </ul>
      {#if data.items.length > shown}
        <button class="link small" onclick={() => (all = !all)}>{all ? t('attention.less') : t('attention.more', { n: data.items.length })}</button>
      {/if}
    {/if}
    {#if recent.length}
      <details>
        <summary class="small">{t('events.title')}</summary>
        <ul class="events">
          {#each recent as e (e.id)}
            <li>
              <span class="dot {e.closedAt ? 'ok' : tone(e.severity)}"></span>
              <div class="grow col">
                <button class="link text" disabled={!e.subjectId || e.subject === 'controller'} onclick={() => open(e.subject, e.subjectId)}>{e.text}</button>
                <span class="muted small">
                  {when(e.openedAt)}{#if e.count > 1} · {t('events.count', { n: e.count })}{/if}
                  {#if e.closedAt} · {t('events.closed', { at: when(e.closedAt), text: e.closeText })}{:else} · {t('events.open')}{/if}
                </span>
              </div>
            </li>
          {/each}
        </ul>
      </details>
    {/if}
  </section>
{/if}

{#snippet item(it: AttentionItem)}
  <li>
    <span class="dot {tone(it.severity)}"></span>
    <div class="grow col">
      {#if it.subject !== 'controller' && it.subjectId}
        <button class="link name ellipsis" onclick={() => open(it.subject, it.subjectId)}>{it.name || t('attention.job')}</button>
      {:else}
        <b class="name">{t('attention.controller')}</b>
      {/if}
      <span class="small text">{it.text}</span>
    </div>
    {#if it.since}<span class="muted small since">{when(it.since)}</span>{/if}
  </li>
{/snippet}

<style>
  .banner { margin-top: 16px; }
  .attention { margin-top: 20px; }
  ul { list-style: none; margin: 0 0 8px; padding: 0; display: flex; flex-direction: column; gap: 10px; }
  li { display: flex; align-items: flex-start; gap: 10px; min-width: 0; }
  li .dot { margin-top: 6px; }
  .col { display: flex; flex-direction: column; min-width: 0; gap: 2px; }
  .name { color: var(--text); text-align: left; justify-content: flex-start; }
  .name:hover { color: var(--accent); }
  .text { color: var(--text); text-align: left; justify-content: flex-start; white-space: normal; user-select: text; }
  button.text:disabled { cursor: default; opacity: 1; }
  .since { white-space: nowrap; }
  details { margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px; }
  summary { cursor: pointer; color: var(--muted); }
  .events { margin-top: 10px; }
</style>
