<script lang="ts">
  // The live Hysteria journal of a server (server-sent events, redacted by
  // the controller). Pause closes the stream; resume starts it again.
  import { onMount, tick } from 'svelte';
  import { journalURL, type JournalEntry } from '../api';
  import { t } from '../i18n';
  import { clock } from './format';

  let { serverId }: { serverId: number } = $props();

  const keep = 1000;
  let entries = $state<JournalEntry[]>([]);
  let live = $state(false);
  let ended = $state('');
  let box = $state<HTMLElement | null>(null);
  let follow = $state(true);
  let source: EventSource | null = null;

  async function down() {
    if (!follow) return;
    await tick();
    box?.scrollTo({ top: box.scrollHeight });
  }

  function start() {
    source?.close();
    entries = [];
    ended = '';
    source = new EventSource(journalURL(serverId));
    live = true;
    source.addEventListener('entry', (e) => {
      entries.push(JSON.parse((e as MessageEvent).data));
      if (entries.length > keep) entries.splice(0, entries.length - keep);
      down();
    });
    source.addEventListener('end', (e) => {
      ended = JSON.parse((e as MessageEvent).data).message;
      stop();
    });
    // An error before any data is an API error (no key, no installation):
    // the stream would only retry it.
    source.onerror = () => {
      if (!entries.length) {
        ended = t('srv.journalEnded');
        stop();
      }
    };
  }

  function stop() {
    source?.close();
    source = null;
    live = false;
  }

  onMount(() => {
    start();
    return stop;
  });
</script>

<section class="card journal">
  <div class="row">
    <h2 class="grow">{t('srv.journal')}</h2>
    {#if live}<span class="live small">● {t('jobs.live')}</span>{/if}
    <button class="ghost" onclick={() => (live ? stop() : start())}>{live ? t('srv.pause') : t('srv.resume')}</button>
  </div>
  <div class="lines mono" bind:this={box} onscroll={() => box && (follow = box.scrollTop + box.clientHeight >= box.scrollHeight - 20)}>
    {#each entries as e, i (i)}
      <div class="line {e.level}"><span class="faint">{clock(e.time)}</span> {e.message}</div>
    {:else}
      <div class="faint">{t('srv.journalEmpty')}</div>
    {/each}
    {#if ended}<div class="faint end">{ended}</div>{/if}
  </div>
</section>

<style>
  .journal h2 { margin: 0; }
  .live { color: var(--direct); }
  .lines { margin-top: 12px; height: 360px; overflow: auto; background: var(--surface-2); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 12px; line-height: 1.6; user-select: text; }
  .line { white-space: pre-wrap; word-break: break-word; }
  .line.warn { color: var(--warn); }
  .line.error { color: var(--block); }
  .line.debug { color: var(--faint); }
  .end { margin-top: 6px; }
</style>
