<script lang="ts">
  // The live Hysteria journal of a server (server-sent events, redacted by
  // the controller). Pause closes the stream; resume starts it again.
  import { onMount, tick } from 'svelte';
  import { api, journalURL, type JournalEntry } from '../api';
  import { t } from '../i18n';
  import { clock } from './format';

  let { serverId }: { serverId: number } = $props();

  const keep = 1000;
  let entries = $state<JournalEntry[]>([]);
  let live = $state(false);
  // waiting: a reconnect is due.
  let waiting = $state(false);
  let ended = $state('');
  let box = $state<HTMLElement | null>(null);
  let follow = $state(true);
  let source: EventSource | null = null;
  // A stream that worked and broke is opened again after backoff ms.
  let worked = false;
  let backoff = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function down() {
    if (!follow) return;
    await tick();
    box?.scrollTo({ top: box.scrollHeight });
  }

  // start opens the stream; again is a reconnect after a break.
  function start(again = false) {
    stop();
    if (!again) {
      worked = false;
      backoff = 0;
      entries = [];
      ended = '';
    }
    // The stream starts with the last lines: after a reconnect they
    // replace what is shown instead of being appended twice.
    let fresh = again;
    const es = new EventSource(journalURL(serverId));
    source = es;
    live = !again;
    waiting = again;
    es.addEventListener('entry', (e) => {
      worked = true;
      backoff = 0;
      if (fresh) {
        fresh = false;
        entries = [];
        ended = '';
        live = true;
        waiting = false;
      }
      entries.push(JSON.parse((e as MessageEvent).data));
      if (entries.length > keep) entries.splice(0, entries.length - keep);
      down();
    });
    es.addEventListener('end', (e) => {
      ended = JSON.parse((e as MessageEvent).data).message;
      stop();
    });
    es.onerror = () => {
      if (source !== es) return;
      const closed = es.readyState === EventSource.CLOSED;
      stop();
      // An answer other than the stream (401 after the session expired,
      // 502 while the controller restarts) closes it for good; ask the
      // API once, so an expired session brings the login screen.
      if (closed) api.server(serverId).catch(() => {});
      // An error before any data is an API error (no key, no
      // installation): opening the stream again would only repeat it.
      if (!worked) {
        ended = t('srv.journalEnded');
        return;
      }
      // Reconnect here rather than let the browser do it: see fresh.
      ended = t('srv.journalReconnect');
      waiting = true;
      backoff = Math.min(backoff ? backoff * 2 : 1000, 30000);
      timer = setTimeout(() => start(true), backoff);
    };
  }

  function stop() {
    clearTimeout(timer);
    waiting = false;
    source?.close();
    source = null;
    live = false;
  }

  // pause is the admin's stop: a due reconnect is called off too.
  function pause() {
    if (waiting) ended = '';
    stop();
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
    <button class="ghost" onclick={() => (live || waiting ? pause() : start())}>{live || waiting ? t('srv.pause') : t('srv.resume')}</button>
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
