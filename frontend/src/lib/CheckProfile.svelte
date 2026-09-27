<script lang="ts">
  // "Check profile": starts the profile's Hysteria (or uses the running
  // one) and tests TCP, the external IP, latency and UDP.
  import { onMount } from 'svelte';
  import { api, errText, type CheckResult } from '../api';
  import { hide } from '../state.svelte';

  let { id, name, onclose }: { id: string; name: string; onclose: () => void } = $props();

  let res = $state<CheckResult | null>(null);
  let error = $state('');
  let running = $state(true);

  async function run() {
    running = true;
    error = '';
    res = null;
    try {
      res = await api.CheckProfile(id);
    } catch (e) {
      error = errText(e);
    }
    running = false;
  }

  onMount(run);
</script>

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && !running && onclose()}>
  <div class="dialog panel">
    <h2>Проверка профиля «{hide(name)}»</h2>
    {#if running}
      <p class="muted">Запуск Hysteria и проверка соединения… (до 30 секунд)</p>
    {/if}
    {#if error}<div class="note error">{hide(error)}</div>{/if}
    {#if res}
      <div class="verdict" class:ok={res.ok}>
        {#if res.ok}Профиль работает{:else}Есть проблема{/if}
        {#if res.externalIP} · внешний IP {hide(res.externalIP)}{/if}
        {#if res.latencyMs} · задержка {res.latencyMs} мс{/if}
      </div>
      <ul>
        {#each res.steps as s}
          <li class:ok={s.ok} class:bad={!s.ok && !s.skip} class:skip={s.skip}>
            <span class="mark">{s.ok ? '✓' : s.skip ? '–' : '✗'}</span>
            <b>{s.name}</b>{#if s.ms}<span class="muted ms">{s.ms} мс</span>{/if}
            <div class="detail">{hide(s.detail)}</div>
          </li>
        {/each}
      </ul>
    {/if}
    <div class="row end">
      <button onclick={run} disabled={running}>Повторить</button>
      <button class="primary" onclick={onclose} disabled={running}>Закрыть</button>
    </div>
  </div>
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.45); display: grid; place-items: center; z-index: 20; }
  .dialog { width: min(640px, 92vw); max-height: 88vh; overflow: auto; }
  .verdict { font-weight: 600; font-size: 15px; color: var(--block); margin-bottom: 8px; }
  .verdict.ok { color: var(--direct); }
  ul { list-style: none; padding: 0; margin: 0 0 12px; display: grid; gap: 8px; }
  .mark { display: inline-block; width: 18px; font-weight: 700; }
  li.ok .mark { color: var(--direct); }
  li.bad .mark { color: var(--block); }
  li.skip { opacity: 0.8; }
  .detail { margin-left: 18px; font-size: 12.5px; color: var(--muted); user-select: text; }
  li.bad .detail { color: var(--block); }
  .end { justify-content: flex-end; }
  .ms { margin-left: 8px; }
</style>
