<script lang="ts">
  // "Проверить адрес": which rule would take a site or program and where it
  // would go. Useful when a site goes the wrong way.
  import { api, errText, type Explanation, type Settings } from '../api';
  import { profileName, hide } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { current }: { current: () => Settings | null } = $props();

  let app = $state('');
  let target = $state('');
  // The answer with the query it is for: the fields may have changed since.
  let ex = $state<(Explanation & { q: { app: string; target: string } }) | null>(null);
  let error = $state('');
  let seq = 0;

  async function run() {
    const q = { app, target };
    const my = ++seq;
    error = '';
    try {
      // A slow answer (the name may wait for DNS) must not replace a newer one.
      const res = await api.Explain({ ...q, proto: 'tcp' }, current());
      if (my === seq) ex = { ...res, q };
    } catch (e) {
      if (my === seq) error = errText(e);
    }
  }

  function routeText(a: string, profile: string): string {
    if (a === 'direct') return 'напрямую';
    if (a === 'block') return 'будет заблокировано';
    return profile ? `через ${profileName(profile)}` : 'через основной сервер (не выбран — соединение отклонится)';
  }
</script>

<details class="card check">
  <summary><Icon name="search" size={16} /> Проверить адрес <span class="muted small">— куда пойдёт сайт или программа и почему</span></summary>
  <p class="muted small">
    Сайт идёт не туда? Введите его адрес (и, если нужно, программу) — HyRoute покажет, какое правило сработает.
  </p>
  <div class="row">
    <input class="grow" placeholder="Сайт или IP: youtube.com, ссылка, 1.2.3.4" bind:value={target} onkeydown={(e) => e.key === 'Enter' && run()} />
    <input class="grow" placeholder="Программа (необязательно): chrome" bind:value={app} onkeydown={(e) => e.key === 'Enter' && run()} />
    <button class="primary" onclick={run} disabled={!target.trim() && !app.trim()}>Проверить</button>
  </div>
  {#if error}<div class="note error">{error}</div>{/if}
  {#if ex}
    <div class="result route-{ex.winner.action}">
      {hide(ex.q.target) || ex.q.app} → {routeText(ex.winner.action, ex.winner.profile)}
    </div>
    <div class="muted small">
      {#if ex.winner.index < 0}Ни одно правило не подошло, сработало «Всё остальное».{:else}Сработало правило «{ex.winner.name}»: {hide(ex.winner.reason)}.{/if}
    </div>
    <details class="more">
      <summary class="small">Подробно по каждому правилу</summary>
      <ol>
        {#each ex.steps as st}
          <li class:win={st.winner}>
            <span class="mark">{st.winner ? '★' : st.matched ? '✓' : '·'}</span>
            <b>{st.index < 0 ? 'Всё остальное' : st.name}</b> <span class="muted">— {hide(st.reason)}</span>
          </li>
        {/each}
      </ol>
      {#each ex.notes as n}<div class="note info small">{hide(n)}</div>{/each}
    </details>
  {/if}
</details>

<style>
  .check summary { cursor: pointer; display: flex; align-items: center; gap: 8px; font-weight: 600; list-style: none; }
  .check summary::-webkit-details-marker { display: none; }
  .check[open] summary { margin-bottom: 8px; }
  .result { font-weight: 650; font-size: 15px; margin: 12px 0 2px; }
  .more { margin-top: 8px; }
  .more summary { cursor: pointer; color: var(--muted); }
  ol { list-style: none; padding: 0; margin: 8px 0; display: grid; gap: 3px; font-size: 12.5px; }
  .mark { display: inline-block; width: 18px; color: var(--faint); }
  .win { background: var(--surface-2); border-radius: 6px; }
  .win .mark { color: var(--warn); }
</style>
