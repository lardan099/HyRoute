<script lang="ts">
  // «Статистика»: how much went through the VPN, by server and by program.
  // Only the amounts are kept, never the sites.
  import { onMount } from 'svelte';
  import { api, errText, fmtBytes, type TrafficPeriod, type TrafficReport, type TrafficItem } from '../api';
  import { hide } from '../state.svelte';
  import Icon from './Icon.svelte';
  import Help from './Help.svelte';

  function storedPeriod(): TrafficPeriod {
    try {
      const v = localStorage.getItem('hyroute.traffic.period');
      if (v === 'day' || v === 'week' || v === 'month' || v === 'year') return v;
    } catch {}
    return 'week';
  }

  let period = $state<TrafficPeriod>(storedPeriod());
  let r = $state<TrafficReport | null>(null);
  let error = $state('');
  let seq = 0;

  async function load() {
    const my = ++seq;
    try {
      const v = await api.TrafficReport(period);
      if (my === seq) {
        r = v;
        error = '';
      }
    } catch (e) {
      if (my === seq) error = errText(e);
    }
  }

  function setPeriod(p: TrafficPeriod) {
    period = p;
    try {
      localStorage.setItem('hyroute.traffic.period', p);
    } catch {}
    load();
  }

  onMount(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  });

  async function clear() {
    if (!confirm('Удалить всю статистику трафика? Её нельзя будет вернуть.')) return;
    try {
      await api.ClearTraffic();
      await load();
    } catch (e) {
      error = errText(e);
    }
  }

  const periods: { v: TrafficPeriod; l: string }[] = [
    { v: 'day', l: 'Сегодня' },
    { v: 'week', l: '7 дней' },
    { v: 'month', l: '30 дней' },
    { v: 'year', l: 'Год' },
  ];

  const tot = (x: { sent: number; recv: number }) => x.sent + x.recv;
  const months = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];

  function dayLabel(d: string): string {
    const [, m, day] = d.split('-').map(Number);
    return `${day} ${months[m - 1]}`;
  }

  function barLabel(label: string): string {
    return r?.period === 'day' ? `${label}:00` : dayLabel(label);
  }

  // A year of days is too many bars: one per week there.
  const bars = $derived.by(() => {
    const s = r?.series ?? [];
    if (r?.period !== 'year') return s.map((p) => ({ label: barLabel(p.label), sent: p.sent, recv: p.recv }));
    const out: { label: string; sent: number; recv: number }[] = [];
    for (let i = 0; i < s.length; i += 7) {
      const w = s.slice(i, i + 7);
      out.push({ label: `${dayLabel(w[0].label)} – ${dayLabel(w[w.length - 1].label)}`, sent: w.reduce((a, p) => a + p.sent, 0), recv: w.reduce((a, p) => a + p.recv, 0) });
    }
    return out;
  });
  const barPeak = $derived(Math.max(1, ...bars.map(tot)));

  function share(list: TrafficItem[], it: TrafficItem): number {
    const top = Math.max(1, ...list.map(tot));
    return (tot(it) / top) * 100;
  }

  function appName(id: string): string {
    return id === '?' ? 'Программа не определена' : id;
  }
</script>

<div class="page-wrap">
  <header class="row">
    <div class="grow">
      <h1>Статистика</h1>
      <p class="muted sub">Сколько трафика прошло через VPN: по серверам и по программам. Прямой трафик не считается.</p>
    </div>
    <div class="seg">
      {#each periods as p}<button class:on={period === p.v} onclick={() => setPeriod(p.v)}>{p.l}</button>{/each}
    </div>
  </header>

  <Help id="traffic" title="Что здесь считается">
    <p>
      Только объём: сколько отправлено и скачано через каждый сервер и какой программой. Какие сайты вы открывали, HyRoute не записывает — ни здесь, ни в
      других файлах.
    </p>
    <p>Если у подписки есть лимит трафика, здесь видно, на что он уходит.</p>
  </Help>

  {#if error}<div class="note error">{error}</div>{/if}

  {#if r}
    <div class="cards">
      <div class="card stat">
        <span class="muted">Всего через VPN</span>
        <b>{fmtBytes(tot(r.total))}</b>
      </div>
      <div class="card stat">
        <span class="muted">Скачано</span>
        <b>{fmtBytes(r.total.recv)}</b>
      </div>
      <div class="card stat">
        <span class="muted">Отправлено</span>
        <b>{fmtBytes(r.total.sent)}</b>
      </div>
    </div>

    <div class="card chart">
      {#if tot(r.total) === 0}
        <p class="muted empty">
          {r.since ? 'За этот период через VPN ничего не прошло.' : 'Статистики пока нет: она появится, когда через VPN пойдёт трафик.'}
        </p>
      {:else}
        <div class="bars" class:dense={bars.length > 20}>
          {#each bars as b}
            <div class="bar" title="{b.label}: {fmtBytes(tot(b))} (скачано {fmtBytes(b.recv)}, отправлено {fmtBytes(b.sent)})">
              <div class="fill" style="height: {(tot(b) / barPeak) * 100}%">
                <div class="up" style="height: {tot(b) ? (b.sent / tot(b)) * 100 : 0}%"></div>
              </div>
            </div>
          {/each}
        </div>
        <div class="axis muted small">
          <span>{bars[0]?.label}</span>
          <span class="legend"><i class="k recv"></i>скачано <i class="k sent"></i>отправлено</span>
          <span>{bars[bars.length - 1]?.label}</span>
        </div>
      {/if}
    </div>

    <div class="lists">
      <div class="card">
        <h3><Icon name="server" size={16} /> По серверам</h3>
        {#each r.servers as it (it.id)}
          <div class="item">
            <span class="ellipsis" title={hide(it.name || it.id)}>{hide(it.name || it.id)}</span>
            <b>{fmtBytes(tot(it))}</b>
            <div class="meter"><div style="width: {share(r.servers, it)}%"></div></div>
          </div>
        {:else}
          <p class="muted small">Пусто.</p>
        {/each}
      </div>
      <div class="card">
        <h3><Icon name="app" size={16} /> По программам</h3>
        {#each r.apps as it (it.id)}
          <div class="item">
            <span class="ellipsis" title={it.id}>{appName(it.id)}</span>
            <b>{fmtBytes(tot(it))}</b>
            <div class="meter"><div style="width: {share(r.apps, it)}%"></div></div>
          </div>
        {:else}
          <p class="muted small">Пусто.</p>
        {/each}
        {#if r.appsFrom}<p class="muted small">По программам данные хранятся 3 месяца: здесь с {dayLabel(r.appsFrom)}.</p>{/if}
      </div>
    </div>

    <div class="row foot">
      <span class="muted small grow">
        {#if r.since}Статистика ведётся с {dayLabel(r.since)} {r.since.slice(0, 4)}. По дням хранится год, по программам — 3 месяца.{/if}
      </span>
      <button class="ghost" onclick={clear} disabled={!r.since}><Icon name="trash" size={15} />Очистить</button>
    </div>
  {/if}
</div>

<style>
  .page-wrap { display: grid; gap: 14px; }
  .sub { margin: 4px 0 0; }
  .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .stat { display: grid; gap: 4px; padding: 14px 16px; }
  .stat b { font-size: 22px; font-weight: 700; }
  .chart { padding: 16px; }
  .bars { display: flex; align-items: flex-end; gap: 4px; height: 160px; }
  .bars.dense { gap: 2px; }
  .bar { flex: 1; height: 100%; display: flex; align-items: flex-end; min-width: 0; }
  .fill { width: 100%; min-height: 1px; border-radius: 4px 4px 0 0; background: var(--accent); display: flex; flex-direction: column; overflow: hidden; }
  .up { width: 100%; background: color-mix(in srgb, var(--accent) 45%, var(--surface)); }
  .axis { display: flex; justify-content: space-between; gap: 10px; margin-top: 8px; }
  .legend { display: flex; align-items: center; gap: 6px; }
  .k { display: inline-block; width: 10px; height: 10px; border-radius: 2px; }
  .k.recv { background: var(--accent); }
  .k.sent { background: color-mix(in srgb, var(--accent) 45%, var(--surface)); margin-left: 8px; }
  .empty { margin: 30px 0; text-align: center; }
  .lists { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .lists h3 { display: flex; align-items: center; gap: 8px; margin: 0 0 10px; font-size: 14px; }
  .item { display: grid; grid-template-columns: 1fr auto; gap: 2px 10px; padding: 6px 0; font-size: 13px; }
  .meter { grid-column: 1 / -1; height: 4px; border-radius: 2px; background: var(--surface-2); }
  .meter div { height: 100%; border-radius: 2px; background: var(--accent); }
  .foot { align-items: center; }
  @media (max-width: 760px) {
    .cards, .lists { grid-template-columns: 1fr; }
  }
</style>
