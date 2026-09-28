<script lang="ts">
  // "Проверить адрес": which rule would take a site or program and where it
  // would go. Useful when a site goes the wrong way.
  import { onMount } from 'svelte';
  import { api, errText, dnsRuleLabel, type DNSExplain, type Explanation, type Settings } from '../api';
  import { ui, profileName, hide } from '../state.svelte';
  import Icon from './Icon.svelte';

  // initial (conn-rules): prefilled from a connection and run at once, with
  // a note above the answer; onclose: a close button (in a dialog).
  let {
    current,
    initial,
    onclose,
  }: {
    current: () => Settings | null;
    initial?: { app: string; target: string; proto: string; port?: number; note: string };
    onclose?: () => void;
  } = $props();

  // svelte-ignore state_referenced_locally
  const init = initial;
  let app = $state(init?.app ?? '');
  let target = $state(init?.target ?? '');
  // ports: one destination port (a connection has one) and the protocol.
  let port = $state(init?.port ? String(init.port) : '');
  let proto = $state<'tcp' | 'udp'>(init?.proto === 'udp' ? 'udp' : 'tcp');
  // A prefilled address stays masked in Privacy mode until the field is
  // focused (then it is the user's to see and edit).
  let revealed = $state(!init);

  onMount(() => {
    if (init) run();
  });
  // The answer with the query it is for: the fields may have changed since.
  let ex = $state<(Explanation & { q: { app: string; target: string; proto: string } }) | null>(null);
  let error = $state('');
  let seq = 0;

  async function run() {
    const p = port.trim();
    if (p && (!/^\d+$/.test(p) || Number(p) < 1 || Number(p) > 65535)) {
      // An answer for another query (or one still on its way) goes too.
      error = 'Порт — число от 1 до 65535';
      ex = null;
      seq++;
      return;
    }
    const q = { app, target, proto };
    const my = ++seq;
    error = '';
    try {
      // A slow answer (the name may wait for DNS) must not replace a newer one.
      const res = await api.Explain({ ...q, port: Number(p) || 0 }, current());
      if (my === seq) ex = { ...res, q };
    } catch (e) {
      if (my === seq) error = errText(e);
    }
  }

  // The result line: what was checked (the port Go actually used).
  function queryText(e: NonNullable<typeof ex>): string {
    const what = hide(e.q.target.trim()) || e.q.app.trim();
    const udp = e.q.proto === 'udp' ? ', UDP' : '';
    if (!what) return e.port ? `Соединения на порт ${e.port}${udp}` : `Соединения${udp}`;
    return `${what}${e.port ? `, порт ${e.port}` : ''}${udp}`;
  }

  // dns: how the name resolves with the DNS settings. With a program and a
  // different answer through the Windows DNS client, both (p: the lead).
  function dnsText(d: DNSExplain, p = 'DNS'): string {
    const rule = (r?: string) => (!r || r === 'default' ? 'Всё остальное' : (dnsRuleLabel[r] ?? hide(r)));
    let cond = '';
    if (d.cond === 'app') cond = ` Так решает правило «${rule(d.rule)}» для программы: спрашивает служба DNS Windows, и программа неизвестна.`;
    else if (d.cond === 'proto') cond = ` Так решает правило «${rule(d.rule)}» для ${d.proto || 'некоторых портов'}.`;
    switch (d.route) {
      case 'tunnel':
        return `${p}: имя разрешается через ${profileName(d.profile ?? '')} (${d.upstream ?? ''}).${cond}`;
      case 'block':
        return `${p}: имя не разрешается — правило «${rule(d.rule)}».${cond}`;
      case 'upstream':
        return `${p}: напрямую через ${d.upstream ?? ''}.`;
      case 'addr':
        return `${p}: как обычно, через DNS-сервер сети: выше есть правило «${rule(d.rule)}» по IP/geoip, и через VPN адрес сайта мог бы оказаться другим.`;
      case 'server':
        return `${p}: адрес сервера Hysteria — всегда через DNS-сервер сети.`;
      case 'local':
        return `${p}: локальное имя — как обычно.`;
      case 'service':
        return `${p}: имя нужно Windows или самому HyRoute — всегда через DNS-сервер сети.`;
    }
    return `${p}: как обычно, через DNS-сервер сети.`;
  }

  function routeText(a: string, profile: string, group?: boolean, via?: string): string {
    if (a === 'direct') return 'напрямую';
    if (a === 'block') return 'будет заблокировано';
    // A group: its member of the moment (connected failover and latency).
    if (group) return `через группу «${profileName(profile)}»${via ? ` — сейчас через «${hide(via)}»` : ''}`;
    return profile ? `через ${profileName(profile)}` : 'через основной сервер (не выбран — соединение отклонится)';
  }
</script>

<details class="card check" open={!!init}>
  <summary
    ><Icon name="search" size={16} /> Проверить адрес <span class="muted small grow">— куда пойдёт сайт или программа и почему</span>{#if onclose}<button
        class="icon"
        aria-label="Закрыть"
        title="Закрыть"
        onclick={(e) => {
          e.preventDefault();
          onclose();
        }}><Icon name="x" size={16} /></button
      >{/if}</summary
  >
  <p class="muted small">
    Сайт идёт не туда? Введите его адрес (и, если нужно, программу) — HyRoute покажет, какое правило сработает. Можно указать порт и
    протокол.
  </p>
  <div class="row">
    {#if ui.privacy && !revealed}
      <input class="grow site" readonly value={hide(target)} aria-label="Сайт или IP" onfocus={() => (revealed = true)} />
    {:else}
      <input class="grow site" placeholder="Сайт или IP: youtube.com, ссылка, 1.2.3.4" bind:value={target} onkeydown={(e) => e.key === 'Enter' && run()} />
    {/if}
    <input class="grow prog" placeholder="Программа (необязательно): chrome" bind:value={app} onkeydown={(e) => e.key === 'Enter' && run()} />
    <input class="port" placeholder="Порт" inputmode="numeric" aria-label="Порт (необязательно)" bind:value={port} onkeydown={(e) => e.key === 'Enter' && run()} />
    <div class="seg" role="group" aria-label="Протокол">
      <button class:on={proto === 'tcp'} aria-pressed={proto === 'tcp'} onclick={() => (proto = 'tcp')}>TCP</button>
      <button class:on={proto === 'udp'} aria-pressed={proto === 'udp'} onclick={() => (proto = 'udp')}>UDP</button>
    </div>
    <button class="primary" onclick={run} disabled={!target.trim() && !app.trim() && !port.trim()}>Проверить</button>
  </div>
  {#if error}<div class="note error">{hide(error)}</div>{/if}
  {#if init?.note}<div class="note info small">{init.note}</div>{/if}
  {#if ex}
    <div class="result route-{ex.winner.action}">
      {queryText(ex)} → {routeText(ex.winner.action, ex.winner.profile, ex.group, ex.via)}
    </div>
    <div class="muted small">
      {#if ex.winner.index === -2}QUIC с неизвестным сайтом блокируется («Блокировать QUIC с неизвестным сайтом»).{:else if ex.winner.index < 0}Ни одно правило не подошло, сработало «Всё остальное».{:else}Сработало правило «{hide(ex.winner.name)}»: {hide(ex.winner.reason)}.{/if}
    </div>
    {#if ex.dns}
      {#if ex.dns.system}
        <div class="muted small">{dnsText(ex.dns, 'DNS, если программа спрашивает DNS сама')}</div>
        <div class="muted small">{dnsText(ex.dns.system, 'DNS через службу DNS Windows (так спрашивает большинство программ)')}</div>
      {:else}
        <div class="muted small">{dnsText(ex.dns)}</div>
      {/if}
      {#if ex.dns.noIPv6}<div class="muted small">DNS: IPv6-адреса для него не выдаются («Не пускать IPv6 в VPN»).</div>{/if}
    {/if}
    <details class="more">
      <summary class="small">Подробно по каждому правилу</summary>
      <ol>
        {#each ex.steps as st}
          <li class:win={st.winner}>
            <span class="mark">{st.winner ? '★' : st.matched ? '✓' : '·'}</span>
            <b>{st.index === -2 ? 'Блокировка QUIC' : st.index < 0 ? 'Всё остальное' : hide(st.name)}</b> <span class="muted">— {hide(st.reason)}</span>
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
  .port { width: 80px; flex: none; }
  /* In a narrow window the port and protocol wrap instead of the fields
     shrinking under their placeholders. */
  .site { min-width: 260px; }
  .prog { min-width: 200px; }
  .more { margin-top: 8px; }
  .more summary { cursor: pointer; color: var(--muted); }
  ol { list-style: none; padding: 0; margin: 8px 0; display: grid; gap: 3px; font-size: 12.5px; }
  .mark { display: inline-block; width: 18px; color: var(--faint); }
  .win { background: var(--surface-2); border-radius: 6px; }
  .win .mark { color: var(--warn); }
</style>
