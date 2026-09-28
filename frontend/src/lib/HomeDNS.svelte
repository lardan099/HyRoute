<script module lang="ts">
  import type { DNSHealth, Status } from '../api';

  // dns: Home's DNS notes while connected, in «Требует внимания»: a tunnel's
  // DNS server that does not answer, the encrypted direct DNS not working,
  // and the captive-portal pause («Разрешить имена напрямую на 5 минут»).

  function online(st: Status | null): boolean {
    return !!st && st.state !== 'disconnected' && !(st.state === 'error' && !st.stats);
  }

  function connected(st: Status | null, id?: string): boolean {
    return !!st?.tunnels.some((t) => t.state === 'connected' && (id === undefined || t.id === id));
  }

  // allTunnelsDown: the rules use tunnels and none of them works (not while
  // they start). Only then do names through VPN fail as a whole.
  export function allTunnelsDown(st: Status | null): boolean {
    return !!st && st.state === 'tunnel-down' && !st.noTunnel && st.tunnels.length > 0 && !connected(st);
  }

  // A tunnel that works while the DNS server behind it does not (a tunnel
  // that is down is on the hero already).
  function tunnelHealth(st: Status | null): DNSHealth[] {
    return online(st) ? (st?.dns?.health ?? []).filter((h) => h.via === 'tunnel' && connected(st, h.profile)) : [];
  }

  function directDown(st: Status | null): boolean {
    return online(st) && (st?.dns?.health ?? []).some((h) => h.via === 'direct');
  }

  function pauseLeft(st: Status | null): number {
    return online(st) ? (st?.dns?.pauseLeft ?? 0) : 0;
  }

  // canPause: the portal button, while every tunnel the rules use is down.
  export function canPause(st: Status | null): boolean {
    return online(st) && !!st?.dns?.byRules && !pauseLeft(st) && allTunnelsDown(st);
  }

  // dnsNotesShown: Home shows «Требует внимания» for these notes too.
  export function dnsNotesShown(st: Status | null): boolean {
    return tunnelHealth(st).length > 0 || directDown(st) || pauseLeft(st) > 0 || canPause(st);
  }
</script>

<script lang="ts">
  import { api, errText } from '../api';
  import { ui, hide, profileName } from '../state.svelte';

  let { go }: { go: (page: string) => void } = $props();

  let error = $state('');
  let busy = $state(false);

  const st = $derived(ui.status);
  const health = $derived(tunnelHealth(st));
  const direct = $derived(directDown(st));
  const left = $derived(pauseLeft(st));
  const pausable = $derived(canPause(st));

  function openDNS(e: Event) {
    e.preventDefault();
    ui.scrollTo = 'dns';
    go('settings');
  }

  async function run(f: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await f();
      ui.status = await api.Status();
    } catch (e) {
      error = errText(e);
    }
    busy = false;
  }
</script>

{#if error}<div class="note error">{hide(error)}</div>{/if}
{#each health as h}
  <div class="note warn">
    DNS-сервер для VPN ({h.upstream}) не отвечает через {profileName(h.profile ?? '')}: сайты через VPN не открываются.
    {#if ui.expert}<a href="#dns" onclick={openDNS}>Настройки DNS</a>{:else}Выберите другой DNS-сервер для VPN: «Настройки» → «DNS» в режиме
      «Для опытных».{/if}
  </div>
{/each}
{#if direct}<div class="muted small direct">Шифрование прямых DNS-запросов не работает: DNS-сервер не отвечает</div>{/if}
{#if left > 0}
  <div class="note info row">
    <span class="grow">Имена через VPN сейчас разрешаются напрямую, пока VPN недоступен — ещё {Math.ceil(left / 60)} мин.</span>
    <button class="link" disabled={busy} onclick={() => run(() => api.CancelDNSPause())}>Отменить</button>
  </div>
{:else if pausable}
  <div class="note warn">
    <button class="small" disabled={busy} onclick={() => run(() => api.PauseDNSTunnel())}>Разрешить имена напрямую на 5 минут</button>
    <p class="muted small">
      Для входа в сеть с авторизацией (гостиница, аэропорт): пока VPN недоступен, имена сайтов через VPN будут спрашиваться у DNS-сервера сети —
      он их увидит.
    </p>
  </div>
{/if}

<style>
  .note p { margin: 6px 0 0; }
  .direct { margin: 6px 0; }
</style>
