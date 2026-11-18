<script lang="ts">
  import { api, connFacts, dnsRuleLabel, errText, isGroupId, type ConnectionRoute, type Flow } from '../api';
  import { hide, profileName, targetText, ui } from '../state.svelte';

  let { flow }: { flow: Flow } = $props();
  let plan = $state<ConnectionRoute | null>(null);
  let error = $state('');
  // Polling updates byte counts every second. Recalculate only when facts
  // relevant to routing or the active configuration change.
  const facts = $derived(JSON.stringify(connFacts(flow)));
  const main = $derived(ui.status?.mainId);
  const ruleset = $derived(ui.status?.ruleset.token);
  $effect(() => {
    void main;
    void ruleset;
    void ui.settingsRev;
    const query = JSON.parse(facts);
    let current = true;
    plan = null;
    error = '';
    api.ConnectionRoute(query).then(
      (value) => { if (current) plan = value; },
      (e) => { if (current) error = errText(e); },
    );
    return () => { current = false; };
  });

  function ruleName(name: string): string {
    return name === 'default' ? 'Всё остальное' : dnsRuleLabel[name] ?? hide(name);
  }
  function target(id: string): string {
    return id === 'telegram-ws' ? 'Мост Telegram' : targetText(id);
  }
  function recorded(f: Flow): string {
    if (f.route === 'block' && /^(rst:|dropped:)/.test(f.outcome)) return 'Заблокировано';
    if (f.route === 'direct' && ['passed', 'relayed'].includes(f.outcome)) return 'Напрямую';
    if (f.route === 'tunnel' && (f.outcome === 'relayed' || (f.outcome === 'tunneled' && (f.sent > 0 || f.recv > 0)))) {
      if (f.profile === 'telegram-ws') return 'Мост Telegram · внешний выход неизвестен';
      if (!f.profile || isGroupId(f.profile)) return 'Через VPN · сервер неизвестен';
      return [profileName(f.profile), f.group && targetText(f.group), f.failover && 'запасной'].filter(Boolean).join(' · ');
    }
    if (/^(rst:|dropped:|aborted)/.test(f.outcome)) return 'Выход не подтверждён · ' + hide(f.outcome);
    return f.closed ? 'Выход не подтверждён' : 'Выход пока не подтверждён';
  }
</script>

<div class="comparison">
  <section>
    <h3>По правилам сейчас</h3>
    {#if error}<span class="bad-text">{hide(error)}</span>
    {:else if !plan}<span class="muted">Проверяем…</span>
    {:else if plan.note}{hide(plan.note)}
    {:else}
      <strong>{plan.action === 'direct' ? 'Напрямую' : plan.action === 'block' ? 'Блокировка' : plan.profile ? target(plan.profile) : 'Основной сервер не выбран'}</strong>
      {#if plan.rule}<div class="muted small">{ruleName(plan.rule)}</div>{/if}
      {#if plan.fallback?.length}<div class="muted small">Запасные по порядку: {plan.fallback.map(target).join(', ')}</div>{/if}
    {/if}
  </section>
  <section>
    <h3>По записи соединения</h3>
    <strong>{recorded(flow)}</strong>
    {#if flow.rule}<div class="muted small">{ruleName(flow.rule)}</div>{/if}
  </section>
</div>

<style>
  .comparison { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr)); gap: 8px; }
  section { padding: 8px 10px; border-radius: var(--radius-sm); background: var(--surface-2); overflow-wrap: anywhere; }
  h3 { margin: 0 0 4px; font-size: 12px; color: var(--muted); }
</style>
