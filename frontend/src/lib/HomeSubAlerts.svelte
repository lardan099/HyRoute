<script lang="ts">
  // Home notes for subscriptions whose traffic or term runs out
  // (Status.subAlerts minus the ones the user dismissed). HyRoute changes no
  // routing because of them; «Обновить» downloads the subscription (its
  // traffic goes direct, so it works even when the servers do not).
  import { api, errText, type SubAlert } from '../api';
  import { ackSubAlert, hide, subAlerts } from '../state.svelte';

  let { go }: { go: (page: string) => void } = $props();

  const alerts = $derived(subAlerts());
  let updating = $state('');
  let alertError = $state<{ id: string; text: string } | null>(null);
  // updated: the subscription «Обновить» just downloaded; the alert stays
  // while the service still reports the same, so the click is confirmed.
  let updated = $state('');

  async function update(a: SubAlert) {
    updating = a.id;
    alertError = null;
    updated = '';
    try {
      await api.UpdateSubscription(a.id);
      updated = a.id;
    } catch (e) {
      alertError = { id: a.id, text: errText(e) };
    } finally {
      updating = '';
    }
  }
</script>

{#each alerts as a (a.id)}
  <div class="note {a.level === 'out' ? 'error' : 'warn'} sub-alert" role="status">
    <div class="grow">
      Подписка «{hide(a.name)}»: {a.text}.{#if a.level === 'out'}
        Серверы этой подписки, скорее всего, уже не работают (сервис мог заменить их заглушками). Если сайт сервиса не
        открывается, отключите HyRoute: трафик к нему может идти через эти серверы. После продления нажмите «Обновить».{/if}
      {#if alertError?.id === a.id}<div class="err">{hide(alertError.text)}</div>{/if}
      {#if updated === a.id}<div class="muted small">Подписка обновлена. Предупреждение останется, пока сервис сообщает то же самое.</div>{/if}
    </div>
    <div class="acts">
      <button onclick={() => update(a)} disabled={updating !== ''}>{updating === a.id ? 'Обновление…' : 'Обновить'}</button>
      <button onclick={() => go('subs')}>Подписки</button>
      <button class="ghost" title="Не показывать, пока положение не изменится" onclick={() => ackSubAlert(a)}>Скрыть</button>
    </div>
  </div>
{/each}

<style>
  .sub-alert { display: flex; align-items: center; gap: 12px; margin: 0; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; flex: none; }
  .acts button { padding: 5px 10px; }
  .err { margin-top: 6px; font-weight: 600; }
  .small { margin-top: 6px; font-size: 12px; }
  @media (max-width: 900px) {
    .sub-alert { flex-direction: column; align-items: stretch; }
  }
</style>
