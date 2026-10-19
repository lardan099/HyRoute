<script lang="ts">
  // The release notice of the overview (P4-07): «доступна vX.Y.Z» when
  // servers of the user's scope have an older Hysteria, and «Обновить
  // все» — a batch of updates over them, the canary first.
  import { onMount } from 'svelte';
  import { api, type HysteriaRelease, type Server } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import { can, canOn } from '../session.svelte';
  import { when } from './format';
  import BatchDialog from './BatchDialog.svelte';

  let { servers }: { servers: Server[] | null } = $props();

  let rel = $state<HysteriaRelease | null>(null);
  let open = $state(false);
  const shown = 6;

  onMount(async () => {
    try {
      rel = await api.hysteriaRelease();
    } catch {} // the notice is optional
  });

  let byId = $derived(Object.fromEntries((servers ?? []).map((s) => [s.id, s])));
  let targets = $derived((rel?.outdated ?? []).map((o) => byId[o.id]).filter((s): s is Server => !!s));
  // may: the user may update every one of them.
  let may = $derived(can('deploy') && !!rel && targets.length === rel.outdated.length && targets.every((s) => canOn(s, 'deploy')));
  let names = $derived(
    (rel?.outdated ?? [])
      .slice(0, shown)
      .map((o) => `${o.name} (${o.version})`)
      .join(', ') + ((rel?.outdated.length ?? 0) > shown ? ', …' : ''),
  );
</script>

{#if rel && rel.outdated.length}
  <section class="card release">
    <div class="grow col">
      <b>{t('release.available', { version: rel.target })}</b>
      <span class="small muted">{t('release.servers', { n: rel.outdated.length, list: names })}</span>
      <span class="small faint">
        {#if !rel.check}{t('release.off', { version: rel.target })}{:else if rel.checkedAt}{t('release.checked', { at: when(rel.checkedAt) })}{:else}{t('release.notChecked', { version: rel.target })}{/if}
      </span>
    </div>
    {#if may}
      <button class="primary" onclick={() => (open = true)}>{t('release.updateAll')}</button>
    {:else}
      <span class="small faint right">{t('release.noRight')}</span>
    {/if}
  </section>
{/if}

{#if open && rel}
  <BatchDialog action="maintain" servers={targets} version={rel.target} onclose={() => (open = false)} oncreated={(b) => go('batches', b.id)} />
{/if}

<style>
  .release { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
  .col { display: flex; flex-direction: column; gap: 3px; min-width: 240px; }
  .right { max-width: 280px; }
</style>
