<script lang="ts">
  // The «По сервисам» tab of the routing editor: a switch per service of
  // the catalog (leave alone, direct, through the exit on a cascade entry,
  // an outbound of the server, block). Each change asks the controller to
  // build the group «По сервисам» into the draft; the editor then checks
  // the draft as after any edit (problems, changed routes, diff). A group
  // changed by hand is overwritten only after the admin agrees.
  import { onMount } from 'svelte';
  import { api, asApiError, type AclDocument, type ApiError, type ServicesState, type ServicesView } from '../api';
  import { t } from '../i18n';
  import Dialog from './Dialog.svelte';
  import { categories, offered, split, withChoice, type Dropped } from './services';

  let {
    serverId,
    acl,
    outbounds,
    onbuild,
    onshow,
  }: {
    serverId: number;
    acl: () => AclDocument;
    outbounds: string[];
    onbuild: (doc: AclDocument) => void;
    onshow: () => void;
  } = $props();

  let view = $state<ServicesView | null>(null);
  let st = $state<ServicesState | null>(null);
  let choices = $state<Record<string, string>>({});
  let dropped = $state<Dropped[]>([]);
  let error = $state<ApiError | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  // confirm is a choice that waits for the admin to agree to overwrite a
  // group changed by hand.
  let confirm = $state<{ next: Record<string, string>; changes: string[]; message: string } | null>(null);

  let acts = $derived(offered(outbounds, !!view?.cascade));
  let count = $derived(Object.keys(choices).length);

  onMount(async () => {
    try {
      view = await api.routingServices(serverId, acl());
      st = view.state;
      ({ choices, dropped } = split(view, offered(outbounds, !!view.cascade)));
    } catch (e) {
      error = asApiError(e);
    } finally {
      loading = false;
    }
  });

  function set(id: string, value: string) {
    if ((choices[id] ?? '') === value || busy) return;
    const next = withChoice(choices, id, value);
    if (st?.edited) {
      confirm = { next, changes: st.changes ?? [], message: '' };
      return;
    }
    build(next, false);
  }

  async function build(next: Record<string, string>, overwrite: boolean) {
    confirm = null;
    busy = true;
    try {
      const r = await api.routingServicesBuild(serverId, { acl: acl(), outbounds, choices: next, overwrite });
      choices = next;
      st = r.state;
      dropped = [];
      error = null;
      onbuild(r.acl);
    } catch (e) {
      const err = asApiError(e);
      // The draft's group changed since it was read: the controller says how.
      if (err.code === 'services_edited') confirm = { next, changes: [], message: err.message };
      else error = err;
    } finally {
      busy = false;
    }
  }
</script>

<div class="services">
  {#if loading}
    <p class="muted">{t('cfg.loading')}</p>
  {:else if view && st}
    <p class="small muted intro">{t('svc.intro')}</p>
    {#if view.noGeo}<div class="note warn small">{t('svc.noGeo')}</div>{/if}
    {#if view.ownGeo}<div class="note info small">{t('svc.ownGeo')}</div>{/if}
    {#if st.edited}
      <div class="note warn small">
        {t('svc.edited')}
        <ul>{#each st.changes ?? [] as c, i (i)}<li>{c}</li>{/each}</ul>
      </div>
    {/if}
    {#if dropped.length}
      <div class="note warn small">{t('svc.dropped', { list: dropped.map((d) => `${d.name} (${d.outbound})`).join(', ') })}</div>
    {/if}

    {#if view.sections.length}
      <div class="row bar small">
        <span class="grow muted">{view.cascade ? (view.cascade.hidden ? t('svc.exitNoteHidden') : t('svc.exitNote', { name: view.cascade.name })) : t('svc.noExit')}</span>
        <span class="muted">{t('svc.count', { n: count })}</span>
        {#if st.found}<button class="link" onclick={onshow}>{t('svc.show')}</button>{/if}
      </div>
    {/if}

    {#each view.sections as sec (sec.id)}
      <h3>{sec.name}</h3>
      <div class="list">
        {#each sec.services as c (c.id)}
          <div class="svc">
            <span class="name" title={categories(c)}>{c.name}</span>
            <div class="seg" role="radiogroup" aria-label={c.name}>
              {#each acts as a (a.value)}
                <button
                  role="radio"
                  aria-checked={(choices[c.id] ?? '') === a.value}
                  class:on={(choices[c.id] ?? '') === a.value}
                  class:block={a.value === 'reject'}
                  class:own={a.own}
                  disabled={busy}
                  onclick={() => set(c.id, a.value)}>{a.label}</button
                >
              {/each}
            </div>
          </div>
        {/each}
      </div>
    {/each}

    {#if view.hidden.length && !view.noGeo}
      <p class="small faint">{t('svc.hidden', { list: view.hidden.map((h) => h.name).join(', ') })}</p>
    {/if}
    {#if view.sections.length}<p class="small faint">{t('svc.order')}</p>{/if}
  {/if}
  {#if error}<div class="note error" role="alert">{error.message}</div>{/if}
</div>

{#if confirm}
  <Dialog title={t('svc.overwriteTitle')} onclose={() => (confirm = null)}>
    {#if confirm.message}
      <p>{confirm.message}</p>
    {:else}
      <p>{t('svc.overwriteText')}</p>
      <ul class="small">{#each confirm.changes as c, i (i)}<li>{c}</li>{/each}</ul>
      <p>{t('svc.overwriteNote')}</p>
    {/if}
    {#snippet actions()}
      <button onclick={() => (confirm = null)}>{t('common.cancel')}</button>
      <button class="primary" onclick={() => confirm && build(confirm.next, true)}>{t('svc.overwrite')}</button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .services { margin-top: 14px; }
  .intro { margin: 0 0 8px; }
  .bar { gap: 12px; margin: 10px 0 4px; flex-wrap: wrap; }
  h3 { margin: 16px 0 6px; font-size: 14px; }
  .list { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(460px, 100%), 1fr)); gap: 4px 18px; }
  .svc { display: flex; align-items: center; gap: 10px; padding: 4px 0; border-bottom: 1px solid var(--border); min-width: 0; }
  .name { flex: 1; min-width: 120px; }
  .seg { flex-wrap: wrap; }
  .seg button { padding: 3px 9px; font-size: 12.5px; }
  .seg button.on.block { color: var(--block); }
  .seg button.own { font-family: var(--mono, monospace); }
  ul { margin: 6px 0 0; padding-left: 18px; }
  p { margin: 6px 0 0; }
</style>
