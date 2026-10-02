<script lang="ts">
  // Pick a rule template (or an imported file) and where its rules go: at
  // the top, at the end or instead of the server's rules; its outbounds the
  // server lacks can come along (their passwords are typed on the server).
  import { untrack } from 'svelte';
  import type { RoutingTemplate } from '../api';
  import { t, type Key } from '../i18n';
  import { bad, protoPort, type TemplateMode as Mode } from './acl';
  import Dialog from './Dialog.svelte';

  let {
    templates,
    title,
    onapply,
    onclose,
  }: {
    templates: RoutingTemplate[];
    title: string;
    onapply: (tpl: RoutingTemplate, mode: Mode, withOutbounds: boolean) => void;
    onclose: () => void;
  } = $props();

  let id = $state(untrack(() => templates[0]?.id ?? ''));
  let mode = $state<Mode>('top');
  let withOutbounds = $state(true);
  let tpl = $derived(templates.find((x) => x.id === id) ?? null);
</script>

<Dialog {title} {onclose}>
  <div class="form">
    {#if templates.length > 1}
      <label>
        <span>{t('tpl.template')}</span>
        <select bind:value={id}>
          {#each templates as x (x.id)}<option value={x.id}>{x.name}{x.builtin ? '' : ' · ' + t('tpl.preset')}</option>{/each}
        </select>
      </label>
    {/if}
    {#if tpl}
      {#if tpl.description}<p class="small muted">{tpl.description}</p>{/if}
      <ol class="rules mono small">
        {#each tpl.acl.rules ?? [] as r, i (i)}
          <li class:off={r.off}>{bad(r) ? r.text : `${r.outbound}(${r.address}${protoPort(r) ? ', ' + protoPort(r) : ''}${r.hijack ? ', ' + r.hijack : ''})`}{#if r.comment}<span class="faint"> # {r.comment}</span>{/if}</li>
        {/each}
      </ol>
      {#if tpl.outbounds?.length}
        <label class="check"><input type="checkbox" bind:checked={withOutbounds} /> {t('tpl.outbounds', { list: tpl.outbounds.map((o) => o.name).join(', ') })}</label>
      {/if}
      <div class="seg" role="radiogroup" aria-label={t('tpl.where')}>
        <button type="button" class:on={mode === 'top'} onclick={() => (mode = 'top')}>{t('tpl.top')}</button>
        <button type="button" class:on={mode === 'bottom'} onclick={() => (mode = 'bottom')}>{t('tpl.bottom')}</button>
        <button type="button" class:on={mode === 'replace'} onclick={() => (mode = 'replace')}>{t('tpl.replace')}</button>
      </div>
      <p class="hint">{t(`tpl.hint.${mode}` as Key)}</p>
    {/if}
  </div>
  {#snippet actions()}
    <button type="button" onclick={onclose}>{t('common.cancel')}</button>
    <button class="primary" disabled={!tpl} onclick={() => tpl && onapply(tpl, mode, withOutbounds)}>{t('tpl.apply')}</button>
  {/snippet}
</Dialog>

<style>
  .form { display: flex; flex-direction: column; gap: 12px; min-width: min(560px, 82vw); }
  label:not(.check) { display: flex; flex-direction: column; gap: 5px; }
  label span { color: var(--muted); font-size: 12.5px; }
  .rules { margin: 0; padding: 8px 8px 8px 30px; background: var(--surface-2); border-radius: var(--radius-sm); max-height: 260px; overflow: auto; }
  .rules li.off { opacity: 0.55; }
  .seg { align-self: flex-start; }
  .hint { color: var(--faint); font-size: 12px; margin: -4px 0 0; }
  p { margin: 0; }
</style>
