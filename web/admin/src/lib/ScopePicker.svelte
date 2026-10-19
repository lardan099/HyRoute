<script lang="ts">
  // The scope of a user: all servers, or the servers with one of the
  // chosen tags (those in use are offered; another one can be typed). The
  // controller normalizes and checks it.
  import type { Scope } from '../api';
  import { t } from '../i18n';

  let { scope = $bindable(), tags }: { scope: Scope; tags: string[] } = $props();

  let other = $state('');
  let chosen = $derived(scope.all ? [] : (scope.tags ?? []));
  // offered: the tags in use and those of the scope that no server has now.
  let offered = $derived([...new Set([...tags, ...chosen])].sort((a, b) => a.localeCompare(b)));

  const has = (tag: string) => chosen.some((c) => c.toLowerCase() === tag.toLowerCase());

  function toggle(tag: string) {
    scope = { tags: has(tag) ? chosen.filter((c) => c.toLowerCase() !== tag.toLowerCase()) : [...chosen, tag] };
  }

  function addOther() {
    const add = other
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s && !has(s));
    if (add.length) scope = { tags: [...chosen, ...add] };
    other = '';
  }
</script>

<div class="scope">
  <div class="seg" role="radiogroup" aria-label={t('scope.title')}>
    <button type="button" class:on={!!scope.all} onclick={() => (scope = { all: true })}>{t('scope.all')}</button>
    <button type="button" class:on={!scope.all} onclick={() => (scope = { tags: chosen })}>{t('scope.tags')}</button>
  </div>
  {#if !scope.all}
    <div class="tags">
      {#each offered as tag (tag)}
        <button type="button" class="chip" class:on={has(tag)} aria-pressed={has(tag)} onclick={() => toggle(tag)}>{tag}</button>
      {/each}
      <input
        type="text"
        maxlength="200"
        placeholder={t('scope.other')}
        aria-label={t('scope.other')}
        bind:value={other}
        onkeydown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            addOther();
          }
        }}
        onblur={addOther}
      />
    </div>
    <p class="small muted">{chosen.length ? t('scope.tagsHint') : t('scope.pick')}</p>
  {/if}
</div>

<style>
  .scope { display: flex; flex-direction: column; gap: 8px; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .chip { padding: 3px 10px; border-radius: 999px; font-size: 12.5px; }
  .chip.on { background: var(--accent-soft); color: var(--accent); border-color: var(--accent); }
  .tags input { width: 160px; }
  p { margin: 0; }
</style>
