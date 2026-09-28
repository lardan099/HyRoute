<script lang="ts">
  // The <option>s of a target select (rule, «Всё остальное», fallbacks,
  // proxies, the main server): the servers, then the server groups. A
  // current value that is neither (deleted) gets an option of its own.
  import { isGroupId, type GroupView } from '../api';
  import { ui, hide } from '../state.svelte';

  let { exclude = () => false, current = '' }: { exclude?: (id: string) => boolean; current?: string } = $props();

  const servers = $derived(ui.profiles.filter((p) => !exclude(p.id)));
  const groups = $derived(ui.groups.filter((g) => !exclude(g.id)));
  const dangling = $derived(!!current && !exclude(current) && !ui.profiles.some((p) => p.id === current) && !ui.groups.some((g) => g.id === current));
  const count = (g: GroupView) => g.members.length - g.missing;
</script>

{#each servers as p (p.id)}
  <option value={p.id}>{hide(p.name)}{p.sourceName ? ` · ${hide(p.sourceName)}` : ''}{p.missing ? ' — нет в подписке' : ''}</option>
{/each}
{#if groups.length}
  <optgroup label="Группы серверов">
    {#each groups as g (g.id)}<option value={g.id}>«{hide(g.name)}» (группа · {count(g)})</option>{/each}
  </optgroup>
{/if}
{#if dangling}<option value={current}>{isGroupId(current) ? 'удалённая группа' : 'удалённый сервер'}</option>{/if}
