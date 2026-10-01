<script lang="ts">
  // Fallback servers (or groups) of a "через VPN" route: tried in order
  // when the route's own server is down. "" is the main server.
  import { isGroupId } from '../api';
  import { ui, hide, mainTarget, mainText, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { value, primary, onchange, compact = false }: { value: string[]; primary: string; onchange: (v: string[]) => void; compact?: boolean } =
    $props();

  const main = $derived(mainTarget());
  // Labels as in the other server selects (TargetOptions): servers of
  // the same name from different subscriptions differ by the
  // subscription's name.
  const label = (id: string) => {
    if (!id) return `Основной${main ? ` — ${mainText(main)}` : ''}`;
    if (isGroupId(id)) return `«${profileName(id)}» (группа)`;
    const p = ui.profiles.find((x) => x.id === id);
    if (!p) return 'удалённый сервер';
    return `${hide(p.name)}${p.sourceName ? ` · ${hide(p.sourceName)}` : ''}${p.missing ? ' — нет в подписке' : ''}`;
  };
  // Servers resolved: "" is the main one, so "Основной" and the main
  // server by name are the same server.
  const key = (id: string) => id || main?.id || '';
  const own = $derived(key(primary));
  const taken = (id: string) => key(id) === own || value.some((v) => key(v) === key(id));
  // A copy of another server (the very same connection: duplicateOf)
  // would only repeat it as a reserve: the kept one is offered instead.
  const servers = $derived(ui.profiles.filter((p) => !p.duplicateOf && !taken(p.id)));
  const groups = $derived(ui.groups.filter((g) => !taken(g.id)));
  const offerMain = $derived(!taken(''));
  // Entries routing skips (the route's own server or a repeat), e.g. after
  // the main server changed: shown as unused rather than as a reserve, and
  // dropped when the route is saved (cleanSettings).
  const idle = (i: number) => key(value[i]) === own || value.slice(0, i).some((v) => key(v) === key(value[i]));
</script>

<div class="fb" class:compact>
  {#if !compact}<span class="muted">Запасные</span>{/if}
  <div class="list">
    {#each value as id, i (id + i)}
      <span
        class="chip"
        class:idle={idle(i)}
        title={idle(i) ? 'Не используется: это сервер маршрута или повтор. Уберётся при сохранении.' : 'Используется, если недоступны серверы левее'}
      >
        <span class="n">{i + 1}</span>
        <span class="ellipsis">{label(id)}</span>
        <button class="x" onclick={() => onchange(value.filter((_, j) => j !== i))} title="Убрать"><Icon name="x" size={12} /></button>
      </span>
    {/each}
    {#if offerMain || servers.length || groups.length}
      <select
        value="__add"
        onchange={(e) => {
          const v = (e.currentTarget as HTMLSelectElement).value;
          (e.currentTarget as HTMLSelectElement).value = '__add';
          if (v !== '__add') onchange([...value, v]);
        }}
      >
        <option value="__add" disabled>{value.length ? '+ ещё запасной' : '+ запасной сервер'}</option>
        {#if offerMain}<option value="">{label('')}</option>{/if}
        {#each servers as p (p.id)}<option value={p.id}>{label(p.id)}</option>{/each}
        {#if groups.length}
          <optgroup label="Группы серверов">
            {#each groups as g (g.id)}<option value={g.id}>{label(g.id)}</option>{/each}
          </optgroup>
        {/if}
      </select>
    {/if}
  </div>
</div>

<style>
  .fb { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .list { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; flex: 1; min-width: 0; }
  .chip { display: inline-flex; align-items: center; gap: 6px; max-width: 260px; padding: 3px 4px 3px 4px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); font-size: 13px; }
  .chip.idle { opacity: 0.55; text-decoration: line-through; }
  .n { width: 18px; height: 18px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; background: var(--accent-soft); color: var(--accent); flex: none; }
  .x { padding: 2px; background: none; }
  select { width: auto; max-width: 240px; }
  .compact select { font-size: 12.5px; }
</style>
