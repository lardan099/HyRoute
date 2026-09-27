<script lang="ts">
  // Fallback servers of a "через VPN" route: tried in order when the
  // route's own server is down. "" is the main server.
  import { ui, hide, mainProfile, profileName } from '../state.svelte';
  import Icon from './Icon.svelte';

  let { value, primary, onchange, compact = false }: { value: string[]; primary: string; onchange: (v: string[]) => void; compact?: boolean } =
    $props();

  const main = $derived(mainProfile());
  const label = (id: string) => (id ? profileName(id) : `Основной${main ? ` — ${hide(main.name)}` : ''}`);
  // Servers resolved: "" is the main one, so "Основной" and the main
  // server by name are the same server.
  const key = (id: string) => id || main?.id || '';
  const own = $derived(key(primary));
  const taken = (id: string) => key(id) === own || value.some((v) => key(v) === key(id));
  const options = $derived([{ id: '', name: label('') }, ...ui.profiles.map((p) => ({ id: p.id, name: p.name }))].filter((o) => !taken(o.id)));
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
    {#if options.length}
      <select
        value="__add"
        onchange={(e) => {
          const v = (e.currentTarget as HTMLSelectElement).value;
          (e.currentTarget as HTMLSelectElement).value = '__add';
          if (v !== '__add') onchange([...value, v]);
        }}
      >
        <option value="__add" disabled>{value.length ? '+ ещё запасной' : '+ запасной сервер'}</option>
        {#each options as o (o.id)}<option value={o.id}>{hide(o.name)}</option>{/each}
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
