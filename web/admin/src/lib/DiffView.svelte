<script lang="ts">
  // A line diff with 3 lines of context around changes.
  import type { DiffLine } from '../api';

  let { lines }: { lines: DiffLine[] } = $props();
  const context = 3;

  type Row = DiffLine | { gap: number };
  let rows = $derived.by(() => {
    const keep = lines.map(() => false);
    lines.forEach((l, i) => {
      if (l.op === ' ') return;
      for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j++) keep[j] = true;
    });
    const out: Row[] = [];
    let skipped = 0;
    lines.forEach((l, i) => {
      if (keep[i]) {
        if (skipped) out.push({ gap: skipped });
        skipped = 0;
        out.push(l);
      } else skipped++;
    });
    if (skipped && out.length) out.push({ gap: skipped });
    return out;
  });
</script>

<div class="diff mono">
  {#each rows as r, i (i)}
    {#if 'gap' in r}
      <div class="gap">⋯ {r.gap}</div>
    {:else}
      <div class="l {r.op === '+' ? 'add' : r.op === '-' ? 'del' : ''}"><span class="op">{r.op}</span>{r.text}</div>
    {/if}
  {/each}
</div>

<style>
  .diff { background: var(--surface-2); border-radius: var(--radius-sm); padding: 8px 0; font-size: 12px; line-height: 1.55; overflow-x: auto; user-select: text; }
  .l { white-space: pre; padding: 0 12px; }
  .op { display: inline-block; width: 16px; color: var(--faint); }
  .add { background: color-mix(in srgb, var(--direct) 14%, transparent); }
  .del { background: color-mix(in srgb, var(--block) 12%, transparent); }
  .gap { color: var(--faint); padding: 2px 12px; }
</style>
