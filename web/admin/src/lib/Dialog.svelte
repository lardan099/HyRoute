<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, onclose, children, actions }: { title: string; onclose: () => void; children: Snippet; actions?: Snippet } = $props();

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }

  // Only a click that starts on the backdrop closes the dialog: selecting
  // text in a field and letting go outside the dialog also ends in a click
  // on it, and what was typed would be lost.
  let downOnBackdrop = false;
</script>

<svelte:window onkeydown={key} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div
  class="backdrop"
  onmousedown={(e) => (downOnBackdrop = e.target === e.currentTarget)}
  onclick={(e) => downOnBackdrop && e.target === e.currentTarget && onclose()}
>
  <div class="dialog" role="dialog" aria-modal="true" aria-label={title}>
    <h2>{title}</h2>
    {@render children()}
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
  </div>
</div>
