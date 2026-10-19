<script lang="ts">
  // A QR code from the controller's matrix (rows of "0" and "1").
  let { rows, label }: { rows: string[]; label: string } = $props();
  const quiet = 4;
  let size = $derived(rows.length + quiet * 2);
  let path = $derived.by(() => {
    let d = '';
    rows.forEach((row, y) => {
      let x = 0;
      while (x < row.length) {
        if (row[x] !== '1') {
          x++;
          continue;
        }
        let n = 0;
        while (row[x + n] === '1') n++;
        d += `M${x + quiet} ${y + quiet}h${n}v1h-${n}z`;
        x += n;
      }
    });
    return d;
  });
</script>

<svg class="qr" viewBox="0 0 {size} {size}" role="img" aria-label={label} shape-rendering="crispEdges">
  <rect width={size} height={size} fill="#fff" />
  <path d={path} fill="#000" />
</svg>

<style>
  .qr { width: 220px; height: 220px; border-radius: var(--radius-sm); flex: none; }
</style>
