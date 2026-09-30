<script lang="ts">
  import { t } from '../i18n';

  let { title, text }: { title: string; text: string } = $props();
</script>

<h1>{title}</h1>
<div class="card soon">
  <h2>{t('soon.title')}</h2>
  <p class="muted">{text}</p>
</div>

<style>
  .soon { margin-top: 20px; max-width: 640px; }
  p { margin: 0; }
</style>
