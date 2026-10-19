<script lang="ts">
  // The client users of a server for those who manage clients (P4-04): add
  // one, give one a new password, remove one. Each change is an ordinary
  // config job that changes these users and nothing else; a generated
  // password is shown once. The links and QR codes are in «Подключение
  // клиентов».
  import { onDestroy, onMount } from 'svelte';
  import { api, asApiError, type ApiError, type ClientChange, type ClientSummary, type Job } from '../api';
  import { t } from '../i18n';
  import { go } from '../router.svelte';
  import Dialog from './Dialog.svelte';

  // revision: the current config's, the base of a change; onchanged: a
  // change was applied (the page reads the config again).
  let { serverId, revision, onchanged }: { serverId: number; revision: number; onchanged: () => void } = $props();

  type Op = 'add' | 'password' | 'remove';

  let summary = $state<ClientSummary | null>(null);
  let error = $state<ApiError | null>(null);
  let name = $state('');
  let busy = $state(false);
  let confirm = $state<{ op: 'password' | 'remove'; user: string } | null>(null);
  // last: the change in progress or just made, with the password shown
  // once; job: its job as last read.
  let last = $state<{ op: Op; change: ClientChange } | null>(null);
  let job = $state<Job | null>(null);
  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let gone = false;

  let running = $derived(!!job && job.state !== 'completed' && job.state !== 'failed');

  async function load() {
    try {
      summary = await api.clientSummary(serverId);
      error = null;
    } catch (e) {
      const err = asApiError(e);
      if (err.code !== 'no_config') error = err;
    }
  }
  onMount(load);
  onDestroy(() => {
    gone = true;
    clearTimeout(timer);
  });

  async function run(op: Op, user: string) {
    confirm = null;
    busy = true;
    error = null;
    copied = false;
    try {
      const call = op === 'add' ? api.addClient : op === 'password' ? api.clientPassword : api.removeClient;
      const change = await call(serverId, revision, user);
      last = { op, change };
      job = change.job;
      if (op === 'add') name = '';
      watch(change.job.id);
    } catch (e) {
      error = asApiError(e);
    } finally {
      busy = false;
    }
  }

  // watch follows the job until it ends; the list and the page are read
  // again once it applied the change.
  async function watch(id: number) {
    try {
      const j = await api.job(id);
      job = j;
      if (j.state === 'completed') {
        await load();
        onchanged();
        return;
      }
      if (j.state === 'failed') return;
    } catch {}
    if (!gone) timer = setTimeout(() => watch(id), 1000);
  }

  function add(e: Event) {
    e.preventDefault();
    if (name.trim()) run('add', name.trim());
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      copied = false;
    }
  }

  function dismiss() {
    // The password is not kept once its note is closed.
    last = null;
    job = null;
  }

  const opText = { add: 'clients.added', password: 'clients.rekeyed', remove: 'clients.removed' } as const;
</script>

<section class="card clients">
  <h2>{t('clients.title')}</h2>
  {#if error}<div class="note error">{error.message}</div>{/if}
  {#if summary && summary.auth !== 'userpass'}
    <p class="muted small">{t('clients.notUserpass')}</p>
  {:else if summary}
    <table>
      <tbody>
        {#each summary.users ?? [] as u (u)}
          <tr>
            <td class="mono">{u}</td>
            <td class="act">
              <button class="ghost" disabled={busy || running} onclick={() => (confirm = { op: 'password', user: u })}>{t('clients.newPassword')}</button>
              <button class="ghost danger" disabled={busy || running} onclick={() => (confirm = { op: 'remove', user: u })}>{t('common.delete')}</button>
            </td>
          </tr>
        {:else}
          <tr><td class="muted small">{t('clients.none')}</td></tr>
        {/each}
        {#each summary.links ?? [] as u (u)}
          <tr><td class="mono faint">{u}</td><td class="act small faint">{t('clients.linkUser')}</td></tr>
        {/each}
      </tbody>
    </table>
    <form class="row add" onsubmit={add}>
      <input type="text" maxlength="64" autocomplete="off" placeholder={t('clients.name')} aria-label={t('clients.name')} bind:value={name} />
      <button class="primary" type="submit" disabled={busy || running || !name.trim()}>{t('clients.add')}</button>
    </form>
    <p class="small faint">{t('clients.hint')}</p>
  {/if}

  {#if last}
    <div class="note {job?.state === 'failed' ? 'error' : job?.state === 'completed' ? 'ok' : 'info'}">
      {t(opText[last.op], { user: last.change.user })}
      {#if job?.state === 'failed'}{job.errorMessage}{:else if running}{t('clients.applying')}{:else}{t('clients.done')}{/if}
      <button class="link" onclick={() => go('deployments', last!.change.job.id)}>{t('srv.openJob', { id: last.change.job.id })}</button>
      {#if last.change.password}
        <p class="small">{t('clients.passwordOnce')}</p>
        <div class="row">
          <input class="grow mono" type="text" readonly value={last.change.password} aria-label={t('auth.password')} onfocus={(e) => e.currentTarget.select()} />
          <button onclick={() => copy(last!.change.password!)}>{copied ? t('users.copied') : t('users.copy')}</button>
        </div>
      {/if}
      {#if !running}<button class="link" onclick={dismiss}>{t('common.close')}</button>{/if}
    </div>
  {/if}
</section>

{#if confirm}
  <Dialog title={confirm.op === 'remove' ? t('clients.removeTitle', { user: confirm.user }) : t('clients.passwordTitle', { user: confirm.user })} onclose={() => (confirm = null)}>
    <p>{confirm.op === 'remove' ? t('clients.removeText') : t('clients.passwordText')}</p>
    {#snippet actions()}
      <button onclick={() => (confirm = null)}>{t('common.cancel')}</button>
      <button class="primary {confirm?.op === 'remove' ? 'danger-bg' : ''}" onclick={() => run(confirm!.op, confirm!.user)}>
        {confirm?.op === 'remove' ? t('common.delete') : t('clients.newPassword')}
      </button>
    {/snippet}
  </Dialog>
{/if}

<style>
  .clients { margin-bottom: 16px; }
  .clients h2 { margin: 0 0 10px; }
  table { width: 100%; max-width: 560px; }
  td { padding: 5px 8px; border-top: 1px solid var(--border); }
  .act { text-align: right; white-space: nowrap; }
  .add { margin-top: 12px; max-width: 560px; }
  .add input { flex: 1; }
  p { margin: 8px 0 0; }
  .note .row { margin-top: 6px; }
  .note .link { margin-left: 8px; }
</style>
