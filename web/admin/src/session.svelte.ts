// Who is logged in. The app shows the setup or login screen until status
// is 'ready'.

import { api, setCSRF, whenUnauthorized, type User, type SessionState } from './api';

export const session = $state<{ status: 'loading' | 'setup' | 'login' | 'ready' | 'offline'; user: User | null }>({
  status: 'loading',
  user: null,
});

export function signedIn(s: SessionState) {
  setCSRF(s.csrfToken);
  session.user = s.user;
  session.status = 'ready';
}

export function signedOut() {
  setCSRF('');
  session.user = null;
  session.status = 'login';
}

whenUnauthorized(signedOut);

export async function loadSession() {
  try {
    signedIn(await api.session());
    return;
  } catch (e: any) {
    if (e?.code !== 'unauthorized') {
      session.status = 'offline';
      return;
    }
  }
  try {
    const { needed } = await api.setupNeeded();
    session.status = needed ? 'setup' : 'login';
  } catch {
    session.status = 'offline';
  }
}

export const canWrite = (u: User | null) => !!u && u.role !== 'readonly';
export const canManageUsers = (u: User | null) => !!u && (u.role === 'owner' || u.role === 'admin');
// canForce: may delete a cascade without its unreachable server.
export const canForce = (u: User | null) => !!u && (u.role === 'owner' || u.role === 'admin');
// canBackup: copies of the database are the owner's.
export const canBackup = (u: User | null) => !!u && u.role === 'owner';
