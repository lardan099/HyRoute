// Who is logged in. The app shows the setup or login screen until status
// is 'ready'.

import { api, setCSRF, whenUnauthorized, type Permission, type User, type SessionState } from './api';

export const session = $state<{ status: 'loading' | 'setup' | 'login' | 'ready' | 'offline'; user: User | null; permissions: Permission[] }>({
  status: 'loading',
  user: null,
  permissions: [],
});

export function signedIn(s: SessionState) {
  setCSRF(s.csrfToken);
  session.user = s.user;
  session.permissions = s.permissions ?? [];
  session.status = 'ready';
}

export function signedOut() {
  setCSRF('');
  session.user = null;
  session.permissions = [];
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

// can: the role holds p. For a permission held on servers that is what to
// offer in general (adding a server, a new cascade); on a server ask
// canOn, which follows the user's scope as the controller reports it.
export const can = (p: Permission) => session.permissions.includes(p);
// canOn: the caller may do p on the server (its perms from the API).
export const canOn = (s: { perms?: Permission[] } | null | undefined, p: Permission) => !!s?.perms?.includes(p);
// allServers: the user reaches every server (the controller's own log is
// about all of them).
export const allServers = () => !!session.user?.scope?.all;
export const canManageUsers = (u: User | null) => !!u && session.permissions.includes('users');
// canForce: may delete a cascade without its unreachable server.
export const canForce = (u: User | null) => !!u && (u.role === 'owner' || u.role === 'admin');
// canBackup: copies of the database are the owner's.
export const canBackup = (u: User | null) => !!u && u.role === 'owner';
