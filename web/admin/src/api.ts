// Client of the controller API (/api/v1). Every failure is an ApiError with
// the structured error of the server: message for people, details for the
// technical cause. Writes carry the CSRF token of the session.

import { t } from './i18n';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details = '',
    public data: Record<string, string> = {},
  ) {
    super(message);
  }
}

let csrfToken = '';
let onUnauthorized: () => void = () => {};

export function setCSRF(token: string) {
  csrfToken = token;
}

// whenUnauthorized is called when a request finds the session gone.
export function whenUnauthorized(fn: () => void) {
  onUnauthorized = fn;
}

export function asApiError(e: unknown): ApiError {
  return e instanceof ApiError ? e : new ApiError(0, 'unknown', t('error.unknown'), String(e));
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  let res: Response;
  try {
    res = await fetch('/api/v1' + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
  } catch (e) {
    throw new ApiError(0, 'network', t('error.network'), String(e));
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = data?.error;
    const e = new ApiError(res.status, err?.code ?? 'unknown', err?.message ?? t('error.unknown'), err?.details ?? '', err?.data ?? {});
    if (e.code === 'unauthorized' && !path.startsWith('/session')) onUnauthorized();
    throw e;
  }
  return data as T;
}

export interface Health {
  status: string;
  version: string;
  schemaVersion: number;
}

export type Role = 'owner' | 'admin' | 'operator' | 'readonly';

export interface User {
  id: number;
  username: string;
  role: Role;
  disabled: boolean;
  createdAt: string;
}

export interface SessionState {
  user: User;
  csrfToken: string;
}

export interface SessionInfo {
  id: number;
  userId: number;
  current: boolean;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip: string;
  userAgent: string;
}

export type AuthType = 'password' | 'key';
export type ServerRole = 'standalone' | 'entry' | 'relay' | 'exit';
export type ServerState = 'new' | 'deploying' | 'healthy' | 'degraded' | 'offline' | 'needs_attention';

export interface Server {
  id: number;
  name: string;
  tags: string[];
  country: string;
  location: string;
  host: string;
  sshPort: number;
  sshUser: string;
  authType: AuthType;
  role: ServerRole;
  notes: string;
  state: ServerState;
  createdAt: string;
  updatedAt: string;
  hasPassword: boolean;
  hasKey: boolean;
  hasKeyPassphrase: boolean;
  hostKey: HostKey | null;
}

export interface HostKey {
  type: string;
  fingerprint: string;
  trustedAt: string;
}

export interface Probe {
  user: string;
  root: boolean;
  sudo: boolean;
  hostname: string;
  kernel: string;
  arch: string;
}

export interface CheckResult {
  ok: boolean;
  probe: Probe;
  warning?: { code: string; message: string };
}

export type JobState =
  | 'queued'
  | 'connecting'
  | 'preflight'
  | 'downloading'
  | 'installing'
  | 'configuring'
  | 'firewall'
  | 'starting'
  | 'verifying'
  | 'rolling_back'
  | 'recovering'
  | 'completed'
  | 'failed';

export type StepState = 'pending' | 'running' | 'done' | 'skipped' | 'failed' | 'rolled_back';

export interface Job {
  id: number;
  kind: string;
  serverId: number;
  state: JobState;
  currentStep: string;
  params: Record<string, unknown>;
  attempt: number;
  errorMessage: string;
  errorDetails: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface JobStep {
  idx: number;
  name: string;
  phase: JobState;
  state: StepState;
  attempt: number;
  startedAt: string | null;
  finishedAt: string | null;
  error: string;
}

export interface JobDetail extends Job {
  steps: JobStep[];
}

export interface JobLog {
  seq: number;
  time: string;
  level: string;
  step: string;
  message: string;
}

export const jobEventsURL = (id: number) => `/api/v1/jobs/${id}/events`;

// ServerInput: credentials left undefined keep the stored ones on update.
export interface ServerInput {
  name: string;
  tags: string[];
  country: string;
  location: string;
  host: string;
  sshPort: number;
  sshUser: string;
  authType: AuthType;
  role: ServerRole;
  notes: string;
  password?: string;
  key?: string;
  keyPassphrase?: string;
}

export const api = {
  health: () => request<Health>('GET', '/health'),
  setupNeeded: () => request<{ needed: boolean }>('GET', '/setup'),
  setup: (token: string, username: string, password: string) => request<SessionState>('POST', '/setup', { token, username, password }),
  login: (username: string, password: string) => request<SessionState>('POST', '/session', { username, password }),
  session: () => request<SessionState>('GET', '/session'),
  logout: () => request<void>('DELETE', '/session'),
  sessions: (all = false) => request<SessionInfo[]>('GET', '/sessions' + (all ? '?all=1' : '')),
  revokeSession: (id: number) => request<void>('DELETE', `/sessions/${id}`),
  users: () => request<User[]>('GET', '/users'),
  createUser: (username: string, password: string, role: Role) => request<User>('POST', '/users', { username, password, role }),
  servers: () => request<Server[]>('GET', '/servers'),
  server: (id: number) => request<Server>('GET', `/servers/${id}`),
  createServer: (s: ServerInput) => request<Server>('POST', '/servers', s),
  updateServer: (id: number, s: ServerInput) => request<Server>('PATCH', `/servers/${id}`, s),
  deleteServer: (id: number) => request<void>('DELETE', `/servers/${id}`),
  checkServer: (id: number) => request<CheckResult>('POST', `/servers/${id}/check`),
  trustHostKey: (id: number, fingerprint: string, replace: boolean) => request<HostKey>('POST', `/servers/${id}/host-key`, { fingerprint, replace }),
  jobs: (serverId = 0) => request<Job[]>('GET', '/jobs' + (serverId ? `?server=${serverId}` : '')),
  job: (id: number) => request<JobDetail>('GET', `/jobs/${id}`),
  retryJob: (id: number) => request<Job>('POST', `/jobs/${id}/retry`),
};
