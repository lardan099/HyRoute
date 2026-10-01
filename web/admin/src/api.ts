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
  data: Record<string, string>;
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

export interface PreflightCheck {
  id: string;
  level: 'ok' | 'warn' | 'fail';
  title: string;
  details?: string;
}

export interface PreflightReport {
  user: string;
  root: boolean;
  os: string;
  kernel: string;
  arch: string;
  hysteriaArch: string;
  cpus: number;
  memoryMiB: number;
  diskFreeMiB: number;
  firewall: string;
  github: boolean;
  hysteria: { installed: boolean; version?: string; unit?: string; active?: boolean };
  checks: PreflightCheck[];
  blocked: boolean;
}

export type TLSMode = 'self-signed' | 'acme';
export type DeploySource = 'auto' | 'direct' | 'relay';

// DeployParams are the choices of a deploy; passwords and the certificate
// are made by the controller (a redeploy keeps them).
export interface DeployParams {
  version?: string;
  port?: number;
  hopPorts?: string;
  tls: TLSMode;
  domain?: string;
  email?: string;
  challenge?: 'http' | 'tls';
  sni?: string;
  obfs?: boolean;
  masquerade?: string;
  source?: DeploySource;
  keepFirewall?: boolean;
  replace?: boolean;
}

export type ConfigSource = 'deploy' | 'import' | 'edit' | 'rollback';

// ServerConfig is the current config revision of a server: its summary,
// never the config itself.
export interface ServerConfig {
  revision: number;
  sha256: string;
  source: ConfigSource;
  fromRevision?: number;
  jobId: number;
  createdAt: string;
  meta: ConfigMeta;
}

// ConfigRevision is a revision in the config history (no config text).
export interface ConfigRevision {
  revision: number;
  source: ConfigSource;
  fromRevision?: number;
  meta: ConfigMeta;
  jobId?: number;
  by?: string;
  createdAt: string;
  current: boolean;
}

// ConfigComparison is what changes from one revision to another, secrets
// only as paths.
export interface ConfigComparison {
  from: number;
  to: number;
  diff: DiffLine[];
  secrets: string[];
}

// ConfigMeta is the non-secret summary of a revision.
export interface ConfigMeta {
  version?: string;
  listen?: string;
  ports?: string;
  tls?: string;
  pinSHA256?: string;
  sni?: string;
  obfs?: string;
  auth?: string;
}

export interface ImportFinding {
  id: string;
  level: 'warn' | 'info';
  title: string;
  details?: string;
}

// ImportReport is what an import found on a server (no secrets).
export interface ImportReport {
  unit: string;
  unitPath: string;
  binary: string;
  version: string;
  config: string;
  user: string;
  active: boolean;
  enabled: boolean;
  others?: string[];
  meta: ServerConfig['meta'];
  unknown?: string[];
  findings: ImportFinding[];
}

export interface ServiceStatus {
  unit: string;
  state: string;
  subState: string;
  active: boolean;
  enabled: boolean;
  pid?: number;
  restarts: number;
  uptimeSec: number;
  memoryMiB: number;
  version: string;
  ports: number[];
  system: {
    uptimeSec: number;
    load: [number, number, number];
    cpus: number;
    memTotalMiB: number;
    memAvailMiB: number;
    diskFreeMiB: number;
    checkedAt: string;
  };
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

// JournalEntry is a record of the Hysteria journal, redacted.
export interface JournalEntry {
  time: string;
  level: LogLevel;
  message: string;
}

export interface LogEntry {
  time: string;
  level: LogLevel;
  message: string;
  attrs?: string;
  serverId?: number;
  jobId?: number;
  kind?: string;
  step?: string;
}

export type ServiceAction = 'start' | 'stop' | 'restart';

// Hidden stands for a secret the editor does not show; keeping it keeps
// the current value.
export const HIDDEN = '[REDACTED]';

// MetricPoint is one monitoring point: MiB, percent, bytes per second.
export interface MetricPoint {
  t: string;
  cpu: number | null;
  memUsed: number;
  memTotal: number;
  diskUsed: number;
  diskTotal: number;
  load1: number;
  rx: number | null;
  tx: number | null;
}

export type MetricPeriod = '1h' | '6h' | '24h' | '48h' | '7d' | '30d';

export interface MetricSeries {
  period: MetricPeriod;
  step: number; // 0: samples; else seconds per average
  from: string;
  to: string;
  points: MetricPoint[];
}

export interface HealthCheck {
  at: string;
  status: ServerState;
  reason?: string;
  sshMs: number;
  service?: string;
  listening: boolean | null;
  udp: 'ok' | 'no_answer' | 'error' | 'skipped';
  udpMs?: number;
  egress?: string;
}

export interface ServerHealth {
  latest: HealthCheck | null;
  changes: HealthCheck[];
}

export interface LatestMetric extends MetricPoint {
  serverId: number;
}

// ConfigFields are the main settings of a server config.
export interface ConfigFields {
  listen: string;
  tls: '' | 'file' | 'acme';
  cert: string;
  key: string;
  sniGuard: string;
  acmeDomains: string[];
  acmeEmail: string;
  authType: string;
  authPassword: string;
  obfs: string;
  obfsPassword: string;
  masquerade: string;
  masqueradeUrl: string;
  rewriteHost: boolean;
  bandwidthUp: string;
  bandwidthDown: string;
  ignoreClientBandwidth: boolean;
  speedTest: boolean;
  disableUDP: boolean;
  udpIdleTimeout: string;
}

export interface ConfigView {
  revision: number;
  sha256: string;
  yaml: string;
  fields: ConfigFields;
  unknown: string[];
}

export interface DiffLine {
  op: ' ' | '-' | '+';
  text: string;
}

export interface ConfigProblem {
  field: string;
  message: string;
  warning?: boolean;
}

export interface ConfigCheck {
  yaml: string;
  fields: ConfigFields;
  problems: ConfigProblem[];
  diff: DiffLine[];
  secrets: string[];
  unknown: string[];
  ok: boolean;
}

export interface ConfigInput {
  revision: number;
  yaml: string;
  fields?: ConfigFields;
}

export interface ClientSummary {
  name: string;
  host: string;
  ports: string;
  sni?: string;
  insecure: boolean;
  pinSHA256?: string;
  obfs?: string;
  auth: string;
  users?: string[];
  warnings: string[];
}

export interface ClientProfile extends ClientSummary {
  user?: string;
  uri: string;
  compat: string;
  config: string;
  qr: string[];
  qrCompat: string[];
}

export const journalURL = (serverId: number, lines = 200) => `/api/v1/servers/${serverId}/journal?follow=1&lines=${lines}`;

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
  // jobs lists jobs, newest first (limit 0: the controller's default).
  jobs: (serverId = 0, limit = 0) => {
    const q = new URLSearchParams();
    if (serverId) q.set('server', String(serverId));
    if (limit) q.set('limit', String(limit));
    const qs = q.toString();
    return request<Job[]>('GET', '/jobs' + (qs ? '?' + qs : ''));
  },
  job: (id: number) => request<JobDetail>('GET', `/jobs/${id}`),
  retryJob: (id: number) => request<Job>('POST', `/jobs/${id}/retry`),
  startDeploy: (serverId: number, p: DeployParams) => request<Job>('POST', `/servers/${serverId}/deploy`, p),
  startImport: (serverId: number) => request<Job>('POST', `/servers/${serverId}/import`),
  serviceStatus: (serverId: number) => request<ServiceStatus>('GET', `/servers/${serverId}/status`),
  serviceAction: (serverId: number, action: ServiceAction) => request<Job>('POST', `/servers/${serverId}/service/${action}`),
  journal: (serverId: number, lines = 500) => request<JournalEntry[]>('GET', `/servers/${serverId}/journal?lines=${lines}`),
  logs: (p: { source: 'controller' | 'jobs'; server?: number; level?: string; q?: string; limit?: number }) => {
    const q = new URLSearchParams({ source: p.source });
    if (p.server) q.set('server', String(p.server));
    if (p.level) q.set('level', p.level);
    if (p.q) q.set('q', p.q);
    if (p.limit) q.set('limit', String(p.limit));
    return request<LogEntry[]>('GET', '/logs?' + q.toString());
  },
  configEdit: (serverId: number) => request<ConfigView>('GET', `/servers/${serverId}/config/edit`),
  renderConfig: (serverId: number, input: ConfigInput) => request<ConfigCheck>('POST', `/servers/${serverId}/config/render`, input),
  applyConfig: (serverId: number, input: ConfigInput) => request<Job>('POST', `/servers/${serverId}/config/apply`, input),
  serverMetrics: (serverId: number, period: MetricPeriod) => request<MetricSeries>('GET', `/servers/${serverId}/metrics?period=${period}`),
  serverHealth: (serverId: number) => request<ServerHealth>('GET', `/servers/${serverId}/health`),
  latestMetrics: () => request<LatestMetric[]>('GET', '/metrics/latest'),
  configRevisions: (serverId: number) => request<ConfigRevision[]>('GET', `/servers/${serverId}/config/revisions`),
  configRevision: (serverId: number, rev: number) => request<ConfigView>('GET', `/servers/${serverId}/config/revisions/${rev}`),
  compareConfigs: (serverId: number, from: number, to: number) =>
    request<ConfigComparison>('GET', `/servers/${serverId}/config/compare?from=${from}&to=${to}`),
  rollbackConfig: (serverId: number, base: number, revision: number) =>
    request<Job>('POST', `/servers/${serverId}/config/rollback`, { base, revision }),
  clientSummary: (serverId: number) => request<ClientSummary>('GET', `/servers/${serverId}/client`),
  clientProfile: (serverId: number, user = '') =>
    request<ClientProfile>('POST', `/servers/${serverId}/client/reveal`, { user }),
  serverConfig: (serverId: number) => request<ServerConfig>('GET', `/servers/${serverId}/config`),
  startPreflight: (serverId: number, udpPort = 443) => request<Job>('POST', `/servers/${serverId}/preflight`, { udpPort }),
};
