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

// requestText is a GET whose answer is text (a file to save).
async function requestText(path: string): Promise<string> {
  let res: Response;
  try {
    res = await fetch('/api/v1' + path, { credentials: 'same-origin' });
  } catch (e) {
    throw new ApiError(0, 'network', t('error.network'), String(e));
  }
  if (!res.ok) {
    const err = (await res.json().catch(() => null))?.error;
    throw new ApiError(res.status, err?.code ?? 'unknown', err?.message ?? t('error.unknown'), err?.details ?? '', err?.data ?? {});
  }
  return res.text();
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
  // hopInterval of the client links, seconds (0: the client's default).
  hopInterval: number;
  // chains are the cascades the server is a node of.
  chains: { id: number; name: string; state: LinkState }[];
}

// PortsInput changes the ports of a server (an apply job) and the hop
// interval of its client links (saved at once).
export interface PortsInput {
  base: number;
  ports: string[];
  // host: '' every address (IPv4 and IPv6), '0.0.0.0' IPv4 only, or an
  // address of the server.
  host: string;
  hopInterval: number;
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
  // The other servers the job changes (a cascade link: entry and exit).
  servers: number[];
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
export type DeploySource = 'auto' | 'direct' | 'relay' | 'node';

// The Hysteria version HyRoute deploys unless asked otherwise (its hashes
// are pinned in hyrelease).
export const defaultHysteria = 'v2.12.3';

export type MaintainOp = 'upgrade' | 'reinstall';

export interface MaintainParams {
  op: MaintainOp;
  version?: string;
  source?: DeploySource;
  // via: the server that provides the binary (source 'node').
  via?: number;
}

export type ACMEChallenge = 'http' | 'tls' | 'dns';
export type MasqType = '' | 'proxy' | 'file' | 'string';
export type OutboundType = '' | 'direct' | 'socks5' | 'http';

// DeployParams are the choices of a deploy (deploy.Params); passwords and
// the certificate are made by the controller (a redeploy keeps them). A
// missing advanced value leaves Hysteria's default.
export interface DeployParams {
  version?: string;
  port?: number;
  hopPorts?: string;
  tls: TLSMode;
  domain?: string;
  email?: string;
  challenge?: ACMEChallenge;
  dnsProvider?: string;
  sni?: string;
  obfs?: boolean;
  // masquerade: the site of the proxy masquerade.
  masquerade?: string;
  masq?: { type?: MasqType; dir?: string; text?: string; status?: number; tcp?: boolean };
  // auth: '' keeps the current config's (a new server: a password).
  auth?: '' | 'password' | 'userpass';
  users?: string[];
  bandwidth?: { upMbps?: number; downMbps?: number; ignoreClient?: boolean };
  quic?: { streamWindowMB?: number; connWindowMB?: number; idleTimeout?: number; maxStreams?: number; disableMTUDiscovery?: boolean };
  udp?: { disable?: boolean; idleTimeout?: number };
  sniff?: { enable?: boolean; timeout?: number; rewriteDomain?: boolean; tcpPorts?: string; udpPorts?: string };
  outbound?: { type?: OutboundType; mode?: string; bindIPv4?: string; bindIPv6?: string; bindDevice?: string; addr?: string; user?: string };
  // preset: sections of a preset laid over the config (not ports, obfs);
  // name: the preset's in a job's params (Submit reads it again by id).
  preset?: { id: number; sections: PresetSection[]; name?: string };
  source?: DeploySource;
  via?: number;
  keepFirewall?: boolean;
  replace?: boolean;
  // overwrite: replace a current config no deploy made (edited, rolled
  // back, imported); without it the controller answers 409 config_changed.
  overwrite?: boolean;
}

// DeploySecrets are what only the admin knows (deploy.Input): sealed with
// the job, never in its params. An empty value keeps the current one.
export interface DeploySecrets {
  dns?: Record<string, string>;
  outPassword?: string;
}

// dnsProviders are the DNS providers Hysteria issues certificates with and
// the keys of their settings (deploy.DNSProviders).
export const dnsProviders: Record<string, { key: string; required: boolean }[]> = {
  cloudflare: [{ key: 'cloudflare_api_token', required: true }],
  duckdns: [
    { key: 'duckdns_api_token', required: true },
    { key: 'duckdns_override_domain', required: false },
  ],
  gandi: [{ key: 'gandi_api_token', required: true }],
  godaddy: [{ key: 'godaddy_api_token', required: true }],
  namecheap: [
    { key: 'namecheap_api_user', required: true },
    { key: 'namecheap_api_key', required: true },
    { key: 'namecheap_api_endpoint', required: false },
    { key: 'namecheap_client_ip', required: false },
  ],
  njalla: [{ key: 'njalla_api_token', required: true }],
  porkbun: [
    { key: 'porkbun_api_key', required: true },
    { key: 'porkbun_api_secret_key', required: true },
  ],
  vultr: [{ key: 'vultr_api_token', required: true }],
};

export type ConfigSource = 'deploy' | 'import' | 'edit' | 'rollback' | 'rotate' | 'cascade' | 'geo';

// Rotation: what gets new values (users: of userpass auth; none: all).
export interface Rotation {
  auth: boolean;
  users?: string[];
  obfs: boolean;
  cert: boolean;
}

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
  // installed: the Hysteria version of the server's installation (an
  // upgrade changes it, not the revision's meta).
  installed?: string;
  // keepFirewall: the deploy was told to leave the firewall alone.
  keepFirewall?: boolean;
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
  // findings: null in the reports of earlier builds without findings.
  findings: ImportFinding[] | null;
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
  // managed: HyRoute installed it (a reinstall is possible).
  managed: boolean;
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

export type TrafficPeriod = '24h' | '7d' | '30d' | '90d';

// Traffic of a server's Hysteria users: tx is the client's upload, rx its
// download.
export interface ServerTraffic {
  period: TrafficPeriod;
  from: string;
  to: string;
  enabled: boolean;
  hours: { t: string; tx: number; rx: number }[];
  users: { user: string; tx: number; rx: number }[];
}

export interface TrafficOnline {
  at: string;
  users: { user: string; connections: number }[];
}

export interface TrafficStream {
  state: string;
  user: string;
  connection: number;
  stream: number;
  addr: string;
  hookedAddr: string;
  tx: number;
  rx: number;
  since: string;
  lastActive: string;
}

export interface TrafficStreams {
  at: string;
  total: number;
  streams: TrafficStream[];
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
  trafficStats: boolean;
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

export type PresetSection = 'ports' | 'obfs' | 'masquerade' | 'speed' | 'quic' | 'udp' | 'resolver' | 'sniff' | 'acl' | 'outbounds';

// AclRule is one routing rule (acl.Rule): outbound(address[, proto/port[,
// hijack]]). text is the line as read: the controller writes it back while
// the fields say the same; a line Hysteria cannot read has only text.
export interface AclRule {
  outbound: string;
  address: string;
  proto?: string;
  port?: string;
  hijack?: string;
  comment?: string;
  group?: string;
  off?: boolean;
  text?: string;
  before?: string[];
}

export interface AclDocument {
  rules: AclRule[] | null;
  tail?: string[];
}

// AclProblem: rule is the index in the rules (-1: the ACL as a whole); fix
// are rules to add at the top.
export interface AclProblem {
  rule: number;
  line?: number;
  level: 'error' | 'warn';
  code: string;
  message: string;
  detail?: string;
  other?: number;
  fix?: AclRule[];
}

// RoutingOutbound: a password the editor got as HIDDEN and sends back so
// keeps the current one; from is the current name (rules follow a rename).
export interface RoutingOutbound {
  name: string;
  from?: string;
  type: string; // direct, socks5, http
  direct?: { mode?: string; bindIPv4?: string; bindIPv6?: string; bindDevice?: string; fastOpen?: boolean };
  socks5?: { addr: string; username?: string; password?: string };
  http?: { url: string; password?: string; insecure?: boolean };
  locked?: boolean;
}

export interface RoutingResolver {
  type: 'system' | 'udp' | 'tcp' | 'tls' | 'https' | string;
  addr?: string;
  timeout?: string;
  sni?: string;
  insecure?: boolean;
}

export interface RoutingView {
  revision: number;
  acl: AclDocument;
  file?: string;
  outbounds: RoutingOutbound[];
  resolver: RoutingResolver;
  cascade?: { id: number; name: string };
  problems: AclProblem[];
}

export interface AclRequest {
  host: string;
  ips?: string[];
  proto?: string;
  port: number;
}

export interface AclVerdict {
  rule: number;
  outbound: string;
  hijack?: string;
  reason: string;
  unknown?: number[];
}

export interface RoutingInput {
  base: number;
  acl: AclDocument;
  keepFile?: boolean;
  outbounds: RoutingOutbound[];
  resolver: RoutingResolver;
  requests?: AclRequest[];
}

export interface RoutingPreview extends ConfigCheck {
  acl: AclDocument;
  rules: AclProblem[];
  changes: { request: AclRequest; before: AclVerdict; after: AclVerdict }[];
  ok: boolean;
  same: boolean;
}

export interface RoutingFile {
  path: string;
  acl: AclDocument;
  problems: AclProblem[];
}

// RoutingTemplate is a set of rules (and outbounds without passwords) to
// put at the top, at the end or instead of a server's rules.
export interface RoutingTemplate {
  id: string;
  name: string;
  description?: string;
  acl: AclDocument;
  outbounds?: RoutingOutbound[];
  resolver?: RoutingResolver;
  builtin?: boolean;
}

// ChainTemplate is a cascade without servers and secrets: the link's
// settings and, optionally, the entry's rules and resolver.
export interface ChainTemplate {
  format: string;
  version: number;
  id?: string;
  name: string;
  description?: string;
  builtin?: boolean;
  link: LinkParams;
  entry?: { acl: AclDocument; outbounds?: RoutingOutbound[]; resolver?: RoutingResolver };
}

export interface GeoInfo {
  release: string;
  files: { name: string; sha256: string; size: number; url: string }[];
  at: string;
  checkedAt: string;
}

export interface ServerGeo {
  release: string;
  at?: string;
  latest: boolean;
  paths: boolean;
  rules: boolean;
}

// presetSections in config order; deploySections are those a deploy takes
// (the form sets the ports and the obfuscation).
export const presetSections: PresetSection[] = ['ports', 'obfs', 'masquerade', 'speed', 'quic', 'udp', 'resolver', 'sniff', 'acl', 'outbounds'];
export const deploySections: PresetSection[] = ['masquerade', 'speed', 'quic', 'udp', 'resolver', 'sniff', 'acl', 'outbounds'];

// ==== cascades (Phase 3) ====

export type LinkState = 'new' | 'linking' | 'active' | 'stale' | 'unlinking' | 'failed';

// LinkParams are a link's settings (no secrets).
export interface LinkParams {
  localPort?: number;
  up?: string;
  down?: string;
  noUdp?: boolean;
  checkTarget?: string;
}

// LinkCheck is one check of a link from its entry.
export interface LinkCheck {
  at: string;
  status: ServerState;
  reason: string;
  service: string;
  handshakeMs: number;
  tcpMs: number;
}

export interface ChainNode {
  serverId: number;
  name: string;
  role: ServerRole;
}

export interface ChainLink {
  idx: number;
  from: number;
  to: number;
  state: LinkState;
  params: LinkParams;
  updatedAt: string;
  check: LinkCheck | null;
}

// Chain is a cascade: servers in order, entry first, and the links.
export interface Chain {
  id: number;
  name: string;
  notes: string;
  state: LinkState;
  health: ServerState | '';
  egress: string;
  nodes: ChainNode[];
  links: ChainLink[];
  createdAt: string;
  updatedAt: string;
}

// Preset is a part of a server config without secrets and addresses.
export interface Preset {
  id: number;
  name: string;
  sections: PresetSection[];
  notes: string[];
  config: string;
  createdAt: string;
  updatedAt: string;
}

export interface PresetCheck extends ConfigCheck {
  newObfs: boolean;
}

export interface PresetApply {
  base: number;
  preset: number;
  sections: PresetSection[];
}

// TuningSetting is a kernel parameter HyRoute offers to set.
export interface TuningSetting {
  key: string;
  group: 'udp' | 'tcp';
  current: string;
  want: string;
  done: boolean;
  supported: boolean;
  why?: string;
  inFile: boolean;
}

// TuningState is the kernel's settings for Hysteria and, beside them, the
// congestion settings of Hysteria's config (not the kernel's).
export interface TuningState {
  kernel: string;
  available: string[];
  bbr: boolean;
  file: string;
  settings: TuningSetting[];
  quic: { type: string; profile: string };
  brutal: { up: string; down: string; ignoreClient: boolean };
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
  // users: the clients; links: the users of cascade links into the
  // server (the entry logs in with them; no client link, no rotation).
  users?: string[];
  links?: string[];
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
// The role is not entered: it follows the server's place in cascades.
export interface ServerInput {
  name: string;
  tags: string[];
  country: string;
  location: string;
  host: string;
  sshPort: number;
  sshUser: string;
  authType: AuthType;
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
  startDeploy: (serverId: number, p: DeployParams, secrets?: DeploySecrets) =>
    request<Job>('POST', `/servers/${serverId}/deploy`, secrets ? { ...p, secrets } : p),
  startImport: (serverId: number) => request<Job>('POST', `/servers/${serverId}/import`),
  startMaintain: (serverId: number, p: MaintainParams) => request<Job>('POST', `/servers/${serverId}/maintain`, p),
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
  serverTraffic: (serverId: number, period: TrafficPeriod) => request<ServerTraffic>('GET', `/servers/${serverId}/traffic?period=${period}`),
  trafficOnline: (serverId: number) => request<TrafficOnline>('GET', `/servers/${serverId}/traffic/online`),
  trafficStreams: (serverId: number) => request<TrafficStreams>('GET', `/servers/${serverId}/traffic/streams`),
  latestMetrics: () => request<LatestMetric[]>('GET', '/metrics/latest'),
  configRevisions: (serverId: number) => request<ConfigRevision[]>('GET', `/servers/${serverId}/config/revisions`),
  configRevision: (serverId: number, rev: number) => request<ConfigView>('GET', `/servers/${serverId}/config/revisions/${rev}`),
  compareConfigs: (serverId: number, from: number, to: number) =>
    request<ConfigComparison>('GET', `/servers/${serverId}/config/compare?from=${from}&to=${to}`),
  rollbackConfig: (serverId: number, base: number, revision: number) =>
    request<Job>('POST', `/servers/${serverId}/config/rollback`, { base, revision }),
  rotateConfig: (serverId: number, base: number, r: Rotation) => request<Job>('POST', `/servers/${serverId}/config/rotate`, { base, ...r }),
  setPorts: (serverId: number, p: PortsInput) => request<{ job: Job | null }>('POST', `/servers/${serverId}/ports`, p),
  tuning: (serverId: number) => request<TuningState>('GET', `/servers/${serverId}/tuning`),
  startTuning: (serverId: number, keys: string[]) => request<Job>('POST', `/servers/${serverId}/tuning`, { keys }),
  presets: () => request<Preset[]>('GET', '/presets'),
  createPreset: (name: string, from: { serverId?: number; from?: number }) => request<Preset>('POST', '/presets', { name, ...from }),
  renamePreset: (id: number, name: string) => request<Preset>('PATCH', `/presets/${id}`, { name }),
  deletePreset: (id: number) => request<void>('DELETE', `/presets/${id}`),
  exportPreset: (id: number) => request<unknown>('GET', `/presets/${id}/export`),
  importPreset: (data: string) => request<Preset>('POST', '/presets/import', { data }),
  chains: () => request<Chain[]>('GET', '/chains'),
  chain: (id: number) => request<Chain>('GET', `/chains/${id}`),
  createChain: (input: { name: string; notes: string; nodes: number[]; link: LinkParams }) => request<Chain>('POST', '/chains', input),
  updateChain: (id: number, name: string, notes: string) => request<Chain>('PATCH', `/chains/${id}`, { name, notes }),
  deleteChain: (id: number) => request<void>('DELETE', `/chains/${id}`),
  linkChain: (id: number) => request<Job>('POST', `/chains/${id}/link`),
  unlinkChain: (id: number, del: boolean) => request<Job>('POST', `/chains/${id}/unlink`, { delete: del }),
  checkChain: (id: number) => request<Chain>('POST', `/chains/${id}/check`),
  chainChecks: (id: number, idx = 0, limit = 100) => request<LinkCheck[]>('GET', `/chains/${id}/checks?idx=${idx}&limit=${limit}`),
  routing: (serverId: number) => request<RoutingView>('GET', `/servers/${serverId}/routing`),
  routingPreview: (serverId: number, input: RoutingInput) => request<RoutingPreview>('POST', `/servers/${serverId}/routing/preview`, input),
  routingApply: (serverId: number, input: RoutingInput) => request<Job>('POST', `/servers/${serverId}/routing/apply`, input),
  routingCheck: (serverId: number, input: { acl: AclDocument; outbounds: string[]; request: AclRequest }) =>
    request<AclVerdict>('POST', `/servers/${serverId}/routing/check`, input),
  chainTemplates: () => request<ChainTemplate[]>('GET', '/chain-templates'),
  importChainTemplate: (data: string) => request<ChainTemplate>('POST', '/chain-templates/import', { data }),
  chainTemplate: (id: number) => request<ChainTemplate>('GET', `/chains/${id}/template`),
  routingTemplates: () => request<RoutingTemplate[]>('GET', '/routing/templates'),
  routingImport: (data: string) => request<{ acl: AclDocument; outbounds?: RoutingOutbound[]; resolver?: RoutingResolver }>('POST', '/routing/import', { data }),
  routingExport: (serverId: number, format: 'json' | 'text') => requestText(`/servers/${serverId}/routing/export?format=${format}`),
  routingFile: (serverId: number) => request<RoutingFile>('GET', `/servers/${serverId}/routing/file`),
  geoInfo: () => request<GeoInfo>('GET', '/geo'),
  geoUpdate: () => request<{ info: GeoInfo; changed: boolean }>('POST', '/geo/update'),
  geoCategories: (kind: 'geoip' | 'geosite', q: string) =>
    request<{ names: string[] }>('GET', `/geo/categories?kind=${kind}&q=${encodeURIComponent(q)}`),
  serverGeo: (serverId: number) => request<ServerGeo>('GET', `/servers/${serverId}/geo`),
  installGeo: (serverId: number, source: DeploySource, via?: number) => request<Job>('POST', `/servers/${serverId}/geo`, { source, via: via ?? 0 }),
  presetPreview: (serverId: number, p: PresetApply) => request<PresetCheck>('POST', `/servers/${serverId}/preset/preview`, p),
  presetApply: (serverId: number, p: PresetApply) => request<Job>('POST', `/servers/${serverId}/preset/apply`, p),
  clientSummary: (serverId: number) => request<ClientSummary>('GET', `/servers/${serverId}/client`),
  clientProfile: (serverId: number, user = '') =>
    request<ClientProfile>('POST', `/servers/${serverId}/client/reveal`, { user }),
  serverConfig: (serverId: number) => request<ServerConfig>('GET', `/servers/${serverId}/config`),
  startPreflight: (serverId: number, udpPort = 443) => request<Job>('POST', `/servers/${serverId}/preflight`, { udpPort }),
};
