// Thin wrapper over the Wails bindings (window.go.main.GUI.*) and events.

export type Action = 'direct' | 'tunnel' | 'block';

export interface AppMatch {
  pattern: string;
  kind?: string;
  inheritChildren?: boolean;
}

export interface Rule {
  id?: string;
  name: string;
  enabled?: boolean;
  apps?: AppMatch[];
  domains?: string[];
  // Older single-item form, converted to apps/domains when loaded.
  app?: AppMatch | null;
  domain?: { pattern: string } | null;
  protocol?: string;
  action: Action;
  profile?: string;
  // Servers tried in order when `profile` is down ('' = main).
  fallback?: string[];
}

export interface Settings {
  defaultAction: Action;
  defaultProfile?: string;
  defaultFallback?: string[];
  rules: Rule[];
  blockQUIC?: boolean;
  blockIPv6Tunnel?: boolean;
  preferRemoteDNS?: boolean;
  exactWebDomains?: boolean;
  sniffTimeoutMs?: number;
  killSwitch?: boolean;
}

export interface Profile {
  id: string;
  name: string;
  host: string;
  ports: string;
  auth: string;
  tls: { sni?: string; insecure?: boolean; pinSHA256?: string; ca?: string; ech?: string };
  obfs: { type?: string; password?: string; minPacketSize?: number; maxPacketSize?: number };
  hop: { interval?: string; minInterval?: string; maxInterval?: string };
  bandwidth: { up?: string; down?: string };
  congestion: { type?: string; bbrProfile?: string };
  quic: Record<string, unknown>;
  fastOpen?: boolean;
  pinServerIP: boolean;
}

export interface ProfileSummary {
  id: string;
  name: string;
  server: string;
  host: string;
  obfs: string;
  sni: string;
  insecure: boolean;
  pinned: boolean;
  main: boolean;
  source: string;
  sourceName: string;
  missing: boolean;
  usedBy: string[];
}

export interface ImportResult {
  added: ProfileSummary[];
  warnings: string[];
  errors: string[];
}

export interface Stats {
  reflected: number;
  passed: number;
  blocked: number;
  rejected: number;
  unknownOwner: number;
  relayTunnel: number;
  relayDirect: number;
  udpTunneled: number;
  udpDropped: number;
  synRetries: number;
  dnsPairs: number;
  natEntries: number;
  relayPort: number;
  driverVersion: string;
}

export interface TunnelStatus {
  id: string;
  name: string;
  state: 'stopped' | 'connecting' | 'connected' | 'failed';
  message: string;
  udp: boolean;
  socks: string;
  serverIPs: string[];
  restarts: number;
  retryIn: number;
  started: string;
  rejected: number;
  sent: number;
  recv: number;
  test: boolean;
}

export interface RuleWarning {
  index: number;
  rule: string;
  profile: string;
  kind: 'no-main' | 'deleted' | 'missing';
  text: string;
}

export interface RulesTextResult {
  rules: Rule[];
  hasDefault: boolean;
  defaultAction: Action;
  defaultProfile: string;
  errors: { line: number; text: string }[];
  warnings: { line: number; text: string }[];
  summary: string;
}

export interface GeoSource {
  id: string;
  name: string;
  short: string;
  description: string;
  site: string;
  ip: string;
  size: string;
}

export interface GeoFile {
  sha256: string;
  size: number;
  categories: number;
  updated: string;
  url: string;
  verified: boolean;
}

export interface GeoCategory {
  name: string;
  kind: 'site' | 'ip';
  title: string;
  hint: string;
  group: string;
  sources: string[]; // preset IDs that have it
  inSource: boolean | null; // in the source in use (null = unknown)
}

export interface GeoInfo {
  sources: GeoSource[];
  source: string;
  custom: GeoSource;
  auto: boolean;
  hours: number;
  site: GeoFile | null;
  ip: GeoFile | null;
  checked: string;
  error: string;
  busy: boolean;
  progress: [number, number];
  hasPrevious: boolean;
  used: string[];
  warnings: string[];
  viaVPN: boolean;
  sourceName: string;
  popular: GeoCategory[];
}

export interface LintIssue {
  index: number;
  severity: 'warn' | 'info';
  text: string;
}

export interface ExplainStep {
  index: number;
  name: string;
  enabled: boolean;
  matched: boolean;
  winner: boolean;
  reason: string;
  action: Action;
  profile: string;
}

export interface Explanation {
  steps: ExplainStep[];
  winner: ExplainStep;
  notes: string[];
  profileName: string;
}

export type State = 'disconnected' | 'starting' | 'connecting' | 'connected' | 'tunnel-down' | 'error';

// A local proxy port (SOCKS5 and HTTP on one port) through one server.
export interface ProxyInput {
  id: string;
  name: string;
  enabled: boolean;
  profile: string; // '' = main server
  port: number;
  lan: boolean;
  username: string;
  password: string;
}

export interface ProxyView extends ProxyInput {
  profileName: string;
  state: 'off' | 'waiting' | 'listening' | 'error';
  error?: string;
  active: number;
  total: number;
  sent: number;
  recv: number;
  addresses: string[];
}

// A running program (rule editor suggestions).
export interface RunningApp {
  name: string; // file name, e.g. Discord.exe
  path: string;
  description: string; // e.g. "Telegram Desktop"
  windowed: boolean; // has a visible window
  system: boolean; // part of Windows
  count: number; // processes
}

export interface Status {
  state: State;
  message: string;
  main: string;
  mainId: string;
  since: string;
  tunnels: TunnelStatus[];
  stats?: Stats;
  warnings: RuleWarning[];
  loadError?: string;
  noTunnel: boolean;
  // '' = off, 'armed' = protects the connection, 'blocking' = internet closed
  killSwitch: '' | 'armed' | 'blocking';
  killSwitchError?: string;
}

export interface Flow {
  id: number;
  pid: number;
  process: string;
  path: string;
  proto: string;
  src: string;
  dst: string;
  domain: string;
  domainSrc: string;
  rule: string;
  route: string;
  profile: string;
  outcome: string;
  attrib: string;
  stage: string;
  sent: number;
  recv: number;
  start: string;
  duration: number; // ns
  closed: boolean;
}

export interface Connections {
  active: Flow[];
  closed: Flow[];
}

export interface LogEntry {
  seq: number;
  time: string;
  level: string;
  msg: string;
}

export interface SystemInfo {
  build: string;
  dataDir: string;
  programDir: string;
  firewallRule: string;
  driver: string;
  driverStale: boolean;
  legacy: string[];
  missing: string[];
  firewallRuleOK: boolean;
  hysteria: string;
  hysteriaPath: string;
  protectedLocation: boolean;
  runtimeDir: string;
  moveTarget: string;
}

export interface Prefs {
  logsToDisk?: boolean;
  logMaxMB?: number;
  logKeep?: number;
  updateCheck?: '' | 'auto' | 'manual';
  updateChannel?: string;
  skipVersion?: string;
  autoConnect?: boolean;
  closeToTray?: boolean;
}

export interface AutostartInfo {
  enabled: boolean;
  command: string; // exe the sign-in task starts
  current: boolean; // it is this copy
  allowed: boolean; // this copy is in Program Files
  error?: string;
}

export interface CheckStep {
  name: string;
  ok: boolean;
  skip: boolean;
  detail: string;
  ms: number;
}

export interface CheckResult {
  profile: string;
  ok: boolean;
  steps: CheckStep[];
  externalIP: string;
  latencyMs: number;
}

export interface AppUpdate {
  version: string;
  notes: string;
  published: string;
  page: string;
  size: number;
}

export interface CoreUpdate {
  version: string;
  tag: string;
  notes: string;
  published: string;
  page: string;
}

export interface CoreInfo {
  path: string;
  version: string;
  bundled: string;
  updated: boolean;
  previous: string;
  error: string;
}

export interface Updates {
  current: string;
  dev: boolean;
  repo: string;
  checked: string;
  checking: boolean;
  app: AppUpdate | null;
  appError: string;
  appStage: '' | 'downloading' | 'ready';
  appProgress: number;
  appSkipped: boolean;
  core: CoreInfo;
  coreUpdate: CoreUpdate | null;
  coreError: string;
  coreBusy: boolean;
  coreProgress: number;
  coreNeedsReconnect: boolean;
}

export interface Subscription {
  id: string;
  name: string;
  url: string; // masked: scheme://host/…
  enabled: boolean;
  interval: 'manual' | 'startup' | '6h' | '12h' | '24h';
  lastUpdate: string;
  lastAttempt: string;
  lastError: string;
  count: number;
  ignored: Record<string, number> | null;
  warnings: string[] | null;
  userInfo: string;
  hasPrevious: boolean;
  profiles: number;
  missing: number;
  nextAt: string;
  traffic: string;
}

export interface SubPreview {
  token: string;
  title: string;
  count: number;
  names: string[];
  ignored: Record<string, number>;
  ignoredTotal: number;
  warnings: string[];
  errors: string[];
  base64: boolean;
  traffic: string;
}

// token is a preview's (PreviewSubscription): the link to add, or on edit
// the new link (empty = keep).
export interface SubInput {
  id?: string;
  token?: string;
  name: string;
  enabled: boolean;
  interval: string;
}

export interface MergeStats {
  added: number;
  updated: number;
  removed: number;
  missingKept: number;
}

interface GUI {
  Status(): Promise<Status>;
  Connect(): Promise<void>;
  Disconnect(): Promise<void>;
  Reconnect(): Promise<void>;
  ReleaseKillSwitch(): Promise<void>;
  Autostart(): Promise<AutostartInfo>;
  SetAutostart(on: boolean): Promise<void>;
  Profiles(): Promise<ProfileSummary[]>;
  Profile(id: string): Promise<Profile>;
  ImportURIs(text: string): Promise<ImportResult>;
  ImportClipboard(): Promise<ImportResult>;
  SaveProfile(p: Profile): Promise<ProfileSummary>;
  DeleteProfile(id: string): Promise<void>;
  SetMain(id: string): Promise<void>;
  MoveProfile(id: string, to: number): Promise<void>;
  CopyURI(id: string): Promise<void>;
  Settings(): Promise<Settings>;
  SaveSettings(s: Settings): Promise<{ needsReconnect: boolean }>;
  RuleWarnings(): Promise<RuleWarning[]>;
  RulesText(): Promise<string>;
  ParseRulesText(text: string): Promise<RulesTextResult>;
  ApplyRulesText(text: string, replace: boolean): Promise<RulesTextResult>;
  LintRules(s: Settings): Promise<LintIssue[]>;
  Explain(q: { app: string; target: string; proto: string }, s: Settings | null): Promise<Explanation>;
  BrowseExe(): Promise<string>;
  RunningApps(query: string, all: boolean, limit: number): Promise<RunningApp[]>;
  Proxies(): Promise<ProxyView[]>;
  SaveProxy(p: ProxyInput): Promise<ProxyView>;
  DeleteProxy(id: string): Promise<void>;
  Connections(limit: number): Promise<Connections>;
  Logs(kind: string, after: number): Promise<LogEntry[]>;
  SaveLog(kind: string, sanitized: boolean): Promise<string>;
  Sanitize(text: string): Promise<string>;
  ClearLogs(): Promise<void>;
  OpenLogDir(): Promise<void>;
  Prefs(): Promise<Prefs>;
  SavePrefs(p: Prefs): Promise<void>;
  CheckProfile(id: string): Promise<CheckResult>;
  Diagnostics(privacy: boolean): Promise<string>;
  CopyDiagnostics(privacy: boolean): Promise<void>;
  Updates(): Promise<Updates>;
  CheckUpdates(): Promise<Updates>;
  InstallCore(): Promise<void>;
  RollbackCore(): Promise<void>;
  DownloadAppUpdate(): Promise<void>;
  ApplyAppUpdate(): Promise<void>;
  SkipAppVersion(v: string): Promise<void>;
  StartupNotice(): Promise<string>;
  System(): Promise<SystemInfo>;
  RemoveFirewallRule(): Promise<void>;
  DeleteStaleDriverService(): Promise<void>;
  OpenDataDir(): Promise<void>;
  MoveToProgramFiles(): Promise<void>;
  CopyText(text: string): Promise<void>;
  Subscriptions(): Promise<Subscription[]>;
  PreviewSubscription(url: string): Promise<SubPreview>;
  AddSubscription(i: SubInput): Promise<Subscription>;
  EditSubscription(i: SubInput): Promise<void>;
  UpdateSubscription(id: string): Promise<MergeStats>;
  RollbackSubscription(id: string): Promise<MergeStats>;
  DeleteSubscription(id: string): Promise<void>;
  GeoInfo(): Promise<GeoInfo>;
  UpdateGeo(force: boolean): Promise<{ changed: boolean; notes: string[] }>;
  RollbackGeo(): Promise<void>;
  SetGeoPrefs(source: string, siteURL: string, ipURL: string, auto: boolean, hours: number): Promise<void>;
  GeoCategories(kind: 'site' | 'ip', query: string): Promise<string[]>;
  Inspect(query: string): Promise<InspectResult>;
  GeoList(kind: 'site' | 'ip', name: string, filter: string, offset: number, limit: number): Promise<GeoListing>;
  ConvertACL(text: string, mode: 'domains' | 'rules', suffix: string, actions: string): Promise<ConvertResult>;
}

export interface InspectHit {
  tag: string;
  title: string;
  entry: string;
  attrs: string;
  size: number;
  priority: number;
  broad: boolean;
  ip: string;
  usedBy: string[] | null;
}

export interface GeoListing {
  category: string;
  kind: 'site' | 'ip';
  total: number;
  matched: number;
  entries: string[];
}

export interface InspectResult {
  query: string;
  host: string;
  ips: string[];
  site: InspectHit[];
  ip: InspectHit[];
  errors: string[];
  route: Explanation | null;
  sourceName: string;
  list: GeoListing | null;
}

export interface ConvertResult {
  text: string;
  count: number;
  warnings: string[];
}

const w = window as any;

export const api: GUI = new Proxy({} as GUI, {
  get(_t, method: string) {
    return (...args: unknown[]) => {
      const fn = w.go?.main?.GUI?.[method];
      if (!fn) return Promise.reject(new Error('Нет связи с HyRoute (запущено вне приложения)'));
      return fn(...args);
    };
  },
});

export function onEvent(name: string, cb: (...data: unknown[]) => void): () => void {
  const off = w.runtime?.EventsOn?.(name, cb);
  return typeof off === 'function' ? off : () => {};
}

export function errText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

export function fmtBytes(n: number): string {
  if (n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

// fmtDuration rounds before picking the unit, so 119.6 s is "2 мин 0 с",
// not "1 мин 60 с".
export function fmtDuration(ns: number): string {
  const ms = Math.round(ns / 1e6);
  if (ms < 1000) return `${ms} мс`;
  const ds = Math.round(ns / 1e8); // tenths of a second
  if (ds < 600) return `${(ds / 10).toFixed(1)} с`;
  const s = Math.round(ns / 1e9);
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} мин ${s % 60} с`;
  return `${Math.floor(m / 60)} ч ${m % 60} мин`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString('ru-RU', { hour12: false });
}

export const actionLabel: Record<string, string> = {
  tunnel: 'Туннель',
  direct: 'Напрямую',
  block: 'Блок',
  pending: 'Решается…',
};

export function fmtDateTime(iso: string): string {
  if (!iso || iso.startsWith('0001')) return '—';
  const d = new Date(iso);
  return d.toLocaleString('ru-RU', { hour12: false, day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

export function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10,
    m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

// toLists moves the old single app/domain into the lists.
export function toLists(r: Rule): Rule {
  const apps = [...(r.apps ?? [])];
  const domains = [...(r.domains ?? [])];
  if (r.app?.pattern) apps.push(r.app);
  if (r.domain?.pattern) domains.push(r.domain.pattern);
  const out: Rule = { ...r, apps, domains };
  delete out.app;
  delete out.domain;
  return out;
}

// cleanFallback drops the fallback servers routing skips: the route's own
// server and repeats. "" is the main server; mainId resolves it ("" when
// unknown: then "" only equals "").
export function cleanFallback(fb: string[] | undefined, primary: string | undefined, mainId = ''): string[] {
  const key = (id: string) => id || mainId;
  const seen = new Set([key(primary ?? '')]);
  return (fb ?? []).filter((id) => {
    const k = key(id);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// cleanRule drops empty fields before saving. A direct or block rule keeps
// no server: a stale one would still pin it (it could not be deleted).
// Fallbacks routing skips go too (shown struck through until then), also
// those that repeat the main server (mainId) after it changed.
export function cleanRule(r: Rule, mainId: string | undefined): Rule {
  const out: Rule = { ...toLists(r) };
  out.apps = (out.apps ?? []).filter((a) => a.pattern.trim()).map((a) => ({ ...a, pattern: a.pattern.trim() }));
  out.domains = (out.domains ?? []).map((d) => d.trim()).filter(Boolean);
  if (!out.apps.length) delete out.apps;
  if (!out.domains.length) delete out.domains;
  if (!out.protocol) delete out.protocol;
  if (out.enabled !== false) delete out.enabled;
  out.fallback = out.action === 'tunnel' ? cleanFallback(out.fallback, out.profile, mainId) : [];
  if (!out.fallback.length) delete out.fallback;
  if (out.action !== 'tunnel' || !out.profile) delete out.profile;
  return out;
}

// cleanSettings is what SaveSettings gets; mainId is the main server's ID
// (mainProfile()?.id, undefined when none).
export function cleanSettings(s: Settings, mainId: string | undefined): Settings {
  const c: Settings = JSON.parse(JSON.stringify(s));
  c.rules = (c.rules ?? []).map((r) => cleanRule(r, mainId));
  c.defaultFallback = c.defaultAction === 'tunnel' ? cleanFallback(c.defaultFallback, c.defaultProfile, mainId) : [];
  if (!c.defaultFallback.length) delete c.defaultFallback;
  if (c.defaultAction !== 'tunnel' || !c.defaultProfile) delete c.defaultProfile;
  return c;
}
