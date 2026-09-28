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
  // Destination ports: "443", "80,443,27000-27200" ('' or absent = any
  // port). Go writes this v1.2.0 string form; items: portItems/parsePorts.
  ports?: string;
  action: Action;
  // A server or group ID ('' = the main target).
  profile?: string;
  // Servers or groups tried in order when `profile` is down ('' = main).
  fallback?: string[];
}

export interface Settings {
  defaultAction: Action;
  defaultProfile?: string; // a server or group ID ('' = the main target)
  defaultFallback?: string[];
  rules: Rule[];
  blockQUIC?: boolean;
  blockIPv6Tunnel?: boolean;
  preferRemoteDNS?: boolean;
  exactWebDomains?: boolean;
  sniffTimeoutMs?: number;
  killSwitch?: boolean;
  // foundation: the Settings() view only (never stored). rev is always the
  // settings revision the copy was read at; a save sends it back (EditGuard).
  ruleset?: string;
  rev?: number;
  editRev?: number;
  warnings?: RuleWarning[];
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
  // groups: failed connections through it are invisible to error streaks
  fastOpen: boolean;
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
  // dns: queries HyRoute resolved through a tunnel or directly, passed on,
  // answered NXDOMAIN by a block rule, for browser DoH, SERVFAIL, truncated,
  // passed during the portal pause; systemDoH: Windows' own encrypted DNS seen
  dnsTunnel?: number;
  dnsDirect?: number;
  dnsPassed?: number;
  dnsBlocked?: number;
  dnsDoH?: number;
  dnsFailed?: number;
  dnsTruncated?: number;
  dnsPortalPassed?: number;
  systemDoH?: number;
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
  kind: 'no-main' | 'deleted' | 'missing' | 'empty';
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
  // groups: the winner is a server group; via is the member a connection
  // would take now (connected, failover or latency groups).
  group?: boolean;
  via?: string;
  // ports: the port checked (0 = none); an enabled rule has ports.
  // winner.index -2 (StepQUICBlock) is the synthetic «Блокировка QUIC».
  port: number;
  portRules: boolean;
  // dns: how the name resolves (a domain target, a DNS option on)
  dns?: DNSExplain | null;
}

export type State = 'disconnected' | 'starting' | 'connecting' | 'connected' | 'tunnel-down' | 'error';

// A local proxy port (SOCKS5 and HTTP on one port) through one server.
export interface ProxyInput {
  id: string;
  name: string;
  enabled: boolean;
  profile: string; // a server or group ID ('' = the main target)
  port: number;
  lan: boolean;
  username: string;
  password: string;
  udp?: '' | 'on' | 'off'; // socks-udp: SOCKS5 UDP ASSOCIATE; ''/absent = default (on here, off for LAN)
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
  // socks-udp: active/total count TCP connections only (UDP ASSOCIATE
  // control connections excluded); sent/recv are TCP + UDP payload bytes.
  udpOn: boolean; // effective switch value
  udpServed: boolean; // UDP ASSOCIATE served now
  udpActive: number;
  udpTotal: number;
  udpDropped: number;
  udpError?: string; // LAN: the UDP port did not open (retrying) or has no firewall rule; TCP works
  udpBlocked?: 'server' | 'group'; // the target cannot carry UDP right now
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
  // foundation: the settings revision (also the payload of the "settings" event)
  settingsRev: number;
  // groups: mainId is the main target (a server or a group); mainGroup the
  // loaded main group; mainUnloaded: the main is a group groups.json could
  // not load; groupsNote: what a broken groups.json means now.
  mainUnloaded?: boolean;
  mainGroup?: GroupBrief;
  groupsNote?: string;
  // rulesets: the active rule profile (rev and token make pages reload)
  ruleset: RulesetRef;
  // subinfo: subscriptions whose traffic or term runs out; subsOK: the
  // subscription list is authoritative (dismissals may be pruned)
  subAlerts: SubAlert[];
  subsOK: boolean;
  // dns: while connected with a DNS option on
  dns?: DNSStatus;
  // netmodes: the network rules while «Сети» is on
  net?: NetState;
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
  // foundation: the mandatory exclusion the flow fell under (rules do not apply)
  excluded?: string; // hysteria | system-dns
  // groups: the server group profile was chosen through; failover: the flow
  // could not use its preferred server
  group?: string;
  failover?: boolean;
  // bigudp: UDP datagrams dropped as larger than Hysteria carries; a tunneled
  // flow of which nothing got through has outcome 'dropped: larger than Hysteria carries'
  tooBig?: number;
  // dns: a DNS row (stage 'dns', domainSrc 'query'): the queries it counts
  count?: number;
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
  proxyRules: string[]; // socks-udp: names of HyRoute's local-proxy firewall rules that exist
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
  cli?: '' | CLIMode; // cli: '' (unset) = read-only
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
  // subinfo: when the panel reported userInfo; its view (null: nothing
  // reported); the panel's public support link
  infoAt?: string;
  info: SubInfo | null;
  supportUrl?: string;
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
  // subinfo: the panel's figures and the update interval it advises (hours, 0 = none)
  info: SubInfo | null;
  updateHours: number;
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
  ClipboardText(): Promise<string>;
  SaveProfile(p: Profile): Promise<ProfileSummary>;
  DeleteProfile(id: string): Promise<void>;
  SetMain(id: string): Promise<void>;
  MoveProfile(id: string, to: number): Promise<void>;
  CopyURI(id: string): Promise<void>;
  Settings(): Promise<Settings>;
  SaveSettings(s: Settings): Promise<SaveResult>;
  RuleWarnings(): Promise<RuleWarning[]>;
  RulesText(ruleset: string): Promise<RulesTextView>;
  ParseRulesText(text: string): Promise<RulesTextResult>;
  ApplyRulesText(text: string, replace: boolean, guard: EditGuard): Promise<RulesTextResult>;
  LintRules(s: Settings): Promise<LintIssue[]>;
  Explain(q: { app: string; target: string; proto: string; port?: number }, s: Settings | null): Promise<Explanation>;
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
  // The geosite lists that hold a site (no DNS lookups), most specific first.
  SiteLists(domain: string): Promise<InspectHit[]>;
  // Backup: full (servers, subscriptions, rules, proxies, preferences;
  // encrypted with the password) or rules only. Returns the path ('' =
  // cancelled). Restore: ChooseBackup reads a file, RestoreBackup applies it.
  SaveBackup(full: boolean, password: string): Promise<string>;
  ChooseBackup(): Promise<BackupChoice>;
  RestoreBackup(password: string): Promise<RestoreResult>;
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

export interface BackupChoice {
  name: string; // '' = cancelled
  kind: 'full' | 'rules';
  created: string;
  app: string;
  encrypted: boolean;
  rules: number; // -1 = not known before the password
}

export interface RestoreResult {
  kind: 'full' | 'rules';
  rules: number;
  profiles: number;
  subscriptions: number;
  proxies: number;
  remapped: number;
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
  // Ports are validated by Go; the editor canonicalises them (parsePorts).
  out.ports = (out.ports ?? '').trim();
  if (!out.ports) delete out.ports;
  if (out.enabled !== false) delete out.enabled;
  out.fallback = out.action === 'tunnel' ? cleanFallback(out.fallback, out.profile, mainId) : [];
  if (!out.fallback.length) delete out.fallback;
  if (out.action !== 'tunnel' || !out.profile) delete out.profile;
  return out;
}

// cleanSettings is what SaveSettings gets; mainId is the main target's ID
// (mainTarget()?.id, undefined when none). The copy's ruleset, rev and
// editRev stay: Go checks the save against them.
export function cleanSettings(s: Settings, mainId: string | undefined): Settings {
  const c: Settings = JSON.parse(JSON.stringify(s));
  c.rules = (c.rules ?? []).map((r) => cleanRule(r, mainId));
  c.defaultFallback = c.defaultAction === 'tunnel' ? cleanFallback(c.defaultFallback, c.defaultProfile, mainId) : [];
  if (!c.defaultFallback.length) delete c.defaultFallback;
  if (c.defaultAction !== 'tunnel' || !c.defaultProfile) delete c.defaultProfile;
  delete c.warnings;
  return c;
}

// ==== foundation ====

// What a writer based its change on (Go app.EditGuard): the revision of the
// copy it read. 0 = no check.
export interface EditGuard {
  ruleset: string;
  rev: number;
  editRev: number;
}

export interface SaveResult {
  needsReconnect: boolean;
  rev: number; // the settings revision after the save
  editRev?: number;
}

// The rules as text with the revision «заменить всё» sends back.
export interface RulesTextView {
  text: string;
  ruleset: string;
  rev: number;
  editRev?: number;
}

// The engine options: the part of Settings outside the rules, saved on its
// own («Настройки»), so it never writes back an old copy of the rules.
export interface EngineOptions {
  blockQUIC?: boolean;
  blockIPv6Tunnel?: boolean;
  preferRemoteDNS?: boolean;
  exactWebDomains?: boolean;
  sniffTimeoutMs?: number;
  killSwitch?: boolean;
}

// optionsOf picks the six engine options of s.
export function optionsOf(s: Settings): EngineOptions {
  const { blockQUIC, blockIPv6Tunnel, preferRemoteDNS, exactWebDomains, sniffTimeoutMs, killSwitch } = s;
  return { blockQUIC, blockIPv6Tunnel, preferRemoteDNS, exactWebDomains, sniffTimeoutMs, killSwitch };
}

// guardOf is the revision a copy of the settings (or of the rules text)
// sends back with a save.
export function guardOf(v: { ruleset?: string; rev?: number; editRev?: number }): EditGuard {
  return { ruleset: v.ruleset ?? '', rev: v.rev ?? 0, editRev: v.editRev ?? 0 };
}

// staleText starts Go's refusal of a save built on rules changed elsewhere
// (the page reloads then).
const staleText = 'Правила изменились в другом месте';

export function isStale(e: unknown): boolean {
  return errText(e).startsWith(staleText);
}

interface GUI {
  SaveEngineOptions(o: EngineOptions): Promise<SaveResult>;
}

// ==== groups ====

export type Strategy = 'failover' | 'latency' | 'roundrobin' | 'random' | 'sticky';

export interface Group {
  id: string; // 'grp-…'; '' when creating
  name: string;
  strategy: Strategy;
  members: string[]; // server IDs, ordered
  revert?: boolean; // failover
  toleranceMs?: number; // latency (0/undefined = 50)
  switchAfterErrors?: number; // 0/undefined = off, 2..20
}

export interface GroupMember {
  id: string;
  name: string;
  state: 'stopped' | 'connecting' | 'connected' | 'failed';
  udp: boolean;
  fastOpen: boolean;
  latencyMs: number;
  lastMs: number;
  probeAt: number; // Unix ms, 0 = never
  probeError: string;
  errors: number;
  skipped: boolean;
  reason: '' | 'errors' | 'trial' | 'probe';
  missing: boolean; // not in the server list («удалён»)
  notInSub: boolean; // kept although its subscription dropped it («нет в подписке»)
}

export interface GroupView extends Group {
  main: boolean;
  usedBy: string[];
  active: string;
  up: number;
  running: boolean;
  missing: number;
  rejected: number;
  probeBroken: boolean;
  memberViews: GroupMember[];
}

export interface ProbeSettings {
  url?: string;
  intervalSec?: number;
}

export interface GroupsInfo {
  groups: GroupView[];
  probe: ProbeSettings;
  defaultProbeURL: string;
  loadError?: string;
  serversBroken?: boolean; // profiles.json did not load: groups are not changed
  activeServer: string; // the main again once a main group is deleted ('' = none)
}

export interface GroupBrief {
  id: string;
  name: string;
  strategy: Strategy;
  active: string;
  activeName: string;
  up: number;
  total: number;
  rejected: number;
}

// isGroupId: a target ID naming a server group (servers and groups share
// one namespace; the prefix keeps them apart).
export function isGroupId(id: string | undefined | null): boolean {
  return !!id && id.startsWith('grp-');
}

export const strategyLabel: Record<Strategy, string> = {
  failover: 'По порядку',
  latency: 'Самый быстрый',
  roundrobin: 'По кругу',
  random: 'Случайно',
  sticky: 'Закреплять сайт',
};

interface GUI {
  Groups(): Promise<GroupsInfo>;
  SaveGroup(g: Group): Promise<GroupView>;
  DeleteGroup(id: string): Promise<void>;
  ProbeGroup(id: string): Promise<GroupView>;
  SetProbe(p: ProbeSettings): Promise<void>;
}

// ==== ports ====

// parsePorts reads "80, 443 8000-8100" like Go's rules.ParsePortList:
// spaced ranges are one item ("8000 - 8100", en/em dash too), items are
// split by commas, semicolons and spaces; canonical items (order kept,
// repeats dropped) or the first error, in Go's words. Each side of an item
// must be digits only before Number(), as strconv.ParseUint wants.
// Reference cases (Go's TestParsePortItem):
//   ok:  "443", "0443"->"443", "000443"->"443", "8000-8100", "8000–8100", "8000 - 8100",
//        "1-65535", "443-443"->"443"
//   bad: "0", "65536", "-1", "+443", "0x1bb", "1e3", "443-", "-443",
//        "100-50" (reversed message), "abc", "1-2-3"
// Spaces are Go's unicode.IsSpace (JS \s differs: it has U+FEFF, lacks U+0085).
const portSp = '[\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const portDash = new RegExp(`${portSp}*[-–—]${portSp}*`, 'g');
const portSplit = new RegExp(`(?:${portSp}|[,;])+`);

export function parsePorts(text: string): { ports: string[]; error: string } {
  const items = portItems(text);
  // Separators only («,») name no port: not an empty list, which is any port.
  if (!items.length && text.trim()) return { ports: [], error: 'не указан ни один порт: например, 443 или 80, 443' };
  if (items.length > 256) return { ports: [], error: 'слишком много портов в правиле (больше 256): объедините их в диапазоны' };
  const ports: string[] = [];
  for (const it of items) {
    const echo = [...it].length > 24 ? [...it].slice(0, 24).join('') + '…' : it;
    const bad = `неверный порт «${echo}»: нужно число от 1 до 65535 или диапазон, например 8000-8100`;
    const dash = it.indexOf('-');
    const sides = dash < 0 ? [it] : [it.slice(0, dash), it.slice(dash + 1)];
    if (!sides.every((s) => /^\d+$/.test(s))) return { ports: [], error: bad };
    const [lo, hi] = [Number(sides[0]), Number(sides[sides.length - 1])];
    if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535) return { ports: [], error: bad };
    if (lo > hi) return { ports: [], error: `диапазон «${echo}» наоборот: меньший порт пишется первым, например 8000-8100` };
    const c = lo === hi ? String(lo) : `${lo}-${hi}`;
    if (!ports.includes(c)) ports.push(c);
  }
  return { ports, error: '' };
}

// portItems splits a stored list ("80,443,27000-27200", the v1.2.0 form Go
// writes) or typed text into raw items, as Go's splitPortText.
export function portItems(text: string | undefined): string[] {
  return (text ?? '').replace(portDash, '-').split(portSplit).filter(Boolean);
}

// portsText is the label of a rule by protocol and ports, as Go's
// rules.PortsLabel: "TCP", "TCP 22", "UDP 50000-65535", "порт 443",
// "порты 80, 443". max > 0 shows that many items and "…". '' when neither
// is set.
export function portsText(r: Pick<Rule, 'protocol' | 'ports'>, max = 0): string {
  const proto = r.protocol && r.protocol !== 'any' ? r.protocol.toUpperCase() : '';
  const raw = portItems(r.ports);
  const ports = canonPorts(raw) ?? raw;
  if (!ports.length) return proto;
  const list = (max > 0 && ports.length > max ? ports.slice(0, max) : ports).join(', ') + (max > 0 && ports.length > max ? '…' : '');
  if (proto) return `${proto} ${list}`;
  return `${ports.length === 1 && !ports[0].includes('-') ? 'порт' : 'порты'} ${list}`;
}

// canonPorts is stored items made canonical, item by item as Go's
// rules.CanonPorts ("0443" -> "443", repeats dropped); null when an item
// is not one valid port or range (a hand-edited settings.json).
export function canonPorts(items: string[]): string[] | null {
  if (items.length > 256) return null;
  const out: string[] = [];
  for (const it of items) {
    const p = parsePorts(it);
    if (p.error || p.ports.length !== 1) return null;
    if (!out.includes(p.ports[0])) out.push(p.ports[0]);
  }
  return out;
}

// portRange reads a canonical item: [lo, hi].
export function portRange(item: string): [number, number] {
  const [lo, hi] = item.split('-').map(Number);
  return [lo, hi ?? lo];
}

// ==== rulesets ====

// The rules part of the settings: what a rule profile holds.
export interface RulesConfig {
  defaultAction: Action;
  defaultProfile?: string;
  defaultFallback?: string[];
  rules: Rule[];
}

// The active rule profile (Status.ruleset). id is '' and name «Основной»
// while there is only one; count 0 when rulesets.json did not load.
export interface RulesetRef {
  id: string;
  name: string;
  count: number;
  token: string;
  rev: number;
}

export interface RulesetView {
  id: string;
  name: string;
  rules: number;
  defaultAction: Action;
  active: boolean;
  warnings: number;
  error?: string; // does not load: cannot be switched to
  newer?: boolean; // saved by a newer HyRoute: no edit mode, no copy
  usedBy: string[]; // network rules that switch to it
}

export interface RulesetsView {
  active: string;
  list: RulesetView[];
  saved: boolean;
  error?: string;
  token: string;
  rev: number;
}

// from: 'active', a profile ID, or '' (config).
export interface RulesetInput {
  name: string;
  from: string;
  config?: RulesConfig;
  activate: boolean;
  firstName?: string;
}

// The window builds its texts from the fields (each name through hide());
// note is Go's own text with the names unmasked (CLI, log).
export interface SwitchResult {
  ruleset: RulesetRef;
  warnings: RuleWarning[];
  connected: boolean;
  stopped: string[];
  note: string;
  reconnected: boolean;
  reconnectError?: string;
}

export interface CreateResult {
  view: RulesetView;
  switch?: SwitchResult;
}

export const defaultLabel: Record<Action, string> = { direct: 'напрямую', tunnel: 'через VPN', block: 'блок' };

// isEditToken: the copy is of an inactive profile opened without switching.
export const isEditToken = (t?: string) => !!t && t.startsWith('edit:');

// tokenStale: a copy made with token no longer belongs to what it was read
// for (the active profile changed, or the edited one became active or, by
// list, a profile list as new as r, was deleted). Go refuses its save
// anyway; the page says so first. 'implicit' cannot go stale while a copy
// is open: only this window creates a second profile.
export function tokenStale(token: string | undefined, r: RulesetRef | undefined, list?: RulesetsView | null): boolean {
  if (!token || !r) return false;
  if (isEditToken(token)) return r.token === token.slice(5) || editGone(token, r, list);
  return token !== 'implicit' && r.token !== token;
}

// editGone: the profile an "edit:<id>" token names is missing from a list
// read at r's revision (an older list proves nothing).
export function editGone(token: string, r: RulesetRef, list?: RulesetsView | null): boolean {
  if (!isEditToken(token) || !list || list.error || list.rev < r.rev) return false;
  const id = token.slice(5);
  return !list.list.some((e) => e.id === id);
}

interface GUI {
  RulesetSettings(id: string): Promise<Settings>;
  Rulesets(): Promise<RulesetsView>;
  SwitchRuleset(id: string): Promise<SwitchResult>;
  CreateRuleset(i: RulesetInput): Promise<CreateResult>;
  RenameRuleset(id: string, name: string): Promise<void>;
  DeleteRuleset(id: string): Promise<void>;
  MoveRuleset(id: string, to: number): Promise<void>;
}

// ==== subinfo ====

// A subscription's traffic and term as the panel reports them
// (subscription-userinfo). Byte counts may exceed 2^53: the UI uses usedPct,
// upDown and the Go-made texts, never arithmetic on them.
export interface SubInfo {
  upload: number;
  download: number;
  used: number;
  total: number; // limit; 0: unlimited or not reported
  unlimited: boolean;
  left: number;
  percent: number; // left share 0..100; -1 without a limit
  usedPct: number; // bar fill 0..100
  expire: number; // Unix seconds; 0: no end date
  secondsLeft: number;
  at?: string; // absent: time unknown (restored from an old backup)
  level: '' | 'low' | 'out';
  summary: string; // «Осталось 86 ГБ / 12 дней»
  details: string; // «использовано 14 ГБ из 100 ГБ, до 10.10.2026»
  warning: string;
  upDown: string; // «↑ 1.2 ГБ ↓ 12.8 ГБ»
}

// A subscription that needs attention (Status.subAlerts). key changes when
// the situation does: «Скрыть» holds until then.
export interface SubAlert {
  id: string;
  name: string;
  level: 'low' | 'out';
  text: string;
  key: string;
}

interface GUI {
  // Opens the support link the panel of subscription id sent, through
  // Explorer; the page never passes a URL.
  OpenSubscriptionSupport(id: string): Promise<void>;
}

// ==== dns ====

// «Настройки» → «DNS» (dns.json). A preset ID, or 'custom' with url.
export interface DNSUpstream {
  preset: string; // '' | 'cloudflare' | 'google' | 'quad9' | 'adguard' | 'yandex' | 'custom'
  url?: string; // custom only
}

export interface DNSConfig {
  blockBrowserDoH: boolean;
  stripECH: boolean;
  byRules: boolean;
  ignoreAddrRules: boolean; // true = «Сверяться с правилами по IP и geoip» off
  tunnel: DNSUpstream; // preset '' = 'cloudflare'
  direct: DNSUpstream; // preset '' = off
}

export interface DNSPreset {
  id: string;
  name: string;
  url: string;
  tunnel: boolean;
  direct: boolean;
}

// An upstream server that does not answer (Status.dns.health).
export interface DNSHealth {
  via: 'tunnel' | 'direct';
  profile?: string; // tunnel: server/group ID → profileName()
  upstream: string; // preset name or 'свой сервер'
  kind: 'timeout' | 'connect' | 'tls' | 'http' | 'answer';
  code?: number;
  retryIn: number; // seconds
}

export interface DNSStatus {
  byRules: boolean;
  direct: boolean;
  health?: DNSHealth[];
  pauseLeft?: number; // captive-portal pause, seconds left
  notApplied?: boolean; // the running session did not take the settings
}

export interface DNSView {
  config: DNSConfig;
  presets: DNSPreset[];
  error?: string; // dns.json did not load
}

export interface DNSExplain {
  route: 'tunnel' | 'block' | 'upstream' | 'direct' | 'addr' | 'server' | 'local' | 'service';
  profile?: string;
  upstream?: string;
  rule?: string;
  cond?: 'app' | 'proto';
  proto?: 'tcp' | 'udp' | '';
  noIPv6?: boolean;
  system?: DNSExplain | null; // with a program: the Windows DNS client, when it resolves otherwise
}

interface GUI {
  DNS(): Promise<DNSView>;
  SaveDNS(c: DNSConfig): Promise<void>;
  PauseDNSTunnel(): Promise<void>;
  CancelDNSPause(): Promise<void>;
}

// The rule texts of HyRoute's own DNS answers, for «Соединения».
export const dnsRuleLabel: Record<string, string> = {
  'dns: DoH canary': 'DoH браузеров отключён',
  'dns: ECH off': 'ECH отключён',
  'dns: IPv6 not through tunnel': 'IPv6 не через VPN',
  'dns: browser DoH': 'DoH браузера заблокирован',
};

// dnsErrorText: why an upstream server does not answer.
export function dnsErrorText(kind: string, code?: number): string {
  switch (kind) {
    case 'timeout':
      return 'Нет ответа';
    case 'connect':
      return 'Не удаётся соединиться';
    case 'tls':
      return 'Ошибка TLS (сертификат или блокировка)';
    case 'http':
      return `Сервер вернул ошибку HTTP ${code ?? ''}`.trim();
    case 'answer':
      return 'Неверный ответ сервера';
  }
  return kind;
}

// ==== stats ====

// Traffic statistics («Статистика»). Counts of one day, row or period.
export interface StatCounters {
  tc?: number; // tunnel: connections
  tu?: number; // tunnel: bytes up
  td?: number; // tunnel: bytes down
  dc?: number; // direct: connection attempts
  du?: number; // direct: bytes up (approximate lower bound; down is not measured)
  bc?: number; // blocked connections (rules, QUIC, IPv6 for VPN)
  f?: number; // failed (refused) connections
  fo?: number; // tunnel connection went to a fallback / non-preferred group member
}

export interface StatRow extends StatCounters {
  k: string; // key: lower-case path | 'proxy:<id>' (verbatim) | site | server ID | group ID | '' (unknown / no server) | '*' (others)
  n?: string; // stored display name
  drops?: number; // servers only
  gone?: boolean; // server/group/proxy deleted since
}

export interface StatDay extends StatCounters {
  day: string;
}

export type StatsMode = '' | 'no-sites' | 'off';

export interface StatsReport {
  period: string;
  from: string;
  to: string;
  total: StatCounters;
  events: { drops?: number; engineFails?: number };
  days: StatDay[];
  apps: StatRow[];
  sites: StatRow[];
  servers: StatRow[];
  groups: StatRow[];
  months: string[];
  since?: string;
  mode: StatsMode;
  storeError?: string;
  // mode.json could not be read: collection is off until a mode is picked.
  modeUnread?: boolean;
}

interface GUI {
  // today | yesterday | 7d | 30d | YYYY-MM
  Stats(period: string): Promise<StatsReport>;
  ResetStats(): Promise<void>;
  SetStatsMode(mode: StatsMode): Promise<void>;
}

// statConns: every connection of a row (VPN, direct attempts, blocked,
// refused); statVPN: bytes through the VPN.
export const statConns = (c: StatCounters) => (c.tc ?? 0) + (c.dc ?? 0) + (c.bc ?? 0) + (c.f ?? 0);
export const statVPN = (c: StatCounters) => (c.tu ?? 0) + (c.td ?? 0);

// ==== netmodes ====

// «Сети»: network rules (internal/netmode, internal/app/netmodes.go).
export type NetConnect = '' | 'connect' | 'disconnect';
export type NetCategory = 'public' | 'private' | 'domain';
export type NetAdapter = 'wifi' | 'ethernet' | 'mobile' | 'other';

export interface NetAction {
  connect?: NetConnect;
  ruleset?: string;
}
export interface NetKnown {
  id: string;
  name: string;
}
export interface NetMatch {
  networks?: NetKnown[];
  ssids?: string[];
  names?: string[];
  categories?: NetCategory[];
  adapters?: NetAdapter[];
}
export interface NetRule extends NetAction {
  id: string;
  name: string;
  enabled?: boolean;
  match: NetMatch;
}
export interface NetModes {
  version: number;
  enabled: boolean;
  rules: NetRule[];
  unknown: NetAction;
}

// netmode.Network (the adapter and gateway fields never reach the UI)
export interface NetInfo {
  id: string;
  name: string;
  category: NetCategory | '';
  adapter: NetAdapter;
  adapterName: string;
  ssid: string;
  ssidDenied: boolean;
  identified: boolean;
}
export interface NetSnapshot {
  active: NetInfo | null;
  others: NetInfo[] | null;
  error?: string;
  nlmDown?: boolean;
}

export interface NetState {
  rule: string;
  ruleId: string;
  unknown: boolean;
  noNet: boolean;
  pending: boolean;
  text: string;
  error?: string;
  at: string;
  override: boolean;
  restored: boolean;
  off: boolean;
  offBy?: string;
}
export interface NetModesView {
  config: NetModes;
  current: NetSnapshot;
  match: ({ ruleId: string; name: string; unknown: boolean } & NetAction) | null;
  state: NetState;
  available: boolean;
  unavailable?: string;
  loadError?: string;
  usesSSID: boolean;
  rulesets: { id: string; name: string }[] | null; // null: no rule profiles
  rulesetsNote?: string;
  ruleErrors: Record<string, string> | null; // key: rule id or 'unknown'
  confirm?: boolean; // ApplyNetModes did not act: match disconnects and was not confirmed
}

interface GUI {
  NetModes(refresh: boolean): Promise<NetModesView>; // false: cached read (status events), true: fresh read
  SaveNetModes(c: NetModes): Promise<NetModesView>; // `enabled` in c is ignored: SetNetModesEnabled is the only toggle
  SetNetModesEnabled(on: boolean): Promise<NetModesView>;
  // confirmDisconnect: the key (rule id, 'unknown') of the disconnecting rule
  // the user confirmed; '' = none. A fresh read's other disconnect → confirm.
  ApplyNetModes(confirmDisconnect: string): Promise<NetModesView>;
  CurrentSSID(): Promise<string>;
}

export const netUnknownName = 'Неизвестная сеть';
export const netCategoryLabel: Record<NetCategory, string> = { public: 'Общедоступная', private: 'Частная', domain: 'Доменная' };
export const netAdapterLabel: Record<NetAdapter, string> = { wifi: 'Wi-Fi', ethernet: 'Ethernet (кабель)', mobile: 'Мобильная связь', other: 'Другое' };
export const netConnectLabel: Record<NetConnect, string> = { '': 'Не менять', connect: 'Подключить', disconnect: 'Отключить — всё напрямую' };

// netAt is state.at as a time, or null when nothing acted yet.
export function netAt(st: NetState | undefined | null): Date | null {
  if (!st?.at || st.at.startsWith('0001')) return null;
  const d = new Date(st.at);
  return isNaN(d.getTime()) ? null : d;
}

// netActionText: «ничего» / «подключить» / «отключить» / «профиль «X»» /
// «профиль «X», подключить»; a profile no longer listed: «профиль (удалён)».
export function netActionText(a: NetAction, rulesets: { id: string; name: string }[] | null): string {
  const parts: string[] = [];
  if (a.ruleset) {
    const rs = rulesets?.find((r) => r.id === a.ruleset);
    parts.push(rs ? `профиль «${rs.name}»` : 'профиль (удалён)');
  }
  if (a.connect === 'connect') parts.push('подключить');
  if (a.connect === 'disconnect') parts.push('отключить');
  return parts.length ? parts.join(', ') : 'ничего';
}

// cleanNetModes drops empty groups and values, trims, and leaves out
// enabled: true (the default).
export function cleanNetModes(c: NetModes): NetModes {
  const list = <T extends string>(v: T[] | undefined, trim = true): T[] | undefined => {
    const out = (v ?? []).map((x) => (trim ? (x.trim() as T) : x)).filter((x) => x !== '');
    return out.length ? [...new Set(out)] : undefined;
  };
  return {
    version: 1,
    enabled: c.enabled,
    rules: c.rules.map((r) => {
      const m: NetMatch = {};
      const nets = (r.match.networks ?? []).filter((k) => k.id);
      if (nets.length) m.networks = nets.map((k) => ({ id: k.id, name: k.name }));
      const ssids = list(r.match.ssids, false);
      if (ssids) m.ssids = ssids;
      const names = list(r.match.names);
      if (names) m.names = names;
      const cats = list(r.match.categories);
      if (cats) m.categories = cats;
      const ads = list(r.match.adapters);
      if (ads) m.adapters = ads;
      const out: NetRule = { id: r.id, name: r.name.trim(), match: m };
      if (r.enabled === false) out.enabled = false;
      if (r.connect) out.connect = r.connect;
      if (r.ruleset) out.ruleset = r.ruleset;
      return out;
    }),
    unknown: { ...(c.unknown.connect ? { connect: c.unknown.connect } : {}), ...(c.unknown.ruleset ? { ruleset: c.unknown.ruleset } : {}) },
  };
}

// emptyNetModes is Go's netmode.Default(): «Неизвестная сеть: подключить».
export function emptyNetModes(): NetModes {
  return { version: 1, enabled: false, rules: [], unknown: { connect: 'connect' } };
}

// netUnknownWarn: «Неизвестная сеть» keeps the connection while a rule
// disconnects: after that network HyRoute stays off everywhere.
export function netUnknownWarn(c: NetModes): string | null {
  if (c.unknown.connect) return null;
  if (!c.rules.some((r) => r.enabled !== false && r.connect === 'disconnect')) return null;
  return 'После сети, где правило отключает HyRoute, в других сетях он останется отключённым — весь трафик пойдёт напрямую. Чтобы в незнакомых сетях HyRoute подключался сам, выберите «Подключить».';
}

// netUnknownRulesetNote: «Неизвестная сеть» keeps the profile while rules
// switch it.
export function netUnknownRulesetNote(c: NetModes): string | null {
  if (c.unknown.ruleset) return null;
  if (!c.rules.some((r) => r.enabled !== false && r.ruleset)) return null;
  return 'В других сетях останется профиль правил последней сети.';
}

// ==== cli ====

// hyroutectl's access: every command, the read-only ones, or no pipe.
export type CLIMode = 'full' | 'read' | 'off';

// The «Командная строка» card (Settings).
export interface CLIInfo {
  mode: CLIMode; // effective: 'off' while prefs.json is broken
  listening: boolean; // the pipe is up
  pipe: string; // the pipe's name (its SID)
  exe: string; // hyroutectl.exe next to HyRoute.exe, '' when missing
  dir: string; // the program folder (PATH hint)
  user: string; // DOMAIN\name commands are accepted from
  userDiffers: boolean; // over-the-shoulder UAC: not the account HyRoute runs as
  error?: string;
  prefsError?: string; // prefs.json failed to load: mode is 'off' and cannot be changed
}

interface GUI {
  CLIInfo(): Promise<CLIInfo>;
  SetCLIMode(mode: CLIMode): Promise<void>;
  // «Правила текстом» → JSON of the profile the page shows (its token).
  RulesJSON(ruleset: string): Promise<string>;
  // The «Правила текстом» preview: replace = mode «Все правила».
  ParseRulesTextFor(text: string, replace: boolean): Promise<RulesTextResult>;
}
