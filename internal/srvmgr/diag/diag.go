// Package diag builds the diagnostic bundle (P4-10): a ZIP a maintainer
// can read in a public issue. It holds the versions, the state of the
// servers with their latest checks and the OS from their last preflight,
// the logs of the latest jobs and of the controller, summaries and lint of
// the configs, and the controller's settings. Secrets never go in:
// summaries are built from masked configs, and every text passes through
// redact with the installation's own secrets registered. Names, addresses,
// domains and users are replaced by server-1, host-1, domain-1, user-1…
// the same way in every file; the table of replacements is not in the
// bundle.
package diag

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const (
	// DefaultJobs is how many of the latest jobs come with their logs.
	DefaultJobs = 20
	// MaxJobs bounds it.
	MaxJobs = 200
	// maxJobLines: a longer job log keeps its last lines.
	maxJobLines = 5000
	// checks is how many of the latest checks a server or a link has.
	checks = 20
	// preflightDepth is how many jobs of a server are searched for its
	// last preflight report.
	preflightDepth = 100
)

// Settings are the controller's settings as the bundle shows them: no
// paths, passphrases or keys. The maintenance command knows only the
// flags of the data directory (Panel false): the running panel may have
// been started with others.
type Settings struct {
	Panel           bool     `json:"panel"`
	Listen          string   `json:"listen,omitempty"`
	TLS             bool     `json:"tls,omitempty"`
	InsecureHTTP    bool     `json:"insecureHttp,omitempty"`
	TrustProxy      bool     `json:"trustProxy,omitempty"`
	AllowedHosts    []string `json:"allowedHosts,omitempty"`
	LogLevel        string   `json:"logLevel,omitempty"`
	MonitorInterval string   `json:"monitorInterval,omitempty"`
	GeoInterval     string   `json:"geoInterval,omitempty"`
	BackupInterval  string   `json:"backupInterval,omitempty"`
	BackupKeep      int      `json:"backupKeep"`
	BackupEncrypted bool     `json:"backupEncrypted"`
	// MasterKey is where the key comes from: env or file.
	MasterKey      string `json:"masterKey"`
	DefaultDataDir bool   `json:"defaultDataDir"`
}

// SettingsOf are the settings of cfg; panel: cfg holds all the flags of
// the running controller, not only those of the data directory.
// encrypted: the copies of the database are encrypted.
func SettingsOf(cfg config.Config, getenv func(string) string, encrypted, panel bool) Settings {
	s := Settings{Panel: panel, BackupKeep: cfg.BackupKeep, BackupEncrypted: encrypted, MasterKey: "file", DefaultDataDir: cfg.DataDir == config.DefaultDataDir()}
	if secrets.KeyInEnv(getenv) {
		s.MasterKey = "env"
	}
	if panel {
		s.Listen, s.TLS, s.InsecureHTTP, s.TrustProxy, s.LogLevel = cfg.Listen, cfg.TLS(), cfg.InsecureHTTP, cfg.TrustProxy, cfg.LogLevel
		s.AllowedHosts = cfg.AllowedHosts
		s.MonitorInterval, s.GeoInterval, s.BackupInterval = cfg.MonitorInterval.String(), cfg.GeoInterval.String(), cfg.BackupInterval.String()
	}
	return s
}

// Builder builds bundles.
type Builder struct {
	Store store.Store
	// Keys open the configs and the secrets the texts are cleaned of.
	Keys *secrets.Keyring
	// Logs is the controller's log buffer; nil in the maintenance
	// command, which has no running process to read it from.
	Logs *logbuf.Buffer
	// Geo are the controller's geo databases, Backups its copies of the
	// database (nil: none).
	Geo     *geo.Store
	Backups *backup.Manager
	Version string
	// Settings: SettingsOf.
	Settings Settings
	// Jobs is how many of the latest jobs come with their logs (0:
	// DefaultJobs, at most MaxJobs).
	Jobs int
	Now  func() time.Time
}

// File is a file of a bundle.
type File struct {
	Name string
	// About says what it holds, for the list before the download.
	About string
	Data  []byte
}

// Bundle is a built bundle.
type Bundle struct {
	At    time.Time
	Files []File
}

// Entry is a file as the list before the download shows it.
type Entry struct {
	Name  string `json:"name"`
	About string `json:"about"`
	Size  int    `json:"size"`
}

// Entries lists the files.
func (b *Bundle) Entries() []Entry {
	out := make([]Entry, len(b.Files))
	for i, f := range b.Files {
		out[i] = Entry{Name: f.Name, About: f.About, Size: len(f.Data)}
	}
	return out
}

// Name is the file name of the bundle.
func (b *Bundle) Name() string {
	return "hyroute-diag-" + b.At.UTC().Format("20060102-150405") + ".zip"
}

// WriteZip writes the bundle as a ZIP.
func (b *Bundle) WriteZip(w io.Writer) error {
	z := zip.NewWriter(w)
	for _, f := range b.Files {
		fw, err := z.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: b.At})
		if err != nil {
			return err
		}
		if _, err := fw.Write(f.Data); err != nil {
			return err
		}
	}
	return z.Close()
}

// build is one Build: what it read and the pseudonyms it gave.
type build struct {
	*Builder
	p     *pseudonyms
	at    time.Time
	notes []string

	schema    int
	servers   []model.Server
	users     []model.User
	chains    []model.Chain
	jobs      []model.Job // the latest, newest first
	steps     map[int64][]model.JobStep
	logs      map[int64][]model.JobLog
	cut       map[int64]int // lines left out at the top of a log
	configs   map[int64]*current
	preflight map[int64]model.Job // the job of the last preflight report
}

// current is the current config revision of a server.
type current struct {
	rev model.ServerConfig
	cfg *hyconfig.Server // nil: it does not open or parse
}

// Build reads the database and makes a bundle. It only reads.
func (b *Builder) Build(ctx context.Context) (*Bundle, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	x := &build{Builder: b, p: newPseudonyms(), at: now().UTC().Truncate(time.Second),
		steps: map[int64][]model.JobStep{}, logs: map[int64][]model.JobLog{}, cut: map[int64]int{},
		configs: map[int64]*current{}, preflight: map[int64]model.Job{}}
	if err := x.load(ctx); err != nil {
		return nil, err
	}
	x.register()
	return x.files(ctx)
}

func (x *build) jobCount() int {
	switch {
	case x.Jobs <= 0:
		return DefaultJobs
	case x.Jobs > MaxJobs:
		return MaxJobs
	}
	return x.Jobs
}

// load reads what the bundle needs and registers every secret it finds
// with the redactor: the passwords of the configs, the SSH credentials,
// the secrets of jobs and of cascade links.
func (x *build) load(ctx context.Context) error {
	var err error
	if x.schema, err = x.Store.SchemaVersion(ctx); err != nil {
		return err
	}
	if x.servers, err = x.Store.ListServers(ctx); err != nil {
		return err
	}
	slices.SortFunc(x.servers, func(a, b model.Server) int { return int(a.ID - b.ID) })
	if x.users, err = x.Store.ListUsers(ctx); err != nil {
		return err
	}
	slices.SortFunc(x.users, func(a, b model.User) int { return int(a.ID - b.ID) })
	if x.chains, err = x.Store.ListChains(ctx); err != nil {
		return err
	}
	slices.SortFunc(x.chains, func(a, b model.Chain) int { return int(a.ID - b.ID) })
	if x.jobs, err = x.Store.ListJobs(ctx, model.JobFilter{Limit: x.jobCount()}); err != nil {
		return err
	}
	for _, j := range x.jobs {
		if x.steps[j.ID], err = x.Store.JobSteps(ctx, j.ID); err != nil {
			return err
		}
		if err := x.loadLog(ctx, j.ID); err != nil {
			return err
		}
		x.jobSecret(ctx, j)
	}
	for _, s := range x.servers {
		if err := x.loadServer(ctx, s); err != nil {
			return err
		}
	}
	for _, c := range x.chains {
		for _, l := range c.Links {
			sealed, err := x.Store.LinkSecrets(ctx, c.ID, l.Idx)
			if err != nil || len(sealed) == 0 {
				continue
			}
			s, err := cascade.OpenSecrets(x.Keys, c.ID, l.Idx, sealed)
			if err != nil {
				x.notes = append(x.notes, fmt.Sprintf("Секреты связи %d каскада %d не открылись.", l.Idx, c.ID))
				continue
			}
			x.p.secret(s.ExitPassword, s.SOCKSUser, s.SOCKSPassword)
		}
	}
	return nil
}

// loadLog reads a job's log, its last maxJobLines lines.
func (x *build) loadLog(ctx context.Context, id int64) error {
	var all []model.JobLog
	for after := int64(0); ; {
		ls, err := x.Store.JobLogs(ctx, id, after, maxJobLines)
		if err != nil {
			return err
		}
		all = append(all, ls...)
		if len(all) > maxJobLines {
			x.cut[id] += len(all) - maxJobLines
			all = all[len(all)-maxJobLines:]
		}
		if len(ls) < maxJobLines {
			break
		}
		after = ls[len(ls)-1].Seq
	}
	x.logs[id] = all
	return nil
}

// jobSecret registers the sealed inputs of a job (DNS API keys, proxy
// passwords): every string in them.
func (x *build) jobSecret(ctx context.Context, j model.Job) {
	sealed, err := x.Store.JobSecret(ctx, j.ID)
	if err != nil || len(sealed) == 0 {
		return
	}
	b, err := x.Keys.Open(sealed, model.JobSecretContext(j.ID))
	if err != nil {
		x.notes = append(x.notes, fmt.Sprintf("Секретные параметры задания %d не открылись.", j.ID))
		return
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		x.p.secret(string(b))
		return
	}
	x.p.secret(stringsIn(v)...)
}

// stringsIn are the strings of a decoded JSON value.
func stringsIn(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, stringsIn(e)...)
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, stringsIn(e)...)
		}
		return out
	}
	return nil
}

// loadServer reads the SSH credentials (registered, never written), the
// current config and the last preflight report of a server.
func (x *build) loadServer(ctx context.Context, s model.Server) error {
	creds, err := x.Store.ServerCredentials(ctx, s.ID)
	if err != nil {
		return err
	}
	for _, c := range creds {
		v, err := x.Keys.OpenString(c.Sealed, model.CredContext(s.ID, c.Kind))
		if err != nil {
			x.notes = append(x.notes, fmt.Sprintf("Учётные данные SSH сервера %d не открылись.", s.ID))
			continue
		}
		x.p.secret(v)
	}
	rev, err := x.Store.CurrentConfig(ctx, s.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return err
	default:
		cur := &current{rev: rev}
		x.configs[s.ID] = cur
		b, err := x.Keys.Open(rev.Sealed, model.ConfigContext(s.ID, rev.Revision))
		if err != nil {
			x.notes = append(x.notes, fmt.Sprintf("Конфиг сервера %d (ревизия %d) не открылся.", s.ID, rev.Revision))
			break
		}
		if c, err := hyconfig.ParseServer(b); err == nil {
			cur.cfg = c
			x.p.secret(service.ConfigSecrets(c)...)
		}
	}
	jobs, err := x.Store.ListJobs(ctx, model.JobFilter{ServerID: s.ID, Limit: preflightDepth})
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.Kind != preflight.JobKind && j.Kind != deploy.JobKind || j.ServerID != s.ID {
			continue
		}
		var r preflight.Report
		if json.Unmarshal([]byte(j.Data["report"]), &r) == nil && r.OS != "" {
			x.preflight[s.ID] = j
			break
		}
	}
	return nil
}

// connectedRe is the line a job logs when it connects: the user and the
// host name of the server (uname -n).
var connectedRe = regexp.MustCompile(`Подключено как (\S+) к (\S+) \(`)

// register gives the pseudonyms of what the database names, in a fixed
// order: the same database makes the same bundle.
func (x *build) register() {
	p := x.p
	for _, s := range x.servers {
		p.name(kindServer, s.Name)
		p.name(kindHost, s.Host)
		p.name(kindUser, s.SSHUser)
	}
	for _, u := range x.users {
		p.name(kindUser, u.Username)
	}
	for _, c := range x.chains {
		p.name(kindChain, c.Name)
	}
	for _, s := range x.servers {
		cur := x.configs[s.ID]
		if cur == nil {
			continue
		}
		p.name(kindHost, hostOf(cur.rev.Meta.Listen))
		p.name(kindDomain, cur.rev.Meta.SNI)
		if c := cur.cfg; c != nil {
			if c.ACME != nil {
				for _, d := range c.ACME.Domains {
					p.name(kindDomain, d)
				}
				p.name(kindEmail, c.ACME.Email)
				p.name(kindHost, c.ACME.ListenHost)
			}
			p.name(kindDomain, hostOf(c.Masquerade.Proxy.URL))
			for _, o := range c.Outbounds {
				p.name(kindHost, hostOf(o.SOCKS5.Addr))
				p.name(kindUser, o.SOCKS5.Username)
				p.name(kindHost, hostOf(o.HTTP.URL))
				p.name(kindHost, o.Direct.BindIPv4)
				p.name(kindHost, o.Direct.BindIPv6)
			}
			for _, r := range []string{c.Resolver.TCP.Addr, c.Resolver.UDP.Addr, c.Resolver.TLS.Addr, c.Resolver.HTTPS.Addr} {
				p.name(kindHost, hostOf(r))
			}
			p.name(kindDomain, c.Resolver.TLS.SNI)
			p.name(kindDomain, c.Resolver.HTTPS.SNI)
			users := make([]string, 0, len(c.Auth.UserPass))
			for u := range c.Auth.UserPass {
				users = append(users, u)
			}
			sort.Strings(users)
			for _, u := range users {
				p.name(kindUser, u)
			}
		}
	}
	for _, c := range x.chains {
		for _, l := range c.Links {
			var lp cascade.Params
			if json.Unmarshal(l.Params, &lp) == nil {
				p.name(kindHost, hostOf(lp.CheckTarget))
			}
		}
	}
	jobs := slices.Clone(x.jobs)
	for _, s := range x.servers {
		if j, ok := x.preflight[s.ID]; ok {
			jobs = append(jobs, j)
		}
	}
	for _, j := range jobs {
		x.registerJob(j)
	}
	for _, h := range x.Settings.AllowedHosts {
		p.name(kindDomain, h)
	}
	if x.Settings.Listen != "" {
		p.name(kindHost, hostOf(x.Settings.Listen))
	}
}

// registerJob gives pseudonyms to the names a job learned or was given:
// the host name and user of the server, the users and names of its
// params, those in the line it logs when it connects.
func (x *build) registerJob(j model.Job) {
	p := x.p
	p.name(kindHost, j.Data["hostname"])
	p.name(kindUser, j.Data["user"])
	var probe struct{ User, Hostname string }
	if json.Unmarshal([]byte(j.Data["probe"]), &probe) == nil {
		p.name(kindHost, probe.Hostname)
		p.name(kindUser, probe.User)
	}
	var params map[string]any
	if json.Unmarshal(j.Params, &params) == nil {
		for k, v := range params {
			switch strings.ToLower(k) {
			case "users", "user", "username":
				for _, u := range stringsIn(v) {
					p.name(kindUser, u)
				}
			case "domain", "sni":
				for _, d := range stringsIn(v) {
					p.name(kindDomain, d)
				}
			case "email":
				for _, e := range stringsIn(v) {
					p.name(kindEmail, e)
				}
			}
		}
	}
	for _, l := range x.logs[j.ID] {
		if m := connectedRe.FindStringSubmatch(l.Message); m != nil {
			p.name(kindUser, m[1])
			p.name(kindHost, m[2])
		}
	}
}

// jsonFile is v as an indented JSON file.
func jsonFile(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		// Only the types below go in: they always encode.
		panic(err)
	}
	return buf.Bytes()
}

func (x *build) files(ctx context.Context) (*Bundle, error) {
	var files []File
	add := func(name, about string, data []byte) {
		files = append(files, File{Name: name, About: about, Data: data})
	}
	settings, err := x.settingsFile(ctx)
	if err != nil {
		return nil, err
	}
	servers, err := x.serversFile(ctx)
	if err != nil {
		return nil, err
	}
	configs := x.configsFile(ctx)
	chains, err := x.chainsFile(ctx)
	if err != nil {
		return nil, err
	}
	jobs, logs := x.jobFiles()
	// version.json is made after the files above: it has their notes.
	add("version.json", "Версии программы и схемы базы, система controller, что не вошло в пакет", jsonFile(x.versionFile()))
	add("settings.json", "Настройки панели без путей и секретов, версии мастер-ключа, базы geo, копии базы", jsonFile(settings))
	add("servers.json", "Серверы: состояние, установка Hysteria, ОС из последней проверки готовности, последние проверки и замер", jsonFile(servers))
	add("configs.json", "Сводки текущих конфигов серверов (из замаскированных конфигов) и проверки правил маршрутизации", jsonFile(configs))
	add("chains.json", "Каскады: узлы, связи, их состояние и последние проверки", jsonFile(chains))
	add("jobs.json", fmt.Sprintf("Последние задания (%d): шаги, ошибки, параметры и результаты", len(x.jobs)), jsonFile(jobs))
	files = append(files, logs...)
	if x.Logs != nil {
		add("controller.log", "Последние записи журнала панели", x.controllerLog())
	}
	m := manifest{Built: x.at, Source: x.source(), Files: (&Bundle{Files: files}).Entries()}
	head := []File{
		{Name: "README.txt", About: "Что в пакете и как он обезличен", Data: []byte(readme)},
		{Name: "manifest.json", About: "Список файлов пакета", Data: jsonFile(m)},
	}
	return &Bundle{At: x.at, Files: append(head, files...)}, nil
}

func (x *build) source() string {
	if x.Settings.Panel {
		return "panel"
	}
	return "command"
}

type manifest struct {
	Built  time.Time `json:"built"`
	Source string    `json:"source"`
	Files  []Entry   `json:"files"`
}

const readme = `Диагностический пакет HyRoute Server

Пакет собран для разбора проблемы: его можно приложить к issue.

Что в нём:
  version.json    версии программы и схемы базы, система controller
  settings.json   настройки панели без путей и секретов
  servers.json    серверы: состояние, установка, ОС из последней проверки
                  готовности, последние проверки и замер
  configs.json    сводки текущих конфигов и проверки правил маршрутизации
  chains.json     каскады: связи, их состояние и проверки
  jobs.json       последние задания: шаги, ошибки, параметры
  jobs/*.log      журналы этих заданий
  controller.log  последние записи журнала панели (только в пакете из
                  панели: у команды hyroute-server diag его нет)

Как пакет обезличен:
  - пароли, ключи, токены, ссылки для клиентов, отпечатки и pinSHA256 не
    попадают в пакет: вместо них [REDACTED]; сводки конфигов собраны из
    конфигов со скрытыми секретами;
  - названия серверов, адреса (IPv4, IPv6, имена хостов), домены, SNI,
    адреса почты и имена пользователей заменены на server-1, host-1,
    domain-1, email-1, user-1 и так далее. Одно и то же значение заменено
    одинаково во всех файлах пакета;
  - таблица замен в пакет не входит: она есть только у того, кто собрал
    пакет, и только пока он собирается. Номер в server-N — по порядку
    добавления серверов в панель, поле id — номер сервера в панели;
  - общие имена (root, localhost, адреса локальных сетей, публичные DNS)
    и адреса сервисов GitHub и Hysteria оставлены как есть.

Перед отправкой файлы можно открыть и проверить.
`

type versionJSON struct {
	Version string    `json:"version"`
	Schema  int       `json:"schema"`
	Go      string    `json:"go"`
	OS      string    `json:"os"`
	Arch    string    `json:"arch"`
	Built   time.Time `json:"built"`
	// Source: panel (the button in Settings) or command (hyroute-server
	// diag).
	Source  string `json:"source"`
	Servers int    `json:"servers"`
	Chains  int    `json:"chains"`
	Jobs    int    `json:"jobs"`
	// Notes say what could not go in.
	Notes []string `json:"notes,omitempty"`
}

func (x *build) versionFile() versionJSON {
	notes := make([]string, len(x.notes))
	for i, n := range x.notes {
		notes[i] = x.p.String(n)
	}
	return versionJSON{Version: x.Version, Schema: x.schema, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, Built: x.at,
		Source: x.source(), Servers: len(x.servers), Chains: len(x.chains), Jobs: len(x.jobs), Notes: notes}
}

type settingsJSON struct {
	Settings
	// KeyVersion is the current version of the master key, KeyVersions
	// all it has, DataVersions those the data is sealed with.
	KeyVersion   uint32   `json:"keyVersion"`
	KeyVersions  []uint32 `json:"keyVersions"`
	DataVersions []uint32 `json:"dataVersions,omitempty"`
	// Users are the panel's users by role.
	Users          map[model.Role]int `json:"users"`
	UnfinishedJobs int                `json:"unfinishedJobs"`
	Geo            *geoJSON           `json:"geo,omitempty"`
	Backups        *backupsJSON       `json:"backups,omitempty"`
}

type geoJSON struct {
	Release   string    `json:"release"`
	At        time.Time `json:"at"`
	CheckedAt time.Time `json:"checkedAt"`
}

type backupsJSON struct {
	Count int        `json:"count"`
	Last  *time.Time `json:"last,omitempty"`
}

func (x *build) settingsFile(ctx context.Context) (settingsJSON, error) {
	s := x.Settings
	s.Listen = x.p.String(s.Listen)
	s.AllowedHosts = nil
	for _, h := range x.Settings.AllowedHosts {
		s.AllowedHosts = append(s.AllowedHosts, x.p.name(kindDomain, h))
	}
	out := settingsJSON{Settings: s, KeyVersion: x.Keys.Current(), KeyVersions: x.Keys.Versions(), Users: map[model.Role]int{}}
	if sv, ok := x.Store.(interface {
		SealedVersions(context.Context) ([]uint32, error)
	}); ok {
		v, err := sv.SealedVersions(ctx)
		if err != nil {
			return out, err
		}
		slices.Sort(v)
		out.DataVersions = v
	}
	for _, u := range x.users {
		out.Users[u.Role]++
	}
	unfinished, err := x.Store.UnfinishedJobs(ctx)
	if err != nil {
		return out, err
	}
	out.UnfinishedJobs = len(unfinished)
	if x.Geo != nil {
		if i, err := x.Geo.Info(); err == nil && i.Release != "" {
			out.Geo = &geoJSON{Release: x.p.String(i.Release), At: i.At.UTC(), CheckedAt: i.CheckedAt.UTC()}
		}
	}
	if x.Backups != nil {
		if items, err := x.Backups.List(); err == nil {
			out.Backups = &backupsJSON{Count: len(items)}
			if len(items) > 0 {
				last := items[0].At.UTC()
				out.Backups.Last = &last
			}
		}
	}
	return out, nil
}

type serverJSON struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	Host         string            `json:"host"`
	SSHPort      int               `json:"sshPort"`
	SSHUser      string            `json:"sshUser"`
	AuthType     model.AuthType    `json:"authType"`
	Role         model.ServerRole  `json:"role"`
	State        model.ServerState `json:"state"`
	Country      string            `json:"country,omitempty"`
	HopInterval  int               `json:"hopInterval,omitempty"`
	CreatedAt    time.Time         `json:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
	Installation *installationJSON `json:"installation,omitempty"`
	Geo          *serverGeoJSON    `json:"geo,omitempty"`
	Preflight    *preflightJSON    `json:"preflight,omitempty"`
	Health       []healthJSON      `json:"health"`
	Metric       *metricJSON       `json:"metric,omitempty"`
}

type installationJSON struct {
	Binary   string    `json:"binary"`
	Config   string    `json:"config"`
	Unit     string    `json:"unit"`
	User     string    `json:"user"`
	Version  string    `json:"version"`
	Managed  bool      `json:"managed"`
	At       time.Time `json:"at"`
	Firewall struct {
		Tool  string `json:"tool,omitempty"`
		Ports string `json:"ports,omitempty"`
		Keep  bool   `json:"keep,omitempty"`
	} `json:"firewall"`
}

type serverGeoJSON struct {
	Release string    `json:"release"`
	JobID   int64     `json:"jobId,omitempty"`
	At      time.Time `json:"at"`
}

type preflightJSON struct {
	JobID  int64     `json:"jobId"`
	Kind   string    `json:"kind"`
	At     time.Time `json:"at"`
	Report any       `json:"report"`
}

type healthJSON struct {
	At        time.Time         `json:"at"`
	Status    model.ServerState `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	SSHMillis int               `json:"sshMs"`
	Service   string            `json:"service,omitempty"`
	Listening *bool             `json:"listening,omitempty"`
	UDP       string            `json:"udp,omitempty"`
	UDPMillis int               `json:"udpMs,omitempty"`
	Egress    string            `json:"egress,omitempty"`
}

type metricJSON struct {
	At           time.Time `json:"at"`
	CPU          *float64  `json:"cpu,omitempty"`
	MemUsedMiB   float64   `json:"memUsedMiB"`
	MemTotalMiB  float64   `json:"memTotalMiB"`
	DiskUsedMiB  float64   `json:"diskUsedMiB"`
	DiskTotalMiB float64   `json:"diskTotalMiB"`
	Load1        float64   `json:"load1"`
	RxBps        *float64  `json:"rxBps,omitempty"`
	TxBps        *float64  `json:"txBps,omitempty"`
}

func (x *build) serversFile(ctx context.Context) ([]serverJSON, error) {
	p := x.p
	geos, err := x.Store.ServerGeos(ctx)
	if err != nil {
		return nil, err
	}
	metrics, err := x.Store.LatestMetrics(ctx, x.at.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	out := []serverJSON{}
	for _, s := range x.servers {
		j := serverJSON{ID: s.ID, Name: p.name(kindServer, s.Name), Host: p.name(kindHost, s.Host), SSHPort: s.SSHPort, SSHUser: p.name(kindUser, s.SSHUser),
			AuthType: s.AuthType, Role: s.Role, State: s.State, Country: s.Country, HopInterval: s.HopInterval, CreatedAt: s.CreatedAt.UTC(), UpdatedAt: s.UpdatedAt.UTC(), Health: []healthJSON{}}
		in, err := x.Store.Installation(ctx, s.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		default:
			ij := &installationJSON{Binary: p.String(in.Binary), Config: p.String(in.Config), Unit: p.String(in.Unit), User: p.name(kindUser, in.User),
				Version: p.String(in.Version), Managed: in.Managed, At: in.At.UTC()}
			ij.Firewall.Tool, ij.Firewall.Ports, ij.Firewall.Keep = in.Firewall.Tool, in.Firewall.Ports, in.Firewall.Keep
			j.Installation = ij
		}
		for _, g := range geos {
			if g.ServerID == s.ID {
				j.Geo = &serverGeoJSON{Release: p.String(g.Release), JobID: g.JobID, At: g.At.UTC()}
			}
		}
		if pj, ok := x.preflight[s.ID]; ok {
			at := pj.FinishedAt
			if at.IsZero() {
				at = pj.CreatedAt
			}
			j.Preflight = &preflightJSON{JobID: pj.ID, Kind: pj.Kind, At: at.UTC(), Report: p.raw([]byte(pj.Data["report"]))}
		}
		hs, err := x.Store.HealthHistory(ctx, s.ID, time.Time{}, checks)
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			j.Health = append(j.Health, healthJSON{At: h.At.UTC(), Status: h.Status, Reason: p.String(h.Reason), SSHMillis: h.SSHMillis, Service: p.String(h.Service),
				Listening: h.Listening, UDP: h.UDP, UDPMillis: h.UDPMillis, Egress: p.String(h.Egress)})
		}
		for _, m := range metrics {
			if m.ServerID == s.ID {
				j.Metric = &metricJSON{At: m.At.UTC(), CPU: m.CPU, MemUsedMiB: m.MemUsedMiB, MemTotalMiB: m.MemTotalMiB, DiskUsedMiB: m.DiskUsedMiB, DiskTotalMiB: m.DiskTotalMiB,
					Load1: m.Load1, RxBps: m.RxBps, TxBps: m.TxBps}
			}
		}
		out = append(out, j)
	}
	return out, nil
}

type configJSON struct {
	ServerID     int64              `json:"serverId"`
	Server       string             `json:"server"`
	Revision     int                `json:"revision"`
	Source       model.ConfigSource `json:"source"`
	FromRevision int                `json:"fromRevision,omitempty"`
	JobID        int64              `json:"jobId,omitempty"`
	At           time.Time          `json:"at"`
	// Meta is the summary the panel keeps, without the pin.
	Meta    metaJSON     `json:"meta"`
	Summary *summaryJSON `json:"summary,omitempty"`
	// Unknown are the fields HyRoute does not know.
	Unknown []string   `json:"unknown,omitempty"`
	Error   string     `json:"error,omitempty"`
	Lint    []lintJSON `json:"lint"`
}

type metaJSON struct {
	Version string `json:"version,omitempty"`
	Listen  string `json:"listen,omitempty"`
	Ports   string `json:"ports,omitempty"`
	TLS     string `json:"tls,omitempty"`
	SNI     string `json:"sni,omitempty"`
	Obfs    string `json:"obfs,omitempty"`
	Auth    string `json:"auth,omitempty"`
}

type summaryJSON struct {
	TLS            string         `json:"tls,omitempty"`
	ACMEDomains    []string       `json:"acmeDomains,omitempty"`
	ACMECA         string         `json:"acmeCa,omitempty"`
	ACMEChallenge  string         `json:"acmeChallenge,omitempty"`
	ACMEDNS        string         `json:"acmeDns,omitempty"`
	SNIGuard       string         `json:"sniGuard,omitempty"`
	ECH            bool           `json:"ech,omitempty"`
	AuthType       string         `json:"authType,omitempty"`
	Users          int            `json:"users,omitempty"`
	Obfs           string         `json:"obfs,omitempty"`
	Masquerade     string         `json:"masquerade,omitempty"`
	MasqueradeURL  string         `json:"masqueradeUrl,omitempty"`
	MasqueradeTCP  bool           `json:"masqueradeTcp,omitempty"`
	BandwidthUp    string         `json:"bandwidthUp,omitempty"`
	BandwidthDown  string         `json:"bandwidthDown,omitempty"`
	IgnoreClientBW bool           `json:"ignoreClientBandwidth,omitempty"`
	Congestion     string         `json:"congestion,omitempty"`
	QUIC           *quicJSON      `json:"quic,omitempty"`
	SpeedTest      bool           `json:"speedTest,omitempty"`
	DisableUDP     bool           `json:"disableUDP,omitempty"`
	UDPIdleTimeout string         `json:"udpIdleTimeout,omitempty"`
	Resolver       string         `json:"resolver,omitempty"`
	ResolverAddr   string         `json:"resolverAddr,omitempty"`
	Sniff          bool           `json:"sniff,omitempty"`
	ACLRules       int            `json:"aclRules,omitempty"`
	ACLFile        bool           `json:"aclFile,omitempty"`
	GeoIP          string         `json:"geoip,omitempty"`
	GeoSite        string         `json:"geosite,omitempty"`
	Outbounds      []outboundJSON `json:"outbounds,omitempty"`
	TrafficStats   bool           `json:"trafficStats,omitempty"`
	Mimic          bool           `json:"mimic,omitempty"`
	Realm          bool           `json:"realm,omitempty"`
}

type quicJSON struct {
	InitStreamReceiveWindow uint64 `json:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64 `json:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64 `json:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64 `json:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          string `json:"maxIdleTimeout,omitempty"`
	MaxIncomingStreams      int64  `json:"maxIncomingStreams,omitempty"`
	DisablePathMTUDiscovery bool   `json:"disablePathMTUDiscovery,omitempty"`
}

type outboundJSON struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Addr string `json:"addr,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type lintJSON struct {
	Rule    int    `json:"rule"`
	Line    int    `json:"line,omitempty"`
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// configsFile summarizes the current configs. The summary is read from
// the config with its secrets masked (apply.Mask); the lint is the
// routing editor's.
func (x *build) configsFile(ctx context.Context) []configJSON {
	p := x.p
	ed := &apply.Editor{Store: x.Store, Keys: x.Keys}
	rs := &routing.Service{Editor: ed, Chains: x.Store}
	if x.Geo != nil {
		rs.Geo = x.Geo.Loader()
	}
	out := []configJSON{}
	for _, s := range x.servers {
		cur := x.configs[s.ID]
		if cur == nil {
			continue
		}
		r, m := cur.rev, cur.rev.Meta
		j := configJSON{ServerID: s.ID, Server: p.name(kindServer, s.Name), Revision: r.Revision, Source: r.Source, FromRevision: r.FromRevision, JobID: r.JobID, At: r.At.UTC(),
			Meta: metaJSON{Version: p.String(m.Version), Listen: p.String(m.Listen), Ports: p.String(m.Ports), TLS: m.TLS, SNI: p.name(kindDomain, m.SNI), Obfs: m.Obfs, Auth: m.Auth},
			Lint: []lintJSON{}}
		// The error texts of a config that does not open or parse are
		// left out: they may quote it.
		if view, err := ed.Open(ctx, s.ID); err != nil {
			j.Error = "Конфиг не открывается или не разбирается как YAML."
		} else if c, err := hyconfig.ParseServer([]byte(view.YAML)); err != nil {
			j.Error = "Конфиг не разбирается как конфиг Hysteria."
		} else {
			j.Summary = x.summary(c, m)
			for _, u := range view.Unknown {
				j.Unknown = append(j.Unknown, p.String(u))
			}
		}
		if v, err := rs.Open(ctx, s.ID); err == nil {
			for _, pr := range v.Problems {
				j.Lint = append(j.Lint, lintJSON{Rule: pr.Rule, Line: pr.Line, Level: pr.Level, Code: pr.Code, Message: p.String(pr.Message), Detail: p.String(pr.Detail)})
			}
		}
		out = append(out, j)
	}
	return out
}

// summary is a masked config in brief: no rules, users or texts of its
// own, addresses through the pseudonyms.
func (x *build) summary(c *hyconfig.Server, m model.ConfigMeta) *summaryJSON {
	p := x.p
	s := &summaryJSON{TLS: m.TLS, ECH: c.ECH.KeyPath != "", AuthType: c.Auth.Kind(), Users: len(c.Auth.UserPass),
		Obfs: strings.ToLower(c.Obfs.Type), Masquerade: strings.ToLower(c.Masquerade.Type), MasqueradeURL: p.String(c.Masquerade.Proxy.URL),
		MasqueradeTCP: c.Masquerade.ListenHTTP != "" || c.Masquerade.ListenHTTPS != "",
		BandwidthUp:   c.Bandwidth.Up, BandwidthDown: c.Bandwidth.Down, IgnoreClientBW: c.IgnoreClientBandwidth, Congestion: strings.ToLower(c.Congestion.Type),
		SpeedTest: c.SpeedTest, DisableUDP: c.DisableUDP, UDPIdleTimeout: string(c.UDPIdleTimeout),
		Resolver: strings.ToLower(c.Resolver.Type), Sniff: c.Sniff.Enable,
		ACLRules: len(c.ACL.Inline), ACLFile: c.ACL.File != "", GeoIP: p.String(c.ACL.GeoIP), GeoSite: p.String(c.ACL.GeoSite),
		TrafficStats: c.TrafficStats.Listen != "", Mimic: c.Mimic.Enabled, Realm: strings.HasPrefix(strings.ToLower(m.Listen), "realm")}
	if c.ACME != nil {
		s.ACMECA, s.ACMEChallenge, s.ACMEDNS = c.ACME.CA, c.ACME.Type, c.ACME.DNS.Name
		for _, d := range c.ACME.Domains {
			s.ACMEDomains = append(s.ACMEDomains, p.name(kindDomain, d))
		}
	}
	if c.TLS != nil {
		s.SNIGuard = c.TLS.SNIGuard
	}
	if c.Congestion.BBRProfile != "" {
		s.Congestion += " " + c.Congestion.BBRProfile
	}
	if q := c.QUIC; q.InitStreamReceiveWindow+q.MaxStreamReceiveWindow+q.InitConnReceiveWindow+q.MaxConnReceiveWindow != 0 || q.MaxIdleTimeout != "" || q.MaxIncomingStreams != 0 || q.DisablePathMTUDiscovery {
		s.QUIC = &quicJSON{q.InitStreamReceiveWindow, q.MaxStreamReceiveWindow, q.InitConnReceiveWindow, q.MaxConnReceiveWindow, string(q.MaxIdleTimeout), q.MaxIncomingStreams, q.DisablePathMTUDiscovery}
	}
	switch r := c.Resolver; strings.ToLower(r.Type) {
	case "tcp":
		s.ResolverAddr = p.String(r.TCP.Addr)
	case "udp":
		s.ResolverAddr = p.String(r.UDP.Addr)
	case "tls":
		s.ResolverAddr = p.String(r.TLS.Addr)
	case "https":
		s.ResolverAddr = p.String(r.HTTPS.Addr)
	}
	for _, o := range c.Outbounds {
		oj := outboundJSON{Name: p.String(o.Name), Type: strings.ToLower(o.Type), Mode: o.Direct.Mode}
		switch oj.Type {
		case "socks5":
			oj.Addr = p.String(o.SOCKS5.Addr)
		case "http":
			oj.Addr = p.String(o.HTTP.URL)
		}
		s.Outbounds = append(s.Outbounds, oj)
	}
	return s
}

type chainJSON struct {
	ID    int64      `json:"id"`
	Name  string     `json:"name"`
	Nodes []nodeJSON `json:"nodes"`
	Links []linkJSON `json:"links"`
}

type nodeJSON struct {
	ServerID int64            `json:"serverId"`
	Server   string           `json:"server"`
	Role     model.ServerRole `json:"role"`
}

type linkJSON struct {
	Idx          int             `json:"idx"`
	From         string          `json:"from"`
	To           string          `json:"to"`
	State        model.LinkState `json:"state"`
	Params       any             `json:"params"`
	FromRevision int             `json:"fromRevision,omitempty"`
	ToRevision   int             `json:"toRevision,omitempty"`
	UpdatedAt    time.Time       `json:"updatedAt"`
	Checks       []linkCheckJSON `json:"checks"`
}

type linkCheckJSON struct {
	At              time.Time         `json:"at"`
	Status          model.ServerState `json:"status"`
	Reason          string            `json:"reason,omitempty"`
	Service         string            `json:"service,omitempty"`
	HandshakeMillis int               `json:"handshakeMs,omitempty"`
	TCPMillis       int               `json:"tcpMs,omitempty"`
}

// serverName is the pseudonym of server id.
func (x *build) serverName(id int64) string {
	for _, s := range x.servers {
		if s.ID == id {
			return x.p.name(kindServer, s.Name)
		}
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", id)
}

func (x *build) chainsFile(ctx context.Context) ([]chainJSON, error) {
	p := x.p
	out := []chainJSON{}
	for _, c := range x.chains {
		j := chainJSON{ID: c.ID, Name: p.name(kindChain, c.Name), Nodes: []nodeJSON{}, Links: []linkJSON{}}
		for i, n := range c.Nodes {
			j.Nodes = append(j.Nodes, nodeJSON{ServerID: n, Server: x.serverName(n), Role: model.NodeRole(i, len(c.Nodes))})
		}
		for _, l := range c.Links {
			lj := linkJSON{Idx: l.Idx, From: x.serverName(l.From), To: x.serverName(l.To), State: l.State, Params: p.raw(l.Params),
				FromRevision: l.FromRevision, ToRevision: l.ToRevision, UpdatedAt: l.UpdatedAt.UTC(), Checks: []linkCheckJSON{}}
			cs, err := x.Store.LinkChecks(ctx, c.ID, l.Idx, time.Time{}, checks)
			if err != nil {
				return nil, err
			}
			for _, k := range cs {
				lj.Checks = append(lj.Checks, linkCheckJSON{At: k.At.UTC(), Status: k.Status, Reason: p.String(k.Reason), Service: p.String(k.Service),
					HandshakeMillis: k.HandshakeMillis, TCPMillis: k.TCPMillis})
			}
			j.Links = append(j.Links, lj)
		}
		out = append(out, j)
	}
	return out, nil
}

type jobJSON struct {
	ID           int64          `json:"id"`
	Kind         string         `json:"kind"`
	ServerID     int64          `json:"serverId,omitempty"`
	Server       string         `json:"server,omitempty"`
	Servers      []string       `json:"servers,omitempty"`
	State        model.JobState `json:"state"`
	CurrentStep  string         `json:"currentStep,omitempty"`
	Attempt      int            `json:"attempt"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
	ErrorDetails string         `json:"errorDetails,omitempty"`
	CreatedBy    string         `json:"createdBy,omitempty"`
	CreatedAt    time.Time      `json:"createdAt"`
	StartedAt    *time.Time     `json:"startedAt,omitempty"`
	FinishedAt   *time.Time     `json:"finishedAt,omitempty"`
	Params       any            `json:"params,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
	Steps        []stepJSON     `json:"steps"`
	// Log is the file of its log in the bundle.
	Log string `json:"log"`
}

type stepJSON struct {
	Idx        int             `json:"idx"`
	Name       string          `json:"name"`
	Phase      model.JobState  `json:"phase"`
	State      model.StepState `json:"state"`
	Attempt    int             `json:"attempt"`
	StartedAt  *time.Time      `json:"startedAt,omitempty"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func (x *build) userName(id int64) string {
	for _, u := range x.users {
		if u.ID == id {
			return x.p.name(kindUser, u.Username)
		}
	}
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("#%d", id)
}

// jobFiles are jobs.json and a log file of each job.
func (x *build) jobFiles() ([]jobJSON, []File) {
	p := x.p
	out := []jobJSON{}
	var logs []File
	for _, j := range x.jobs {
		name := fmt.Sprintf("jobs/%06d-%s.log", j.ID, safeName(j.Kind))
		jj := jobJSON{ID: j.ID, Kind: j.Kind, ServerID: j.ServerID, Server: x.serverName(j.ServerID), State: j.State, CurrentStep: j.CurrentStep, Attempt: j.Attempt,
			ErrorMessage: p.String(j.ErrorMessage), ErrorDetails: p.String(j.ErrorDetails), CreatedBy: x.userName(j.CreatedBy), CreatedAt: j.CreatedAt.UTC(),
			StartedAt: optTime(j.StartedAt), FinishedAt: optTime(j.FinishedAt), Params: p.raw(j.Params), Steps: []stepJSON{}, Log: name}
		for _, id := range j.Servers {
			jj.Servers = append(jj.Servers, x.serverName(id))
		}
		if len(j.Data) > 0 {
			jj.Data = map[string]any{}
			keys := make([]string, 0, len(j.Data))
			for k := range j.Data {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := j.Data[k]
				switch {
				case maskKey(k) && v != "":
					jj.Data[k] = redact.Mask
				case strings.HasPrefix(v, "{") || strings.HasPrefix(v, "["):
					jj.Data[k] = p.raw([]byte(v))
				default:
					jj.Data[k] = p.String(v)
				}
			}
		}
		for _, s := range x.steps[j.ID] {
			jj.Steps = append(jj.Steps, stepJSON{Idx: s.Idx, Name: s.Name, Phase: s.Phase, State: s.State, Attempt: s.Attempt,
				StartedAt: optTime(s.StartedAt), FinishedAt: optTime(s.FinishedAt), Error: p.String(s.Error)})
		}
		out = append(out, jj)
		var b strings.Builder
		if n := x.cut[j.ID]; n > 0 {
			fmt.Fprintf(&b, "… первые строки журнала (%d) в пакет не вошли …\n", n)
		}
		for _, l := range x.logs[j.ID] {
			fmt.Fprintf(&b, "%s %-5s [%s] %s\n", l.Time.UTC().Format(time.RFC3339), l.Level, p.String(l.Step), p.String(l.Message))
		}
		logs = append(logs, File{Name: name, About: fmt.Sprintf("Журнал задания %d (%s)", j.ID, j.Kind), Data: []byte(b.String())})
	}
	return out, logs
}

// safeName keeps letters, digits and dashes of a job kind for a file name.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// controllerLog is the log buffer, oldest first.
func (x *build) controllerLog() []byte {
	recs := x.Logs.Records(logbuf.Filter{})
	var b strings.Builder
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		fmt.Fprintf(&b, "%s %-5s %s", r.Time.UTC().Format(time.RFC3339), r.Level, x.p.String(r.Message))
		if r.Attrs != "" {
			b.WriteString(" " + x.p.String(r.Attrs))
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
