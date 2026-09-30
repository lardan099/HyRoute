// Package importer finds a Hysteria installation on a server and reads it
// into the controller without changing anything there: every command goes
// through remote.ReadOnly.
package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Level of a finding.
type Level string

const (
	// Warn: something to fix; the server needs attention.
	Warn Level = "warn"
	// Info: worth knowing, nothing is wrong.
	Info Level = "info"
)

// Finding is one thing the import noticed about the installation.
type Finding struct {
	ID      string `json:"id"`
	Level   Level  `json:"level"`
	Title   string `json:"title"`
	Details string `json:"details,omitempty"`
}

// Found is what an import found (no secrets: it goes into the job data).
type Found struct {
	Unit     string `json:"unit"`
	UnitPath string `json:"unitPath"`
	Binary   string `json:"binary"`
	Version  string `json:"version"`
	Config   string `json:"config"`
	// ConfigSHA256 is of the config as read; saving checks it again.
	ConfigSHA256 string           `json:"configSha256"`
	User         string           `json:"user"`
	Active       bool             `json:"active"`
	Enabled      bool             `json:"enabled"`
	Others       []string         `json:"others,omitempty"` // other Hysteria services
	Meta         model.ConfigMeta `json:"meta"`
	Unknown      []string         `json:"unknown,omitempty"` // config fields HyRoute does not know
	Findings     []Finding        `json:"findings"`
}

// NeedsAttention: some finding is a warning.
func (f *Found) NeedsAttention() bool {
	return slices.ContainsFunc(f.Findings, func(x Finding) bool { return x.Level == Warn })
}

func (f *Found) add(id string, l Level, title, details string) {
	f.Findings = append(f.Findings, Finding{ID: id, Level: l, Title: title, Details: details})
}

// Error is an import failure with a message for people.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Discover finds the Hysteria service on the server and reads its config.
// It returns the config as read (it holds passwords: never logged or put
// in job data). ex should be read-only; sudo: reading needs sudo.
func Discover(ctx context.Context, ex remote.Executor, sudo bool, now time.Time) (Found, []byte, error) {
	var f Found
	if ok, err := remote.HasSystemd(ctx, ex); err != nil {
		return f, nil, err
	} else if !ok {
		return f, nil, &Error{"На сервере нет systemd: HyRoute импортирует Hysteria, которая работает как служба systemd."}
	}
	u, others, err := findUnit(ctx, ex, sudo)
	if err != nil {
		return f, nil, err
	}
	f.Unit, f.UnitPath, f.Others = u.Name, u.FragmentPath, others
	f.Active, f.Enabled = u.ActiveState == "active", u.UnitFileState == "enabled"
	f.User = u.User

	argv := execArgv(u.ExecStart)
	if len(argv) == 0 || !path.IsAbs(argv[0]) {
		return f, nil, &Error{fmt.Sprintf("Не удалось понять, как служба %s запускает Hysteria (ExecStart).", u.Name)}
	}
	f.Binary = argv[0]
	// Only a program named hysteria* is asked its version: running an
	// unknown program is not reading.
	if strings.HasPrefix(path.Base(f.Binary), "hysteria") {
		v, err := remote.HysteriaVersion(ctx, ex, f.Binary)
		if err != nil {
			return f, nil, err
		}
		if v == "" {
			return f, nil, &Error{fmt.Sprintf("Служба %s запускает %s, но это не похоже на Hysteria (нет ответа на «version»).", u.Name, f.Binary)}
		}
		f.Version = v
	} else {
		f.add("version-unknown", Info, "Версия Hysteria не определена", f.Binary+" назван не hysteria*: HyRoute не запускает незнакомые программы даже для проверки версии.")
	}
	cfgPath, err := configPath(ctx, ex, argv[1:], u, sudo)
	if err != nil {
		return f, nil, err
	}
	f.Config = cfgPath
	raw, err := ex.ReadFile(ctx, cfgPath, sudo)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil, &Error{"Конфиг Hysteria не найден: " + cfgPath + "."}
	} else if err != nil {
		return f, nil, err
	}
	f.ConfigSHA256 = sha(raw)
	c, err := hyconfig.ParseServer(raw)
	if err != nil {
		return f, nil, &Error{"Конфиг " + cfgPath + " не разобрать: " + err.Error() + ". Импорт не меняет сервер; исправьте конфиг и повторите."}
	}
	f.Unknown = hyconfig.UnknownFields(c)

	f.Meta = model.ConfigMeta{Version: f.Version, Listen: c.Listen, Auth: strings.ToLower(c.Auth.Type), Obfs: strings.ToLower(c.Obfs.Type)}
	if l, err := hyconfig.ParseListen(c.Listen); err == nil {
		f.Meta.Ports = l.Ports
	}
	if err := f.inspectTLS(ctx, ex, c, sudo, now); err != nil {
		return f, nil, err
	}
	if err := f.inspectFiles(ctx, ex, sudo); err != nil {
		return f, nil, err
	}
	f.inspectService(u)
	f.inspectConfig(c)
	return f, raw, nil
}

// findUnit picks the Hysteria service: the standard one, others named
// hysteria*, or whatever service runs a program called hysteria. An
// active one wins; the rest are listed.
func findUnit(ctx context.Context, ex remote.Executor, sudo bool) (remote.SystemdUnit, []string, error) {
	names := []string{preflight.StdUnit}
	more, err := remote.ServiceUnits(ctx, ex, "hysteria*")
	if err != nil {
		return remote.SystemdUnit{}, nil, err
	}
	names = append(names, more...)
	ls, err := remote.Listeners(ctx, ex, sudo)
	if err != nil {
		return remote.SystemdUnit{}, nil, err
	}
	for _, l := range ls {
		if !strings.HasPrefix(l.Process, "hysteria") || l.PID == 0 {
			continue
		}
		if n, err := remote.UnitOfPID(ctx, ex, l.PID); err != nil {
			return remote.SystemdUnit{}, nil, err
		} else if n != "" {
			names = append(names, n)
		}
	}
	var found []remote.SystemdUnit
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		u, err := remote.Unit(ctx, ex, n)
		if err != nil {
			return remote.SystemdUnit{}, nil, err
		}
		if u.Exists() && u.ExecStart != "" {
			found = append(found, u)
		}
	}
	if len(found) == 0 {
		return remote.SystemdUnit{}, nil, &Error{"Hysteria на сервере не найдена: нет службы systemd с Hysteria. Разверните её через HyRoute."}
	}
	best := 0
	for i, u := range found {
		if u.ActiveState == "active" && found[best].ActiveState != "active" {
			best = i
		}
	}
	var others []string
	for i, u := range found {
		if i != best {
			others = append(others, u.Name)
		}
	}
	return found[best], others, nil
}

// execArgv is the command line of systemctl's ExecStart property:
// "{ path=… ; argv[]=/usr/local/bin/hysteria server -c … ; … }".
func execArgv(raw string) []string {
	_, rest, ok := strings.Cut(raw, "argv[]=")
	if !ok {
		return nil
	}
	cmd, _, _ := strings.Cut(rest, " ; ")
	return strings.Fields(cmd)
}

// configFlag is the -c/--config value in the arguments ("" when none).
func configFlag(args []string) string {
	for i, a := range args {
		switch {
		case a == "-c" || a == "--config":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "--config="):
			return strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-c="):
			return strings.TrimPrefix(a, "-c=")
		}
	}
	return ""
}

// configPath is the config the service reads: the -c flag (relative to
// its working directory), or the first config.yaml Hysteria looks for
// (working directory, ~/.hysteria, /etc/hysteria).
func configPath(ctx context.Context, ex remote.Executor, args []string, u remote.SystemdUnit, sudo bool) (string, error) {
	wd := u.WorkingDirectory
	home := ""
	if wd == "~" || wd == "" {
		user := u.User
		if user == "" {
			user = "root"
		}
		h, err := remote.UserHome(ctx, ex, user)
		if err != nil {
			return "", err
		}
		home = h
		if wd == "~" {
			wd = h
		}
	}
	if wd == "" {
		wd = "/"
	}
	if p := configFlag(args); p != "" {
		if !path.IsAbs(p) {
			p = path.Join(wd, p)
		}
		return path.Clean(p), nil
	}
	var cands []string
	for _, dir := range []string{wd, path.Join(home, ".hysteria"), "/etc/hysteria"} {
		if dir == "" || dir == ".hysteria" {
			continue
		}
		for _, name := range []string{"config.yaml", "config.yml", "config.json"} {
			cands = append(cands, path.Join(dir, name))
		}
	}
	for _, p := range cands {
		if ok, err := remote.PathExists(ctx, ex, p, sudo); err != nil {
			return "", err
		} else if ok {
			return p, nil
		}
	}
	return "", &Error{fmt.Sprintf("Служба %s запускает Hysteria без -c, и конфиг не найден там, где его ищет Hysteria.", u.Name)}
}

// inspectTLS fills the TLS part of the meta and checks the certificate
// file (never the key).
func (f *Found) inspectTLS(ctx context.Context, ex remote.Executor, c *hyconfig.Server, sudo bool, now time.Time) error {
	switch {
	case c.ACME != nil:
		f.Meta.TLS = "acme"
		if len(c.ACME.Domains) > 0 {
			f.Meta.SNI = strings.ToLower(c.ACME.Domains[0])
		}
		return nil
	case c.TLS == nil || c.TLS.Cert == "":
		return nil // Validate reports the missing TLS
	}
	f.Meta.TLS = "file"
	if !path.IsAbs(c.TLS.Cert) {
		f.add("cert-relative", Info, "Путь к сертификату относительный", "Hysteria ищет "+c.TLS.Cert+" от рабочего каталога службы; HyRoute не проверял файл.")
		return nil
	}
	b, err := ex.ReadFile(ctx, c.TLS.Cert, sudo)
	if errors.Is(err, fs.ErrNotExist) {
		f.add("cert-missing", Warn, "Нет файла сертификата", c.TLS.Cert+" не существует: Hysteria не запустится.")
		return nil
	} else if err != nil {
		return err
	}
	blk, _ := pem.Decode(b)
	var cert *x509.Certificate
	if blk != nil && blk.Type == "CERTIFICATE" {
		cert, _ = x509.ParseCertificate(blk.Bytes)
	}
	if cert == nil {
		f.add("cert-bad", Warn, "Сертификат не читается", c.TLS.Cert+" — не сертификат PEM.")
		return nil
	}
	if len(cert.DNSNames) > 0 {
		f.Meta.SNI = strings.ToLower(cert.DNSNames[0])
	}
	// Self-signed: issued by itself and signed by its own key (not a CA,
	// so CheckSignatureFrom would refuse it as a parent).
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		// Self-signed: clients check it by its fingerprint.
		f.Meta.TLS = "self-signed"
		sum := sha256.Sum256(blk.Bytes)
		f.Meta.PinSHA256 = hex.EncodeToString(sum[:])
	}
	switch left := cert.NotAfter.Sub(now); {
	case left <= 0:
		f.add("cert-expired", Warn, "Сертификат истёк", "Срок действия закончился "+cert.NotAfter.Format("02.01.2006")+"; клиенты без pin его отвергнут.")
	case left < 30*24*time.Hour && f.Meta.TLS == "file":
		f.add("cert-expiring", Warn, "Сертификат скоро истечёт", "Действует до "+cert.NotAfter.Format("02.01.2006")+". Обновите его или перейдите на ACME.")
	}
	return nil
}

// inspectFiles checks who may read the config (it holds passwords).
func (f *Found) inspectFiles(ctx context.Context, ex remote.Executor, sudo bool) error {
	fi, ok, err := remote.Stat(ctx, ex, f.Config, sudo)
	if err != nil || !ok {
		return err
	}
	switch {
	case fi.Mode&0o002 != 0:
		f.add("config-writable", Warn, "Конфиг может изменить любой пользователь сервера", fmt.Sprintf("%s: права %04o. Нужно 0640 (root и группа службы).", f.Config, fi.Mode))
	case fi.Mode&0o004 != 0:
		f.add("config-readable", Warn, "Конфиг с паролями читают все пользователи сервера", fmt.Sprintf("%s: права %04o. Достаточно 0640 (root и группа службы).", f.Config, fi.Mode))
	}
	return nil
}

func (f *Found) inspectService(u remote.SystemdUnit) {
	if !f.Active {
		f.add("inactive", Warn, "Служба не работает", fmt.Sprintf("%s в состоянии %s.", u.Name, u.ActiveState))
	}
	if !f.Enabled {
		f.add("not-enabled", Warn, "Служба не включена в автозапуск", "После перезагрузки сервера Hysteria не запустится.")
	}
	if u.User == "" || u.User == "root" {
		f.add("root", Warn, "Hysteria работает от root", "Официальный установщик запускает её от отдельного пользователя hysteria с нужными capabilities: так уязвимость в Hysteria не даёт прав root.")
	}
	if u.Restart == "no" || u.Restart == "" {
		f.add("no-restart", Info, "Служба не перезапускается после сбоя", "В unit нет Restart=: упавшая Hysteria останется выключенной.")
	}
	var odd []string
	if f.Binary != preflight.StdBinary {
		odd = append(odd, "программа "+f.Binary)
	}
	if f.Config != preflight.StdConfig {
		odd = append(odd, "конфиг "+f.Config)
	}
	if f.Unit != preflight.StdUnit {
		odd = append(odd, "служба "+f.Unit)
	}
	if len(odd) > 0 {
		f.add("paths", Info, "Нестандартное расположение", strings.Join(odd, ", ")+". HyRoute будет работать с ними как есть.")
	}
	if len(f.Others) > 0 {
		f.add("others", Info, "На сервере есть и другие службы Hysteria", "Импортирована "+f.Unit+"; остальные HyRoute не трогает: "+strings.Join(f.Others, ", ")+".")
	}
	if older(f.Version, hyrelease.DefaultVersion) {
		f.add("version", Info, "Hysteria устарела", "Установлена "+f.Version+", HyRoute ставит "+hyrelease.DefaultVersion+".")
	}
}

// minPassword: shorter auth and obfs passwords are guessable.
const minPassword = 12

func (f *Found) inspectConfig(c *hyconfig.Server) {
	for _, p := range c.Validate() {
		l, title := Warn, "Конфиг не пройдёт проверку Hysteria"
		if p.Warning {
			l, title = Info, "Замечание к конфигу"
		}
		f.add("config", l, title, p.Field+": "+p.Message)
	}
	if len(f.Unknown) > 0 {
		f.add("unknown", Info, "В конфиге есть поля, которых HyRoute не знает", strings.Join(f.Unknown, ", ")+". Они сохранятся как есть при любых правках.")
	}
	switch f.Meta.Auth {
	case "password":
		if n := len(c.Auth.Password); n > 0 && n < minPassword {
			f.add("weak-auth", Warn, "Короткий пароль клиентов", fmt.Sprintf("%d символов: такой пароль подбирается. Нужно не меньше %d.", n, minPassword))
		}
	case "userpass":
		f.add("userpass", Info, "У каждого клиента свой пароль", "Для ссылки клиента нужно будет выбрать пользователя.")
	case "http", "command":
		f.add("external-auth", Info, "Пароли проверяет внешняя программа", "HyRoute не знает паролей: ссылки клиентов придётся дополнять вручную.")
	}
	if f.Meta.Obfs == "salamander" {
		if n := len(c.Obfs.Salamander.Password); n > 0 && n < minPassword {
			f.add("weak-obfs", Warn, "Короткий пароль обфускации", fmt.Sprintf("%d символов; нужно не меньше %d.", n, minPassword))
		}
	}
	if c.Masquerade.Type == "" && f.Meta.Obfs == "" {
		f.add("no-masquerade", Info, "Нет сайта-маскировки", "Кто откроет сервер по HTTP/3, увидит «404 Not Found».")
	}
}

// older compares "v2.6.0" < "v2.12.3" (anything unparsable is not older).
func older(v, than string) bool {
	a, okA := semver(v)
	b, okB := semver(than)
	return okA && okB && slices.Compare(a, b) < 0
}

func semver(v string) ([]int, bool) {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return nil, false
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
