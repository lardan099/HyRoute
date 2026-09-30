package importer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// officialConfig is the config of the official installer (get.hy2.sh)
// with fake values.
const officialConfig = `# listen: :443

acme:
  domains:
    - vpn.example.com
  email: admin@example.com

auth:
  type: password
  password: fake-official-pass

masquerade:
  type: proxy
  proxy:
    url: https://news.example.com/
    rewriteHost: true
`

func execStart(argv string) string {
	return "{ path=" + strings.Fields(argv)[0] + " ; argv[]=" + argv + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=4242 ; code=(null) ; status=0/0 }"
}

type unit struct {
	load, active, fragment, exec, user, wd, fileState, restart string
}

// machine is a fake server: systemd units, listeners, files with modes.
type machine struct {
	*fake.Executor
	units map[string]unit
	modes map[string]string // path → "644 root root"
}

func newMachine() *machine {
	m := &machine{Executor: fake.New(), units: map[string]unit{}, modes: map[string]string{}}
	m.ReadOnly = true
	m.On("test", "-e").Do(func(c remote.Cmd) (remote.Result, error) {
		p := c.Args[len(c.Args)-1]
		if _, ok := m.File(p); ok || p == "/run/systemd/system" {
			return remote.Result{}, nil
		}
		return remote.Result{ExitCode: 1}, nil
	})
	m.On("systemctl", "list-units").Do(func(remote.Cmd) (remote.Result, error) {
		var b strings.Builder
		for n, u := range m.units {
			if strings.HasPrefix(n, "hysteria") && u.load == "loaded" {
				b.WriteString(n + " loaded " + u.active + " running Hysteria\n")
			}
		}
		return remote.Result{Stdout: []byte(b.String())}, nil
	})
	m.On("systemctl", "list-unit-files").Do(func(remote.Cmd) (remote.Result, error) {
		var b strings.Builder
		for n, u := range m.units {
			if strings.HasPrefix(n, "hysteria") {
				b.WriteString(n + " " + u.fileState + " enabled\n")
			}
		}
		return remote.Result{Stdout: []byte(b.String())}, nil
	})
	m.On("systemctl", "show").Do(func(c remote.Cmd) (remote.Result, error) {
		u, ok := m.units[c.Args[len(c.Args)-1]]
		if !ok {
			return remote.Result{Stdout: []byte("LoadState=not-found\nActiveState=inactive\nFragmentPath=\nExecStart=\nUser=\nWorkingDirectory=\nUnitFileState=\nRestart=no\n")}, nil
		}
		out := "LoadState=" + u.load + "\nActiveState=" + u.active + "\nFragmentPath=" + u.fragment + "\nExecStart=" + u.exec + "\nUser=" + u.user +
			"\nGroup=" + u.user + "\nWorkingDirectory=" + u.wd + "\nUnitFileState=" + u.fileState + "\nRestart=" + u.restart + "\n"
		return remote.Result{Stdout: []byte(out)}, nil
	})
	m.On("ss").Reply("", 0)
	m.On("getent", "passwd", "hysteria").Reply("hysteria:x:999:999::/var/lib/hysteria:/usr/sbin/nologin\n", 0)
	m.On("getent", "passwd", "root").Reply("root:x:0:0:root:/root:/bin/bash\n", 0)
	m.On("stat").Do(func(c remote.Cmd) (remote.Result, error) {
		p := c.Args[len(c.Args)-1]
		b, ok := m.File(p)
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("stat: cannot statx '" + p + "': No such file or directory")}, nil
		}
		mode := m.modes[p]
		if mode == "" {
			mode = "640 root hysteria"
		}
		return remote.Result{Stdout: []byte(mode + " " + itoa(len(b)) + "\n")}, nil
	})
	return m
}

func itoa(n int) string { return strconv.Itoa(n) }

// official is a server set up by the official installer.
func official() *machine {
	m := newMachine()
	m.units["hysteria-server.service"] = unit{load: "loaded", active: "active", fragment: "/etc/systemd/system/hysteria-server.service",
		exec: execStart("/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml"), user: "hysteria", wd: "~", fileState: "enabled", restart: "no"}
	m.SetFile("/usr/local/bin/hysteria", []byte("binary"))
	m.On("/usr/local/bin/hysteria", "version").Reply("Version:\tv2.6.0\nBuildDate:\t2024-10-19\n", 0)
	m.SetFile("/etc/hysteria/config.yaml", []byte(officialConfig))
	m.modes["/etc/hysteria/config.yaml"] = "644 root root"
	m.On("ss").Reply("udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=4242,fd=7))\n", 0)
	m.On("ps", "-o", "unit=", "-p", "4242").Reply("hysteria-server.service\n", 0)
	return m
}

// discover runs Discover the way the job does: through remote.ReadOnly.
func discover(t *testing.T, m *machine) (Found, []byte, error) {
	t.Helper()
	f, raw, err := Discover(context.Background(), remote.ReadOnly(m), false, now)
	if errors.Is(err, remote.ErrNotReadOnly) {
		t.Fatalf("import tried to change the server: %v", err)
	}
	if len(m.Writes()) != 0 {
		t.Fatalf("writes: %v", m.Writes())
	}
	return f, raw, err
}

func ids(f Found) []string {
	var out []string
	for _, x := range f.Findings {
		out = append(out, string(x.Level)+":"+x.ID)
	}
	return out
}

func has(t *testing.T, f Found, want ...string) {
	t.Helper()
	got := ids(f)
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("no finding %s in %v", w, got)
		}
	}
}

func hasNot(t *testing.T, f Found, bad ...string) {
	t.Helper()
	got := ids(f)
	for _, b := range bad {
		if slices.Contains(got, b) {
			t.Errorf("unexpected finding %s", b)
		}
	}
}

func TestImportOfficialInstallation(t *testing.T) {
	m := official()
	f, raw, err := discover(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != officialConfig {
		t.Fatal("config not returned as read")
	}
	sum := sha256.Sum256([]byte(officialConfig))
	if f.Unit != "hysteria-server.service" || f.Binary != "/usr/local/bin/hysteria" || f.Config != "/etc/hysteria/config.yaml" ||
		f.Version != "v2.6.0" || f.User != "hysteria" || !f.Active || !f.Enabled || len(f.Others) != 0 || f.ConfigSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("%+v", f)
	}
	if f.Meta.TLS != "acme" || f.Meta.SNI != "vpn.example.com" || f.Meta.Ports != "" && f.Meta.Ports != "443" || f.Meta.Auth != "password" || f.Meta.Obfs != "" || f.Meta.Version != "v2.6.0" {
		t.Fatalf("meta %+v", f.Meta)
	}
	// What the official installer leaves as it is.
	has(t, f, "warn:config-readable", "info:no-restart", "info:version")
	hasNot(t, f, "info:paths", "warn:root", "warn:inactive", "warn:not-enabled", "info:no-masquerade", "info:unknown", "warn:weak-auth")
	if !f.NeedsAttention() {
		t.Fatal("a world-readable config with passwords is worth attention")
	}
	for _, x := range f.Findings {
		if strings.Contains(x.Details, "fake-official-pass") || strings.Contains(x.Title, "fake-official-pass") {
			t.Fatalf("password in a finding: %+v", x)
		}
	}
}

func selfSigned(t *testing.T, name string, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestImportNonStandardInstallation(t *testing.T) {
	m := newMachine()
	// A hand-made service found through the process on the port, running
	// as root with a relative -c; a stopped standard unit next to it.
	m.units["hy2.service"] = unit{load: "loaded", active: "active", fragment: "/etc/systemd/system/hy2.service",
		exec: execStart("/opt/hy/hysteria-linux-amd64 -c server.yaml server"), user: "", wd: "/opt/hy", fileState: "disabled", restart: "always"}
	m.units["hysteria-server.service"] = unit{load: "loaded", active: "failed", fragment: "/etc/systemd/system/hysteria-server.service",
		exec: execStart("/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml"), user: "hysteria", wd: "~", fileState: "disabled", restart: "no"}
	m.On("ss").Reply("udp UNCONN 0 0 *:8443 *:* users:((\"hysteria-linux-\",pid=777,fd=3))\n", 0)
	m.On("ps", "-o", "unit=", "-p", "777").Reply("hy2.service\n", 0)
	m.On("/opt/hy/hysteria-linux-amd64", "version").Reply("Version:\tv2.12.3\n", 0)
	cert := selfSigned(t, "cdn.example.com", now.AddDate(0, 0, 5))
	m.SetFile("/opt/hy/cert.pem", cert)
	m.SetFile("/opt/hy/server.yaml", []byte(`listen: :8443,20000-30000
tls:
  cert: /opt/hy/cert.pem
  key: /opt/hy/key.pem
auth:
  type: password
  password: short
obfs:
  type: salamander
  salamander:
    password: fake-obfs-password-long
futureOption: 1
`))
	m.modes["/opt/hy/server.yaml"] = "666 root root"
	f, _, err := discover(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if f.Unit != "hy2.service" || f.Config != "/opt/hy/server.yaml" || f.Binary != "/opt/hy/hysteria-linux-amd64" || f.User != "" || f.Enabled ||
		!slices.Equal(f.Others, []string{"hysteria-server.service"}) {
		t.Fatalf("%+v", f)
	}
	blk, _ := pem.Decode(cert)
	pin := sha256.Sum256(blk.Bytes)
	if f.Meta.TLS != "self-signed" || f.Meta.PinSHA256 != hex.EncodeToString(pin[:]) || f.Meta.SNI != "cdn.example.com" || f.Meta.Ports != "8443,20000-30000" || f.Meta.Obfs != "salamander" {
		t.Fatalf("meta %+v", f.Meta)
	}
	if !slices.Equal(f.Unknown, []string{"futureOption"}) {
		t.Fatalf("unknown %q", f.Unknown)
	}
	has(t, f, "warn:config-writable", "warn:root", "warn:not-enabled", "info:paths", "info:others", "info:unknown", "warn:weak-auth", "info:config")
	// Self-signed certificates are checked by pin: their date is not the
	// clients' concern; no masquerade is expected with obfs.
	hasNot(t, f, "warn:cert-expiring", "warn:cert-expired", "info:no-restart", "info:version", "warn:inactive", "info:no-masquerade", "warn:weak-obfs")
}

func TestImportDefaultConfigSearch(t *testing.T) {
	m := official()
	u := m.units["hysteria-server.service"]
	u.exec = execStart("/usr/local/bin/hysteria server")
	m.units["hysteria-server.service"] = u
	f, _, err := discover(t, m)
	if err != nil || f.Config != "/etc/hysteria/config.yaml" {
		t.Fatalf("%q %v", f.Config, err)
	}
	// The working directory (the service user's home) comes first.
	m.SetFile("/var/lib/hysteria/config.yaml", []byte("listen: :9443\nacme:\n  domains: [a.example.com]\nauth:\n  type: password\n  password: fake-home-password\n"))
	f, _, err = discover(t, m)
	if err != nil || f.Config != "/var/lib/hysteria/config.yaml" || f.Meta.Ports != "9443" {
		t.Fatalf("%q %v", f.Config, err)
	}
}

func TestImportCertificateFile(t *testing.T) {
	m := official()
	// A CA-issued certificate (here: signed by another key) expiring soon.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fake CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(5, 0, 0)}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "vpn.example.com"}, DNSNames: []string{"vpn.example.com"},
		NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, 10)}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	m.SetFile("/etc/hysteria/fullchain.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	m.SetFile("/etc/hysteria/config.yaml", []byte("tls:\n  cert: /etc/hysteria/fullchain.pem\n  key: /etc/hysteria/privkey.pem\nauth:\n  type: password\n  password: fake-long-password\n"))
	f, _, err := discover(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if f.Meta.TLS != "file" || f.Meta.PinSHA256 != "" || f.Meta.SNI != "vpn.example.com" {
		t.Fatalf("meta %+v", f.Meta)
	}
	has(t, f, "warn:cert-expiring", "info:no-masquerade")
	// The key is never read.
	for _, c := range m.Calls() {
		if strings.Contains(strings.Join(c.Args, " ")+c.Path, "privkey") {
			t.Fatalf("the key was touched: %+v", c)
		}
	}
	// A missing certificate: Hysteria will not start.
	m.SetFile("/etc/hysteria/config.yaml", []byte("tls:\n  cert: /etc/hysteria/none.pem\n  key: /etc/hysteria/privkey.pem\nauth:\n  type: password\n  password: fake-long-password\n"))
	f, _, _ = discover(t, m)
	has(t, f, "warn:cert-missing")
}

func TestImportFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(m *machine)
		want  string
	}{
		{"no systemd", func(m *machine) {
			m.On("test", "-e", "/run/systemd/system").Fail("", 1)
		}, "нет systemd"},
		{"no hysteria", func(m *machine) {
			delete(m.units, "hysteria-server.service")
			m.On("ss").Reply("", 0)
		}, "не найдена"},
		{"no config", func(m *machine) {
			u := m.units["hysteria-server.service"]
			u.exec = execStart("/usr/local/bin/hysteria server -c /etc/hysteria/gone.yaml")
			m.units["hysteria-server.service"] = u
		}, "gone.yaml"},
		{"broken config", func(m *machine) {
			m.SetFile("/etc/hysteria/config.yaml", []byte("listen: [unclosed\n"))
		}, "не разобрать"},
		{"not hysteria", func(m *machine) {
			m.On("/usr/local/bin/hysteria", "version").Fail("", 127)
		}, "не похоже на Hysteria"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := official()
			c.setup(m)
			_, raw, err := discover(t, m)
			var e *Error
			if !errors.As(err, &e) || !strings.Contains(e.Msg, c.want) || raw != nil {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestExecArgv(t *testing.T) {
	cases := map[string]string{
		"--config /etc/h.yaml":   "/etc/h.yaml",
		"-c /etc/h.yaml":         "/etc/h.yaml",
		"--config=/etc/h.yaml":   "/etc/h.yaml",
		"-c=/etc/h.yaml":         "/etc/h.yaml",
		"":                       "",
		"--log-level debug":      "",
		"-c":                     "",
		"--disable-update-check": "",
	}
	for args, want := range cases {
		argv := execArgv(execStart("/usr/local/bin/hysteria server " + args))
		if argv[0] != "/usr/local/bin/hysteria" || argv[1] != "server" {
			t.Fatalf("%q", argv)
		}
		if got := configFlag(argv[1:]); got != want {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
	if execArgv("") != nil || execArgv("{ path=/x ; }") != nil {
		t.Fatal("argv from nothing")
	}
	if !older("v2.6.0", "v2.12.3") || older("v2.12.3", "v2.12.3") || older("dev", "v2.12.3") {
		t.Fatal("version order")
	}
}

func TestImportHyRouteDeployment(t *testing.T) {
	p := deploy.Params{TLS: deploy.TLSSelfSigned, Masquerade: "https://www.example.com", HopPorts: "20000-50000", Obfs: true}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	sec, err := deploy.NewSecrets(p, "192.0.2.30", nil)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := deploy.BuildConfig(p, sec)
	cfg, _ := c.Marshal()
	m := newMachine()
	m.units[deploy.Unit] = unit{load: "loaded", active: "active", fragment: deploy.UnitPath,
		exec: execStart(deploy.BinaryPath + " server --config " + deploy.ConfigPath), user: deploy.User, wd: "~", fileState: "enabled", restart: "on-failure"}
	m.On(deploy.BinaryPath, "version").Reply("Version:\t"+hyrelease.DefaultVersion+"\n", 0)
	m.SetFile(deploy.ConfigPath, cfg)
	m.SetFile(deploy.CertPath, []byte(sec[deploy.SecretCert]))
	f, _, err := discover(t, m)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := deploy.Pin([]byte(sec[deploy.SecretCert]))
	if f.Meta.TLS != "self-signed" || f.Meta.PinSHA256 != pin || f.Meta.Ports != "443,20000-50000" || f.Meta.Obfs != "salamander" {
		t.Fatalf("meta %+v", f.Meta)
	}
	if len(f.Findings) != 0 {
		t.Fatalf("findings on HyRoute's own installation: %v", ids(f))
	}
}
