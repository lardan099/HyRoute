// Package diagtest fills a database with canary values for the tests of
// the diagnostic bundle: fake passwords, addresses, domains, SNI, share
// links, SSH keys, pins and names that must not appear in any file of a
// bundle. Every value is made up (documentation address ranges,
// example.com, example.net, example.org).
package diagtest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Canary values. Names and addresses the texts repeat are named.
const (
	ServerName = "Canary Frankfurt Ивана"
	ServerHost = "203.0.113.77"
	ExitName   = "canary-exit-node"
	ExitHost   = "vpn-canary.example.com"
	V6Name     = "canary-v6-node"
	V6Host     = "2001:db8:ca::7"
	SSHUser    = "canary-sshuser"
	Hostname   = "canary-vps-hostname"
	ChainName  = "Canary Chain Петра"

	sshPassword   = "canary-ssh-Pa55word-1"
	keyPassphrase = "canary-key-passphrase-2"
	keyLine1      = "Y2FuYXJ5LXByaXZhdGUta2V5LW1hdGVyaWFsLWxpbmUtMQ"
	keyLine2      = "Y2FuYXJ5LXByaXZhdGUta2V5LW1hdGVyaWFsLWxpbmUtMg"
	sshKey        = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + keyLine1 + "\n" + keyLine2 + "\n-----END OPENSSH PRIVATE KEY-----\n"
	pin           = "ca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1e"
	fingerprint   = "Q2FuYXJ5SG9zdEtleUZpbmdlcnByaW50MTIzNDU2Nzg5"
)

// AllowedHost and Listen are the canaries of the panel's settings.
const (
	AllowedHost = "panel-canary.example.com"
	Listen      = "198.51.100.99:8480"
)

// Canaries are the values no file of a bundle may contain: everything
// identifying or secret Fill stores.
var Canaries = []string{
	ServerName, ServerHost, ExitName, ExitHost, V6Name, V6Host, SSHUser, Hostname, ChainName,
	sshPassword, keyPassphrase, keyLine1, keyLine2, pin, fingerprint,
	"canary-auth-Pa55-6", "canary-user-Pa55-1", "canary-user-Pa55-2", "canary-obfs-Pa55-3", "canary-stats-secret-4", "canary-socks-Pa55-5",
	"canary-dns-token-8", "canary-out-Pa55-9", "canary-link-Pa55-10", "canary-link-socks-11", "canary-link-socks-Pa55-12",
	"canary-unknown-secret-13", "canary-broken-Pa55-14",
	"canary-ivan", "canary-masha", "canary-removed-user", "canary-socks-user", "canary-admin-boris", "canary-operator-vera",
	"acme-canary.example.net", "canary-acme@example.org", "sni-canary.example.com", "masq-canary.example.com", "acl-canary.example.com",
	"check-canary.example.com", "dns-canary.example.com", "evil-canary.example.com", AllowedHost,
	"198.51.100.44", "198.51.100.200", "198.51.100.201", "198.51.100.9", "198.51.100.99", "203.0.113.53",
}

const config1 = `listen: :443
acme:
  domains:
    - acme-canary.example.net
  email: canary-acme@example.org
auth:
  type: userpass
  userpass:
    canary-ivan: canary-user-Pa55-1
    canary-masha: canary-user-Pa55-2
obfs:
  type: salamander
  salamander:
    password: canary-obfs-Pa55-3
masquerade:
  type: proxy
  proxy:
    url: https://masq-canary.example.com/
trafficStats:
  listen: 127.0.0.1:25413
  secret: canary-stats-secret-4
outbounds:
  - name: proxy
    type: socks5
    socks5:
      addr: 198.51.100.44:1080
      username: canary-socks-user
      password: canary-socks-Pa55-5
acl:
  inline:
    - direct(suffix:acl-canary.example.com)
    - proxy(all)
`

const config2 = `listen: :8443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: canary-auth-Pa55-6
futureOption:
  apiSecret: canary-unknown-secret-13
`

// config3 is not a config Hysteria's model reads.
const config3 = `listen: [not, a, string]
auth:
  type: password
  password: canary-broken-Pa55-14
`

// Seed is what Fill stored.
type Seed struct {
	// Server is the first server: ServerName at ServerHost.
	Server int64
	// Logs is a controller log buffer with canaries in its records.
	Logs *logbuf.Buffer
}

// Fill stores the canaries in st, sealed with keys where the controller
// seals them.
func Fill(t testing.TB, st store.Store, keys *secrets.Keyring) Seed {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	seal := func(b []byte, context string) []byte {
		t.Helper()
		out, err := keys.Seal(b, context)
		must(err)
		return out
	}
	server := func(name, host string, auth model.AuthType, creds map[model.CredKind]string) int64 {
		s := model.Server{Name: name, Host: host, SSHPort: 22, SSHUser: SSHUser, AuthType: auth, CreatedAt: now, UpdatedAt: now}
		must(st.CreateServer(ctx, &s, func(id int64) ([]model.Credential, error) {
			var out []model.Credential
			for k, v := range creds {
				out = append(out, model.Credential{Kind: k, Sealed: seal([]byte(v), model.CredContext(id, k))})
			}
			return out, nil
		}))
		return s.ID
	}
	s1 := server(ServerName, ServerHost, model.AuthPassword, map[model.CredKind]string{model.CredSSHPassword: sshPassword})
	s2 := server(ExitName, ExitHost, model.AuthKey, map[model.CredKind]string{model.CredSSHKey: sshKey, model.CredSSHKeyPassphrase: keyPassphrase})
	s3 := server(V6Name, V6Host, model.AuthPassword, map[model.CredKind]string{model.CredSSHPassword: sshPassword})
	must(st.SetServerState(ctx, s1, model.StateDegraded, now))

	addConfig := func(id int64, yaml string, meta model.ConfigMeta) {
		c := model.ServerConfig{ServerID: id, Meta: meta, Source: model.ConfigDeploy, At: now}
		must(st.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return seal([]byte(yaml), model.ConfigContext(id, rev)), nil }))
	}
	addConfig(s1, config1, model.ConfigMeta{Version: "v2.6.0", Listen: ":443", Ports: "443", TLS: "acme", PinSHA256: pin, SNI: "sni-canary.example.com", Obfs: "salamander", Auth: "userpass"})
	addConfig(s2, config2, model.ConfigMeta{Version: "v2.6.0", Listen: ":8443", Ports: "8443", TLS: "file", Auth: "password"})
	addConfig(s3, config3, model.ConfigMeta{Version: "v2.6.0", Auth: "password"})
	must(st.SetInstallation(ctx, model.Installation{ServerID: s1, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Version: "v2.6.0", Managed: true, At: now}))
	must(st.SetServerGeo(ctx, model.ServerGeo{ServerID: s1, Release: "202610010000", At: now}))
	listening := false
	must(st.AddHealth(ctx, model.Health{ServerID: s1, At: now, Status: model.StateDegraded, Reason: "UDP " + ServerHost + ":443 не отвечает (" + ServerName + ")", SSHMillis: 80, Service: "active", Listening: &listening, UDP: model.UDPNoAnswer, Egress: "198.51.100.201"}))
	cpu := 12.5
	must(st.AddMetric(ctx, model.Metric{ServerID: s1, At: now, CPU: &cpu, MemUsedMiB: 300, MemTotalMiB: 1000, DiskUsedMiB: 5000, DiskTotalMiB: 20000, Load1: 0.3}))

	for _, u := range []model.User{{Username: "canary-admin-boris", Role: model.RoleAdmin}, {Username: "canary-operator-vera", Role: model.RoleOperator}} {
		u.PasswordHash, u.CreatedAt, u.UpdatedAt = "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA", now, now
		must(st.CreateUser(ctx, &u))
	}

	report := preflight.Report{User: SSHUser, Root: false, OS: "Ubuntu 22.04.3 LTS", OSID: "ubuntu", OSVersion: "22.04", Kernel: "Linux 6.1.0-18-amd64", Arch: "x86_64",
		HysteriaArch: "amd64", Systemd: true, CPUs: 2, MemoryMiB: 1024, DiskFreeMiB: 9000, Firewall: "ufw", DNS: true, GitHub: true,
		Checks: []preflight.Check{{ID: "dns", Level: preflight.Warn, Title: "DNS", Details: "dns-canary.example.com через 203.0.113.53"}}}
	connected := "Подключено как " + SSHUser + " к " + Hostname + " (Linux 6.1.0-18-amd64, x86_64)."
	job := func(j model.Job, secret string, lines ...string) {
		j.CreatedAt, j.StartedAt, j.FinishedAt = now, now, now
		var sealFn func(int64) ([]byte, error)
		if secret != "" {
			sealFn = func(id int64) ([]byte, error) { return seal([]byte(secret), model.JobSecretContext(id)), nil }
		}
		must(st.CreateJob(ctx, &j, []model.JobStep{{Name: "connect", Phase: model.JobConnecting}}, sealFn))
		must(st.UpdateJob(ctx, j))
		for _, l := range lines {
			must(st.AppendJobLog(ctx, &model.JobLog{JobID: j.ID, Time: now, Level: "info", Step: "connect", Message: l}))
		}
	}
	job(model.Job{Kind: preflight.JobKind, ServerID: s1, State: model.JobCompleted, Params: json.RawMessage(`{"udpPort":443}`),
		Data: map[string]string{"user": SSHUser, "hostname": Hostname, "report": report.JSON()}}, "", connected, "! DNS. dns-canary.example.com через 203.0.113.53")
	// Lines a job log never has (they are redacted when written), to test
	// that the bundle cleans them anyway.
	job(model.Job{Kind: "deploy", ServerID: s1, State: model.JobFailed,
		Params:       json.RawMessage(`{"tls":"acme","domain":"acme-canary.example.net","email":"canary-acme@example.org","sni":"sni-canary.example.com","masquerade":"https://masq-canary.example.com/","auth":"userpass","users":["canary-ivan","canary-masha","canary-removed-user"]}`),
		Data:         map[string]string{"probe": `{"user":"` + SSHUser + `","hostname":"` + Hostname + `"}`},
		ErrorMessage: "Не удалось подключиться к серверу " + ServerName + ".", ErrorDetails: "dial tcp " + ServerHost + ":22: i/o timeout"},
		`{"dns":{"apiToken":"canary-dns-token-8"},"outPassword":"canary-out-Pa55-9"}`,
		connected,
		"client link hysteria2://canary-user-Pa55-1@"+ServerHost+":443/?sni=sni-canary.example.com&obfs=salamander&obfs-password=canary-obfs-Pa55-3#canary-ivan",
		"retry with "+sshPassword+" for "+SSHUser+"@"+ServerHost,
		"DNS token canary-dns-token-8, proxy canary-out-Pa55-9, socks canary-socks-user canary-socks-Pa55-5",
		"server "+ServerName+" uses "+ExitHost+" and ["+V6Host+"]:22",
		"pinSHA256="+pin+", host key SHA256:"+fingerprint,
		"user canary-removed-user removed, canary-masha kept; ACME account canary-acme@example.org",
		"egress 198.51.100.200, key "+sshKey+" passphrase "+keyPassphrase,
		"stats secret canary-stats-secret-4 auth canary-auth-Pa55-6",
		"options canary-unknown-secret-13 and canary-broken-Pa55-14",
		"Не удалось подключиться к серверу "+ServerName+".")

	ch := model.Chain{Name: ChainName, Nodes: []int64{s1, s2}, Links: []model.ChainLink{{Params: json.RawMessage(`{"localPort":20000,"checkTarget":"check-canary.example.com:443"}`)}}, CreatedAt: now, UpdatedAt: now}
	must(st.CreateChain(ctx, &ch, nil))
	ls, err := cascade.SealSecrets(keys, ch.ID, 0, cascade.Secrets{ExitPassword: "canary-link-Pa55-10", SOCKSUser: "canary-link-socks-11", SOCKSPassword: "canary-link-socks-Pa55-12"})
	must(err)
	must(st.SetLinkSecrets(ctx, ch.ID, 0, ls, now))
	must(st.AddLinkCheck(ctx, model.LinkCheck{ChainID: ch.ID, Idx: 0, At: now, Status: model.StateOffline, Reason: "handshake with " + ExitHost + " failed: canary-link-Pa55-10", Service: "active"}))
	job(model.Job{Kind: "link", ServerID: s1, Servers: []int64{s2}, State: model.JobCompleted, Params: json.RawMessage(`{"chain":` + itoa(ch.ID) + `,"idx":0}`)}, "",
		"На сервер выхода добавлен пользователь связи "+cascade.User(ch.ID, 0)+".", "socks canary-link-socks-11:canary-link-socks-Pa55-12")

	// The controller's log as the panel keeps it, here without the
	// redacting handler in front.
	buf := logbuf.New(100, slog.LevelDebug)
	log := slog.New(buf.Handler())
	log.Warn("monitor: server unreachable", "server", ServerName, "err", "dial tcp "+ServerHost+":22: i/o timeout")
	log.Info("monitor: server state", "server", ExitName, "state", "offline", "reason", "UDP "+ExitHost+":8443 не отвечает")
	log.Warn("login failed", "user", "canary-admin-boris", "ip", "198.51.100.9")
	log.Warn("write refused: Origin is not the host of the request", "origin", "https://evil-canary.example.com", "host", AllowedHost)
	log.Info("hyroute-server started", "listen", Listen, "link", "hy2://canary-auth-Pa55-6@"+ExitHost+":8443")
	return Seed{Server: s1, Logs: buf}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// KeyCanaries are the master key as text could hold it.
func KeyCanaries(keyBytes []byte) []string {
	return []string{base64.StdEncoding.EncodeToString(keyBytes), base64.RawURLEncoding.EncodeToString(keyBytes)}
}

// Files reads a bundle: file name → content.
func Files(t testing.TB, b []byte) map[string]string {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = string(data)
	}
	if z.Comment != "" {
		out[".comment"] = z.Comment
	}
	return out
}

// NoCanaries fails when a file name or a file of the bundle has one of
// the values, in any case.
func NoCanaries(t testing.TB, files map[string]string, values ...string) {
	t.Helper()
	for name, data := range files {
		low := strings.ToLower(name + "\n" + data)
		for _, v := range values {
			if strings.Contains(name+"\n"+data, v) || strings.Contains(low, strings.ToLower(v)) {
				t.Errorf("%s holds %q", name, v)
			}
		}
	}
}
