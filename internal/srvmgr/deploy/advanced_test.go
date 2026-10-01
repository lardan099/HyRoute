package deploy

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const (
	fakeDNSToken = "fake-dns-token-for-tests"
	fakeOutPass  = "fake-proxy-pass-for-tests"
)

// build is the config of p (normalized) with new secrets, written and
// read back as Hysteria would read it.
func build(t *testing.T, p Params, in Input) (*hyconfig.Server, map[string]string) {
	t.Helper()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	sec, err := NewSecrets(p, "192.0.2.10", nil, in)
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildConfig(p, sec)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := hyconfig.ParseServer(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if ps := back.Validate(); hyconfig.HasErrors(ps) {
		t.Fatalf("%v\n%s", ps, b)
	}
	return back, sec
}

// Without advanced settings the config has none of their sections:
// Hysteria's defaults apply.
func TestBuildDefaults(t *testing.T) {
	c, _ := build(t, params(), Input{})
	if !reflect.ValueOf(c.Bandwidth).IsZero() || c.IgnoreClientBandwidth || !reflect.ValueOf(c.QUIC).IsZero() || c.DisableUDP || c.UDPIdleTimeout != "" ||
		!reflect.ValueOf(c.Sniff).IsZero() || len(c.Outbounds) != 0 || c.Masquerade.ListenHTTPS != "" {
		t.Fatalf("%+v", c)
	}
	if c.Masquerade.Type != MasqProxy || c.Masquerade.Proxy.URL != "https://www.example.com" || c.Auth.Type != AuthPassword {
		t.Fatalf("%+v", c.Masquerade)
	}
}

func TestBuildBandwidth(t *testing.T) {
	p := params()
	p.Bandwidth = Bandwidth{UpMbps: 200, DownMbps: 50}
	c, _ := build(t, p, Input{})
	if c.Bandwidth.Up != "200 mbps" || c.Bandwidth.Down != "50 mbps" || c.IgnoreClientBandwidth {
		t.Fatalf("%+v", c.Bandwidth)
	}
	if up, _ := hyconfig.ParseBandwidth(c.Bandwidth.Up); up != 25_000_000 {
		t.Fatalf("up %d B/s", up)
	}
	p.Bandwidth = Bandwidth{IgnoreClient: true}
	if c, _ = build(t, p, Input{}); !c.IgnoreClientBandwidth || c.Bandwidth.Up != "" {
		t.Fatalf("%+v", c)
	}
}

func TestBuildQUICAndUDP(t *testing.T) {
	p := params()
	p.QUIC = QUIC{StreamWindowMB: 16, ConnWindowMB: 40, IdleTimeout: 60, MaxStreams: 2048, DisableMTUDiscovery: true}
	p.UDP = UDP{IdleTimeout: 120}
	c, _ := build(t, p, Input{})
	want := hyconfig.ServerQUIC{InitStreamReceiveWindow: 16 << 20, MaxStreamReceiveWindow: 16 << 20, InitConnReceiveWindow: 40 << 20, MaxConnReceiveWindow: 40 << 20,
		MaxIdleTimeout: "60s", MaxIncomingStreams: 2048, DisablePathMTUDiscovery: true}
	c.QUIC.Unknown = nil
	if !reflect.DeepEqual(c.QUIC, want) {
		t.Fatalf("%+v", c.QUIC)
	}
	if c.UDPIdleTimeout != "120s" || c.DisableUDP {
		t.Fatalf("udp %q %v", c.UDPIdleTimeout, c.DisableUDP)
	}
	// One window alone: the other stays Hysteria's.
	p.QUIC = QUIC{ConnWindowMB: 64}
	p.UDP = UDP{Disable: true}
	if c, _ = build(t, p, Input{}); c.QUIC.MaxConnReceiveWindow != 64<<20 || c.QUIC.MaxStreamReceiveWindow != 0 || !c.DisableUDP {
		t.Fatalf("%+v", c.QUIC)
	}
}

func TestBuildSniff(t *testing.T) {
	p := params()
	p.Sniff = Sniff{Enable: true, Timeout: 3, RewriteDomain: true, TCPPorts: " 80,443,8000-9000 ", UDPPorts: "443"}
	c, _ := build(t, p, Input{})
	sn := c.Sniff
	if !sn.Enable || sn.Timeout != "3s" || !sn.RewriteDomain || sn.TCPPorts != "80,443,8000-9000" || sn.UDPPorts != "443" {
		t.Fatalf("%+v", c.Sniff)
	}
}

func TestBuildOutbound(t *testing.T) {
	p := params()
	p.Outbound = Outbound{Type: OutDirect, Mode: "46", BindDevice: "eth0"}
	c, _ := build(t, p, Input{})
	if len(c.Outbounds) != 1 || c.Outbounds[0].Name != "default" || c.Outbounds[0].Direct.Mode != "46" || c.Outbounds[0].Direct.BindDevice != "eth0" {
		t.Fatalf("%+v", c.Outbounds)
	}

	p.Outbound = Outbound{Type: OutSOCKS5, Addr: "127.0.0.1:40000", User: "warp"}
	c, sec := build(t, p, Input{OutPassword: fakeOutPass})
	if o := c.Outbounds[0].SOCKS5; o.Addr != "127.0.0.1:40000" || o.Username != "warp" || o.Password != fakeOutPass || sec[SecretOutPassword] != fakeOutPass {
		t.Fatalf("%+v", o)
	}

	p.Outbound = Outbound{Type: OutHTTP, Addr: "https://proxy.example.com:8443/", User: "warp"}
	c, _ = build(t, p, Input{OutPassword: fakeOutPass})
	if u := c.Outbounds[0].HTTP.URL; u != "https://warp:"+fakeOutPass+"@proxy.example.com:8443" {
		t.Fatalf("%q", u)
	}
	// The password stays out of the params.
	if strings.Contains(p.Outbound.Addr, fakeOutPass) {
		t.Fatal(p.Outbound)
	}
}

func TestBuildMasquerade(t *testing.T) {
	p := params()
	p.Masquerade = ""
	p.Masq = Masq{Type: MasqFile, Dir: "/var/www/site/"}
	c, _ := build(t, p, Input{})
	if c.Masquerade.Type != MasqFile || c.Masquerade.File.Dir != "/var/www/site" {
		t.Fatalf("%+v", c.Masquerade)
	}

	p.Masq = Masq{Type: MasqString, Text: "<h1>Under construction</h1>", Status: 503, TCP: true}
	c, _ = build(t, p, Input{})
	m := c.Masquerade
	if m.Type != MasqString || m.String.Content != p.Masq.Text || m.String.StatusCode != 503 || m.String.Headers["content-type"] != "text/html; charset=utf-8" {
		t.Fatalf("%+v", m)
	}
	if m.ListenHTTP != ":80" || m.ListenHTTPS != ":443" || !m.ForceHTTPS {
		t.Fatalf("tcp %+v", m)
	}
	p.Normalize()
	if got := p.TCPPorts(); !slices.Equal(got, []int{80, 443}) {
		t.Fatalf("tcp ports %v", got)
	}
	if specs := ports(p); len(specs) != 3 || specs[1].Proto != "tcp" || specs[2].From != 443 {
		t.Fatalf("firewall %+v", specs)
	}

	// The proxy site of earlier params, now with TCP.
	p = params()
	p.Masq.TCP = true
	if c, _ = build(t, p, Input{}); c.Masquerade.Proxy.URL != "https://www.example.com" || c.Masquerade.ListenHTTPS != ":443" {
		t.Fatalf("%+v", c.Masquerade)
	}
}

func TestBuildACMEDNS(t *testing.T) {
	p := Params{Version: testVersion, TLS: TLSACME, Domain: "vpn.example.com", Challenge: "dns", DNSProvider: "cloudflare", Masq: Masq{Type: MasqString, Text: "ok", TCP: true}}
	c, sec := build(t, p, Input{DNS: map[string]string{"cloudflare_api_token": " " + fakeDNSToken + " "}})
	if c.ACME == nil || c.ACME.Type != "dns" || c.ACME.DNS.Name != "cloudflare" || c.ACME.DNS.Config["cloudflare_api_token"] != fakeDNSToken {
		t.Fatalf("%+v", c.ACME)
	}
	if sec[SecretDNSPrefix+"cloudflare_api_token"] != fakeDNSToken {
		t.Fatal(sec)
	}
	// No port of a challenge; TCP for the site is fine with DNS.
	if got := p.TCPPorts(); !slices.Equal(got, []int{80, 443}) {
		t.Fatalf("tcp %v", got)
	}
	p.Masq = Masq{}
	if p.TCPPorts() != nil {
		t.Fatal(p.TCPPorts())
	}
	// Optional settings stay out when empty.
	p.DNSProvider = "duckdns"
	c, _ = build(t, p, Input{DNS: map[string]string{"duckdns_api_token": fakeDNSToken}})
	if len(c.ACME.DNS.Config) != 1 {
		t.Fatalf("%v", c.ACME.DNS.Config)
	}
}

func TestBuildUserPass(t *testing.T) {
	p := params()
	p.Auth, p.Users = AuthUserPass, []string{"alice", " bob ", "carol.k"}
	c, sec := build(t, p, Input{})
	if c.Auth.Type != AuthUserPass || len(c.Auth.UserPass) != 3 || c.Auth.UserPass["bob"] == "" || c.Auth.UserPass["alice"] == c.Auth.UserPass["bob"] {
		t.Fatalf("%+v", c.Auth)
	}
	if sec[SecretUsers] != `["alice","bob","carol.k"]` {
		t.Fatal(sec[SecretUsers])
	}
}

// Wrong values and combinations are refused before a job starts, with a
// reason the admin can act on.
func TestAdvancedRefused(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Params)
		want string
	}{
		{"ignore with speeds", func(p *Params) { p.Bandwidth = Bandwidth{UpMbps: 100, IgnoreClient: true} }, "не учитывает скорость клиентов"},
		{"speed too high", func(p *Params) { p.Bandwidth.DownMbps = 200000 }, "100000"},
		{"stream over conn", func(p *Params) { p.QUIC.StreamWindowMB = 32 }, "окно потока (32 МиБ) больше окна соединения (20 МиБ)"},
		{"stream over set conn", func(p *Params) { p.QUIC = QUIC{StreamWindowMB: 8, ConnWindowMB: 4} }, "больше окна соединения"},
		{"quic idle", func(p *Params) { p.QUIC.IdleTimeout = 2 }, "от 4 до 120"},
		{"streams", func(p *Params) { p.QUIC.MaxStreams = 4 }, "от 8 до 65535"},
		{"udp idle", func(p *Params) { p.UDP.IdleTimeout = 1 }, "от 2 до 600"},
		{"udp off with idle", func(p *Params) { p.UDP = UDP{Disable: true, IdleTimeout: 30} }, "пересылка UDP выключена"},
		{"udp off with sniff", func(p *Params) {
			p.UDP.Disable = true
			p.Sniff = Sniff{Enable: true, UDPPorts: "443"}
		}, "пересылка UDP выключена"},
		{"sniff off", func(p *Params) { p.Sniff = Sniff{RewriteDomain: true} }, "само оно выключено"},
		{"sniff ports", func(p *Params) { p.Sniff = Sniff{Enable: true, TCPPorts: "80-"} }, "неверный список портов"},
		{"sniff reversed", func(p *Params) { p.Sniff = Sniff{Enable: true, TCPPorts: "9000-8000"} }, "неверный список портов"},
		{"out without type", func(p *Params) { p.Outbound = Outbound{Mode: "4"} }, "тип выхода не выбран"},
		{"out type", func(p *Params) { p.Outbound = Outbound{Type: "vless"} }, "неизвестный тип выхода"},
		{"direct with proxy", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, Addr: "192.0.2.1:1080"} }, "не нужны для прямого выхода"},
		{"direct device and ip", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, BindDevice: "eth0", BindIPv4: "192.0.2.10"} }, "либо к интерфейсу"},
		{"direct v6 is v4", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, BindIPv6: "192.0.2.10"} }, "IPv6"},
		{"direct mode and ip", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, Mode: "4", BindIPv6: "2001:db8::1"} }, "другой версии IP"},
		{"direct mode", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, Mode: "x"} }, "неизвестный режим"},
		{"device name", func(p *Params) { p.Outbound = Outbound{Type: OutDirect, BindDevice: "eth0; reboot"} }, "имя интерфейса"},
		{"socks addr", func(p *Params) { p.Outbound = Outbound{Type: OutSOCKS5, Addr: "proxy.example.com"} }, "хост:порт"},
		{"socks with mode", func(p *Params) { p.Outbound = Outbound{Type: OutSOCKS5, Addr: "192.0.2.1:1080", Mode: "4"} }, "только для прямого"},
		{"http with password", func(p *Params) {
			p.Outbound = Outbound{Type: OutHTTP, Addr: "http://warp:" + fakeOutPass + "@192.0.2.1:8080"}
		}, "без имени и пароля"},
		{"http scheme", func(p *Params) { p.Outbound = Outbound{Type: OutHTTP, Addr: "socks5://192.0.2.1:1080"} }, "http://"},
		{"tcp without site", func(p *Params) {
			p.Masquerade = ""
			p.Masq.TCP = true
		}, "выберите сайт-маскировку"},
		{"tcp and acme http", func(p *Params) {
			p.TLS, p.Domain = TLSACME, "vpn.example.com"
			p.Masq.TCP = true
		}, "нужны Let's Encrypt для проверки http"},
		{"tcp and acme tls", func(p *Params) {
			p.TLS, p.Domain, p.Challenge = TLSACME, "vpn.example.com", "tls"
			p.Masq.TCP = true
		}, "проверки tls"},
		{"two sites", func(p *Params) { p.Masq = Masq{Type: MasqString, Text: "ok"} }, "другого вида"},
		{"file relative", func(p *Params) {
			p.Masquerade = ""
			p.Masq = Masq{Type: MasqFile, Dir: "www/site"}
		}, "полный путь"},
		{"file dots", func(p *Params) {
			p.Masquerade = ""
			p.Masq = Masq{Type: MasqFile, Dir: "/var/www/../../etc"}
		}, "полный путь"},
		{"file etc", func(p *Params) {
			p.Masquerade = ""
			p.Masq = Masq{Type: MasqFile, Dir: "/etc/hysteria"}
		}, "нельзя показывать"},
		{"string empty", func(p *Params) {
			p.Masquerade = ""
			p.Masq = Masq{Type: MasqString, Text: "  "}
		}, "пуст"},
		{"string status", func(p *Params) {
			p.Masquerade = ""
			p.Masq = Masq{Type: MasqString, Text: "ok", Status: 233}
		}, "кроме 233"},
		{"proxy http", func(p *Params) { p.Masquerade = "http://www.example.com" }, "https://"},
		{"dns without dns", func(p *Params) { p.DNSProvider = "cloudflare" }, "только для проверки Let's Encrypt через DNS"},
		{"dns provider", func(p *Params) {
			p.TLS, p.Domain, p.Challenge, p.DNSProvider = TLSACME, "vpn.example.com", "dns", "route53"
		}, "неизвестный DNS-провайдер"},
		{"users with password", func(p *Params) { p.Users = []string{"alice"} }, "только для входа по имени"},
		{"no users", func(p *Params) { p.Auth = AuthUserPass }, "хотя бы один"},
		{"user name", func(p *Params) { p.Auth, p.Users = AuthUserPass, []string{"al:ice"} }, "имя пользователя"},
		{"same user", func(p *Params) { p.Auth, p.Users = AuthUserPass, []string{"alice", "Alice"} }, "указан дважды"},
		{"auth type", func(p *Params) { p.Auth = "http" }, "неизвестный способ входа"},
		{"port in range", func(p *Params) { p.HopPorts = "400-500" }, "400-500 и 443 пересекаются"},
		{"ranges overlap", func(p *Params) { p.HopPorts = "20000-30000,25000-40000" }, "пересекаются"},
	}
	for _, c := range cases {
		p := params()
		c.edit(&p)
		err := p.Normalize()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The secrets the admin enters must fit the params; empty ones keep
// those of the current config, but only for the same provider or user.
func TestAdvancedSecrets(t *testing.T) {
	dns := Params{Version: testVersion, TLS: TLSACME, Domain: "vpn.example.com", Challenge: "dns", DNSProvider: "porkbun"}
	if err := dns.Normalize(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecrets(dns, "192.0.2.10", nil, Input{DNS: map[string]string{"porkbun_api_key": fakeDNSToken}}); err == nil || !strings.Contains(err.Error(), "porkbun_api_secret_key") {
		t.Fatalf("missing: %v", err)
	}
	if _, err := NewSecrets(dns, "192.0.2.10", nil, Input{DNS: map[string]string{"cloudflare_api_token": fakeDNSToken}}); err == nil || !strings.Contains(err.Error(), "нет настройки") {
		t.Fatalf("foreign key: %v", err)
	}
	if _, err := NewSecrets(params(), "192.0.2.10", nil, Input{DNS: map[string]string{"cloudflare_api_token": fakeDNSToken}}); err == nil {
		t.Fatal("dns settings without dns")
	}

	// The current config's settings of the same provider are kept.
	cur := &hyconfig.Server{ACME: &hyconfig.ACME{Type: "dns", DNS: hyconfig.ACMEDNS{Name: "Porkbun", Config: map[string]string{"porkbun_api_key": "fake-key-a", "porkbun_api_secret_key": "fake-key-b"}}}}
	reuse := map[string]string{}
	reuseAdvanced(cur, reuse)
	sec, err := NewSecrets(dns, "192.0.2.10", reuse, Input{DNS: map[string]string{"porkbun_api_key": "fake-key-new"}})
	if err != nil || sec[SecretDNSPrefix+"porkbun_api_key"] != "fake-key-new" || sec[SecretDNSPrefix+"porkbun_api_secret_key"] != "fake-key-b" {
		t.Fatalf("%v %v", err, sec)
	}
	dns.DNSProvider = "vultr"
	if _, err := NewSecrets(dns, "192.0.2.10", reuse, Input{}); err == nil {
		t.Fatal("another provider took the settings of the current one")
	}

	// The proxy password.
	out := params()
	out.Outbound = Outbound{Type: OutSOCKS5, Addr: "192.0.2.1:1080"}
	if _, err := NewSecrets(out, "192.0.2.10", nil, Input{OutPassword: fakeOutPass}); err == nil || !strings.Contains(err.Error(), "вместе с именем") {
		t.Fatalf("password without user: %v", err)
	}
	cur = &hyconfig.Server{Outbounds: []hyconfig.Outbound{{Name: "x", Type: "socks5", SOCKS5: hyconfig.OutboundSOCKS5{Addr: "192.0.2.1:1080", Username: "warp", Password: fakeOutPass}}}}
	reuse = map[string]string{}
	reuseAdvanced(cur, reuse)
	out.Outbound.User = "warp"
	if sec, _ := NewSecrets(out, "192.0.2.10", reuse, Input{}); sec[SecretOutPassword] != fakeOutPass {
		t.Fatal("password of the same user not kept")
	}
	out.Outbound.User = "other"
	if sec, _ := NewSecrets(out, "192.0.2.10", reuse, Input{}); sec[SecretOutPassword] != "" {
		t.Fatal("password kept for another user")
	}
	cur.Outbounds[0] = hyconfig.Outbound{Name: "x", Type: "http", HTTP: hyconfig.OutboundHTTP{URL: "http://warp:" + fakeOutPass + "@192.0.2.1:8080"}}
	reuse = map[string]string{}
	reuseAdvanced(cur, reuse)
	out.Outbound = Outbound{Type: OutHTTP, Addr: "http://192.0.2.1:8080", User: "warp"}
	if sec, _ := NewSecrets(out, "192.0.2.10", reuse, Input{}); sec[SecretOutPassword] != fakeOutPass {
		t.Fatal("http password not kept")
	}
}

// Users keep their passwords across redeploys; a new user gets one, and
// a change of the auth type gives new ones.
func TestUserPassReuse(t *testing.T) {
	p := params()
	p.Auth, p.Users = AuthUserPass, []string{"alice", "bob"}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	first, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	reuse := secretsOf(func(k string) string { return first[k] })

	p.Users = []string{"alice", "carol"}
	sec, _ := NewSecrets(p, "192.0.2.10", reuse, Input{})
	if sec[SecretUserPrefix+"alice"] != first[SecretUserPrefix+"alice"] || sec[SecretUserPrefix+"carol"] == "" || sec[SecretUserPrefix+"bob"] != "" {
		t.Fatalf("%v", sec)
	}
	// "" keeps the users as they are.
	p.Auth, p.Users = "", nil
	if sec, _ = NewSecrets(p, "192.0.2.10", reuse, Input{}); sec[SecretUsers] != first[SecretUsers] || sec[SecretUserPrefix+"bob"] != first[SecretUserPrefix+"bob"] {
		t.Fatalf("%v", sec)
	}
	// One password for everyone: a new one.
	p.Auth = AuthPassword
	if sec, _ = NewSecrets(p, "192.0.2.10", reuse, Input{}); sec[SecretAuth] == "" || sec[SecretUsers] != "" {
		t.Fatalf("%v", sec)
	}
	pw := map[string]string{SecretAuth: "fake-auth-password"}
	if sec, _ = NewSecrets(p, "192.0.2.10", pw, Input{}); sec[SecretAuth] != "fake-auth-password" {
		t.Fatalf("password not kept: %v", sec)
	}
}

// A deploy with advanced settings: the config on the server has them, the
// firewall opens TCP for the site, and the proxy password is neither in
// the job's params nor in its log. A redeploy keeps it without asking.
func TestDeployAdvanced(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	s.ufw = true
	h := newHarness(t, s)
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	p := params()
	p.Auth, p.Users = AuthUserPass, []string{"alice", "bob"}
	p.Masq.TCP = true
	p.Bandwidth = Bandwidth{UpMbps: 500, DownMbps: 500}
	p.Sniff = Sniff{Enable: true}
	p.Outbound = Outbound{Type: OutSOCKS5, Addr: "127.0.0.1:40000", User: "warp"}
	j, err := sub.Submit(ctx, h.server, p, Input{OutPassword: fakeOutPass}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if strings.Contains(string(j.Params), fakeOutPass) || strings.Contains(h.log(j.ID), fakeOutPass) {
		t.Fatal("the proxy password leaked")
	}
	b, _ := s.file(ConfigPath)
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Auth.UserPass) != 2 || c.Outbounds[0].SOCKS5.Password != fakeOutPass || c.Bandwidth.Up != "500 mbps" || !c.Sniff.Enable || c.Masquerade.ListenHTTPS != ":443" {
		t.Fatalf("config:\n%s", b)
	}
	for _, r := range []string{"80/tcp", "443/tcp", "443/udp"} {
		if !s.ufwRules[r] {
			t.Fatalf("rules %v", s.rules())
		}
	}
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	if cur.Meta.Auth != AuthUserPass {
		t.Fatalf("meta %+v", cur.Meta)
	}

	// The same params without the password: nothing to change.
	s.reset()
	j, err = sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted || h.steps(j.ID)["config"] != model.StepSkipped {
		t.Fatalf("%s %v\n%s", j.State, h.steps(j.ID), h.log(j.ID))
	}
}

// The folder of the site must be on the server.
func TestDeployMasqFolder(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	p := params()
	p.Masquerade, p.Masq = "", Masq{Type: MasqFile, Dir: "/var/www/site"}
	j := h.deploy(p, nil)
	if j.State != model.JobFailed || j.CurrentStep != "preflight" || !strings.Contains(j.ErrorMessage, "/var/www/site") {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	if len(s.writes) != 0 {
		t.Fatalf("wrote %q", s.writes)
	}
	s.dirs["/var/www/site"] = true
	if j = h.deploy(p, nil); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
}

// Submit checks the secrets and the whole config before it queues a job.
func TestSubmitAdvancedRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, newSim())
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	dns := Params{Version: testVersion, TLS: TLSACME, Domain: "vpn.example.com", Challenge: "dns", DNSProvider: "cloudflare"}
	var fe *model.FieldError
	if _, err := sub.Submit(ctx, h.server, dns, Input{}, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "cloudflare_api_token") {
		t.Fatalf("no token: %v", err)
	}
	bad := params()
	bad.Bandwidth = Bandwidth{UpMbps: 100, IgnoreClient: true}
	if _, err := sub.Submit(ctx, h.server, bad, Input{}, 0); !errors.As(err, &fe) {
		t.Fatalf("combination: %v", err)
	}
	if js, _ := h.db.ListJobs(ctx, model.JobFilter{}); len(js) != 0 {
		t.Fatalf("jobs %v", js)
	}
}

const presetYAML = `masquerade:
  type: string
  string:
    content: soon
  listenHTTP: :80
  listenHTTPS: :443
bandwidth:
  up: 800 mbps
acl:
  inline:
    - reject(geoip:private)
    - direct(all)
`

// A deploy lays the chosen sections of a preset over its config; the job
// keeps the preset as it was, and the TCP ports of its site are opened.
func TestDeployPreset(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	s.ufw = true
	h := newHarness(t, s)
	m := model.Preset{Name: "Сайт", Config: presetYAML}
	if err := h.db.CreatePreset(ctx, &m); err != nil {
		t.Fatal(err)
	}
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	p := params()
	p.Masquerade = ""
	p.Preset = &Preset{ID: m.ID, Sections: []string{"masquerade", "speed", "acl"}}
	j, err := sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The preset changes afterwards: the job is not affected.
	m.Config = "bandwidth:\n  up: 1 mbps\n"
	h.db.UpdatePreset(ctx, m)
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	b, _ := s.file(ConfigPath)
	c, _ := hyconfig.ParseServer(b)
	if c.Bandwidth.Up != "800 mbps" || len(c.ACL.Inline) != 2 || c.Masquerade.String.Content != "soon" || c.Masquerade.ListenHTTPS != ":443" {
		t.Fatalf("config:\n%s", b)
	}
	if !s.ufwRules["80/tcp"] || !s.ufwRules["443/tcp"] {
		t.Fatalf("rules %v", s.rules())
	}
	if !strings.Contains(string(j.Params), `"name":"Сайт"`) || !strings.Contains(h.log(j.ID), "Разделы пресета «Сайт»: masquerade, speed, acl.") {
		t.Fatalf("%s\n%s", j.Params, h.log(j.ID))
	}
}

func TestDeployPresetRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, newSim())
	m := model.Preset{Name: "Сайт", Config: presetYAML}
	h.db.CreatePreset(ctx, &m)
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	cases := map[string]func(*Params){
		"порты и обфускацию задаёт форма": func(p *Params) { p.Preset = &Preset{ID: m.ID, Sections: []string{"ports"}} },
		"и в форме, и в пресете":          func(p *Params) { p.Preset = &Preset{ID: m.ID, Sections: []string{"masquerade"}} },
		"нет раздела":                     func(p *Params) { p.Preset = &Preset{ID: m.ID, Sections: []string{"sniff"}} },
		"Такого пресета нет":              func(p *Params) { p.Preset = &Preset{ID: 999, Sections: []string{"acl"}} },
		"выберите разделы":                func(p *Params) { p.Preset = &Preset{ID: m.ID} },
		"нужны Let's Encrypt": func(p *Params) {
			p.Masquerade, p.TLS, p.Domain = "", TLSACME, "vpn.example.com"
			p.Preset = &Preset{ID: m.ID, Sections: []string{"masquerade"}}
		},
	}
	for want, edit := range cases {
		p := params()
		edit(&p)
		var fe *model.FieldError
		if _, err := sub.Submit(ctx, h.server, p, Input{}, 0); !errors.As(err, &fe) || !strings.Contains(strings.ToLower(fe.Msg), strings.ToLower(want)) {
			t.Errorf("%s: %v", want, err)
		}
	}
}
