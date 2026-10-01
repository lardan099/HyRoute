package cascade

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

func parse(t *testing.T, yml string) *hyconfig.Server {
	t.Helper()
	c, err := hyconfig.ParseServer([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const exitPassword = `listen: :443,20000-30000
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: fake-exit-pass
obfs:
  type: salamander
  salamander:
    password: fake-exit-obfs
`

const exitUserpass = `listen: :8443
acme:
  domains: [exit.example.com]
auth:
  type: userpass
  userpass:
    alice: fake-alice-pass
`

func TestParams(t *testing.T) {
	ok := []Params{{}, {LocalPort: 41000, Up: "50 mbps", Down: "200 mbps", NoUDP: true, CheckTarget: "1.1.1.1:443"}, {CheckTarget: "[2001:db8::1]:22"}, {CheckTarget: "exit.example.com:22"}}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := map[string]Params{
		"localPort":   {LocalPort: 80},
		"up":          {Up: "fast", Down: "1 mbps"},
		"one speed":   {Up: "10 mbps"},
		"checkTarget": {CheckTarget: "-oProxyCommand=x:22"},
		"no port":     {CheckTarget: "example.com"},
		"port 0":      {CheckTarget: "example.com:0"},
		"space":       {CheckTarget: "a b:22"},
		"semicolon":   {CheckTarget: "a;b:22"},
	}
	for name, p := range bad {
		var fe *model.FieldError
		if err := p.Validate(); !errors.As(err, &fe) {
			t.Errorf("%s: %+v accepted (%v)", name, p, err)
		}
	}
}

func TestExitCredentials(t *testing.T) {
	c := parse(t, exitPassword)
	if changed, err := ExitWith(c, User(3, 0), "x"); err != nil || changed {
		t.Fatalf("password exit: changed %v, %v", changed, err)
	}

	c = parse(t, exitUserpass)
	if HasUser(c, "LINK-3-0") {
		t.Fatal("user before the link")
	}
	if changed, err := ExitWith(c, User(3, 0), "fake-link-pass"); err != nil || !changed {
		t.Fatalf("userpass exit: changed %v, %v", changed, err)
	}
	if c.Auth.UserPass["link-3-0"] != "fake-link-pass" || c.Auth.UserPass["alice"] != "fake-alice-pass" || !HasUser(c, "LINK-3-0") {
		t.Fatalf("users %v", c.Auth.UserPass)
	}
	if changed, _ := ExitWith(c, User(3, 0), "fake-link-pass"); changed {
		t.Fatal("the same user again counts as a change")
	}
	c.Auth.UserPass["Link-3-0"] = c.Auth.UserPass["link-3-0"]
	delete(c.Auth.UserPass, "link-3-0")
	if changed, _ := ExitWith(c, User(3, 0), "fake-new-pass"); !changed || len(c.Auth.UserPass) != 2 || c.Auth.UserPass["link-3-0"] != "fake-new-pass" {
		t.Fatalf("new password: %v", c.Auth.UserPass)
	}
	if !ExitWithout(c, User(3, 0)) || len(c.Auth.UserPass) != 1 || ExitWithout(c, User(3, 0)) {
		t.Fatalf("without: %v", c.Auth.UserPass)
	}

	c.Auth.Type = "http"
	if _, err := ExitWith(c, "u", "p"); !errors.Is(err, ErrAuth) {
		t.Fatalf("http auth: %v", err)
	}
}

func TestClientConfig(t *testing.T) {
	s := Secrets{ExitPassword: "fake-link-pass", SOCKSUser: "hyroute", SOCKSPassword: "fake-socks-pass"}
	exit := model.Server{Name: "Exit", Host: "198.51.100.7", HopInterval: 30}
	meta := model.ConfigMeta{Ports: "443,20000-30000", TLS: "self-signed", PinSHA256: "abababababababababababababababababababababababababababababababab", SNI: "exit.local"}
	p := Params{LocalPort: 41000, Up: "50 mbps", Down: "200 mbps"}
	c, err := ClientConfig(exit, parse(t, exitPassword), meta, 3, 0, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "198.51.100.7:443,20000-30000" || c.Auth != "fake-exit-pass" || !c.TLS.Insecure || c.TLS.PinSHA256 != "abababababababababababababababababababababababababababababababab" || c.TLS.SNI != "exit.local" ||
		c.Obfs.Salamander.Password != "fake-exit-obfs" || c.Transport.UDP.HopInterval != "30s" || c.Bandwidth.Up != "50 mbps" || c.Lazy || c.HTTP != nil ||
		c.SOCKS5 == nil || c.SOCKS5.Listen != "127.0.0.1:41000" || c.SOCKS5.Username != "hyroute" || c.SOCKS5.Password != "fake-socks-pass" || c.SOCKS5.DisableUDP {
		t.Fatalf("%+v %+v", c, c.SOCKS5)
	}
	yml, err := c.Marshal()
	if err != nil || strings.Contains(string(yml), "http:") || strings.Contains(string(yml), "lazy") {
		t.Fatalf("%s %v", yml, err)
	}

	p.NoUDP = true
	c, err = ClientConfig(exit, parse(t, exitUserpass), model.ConfigMeta{TLS: "acme"}, 3, 0, p, s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth != "link-3-0:fake-link-pass" || c.Server != "198.51.100.7:8443" || c.TLS.SNI != "exit.example.com" || !c.SOCKS5.DisableUDP {
		t.Fatalf("%+v", c)
	}
	if _, err := ClientConfig(exit, parse(t, exitUserpass), meta, 3, 0, Params{}, s); err == nil {
		t.Fatal("no local port accepted")
	}
}

func TestEntryOutbound(t *testing.T) {
	s := Secrets{SOCKSUser: "hyroute", SOCKSPassword: "fake-socks-pass"}
	c := parse(t, "listen: :443\nauth:\n  type: password\n  password: x\n")
	if HasOutbound(c) || !EntryWith(c, 41000, s) || EntryWith(c, 41000, s) {
		t.Fatal("first outbound, then no change")
	}
	if len(c.Outbounds) != 1 || c.Outbounds[0].Name != "cascade" || c.Outbounds[0].SOCKS5.Addr != "127.0.0.1:41000" {
		t.Fatalf("%+v", c.Outbounds)
	}
	yml, _ := c.Marshal()
	back := parse(t, string(yml))
	if len(back.Outbounds) != 1 || back.Outbounds[0].Type != "socks5" || back.Outbounds[0].SOCKS5.Password != "fake-socks-pass" {
		t.Fatalf("round trip %s", yml)
	}
	if !EntryWithout(c) || c.Outbounds != nil || EntryWithout(c) {
		t.Fatalf("without %+v", c.Outbounds)
	}

	// Outbounds of the admin stay, after the link's; one named "Cascade"
	// by hand is replaced.
	c = parse(t, "listen: :443\noutbounds:\n  - name: v4\n    type: direct\n    direct:\n      mode: 4\n  - name: Cascade\n    type: direct\n")
	if !HasOutbound(c) || !EntryWith(c, 41000, s) {
		t.Fatal("replace")
	}
	if len(c.Outbounds) != 2 || c.Outbounds[0].Name != "cascade" || c.Outbounds[1].Name != "v4" {
		t.Fatalf("%+v", c.Outbounds)
	}
	if !EntryWith(c, 42000, s) || c.Outbounds[0].SOCKS5.Addr != "127.0.0.1:42000" {
		t.Fatal("new port")
	}
	if !EntryWithout(c) || len(c.Outbounds) != 1 || c.Outbounds[0].Name != "v4" {
		t.Fatalf("%+v", c.Outbounds)
	}
}

func TestUnitText(t *testing.T) {
	in := model.Installation{Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", User: "hysteria"}
	u, err := UnitText(in, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ExecStart=/usr/local/bin/hysteria client --config /etc/hysteria/link-3-0.yaml --disable-update-check\n",
		"User=hysteria\nGroup=hysteria\n", "Restart=always\n", "WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	in.User, in.Config = "", "/opt/hy/server.yaml"
	if u, _ = UnitText(in, 3, 0); strings.Contains(u, "User=") || !strings.Contains(u, "--config /opt/hy/link-3-0.yaml ") {
		t.Fatalf("root unit:\n%s", u)
	}
	for _, bad := range []model.Installation{
		{Binary: "hysteria", Config: "/etc/hysteria/config.yaml"},
		{Binary: "/usr/bin/hy steria", Config: "/etc/hysteria/config.yaml"},
		{Binary: "/usr/bin/hysteria", Config: "/etc/my hysteria/config.yaml"},
		{Binary: "/usr/bin/hysteria", Config: "/etc/hysteria/config.yaml", User: "bad user"},
	} {
		if _, err := UnitText(bad, 3, 0); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if UnitName(3, 0) != "hyroute-link-3-0.service" || UnitPath(3, 0) != "/etc/systemd/system/hyroute-link-3-0.service" {
		t.Fatal("unit names")
	}
}

func TestSecretsAndParams(t *testing.T) {
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	s := Secrets{ExitPassword: "fake-link-pass", SOCKSUser: "hyroute", SOCKSPassword: "fake-socks-pass"}
	sealed, err := SealSecrets(keys, 3, 0, s)
	if err != nil || bytes.Contains(sealed, []byte("fake-link-pass")) {
		t.Fatalf("sealed %q, %v", sealed, err)
	}
	if got, err := OpenSecrets(keys, 3, 0, sealed); err != nil || got != s {
		t.Fatalf("%+v, %v", got, err)
	}
	if _, err := OpenSecrets(keys, 4, 0, sealed); err == nil {
		t.Fatal("secrets of another link opened")
	}
	if _, err := OpenSecrets(keys, 3, 0, nil); !errors.Is(err, ErrNoSecrets) {
		t.Fatalf("none: %v", err)
	}
	p := Params{LocalPort: 41000, Up: "1 mbps", Down: "2 mbps", CheckTarget: "1.1.1.1:443"}
	if got, err := ParseParams(p.Raw()); err != nil || got != p {
		t.Fatalf("%+v, %v", got, err)
	}
	if got, err := ParseParams([]byte("{}")); err != nil || got != (Params{}) {
		t.Fatalf("%+v, %v", got, err)
	}
	if strings.Contains(string(p.Raw()), "assword") {
		t.Fatal("params carry a secret")
	}
}

func TestNewSecrets(t *testing.T) {
	a, err := NewSecrets()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSecrets()
	if len(a.ExitPassword) != 32 || len(a.SOCKSPassword) != 32 || a.SOCKSUser == "" || a.ExitPassword == b.ExitPassword || a.ExitPassword == a.SOCKSPassword {
		t.Fatalf("%+v %+v", a, b)
	}
}
