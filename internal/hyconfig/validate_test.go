package hyconfig

import (
	"strings"
	"testing"
)

const minimal = `
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: fake-auth-password
`

func problems(t *testing.T, yml string) []Problem {
	t.Helper()
	return parseServer(t, []byte(yml)).Validate()
}

func TestValidConfigs(t *testing.T) {
	if ps := problems(t, minimal); len(ps) != 0 {
		t.Fatalf("minimal: %v", ps)
	}
	for _, name := range []string{"server-full.yaml", "server-acme.yaml"} {
		s := parseServer(t, readFile(t, name))
		if name == "server-full.yaml" {
			s.ACME = nil // the file has tls
		}
		if ps := s.Validate(); HasErrors(ps) {
			t.Errorf("%s: %v", name, ps)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name, yml, field string
	}{
		{"listen port", "listen: :70000", "listen"},
		{"listen range", "listen: :50000-x", "listen"},
		{"listen zero", "listen: :0-100", "listen"},
		{"listen no port", "listen: 0.0.0.0", "listen"},
		{"no cert", "tls: null", "tls"},
		{"tls and acme", "acme:\n  domains: [vpn.example.com]", "tls"},
		{"sni guard", "tls:\n  sniGuard: maybe", "tls.sniGuard"},
		{"auth type", "auth:\n  type: ldap", "auth.type"},
		{"auth empty", "auth:\n  type: password\n  password: ''", "auth.password"},
		{"userpass empty", "auth:\n  type: userpass", "auth.userpass"},
		{"userpass case", "auth:\n  type: userpass\n  userpass:\n    Anna: fake-pass-1\n    anna: fake-pass-2", ""},
		{"userpass colon", "auth:\n  type: userpass\n  userpass:\n    'a:b': fake-pass-1", "auth.userpass.a:b"},
		{"auth http", "auth:\n  type: http\n  http:\n    url: ftp://auth.example.com", "auth.http.url"},
		{"auth command", "auth:\n  type: command", "auth.command"},
		{"obfs type", "obfs:\n  type: xor", "obfs.type"},
		{"obfs short", "obfs:\n  type: salamander\n  salamander:\n    password: abc", "obfs.salamander.password"},
		{"gecko sizes", "obfs:\n  type: gecko\n  gecko:\n    password: fake-obfs\n    minPacketSize: 1300", "obfs.gecko"},
		{"gecko max", "obfs:\n  type: gecko\n  gecko:\n    password: fake-obfs\n    maxPacketSize: 4096", "obfs.gecko"},
		{"bandwidth unit", "bandwidth:\n  up: 100 furlongs", "bandwidth.up"},
		{"bandwidth bare", "bandwidth:\n  down: '100000'", "bandwidth.down"},
		{"bandwidth small", "bandwidth:\n  down: 100 kbps", "bandwidth.down"},
		{"congestion", "congestion:\n  type: cubic", "congestion.type"},
		{"bbr profile", "congestion:\n  bbrProfile: wild", "congestion.bbrProfile"},
		{"quic window", "quic:\n  maxStreamReceiveWindow: 1000", "quic.maxStreamReceiveWindow"},
		{"quic idle", "quic:\n  maxIdleTimeout: 5m", "quic.maxIdleTimeout"},
		{"quic idle syntax", "quic:\n  maxIdleTimeout: soon", "quic.maxIdleTimeout"},
		{"quic streams", "quic:\n  maxIncomingStreams: 4", "quic.maxIncomingStreams"},
		{"udp idle", "udpIdleTimeout: 1s", "udpIdleTimeout"},
		{"resolver type", "resolver:\n  type: carrier-pigeon", "resolver.type"},
		{"resolver addr", "resolver:\n  type: tls", "resolver.tls.addr"},
		{"sniff ports", "sniff:\n  tcpPorts: 80,http", "sniff.tcpPorts"},
		{"acl both", "acl:\n  file: acl.txt\n  inline: [direct(all)]", "acl"},
		{"outbound name", "outbounds:\n  - type: direct", "outbounds[0].name"},
		{"outbound dup", "outbounds:\n  - {name: a, type: direct}\n  - {name: A, type: direct}", "outbounds[1].name"},
		{"outbound type", "outbounds:\n  - {name: a, type: vless}", "outbounds[0].type"},
		{"direct mode", "outbounds:\n  - name: a\n    type: direct\n    direct: {mode: '5'}", "outbounds[0].direct.mode"},
		{"direct bind", "outbounds:\n  - name: a\n    type: direct\n    direct: {bindIPv4: 192.0.2.1, bindDevice: eth0}", "outbounds[0].direct"},
		{"direct v4", "outbounds:\n  - name: a\n    type: direct\n    direct: {bindIPv4: '2001:db8::1'}", "outbounds[0].direct.bindIPv4"},
		{"socks addr", "outbounds:\n  - {name: a, type: socks5}", "outbounds[0].socks5.addr"},
		{"http url", "outbounds:\n  - {name: a, type: http, http: {url: proxy.example.com}}", "outbounds[0].http.url"},
		{"stats listen", "trafficStats:\n  listen: 9999\n  secret: fake-stats-secret", "trafficStats.listen"},
		{"masq type", "masquerade:\n  type: mirror", "masquerade.type"},
		{"masq dir", "masquerade:\n  type: file", "masquerade.file.dir"},
		{"masq proxy", "masquerade:\n  type: proxy\n  proxy:\n    url: www.example.com", "masquerade.proxy.url"},
		{"masq string", "masquerade:\n  type: string", "masquerade.string.content"},
		{"masq status", "masquerade:\n  type: string\n  string:\n    content: x\n    statusCode: 233", "masquerade.string.statusCode"},
		{"masq http only", "masquerade:\n  listenHTTP: :80", "masquerade.listenHTTPS"},
		{"mimic xdp", "mimic:\n  xdpMode: turbo", "mimic.xdpMode"},
		{"realm ip mode", "realm:\n  ipMode: v5", "realm.ipMode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := problems(t, merge(minimal, c.yml))
			if !HasErrors(ps) {
				t.Fatalf("no error: %v", ps)
			}
			if c.field == "" {
				return
			}
			for _, p := range ps {
				if p.Field == c.field && !p.Warning {
					return
				}
			}
			t.Fatalf("no error on %s: %v", c.field, ps)
		})
	}
}

func TestValidateACME(t *testing.T) {
	base := "auth:\n  type: password\n  password: fake-auth-password\n"
	for yml, field := range map[string]string{
		"acme:\n  domains: []":                                                                        "acme.domains",
		"acme:\n  domains: ['bad domain']":                                                            "acme.domains[0]",
		"acme:\n  domains: [vpn.example.com]\n  ca: buypass":                                          "acme.ca",
		"acme:\n  domains: [vpn.example.com]\n  type: email":                                          "acme.type",
		"acme:\n  domains: [vpn.example.com]\n  type: dns":                                            "acme.dns.name",
		"acme:\n  domains: [vpn.example.com]\n  type: dns\n  dns: {name: namedotcom, config: {k: v}}": "acme.dns.name",
		"acme:\n  domains: [vpn.example.com]\n  http: {altPort: 70000}":                               "acme.http.altPort",
	} {
		ps := problems(t, base+yml)
		found := false
		for _, p := range ps {
			found = found || (p.Field == field && !p.Warning)
		}
		if !found {
			t.Errorf("%q: no error on %s: %v", yml, field, ps)
		}
	}
	if ps := problems(t, base+"acme:\n  domains: [vpn.example.com, '*.example.org']\n  type: http"); len(ps) != 0 {
		t.Errorf("valid acme: %v", ps)
	}
}

func TestValidateWarnings(t *testing.T) {
	for yml, field := range map[string]string{
		"trafficStats:\n  listen: 127.0.0.1:9999": "trafficStats.secret",
		"mimic:\n  enabled: true":                 "mimic.enabled",
		"udpIdleTimeout: 60000000000":             "udpIdleTimeout",
		"futureKey: 1":                            "futureKey",
		"quic:\n  futureKnob: 1":                  "quic.futureKnob",
	} {
		ps := problems(t, merge(minimal, yml))
		if HasErrors(ps) {
			t.Errorf("%q: errors %v", yml, ps)
		}
		found := false
		for _, p := range ps {
			found = found || (p.Field == field && p.Warning)
		}
		if !found {
			t.Errorf("%q: no warning on %s: %v", yml, field, ps)
		}
	}
	ps := problems(t, "listen: realm://token@realm.example.com/fake\n"+minimal[strings.Index(minimal, "tls:"):])
	if HasErrors(ps) || len(ps) != 1 || ps[0].Field != "listen" {
		t.Errorf("realm: %v", ps)
	}
	ps = problems(t, strings.Replace(minimal, "fake-auth-password", "short", 1))
	if HasErrors(ps) || len(ps) != 1 || ps[0].Field != "auth.password" {
		t.Errorf("short password: %v", ps)
	}
}

// merge overlays top-level sections of extra onto base (the extra wins).
func merge(base, extra string) string {
	sections := map[string]string{}
	var order []string
	add := func(doc string) {
		key := ""
		for _, line := range strings.Split(doc, "\n") {
			if line == "" {
				continue
			}
			if line[0] != ' ' && line[0] != '-' {
				key, _, _ = strings.Cut(line, ":")
				if _, ok := sections[key]; !ok {
					order = append(order, key)
				}
				sections[key] = ""
			}
			sections[key] += line + "\n"
		}
	}
	add(base)
	add(extra)
	var sb strings.Builder
	for _, k := range order {
		sb.WriteString(sections[k])
	}
	return sb.String()
}

func TestParseBandwidth(t *testing.T) {
	for in, want := range map[string]uint64{"100 mbps": 12_500_000, "1g": 125_000_000, "512 Kbps": 64_000, "8bps": 1, " 2 TB ": 250_000_000_000} {
		if got, err := ParseBandwidth(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "mbps", "100", "1.5 mbps", "-1 mbps", "10 pbps"} {
		if _, err := ParseBandwidth(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

func TestParseListen(t *testing.T) {
	for in, want := range map[string]Listen{
		"":                 {Ports: "443", First: 443},
		":443":             {Ports: "443", First: 443},
		"0.0.0.0:8443":     {Host: "0.0.0.0", Ports: "8443", First: 8443},
		"[::]:20000-50000": {Host: "::", Ports: "20000-50000", First: 20000, Hopping: true},
		":443,20000-50000": {Ports: "443,20000-50000", First: 443, Hopping: true},
		":50000-20000":     {Ports: "50000-20000", First: 20000, Hopping: true},
		"example.com:443":  {Host: "example.com", Ports: "443", First: 443},
	} {
		if got, err := ParseListen(in); err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"443", ":", ":http", ":1-2-3", ":1,", "realm://x@realm.example.com/r"} {
		if _, err := ParseListen(in); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}
