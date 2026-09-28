package dnspolicy

import (
	"strings"
	"testing"
)

func TestParseUpstream(t *testing.T) {
	ok := []struct {
		raw    string
		tunnel bool
		want   Spec
	}{
		{"https://1.1.1.1/dns-query", false, Spec{Scheme: "https", Host: "1.1.1.1", Port: 443, Path: "/dns-query"}},
		{"HTTPS://Dns.Example/", true, Spec{Scheme: "https", Host: "dns.example", Port: 443, Path: "/dns-query"}},
		{"https://dns.example:8443/q/abc?x=1", false, Spec{Scheme: "https", Host: "dns.example", Port: 8443, Path: "/q/abc?x=1"}},
		{"tls://dns.example:8853", false, Spec{Scheme: "tls", Host: "dns.example", Port: 8853}},
		{"tls://dns.example", true, Spec{Scheme: "tls", Host: "dns.example", Port: 853}},
		{"tcp://9.9.9.9", true, Spec{Scheme: "tcp", Host: "9.9.9.9", Port: 53}},
		{"https://[2606:4700::1111]/dns-query", true, Spec{Scheme: "https", Host: "2606:4700::1111", Port: 443, Path: "/dns-query"}},
		{"tls://днс.пример", false, Spec{Scheme: "tls", Host: "xn--d1asm.xn--e1afmkfd", Port: 853}},
		{"https://127.0.0.1:3000/dns-query", false, Spec{Scheme: "https", Host: "127.0.0.1", Port: 3000, Path: "/dns-query"}},
		{"  https://dns.example/dns-query  ", false, Spec{Scheme: "https", Host: "dns.example", Port: 443, Path: "/dns-query"}},
	}
	for _, c := range ok {
		got, err := ParseUpstream(c.raw, c.tunnel)
		c.want.Name = CustomName
		if err != nil || got.Scheme != c.want.Scheme || got.Host != c.want.Host || got.Port != c.want.Port || got.Path != c.want.Path || got.Name != CustomName {
			t.Errorf("%q: %+v %v, want %+v", c.raw, got, err, c.want)
		}
	}
	bad := []struct {
		raw    string
		tunnel bool
		msg    string
	}{
		{"", true, "Укажите адрес DNS-сервера: https://…/dns-query или tls://…"},
		{"   ", false, "Укажите адрес DNS-сервера: https://…/dns-query или tls://…"},
		{"http://dns.example/dns-query", false, "Неверный адрес DNS-сервера: нужен https://…, tls://… или tcp://…"},
		{"dns.example", false, "Неверный адрес DNS-сервера: нужен https://…, tls://… или tcp://…"},
		{"udp://1.1.1.1", true, "Неверный адрес DNS-сервера: нужен https://…, tls://… или tcp://…"},
		{"tls://dns.example/path", true, "Неверный адрес DNS-сервера: нужен https://…, tls://… или tcp://…"},
		{"https://user:pw@dns.example/dns-query", false, "Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы"},
		{"https://user@dns.example/dns-query", false, "Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы"},
		{"https://dns.example/dns-query#x", false, "Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы"},
		{"https://dns.example/dns query", false, "Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы"},
		{"https://dns.example/\x01", false, "Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы"},
		{"https://bad_host!/dns-query", false, "Неверное имя или IP DNS-сервера «bad_host!»"},
		{"https://-x.example/dns-query", false, "Неверное имя или IP DNS-сервера «-x.example»"},
		{"https://[fe80::1%25eth0]/dns-query", false, "Неверное имя или IP DNS-сервера «fe80::1%eth0»"},
		{"tls://dns.example:0", false, "Неверный порт DNS-сервера"},
		{"tls://dns.example:65536", false, "Неверный порт DNS-сервера"},
		{"https://dns.example:/dns-query", false, "Неверный порт DNS-сервера"},
		{"https://dns.example/" + strings.Repeat("a", 2048), false, "Слишком длинный адрес DNS-сервера"},
		{"https://127.0.0.1/dns-query", true, "Этот адрес находится в вашей локальной сети и через VPN недоступен"},
		{"tls://192.168.1.1", true, "Этот адрес находится в вашей локальной сети и через VPN недоступен"},
		{"tcp://[fe80::1]", true, "Этот адрес находится в вашей локальной сети и через VPN недоступен"},
		{"tcp://0.0.0.0", true, "Этот адрес находится в вашей локальной сети и через VPN недоступен"},
		{"tcp://9.9.9.9", false, "Для прямых запросов нужен зашифрованный сервер: https://… или tls://…"},
	}
	for _, c := range bad {
		if _, err := ParseUpstream(c.raw, c.tunnel); err == nil || err.Error() != c.msg {
			t.Errorf("%q (tunnel %v): %v, want %q", c.raw, c.tunnel, err, c.msg)
		}
	}
}

func TestPresets(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets {
		if seen[p.ID] || p.ID == Custom || p.ID == "" {
			t.Fatalf("bad preset ID %q", p.ID)
		}
		seen[p.ID] = true
		if len(p.Bootstrap) == 0 {
			t.Errorf("%s: no bootstrap addresses", p.ID)
		}
		for _, tunnel := range []bool{true, false} {
			if tunnel && !p.Tunnel || !tunnel && !p.Direct {
				if _, err := (Upstream{Preset: p.ID}).Spec(tunnel); err == nil {
					t.Errorf("%s allowed for tunnel=%v", p.ID, tunnel)
				}
				continue
			}
			s, err := (Upstream{Preset: p.ID}).Spec(tunnel)
			if err != nil || s.Scheme != "https" || s.Name != p.Name || len(s.Bootstrap) == 0 {
				t.Errorf("%s: %+v %v", p.ID, s, err)
			}
		}
	}
	if y := FindPreset("yandex"); y == nil || y.Tunnel || !y.Direct {
		t.Fatalf("yandex must be direct only: %+v", y)
	}
	if s, err := (Upstream{}).Spec(true); err != nil || s.Name != "Cloudflare" {
		t.Fatalf("default tunnel: %+v %v", s, err)
	}
}

func TestConfigValidateActive(t *testing.T) {
	for _, c := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{Tunnel: Upstream{Preset: "nope"}}, false},
		{Config{Direct: Upstream{Preset: "nope"}}, false},
		{Config{Tunnel: Upstream{Preset: Custom}}, false},
		{Config{Direct: Upstream{Preset: Custom, URL: "tcp://9.9.9.9"}}, false},
		{Config{Tunnel: Upstream{Preset: Custom, URL: "tcp://9.9.9.9"}}, true},
		{Config{Tunnel: Upstream{Preset: "google", URL: "garbage"}}, true}, // the URL of a preset is ignored
		{Config{Tunnel: Upstream{Preset: "yandex"}}, false},
		{Config{Direct: Upstream{Preset: "yandex"}}, true},
	} {
		if err := c.cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.cfg, err)
		}
	}
	c := Config{Tunnel: Upstream{Preset: "google", URL: "x"}, Direct: Upstream{Preset: Custom, URL: "tls://d.example"}}
	c.Normalize()
	if c.Tunnel.URL != "" || c.Direct.URL == "" {
		t.Fatalf("normalize: %+v", c)
	}
	for _, c := range []struct {
		cfg    Config
		active bool
	}{
		{Config{}, false},
		{Config{StripECH: true, IgnoreAddrRules: true, Tunnel: Upstream{Preset: "google"}}, false},
		{Config{BlockBrowserDoH: true}, true},
		{Config{ByRules: true}, true},
		{Config{Direct: Upstream{Preset: "quad9"}}, true},
	} {
		if c.cfg.Active() != c.active {
			t.Errorf("%+v: active %v", c.cfg, !c.active)
		}
	}
	if (Upstream{Preset: Custom, URL: "https://secret.example/abc"}).UpstreamName(true) != CustomName {
		t.Fatal("a custom server is named by its URL")
	}
}
