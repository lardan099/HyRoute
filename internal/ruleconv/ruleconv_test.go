package ruleconv

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// short form of a result for comparisons: "target[name]: items | proto ports off".
func dump(r Result) []string {
	var out []string
	for _, x := range r.Rules {
		var items []string
		for _, it := range x.Items {
			items = append(items, it.String())
		}
		s := x.Target
		if x.Name != "" {
			s += "[" + x.Name + "]"
		}
		s += ":"
		if len(items) > 0 {
			s += " " + strings.Join(items, " ")
		}
		if x.Proto != "" || len(x.Ports) > 0 {
			s += " | " + strings.TrimSpace(x.Proto+" "+strings.Join(x.Ports, ","))
		}
		if x.Off {
			s += " off"
		}
		out = append(out, s)
	}
	return out
}

func check(t *testing.T, r Result, err error, want []string, def string) {
	t.Helper()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	got := dump(r)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s\nwant:\n%s\nwarnings: %v", strings.Join(got, "\n"), strings.Join(want, "\n"), r.Warnings)
	}
	if r.Default != def {
		t.Fatalf("default %q, want %q", r.Default, def)
	}
}

func hasWarning(r Result, sub string) bool {
	for _, w := range r.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestOmegaConditions(t *testing.T) {
	text := `[SwitchyOmega Conditions]
@with result
; comment

*.example.com +Proxy A
example.org +Proxy A
HostRegex: ^api[0-9]+\.example\.net$ +Proxy A
Ip: 192.0.2.0/24 +Proxy A
*.direct.example +direct
UrlWildcard: *://*.example.io/* +Proxy A
UrlWildcard: https://docs.example.io/path/* +Proxy A
Keyword: tracker +Proxy A
UrlRegex: ^https://x\.example/ +Proxy A
Weekday: 1~5 +Proxy A
* +direct
*.after.example +Proxy A
`
	r, err := Convert(text, Auto)
	if r.Format != Omega {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		`Proxy A: suffix:example.com exact:example.org regexp:^api[0-9]+\.example\.net$ ip:192.0.2.0/24`,
		`direct: suffix:direct.example`,
		`Proxy A: suffix:example.io exact:docs.example.io keyword:tracker`,
	}, "direct")
	for _, w := range []string{"путь страницы", "ищется во всём адресе", "по адресу страницы", "день недели", "правил ниже него (1)"} {
		if !hasWarning(r, w) {
			t.Errorf("no warning %q: %v", w, r.Warnings)
		}
	}
	if len(r.Targets) != 2 || r.Targets[0] != (Target{Name: "Proxy A", Kind: ToProxy}) || r.Targets[1].Kind != ToDirect {
		t.Fatalf("targets %+v", r.Targets)
	}
}

func TestOmegaBackup(t *testing.T) {
	text := `{
  "+auto switch": {"profileType": "SwitchProfile", "name": "auto switch", "defaultProfileName": "direct", "rules": [
    {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.example.com"}, "profileName": "hyst"},
    {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.example.com"}, "profileName": "hyst"},
    {"condition": {"conditionType": "IpCondition", "ip": "192.0.2.0", "prefixLength": 24}, "profileName": "hyst"},
    {"condition": {"conditionType": "UrlWildcardCondition", "pattern": "*://*.example.org/*"}, "profileName": "Kz"},
    {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.pac.example"}, "profileName": "PAC_LIST"},
    {"condition": {"conditionType": "WeekdayCondition", "startDay": 1, "endDay": 5}, "profileName": "hyst"}
  ]},
  "+hyst": {"profileType": "FixedProfile", "name": "hyst", "fallbackProxy": {"scheme": "socks5", "host": "127.0.0.1", "port": 1080}, "bypassList": []},
  "+Kz": {"profileType": "FixedProfile", "name": "Kz", "fallbackProxy": {"scheme": "http", "host": "127.0.0.1", "port": 3128}, "auth": {"fallbackProxy": {"username": "u", "password": "secret-not-shown"}}},
  "+PAC_LIST": {"profileType": "PacProfile", "name": "PAC_LIST", "pacScript": "function FindProxyForURL(url, host) { if (x) { a(); return \"DIRECT\"; } return \"DIRECT\"; }"},
  "-startupProfileName": "auto switch",
  "schemaVersion": 2
}`
	r, err := Convert(text, Auto)
	if r.Format != OmegaBak {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"hyst: suffix:example.com ip:192.0.2.0/24",
		"Kz: suffix:example.org",
		"PAC_LIST: suffix:pac.example",
	}, "direct")
	want := []Target{{"hyst", ToProxy, "socks5 127.0.0.1:1080"}, {"Kz", ToProxy, "http 127.0.0.1:3128"}, {"PAC_LIST", ToProxy, "PAC-профиль"}, {"direct", ToDirect, ""}}
	if fmt.Sprint(r.Targets) != fmt.Sprint(want) {
		t.Fatalf("targets %+v", r.Targets)
	}
	if !hasWarning(r, "PAC-профиль") || !hasWarning(r, "день недели") {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if strings.Contains(fmt.Sprint(r), "secret") {
		t.Fatal("a proxy password in the result")
	}
	if _, err := Convert(`{"+p": {"profileType": "FixedProfile", "name": "p"}, "schemaVersion": 2}`, Auto); err == nil {
		t.Fatal("a backup without a switch profile converted")
	}
}

func TestOmegaRuleList(t *testing.T) {
	// A rule list without results: "!" lines are exceptions, checked first.
	text := "[SwitchyOmega Conditions]\n*.example.com\n!*.cdn.example.com\nexample.org\n"
	r, err := Convert(text, Auto)
	check(t, r, err, []string{
		"Исключение: suffix:cdn.example.com",
		"Совпадение: suffix:example.com exact:example.org",
	}, "")
	// Lines "pattern +Profile" without the header (HyRoute's ACL converter).
	r, err = Convert("*.example.com +hyst\n*.example.org +hyst\n", Auto)
	if r.Format != Omega {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{"hyst: suffix:example.com suffix:example.org"}, "")
}

func TestOmegaPAC(t *testing.T) {
	// The shape SwitchyOmega exports.
	text := `var FindProxyForURL = function(init, profiles) {
    return function(url, host) {
        "use strict";
        var result = init, scheme = url.substr(0, url.indexOf(":"));
        do {
            if (!profiles[result]) return result;
            result = profiles[result];
            if (typeof result === "function") result = result(url, host, scheme);
        } while (typeof result !== "string" || result.charCodeAt(0) === 43);
        return result;
    };
}("+auto switch", {
    "+auto switch": function(url, host, scheme) {
        "use strict";
        if (/(?:^|\.)example\.com$/.test(host)) return "+My proxy";
        if (/^exact\.example\.org$/.test(host)) return "+My proxy";
        if (/(?:^|\.)direct\.example$/.test(host)) return "DIRECT";
        if (/(?:^|\.)example\.net$/.test(host)) return "+My proxy";
        if (isInNet(host, "198.51.100.0", "255.255.255.0")) return "+My proxy";
        if (scheme === "https" && /(?:^|\.)secure\.example$/.test(host)) return "+My proxy";
        if (/^https:\/\/x\.example\//.test(url)) return "+My proxy";
        if (url.indexOf("ads") >= 0) return "+Other";
        return "DIRECT";
    },
    "+My proxy": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";
        return "PROXY 127.0.0.1:8080";
    },
    "+Other": function(url, host, scheme) {
        "use strict";
        if (/(?:^|\.)y\.example$/.test(host)) return "+My proxy";
        return "DIRECT";
    }
});`
	r, err := Convert(text, Auto)
	if r.Format != PAC {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"My proxy: suffix:example.com exact:exact.example.org",
		"DIRECT: suffix:direct.example",
		"My proxy: suffix:example.net ip:198.51.100.0/24 suffix:secure.example",
		"Other: keyword:ads",
	}, "DIRECT")
	want := []Target{{"My proxy", ToProxy, "PROXY 127.0.0.1:8080"}, {"DIRECT", ToDirect, ""}, {"Other", ToProxy, ""}}
	if fmt.Sprint(r.Targets) != fmt.Sprint(want) {
		t.Fatalf("targets %+v", r.Targets)
	}
	if !hasWarning(r, "одной схемы") || !hasWarning(r, "по адресу страницы") || !hasWarning(r, "во всём адресе") {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestPlainPAC(t *testing.T) {
	text := `// A hand-written PAC
function FindProxyForURL(url, host) {
  if (isPlainHostName(host)) return "DIRECT";
  if (shExpMatch(host, "*.example.com") || dnsDomainIs(host, ".example.org")) {
    return "SOCKS5 127.0.0.1:1080; DIRECT";
  }
  if (host == "exact.example.net") return "PROXY 127.0.0.1:3128";
  if (dnsDomainIs(host, "example.io") && shExpMatch(url, "https:*")) return "PROXY 127.0.0.1:3128";
  /* everything else */
  return "DIRECT";
}`
	r, err := Convert(text, Auto)
	check(t, r, err, []string{
		"SOCKS5 127.0.0.1:1080: sub:example.com sub:example.org",
		"PROXY 127.0.0.1:3128: exact:exact.example.net",
	}, "DIRECT")
	if !hasWarning(r, "локальных адресов") || !hasWarning(r, "сложное условие") {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestAutoProxy(t *testing.T) {
	list := "[AutoProxy 0.2.9]\n! comment\n||example.com\n|http://example.org/path\n.example.net\nexample.io/page\nword\n/^https?:\\/\\/x\\.example\\//\n@@||cdn.example.com\n"
	for _, text := range []string{list, base64.StdEncoding.EncodeToString([]byte(list))} {
		r, err := Convert(text, Auto)
		if r.Format != AutoProxy {
			t.Fatalf("format %s", r.Format)
		}
		check(t, r, err, []string{
			"Исключение: suffix:cdn.example.com",
			"Совпадение: suffix:example.com exact:example.org suffix:example.net suffix:example.io keyword:word",
		}, "")
		if !hasWarning(r, "регулярных выражений") {
			t.Fatalf("warnings %v", r.Warnings)
		}
	}
}

func TestV2RayNTable(t *testing.T) {
	// Rows copied from v2rayN's routing rules window.
	text := strings.Join([]string{
		"True\tTorrent\t\tdirect\t\tbittorrent\t\t\t",
		"True\tAds\t\tblock\t\t\t\t\tgeosite:category-ads-all",
		"False\tOff rule\t\tdirect\t\t\t\t\tdomain:off.example",
		"True\tMine\t\tproxy\t\t\t\t\tgeosite:example,domain:example.com,full:exact.example.org,keyword-ish.example,regexp:^a\\.example$,192.0.2.0/24,198.51.100.7,geoip:example,app.exe,C:\\Tools\\tool.exe",
		"True\tGames\t\tproxy\t27000-27100\t\t\ttcp,udp\t",
		"True\tAll\t\tdirect\t0-65535\t\t\t\t",
		"True\tAfter\t\tdirect\t\t\t\t\tgeoip:private",
	}, "\n")
	r, err := Convert(text, Auto)
	if r.Format != V2RayN {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"block[Ads]: geosite:category-ads-all",
		"direct[Off rule]: suffix:off.example off",
		`proxy[Mine]: geosite:example suffix:example.com exact:exact.example.org keyword:keyword-ish.example regexp:^a\.example$ ip:192.0.2.0/24 ip:198.51.100.7 geoip:example`,
		`proxy[Mine (программы)]: app:app.exe app:C:\Tools\tool.exe`,
		"proxy[Games]: | 27000-27100",
	}, "direct")
	if !hasWarning(r, "bittorrent") || !hasWarning(r, "правил ниже него (1)") {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "keyword:") {
		t.Fatalf("notes %v", r.Notes)
	}
}

func TestV2RayNJSON(t *testing.T) {
	text := `[
  {"remarks": "Sites", "outboundTag": "proxy", "domain": ["domain:example.com", "geosite:example"], "enabled": true},
  {"outboundTag": "direct", "ip": ["geoip:private", "203.0.113.0/24"], "port": 443, "network": "udp"},
  {"outboundTag": "proxy", "inboundTag": ["socks"], "domain": ["domain:in.example"]},
  {"outboundTag": "block", "domain": ["ext:custom.dat:ads"]},
  {"ruleType": "dns", "outboundTag": "proxy", "domain": ["domain:dns.example"]}
]`
	r, err := Convert(text, Auto)
	if r.Format != V2RayN {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"proxy[Sites]: suffix:example.com geosite:example",
		"direct: geoip:private ip:203.0.113.0/24 | udp 443",
	}, "")
	if !hasWarning(r, "inboundTag") || !hasWarning(r, "своего файла") || !hasWarning(r, "только для DNS") {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "первый выход") {
		t.Fatalf("notes %v", r.Notes)
	}
	// Xray config with comments.
	r, err = Convert(`{
  // routing of an Xray config
  "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "domain": ["full:x.example"]}]}
}`, Auto)
	if r.Format != Xray {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{"proxy: exact:x.example"}, "")
}

func TestSingBox(t *testing.T) {
	text := `{
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"domain_suffix": ["example.com", ".example.org"], "domain": ["exact.example.net"], "outbound": "proxy"},
      {"rule_set": ["geosite-example", "geoip-example", "my-list"], "outbound": "direct"},
      {"ip_is_private": true, "outbound": "direct"},
      {"process_name": ["app.exe"], "domain_keyword": ["word"], "outbound": "proxy"},
      {"network": "udp", "port": [443], "action": "reject"},
      {"network": "udp", "outbound": "proxy"},
      {"type": "logical", "mode": "and", "rules": [], "outbound": "proxy"},
      {"source_ip_cidr": ["10.0.0.0/8"], "outbound": "direct"}
    ],
    "final": "proxy"
  }
}`
	r, err := Convert(text, Auto)
	if r.Format != SingBox {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"proxy: exact:exact.example.net suffix:example.com sub:example.org",
		"direct: geosite:example geoip:example",
		"direct: geoip:private",
		"proxy: app:app.exe keyword:word",
		"reject: | udp 443",
		"proxy: | udp 1-65535",
	}, "proxy")
	if !hasWarning(r, "my-list") || !hasWarning(r, "логическое") || !hasWarning(r, "source_ip_cidr") {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if r.Targets[2].Kind != ToBlock {
		t.Fatalf("targets %+v", r.Targets)
	}
}

func TestDetectRuleArrays(t *testing.T) {
	for text, want := range map[string]Format{
		`[{"action": "sniff"}, {"domain_suffix": ["example.com"], "outbound": "proxy"}]`:        SingBox,
		`[{"remarks": "x"}, {"outboundTag": "proxy", "domain": ["domain:example.com"]}]`:        V2RayN,
		`{"rules": [{"action": "sniff"}, {"ip_cidr": ["192.0.2.0/24"], "outbound": "direct"}]}`: SingBox,
	} {
		if f := Detect(text); f != want {
			t.Errorf("%s: %s, want %s", text, f, want)
		}
	}
}

func TestThroneAndNekoray(t *testing.T) {
	// A Throne route profile: rules with outbound IDs.
	r, err := Convert(`{"name": "x", "rules": [{"name": "Local", "ip_cidr": ["192.0.2.0/24"], "outboundID": -2}, {"domain_suffix": ["example.com"], "outboundID": -1}], "default_outboundID": -1}`, Auto)
	check(t, r, err, []string{"direct[Local]: ip:192.0.2.0/24", "proxy: suffix:example.com"}, "proxy")
	// Nekoray's simple lists: block, then direct, then proxy.
	r, err = Convert(`{"direct_domain": "geosite:example\ndomain:direct.example", "direct_ip": "geoip:private\n192.0.2.0/24", "proxy_domain": "domain:example.com", "block_domain": "geosite:category-ads-all", "def_outbound": "direct"}`, Auto)
	if r.Format != Nekoray {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"block[block]: geosite:category-ads-all",
		"direct[direct]: geosite:example suffix:direct.example geoip:private ip:192.0.2.0/24",
		"proxy[proxy]: suffix:example.com",
	}, "direct")
}

func TestFoxyProxy(t *testing.T) {
	v8 := `{"mode": "pattern", "data": [
  {"active": true, "title": "Work", "type": "socks5", "hostname": "127.0.0.1", "port": "1080", "username": "u", "password": "secret-not-shown",
   "include": [{"type": "wildcard", "pattern": "*.example.com", "active": true}, {"type": "wildcard", "pattern": "https://example.org/*", "active": true},
               {"type": "regex", "pattern": "(?:^|\\.)example\\.net$", "active": true}, {"type": "wildcard", "pattern": "off.example", "active": false}],
   "exclude": [{"type": "wildcard", "pattern": "cdn.example.com", "active": true}]},
  {"active": true, "title": "All", "type": "http", "hostname": "127.0.0.1", "port": "3128", "include": [{"type": "wildcard", "pattern": "*", "active": true}]}
]}`
	r, err := Convert(v8, Auto)
	if r.Format != FoxyProxy {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"Мимо «Work»[Мимо «Work»]: exact:cdn.example.com",
		"Work[Work]: suffix:example.com exact:example.org suffix:example.net",
	}, "All")
	for _, tg := range r.Targets {
		if strings.Contains(tg.Detail, "secret") || strings.Contains(tg.Detail, "u@") {
			t.Fatalf("a password in a target: %+v", tg)
		}
	}
	if r.Targets[1] != (Target{"Work", ToProxy, "socks5 127.0.0.1:1080"}) {
		t.Fatalf("targets %+v", r.Targets)
	}
	// Older export: proxies by id, in index order.
	old := `{"mode": "patterns", "k2": {"title": "B", "type": 1, "address": "127.0.0.1", "port": 8080, "active": true, "index": 1, "whitePatterns": [{"pattern": "*.example.org", "type": 1, "active": true}], "blackPatterns": []},
"k1": {"title": "A", "type": 3, "address": "127.0.0.1", "port": 1080, "active": true, "index": 0, "whitePatterns": [{"pattern": "*.example.com", "type": 1, "active": true}], "blackPatterns": []}}`
	r, err = Convert(old, Auto)
	check(t, r, err, []string{"A[A]: suffix:example.com", "B[B]: suffix:example.org"}, "")
}

func TestClash(t *testing.T) {
	text := `proxies:
  - {name: a, type: ss}
rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - DOMAIN,exact.example.org,Proxy
  - DOMAIN-KEYWORD,word,Proxy
  - 'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve'
  - GEOIP,private,DIRECT
  - GEOSITE,category-ads-all,REJECT
  - PROCESS-NAME,app.exe,Proxy
  - DST-PORT,22,DIRECT
  - NETWORK,udp,Proxy
  - RULE-SET,my-set,Proxy
  - SRC-IP-CIDR,10.0.0.0/8,DIRECT
  - AND,((DOMAIN,x.example),(NETWORK,udp)),REJECT
  - MATCH,Proxy
  - DOMAIN,after.example,DIRECT
`
	r, err := Convert(text, Auto)
	if r.Format != Clash {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{
		"Proxy: suffix:example.com exact:exact.example.org keyword:word",
		"DIRECT: ip:192.0.2.0/24 geoip:private",
		"REJECT: geosite:category-ads-all",
		"Proxy: app:app.exe",
		"DIRECT: | 22",
		"Proxy: | udp 1-65535",
	}, "Proxy")
	if !hasWarning(r, "my-set") || !hasWarning(r, "составное") || !hasWarning(r, "по источнику") || !hasWarning(r, "правил ниже него (1)") {
		t.Fatalf("warnings %v", r.Warnings)
	}
}

func TestList(t *testing.T) {
	r, err := Convert("example.com\n*.example.org\nhttps://example.net/path\n192.0.2.1, 198.51.100.0/24\ngeosite:example\napp.exe\n", Auto)
	if r.Format != List {
		t.Fatalf("format %s", r.Format)
	}
	check(t, r, err, []string{"Список: suffix:example.com suffix:example.org suffix:example.net ip:192.0.2.1 ip:198.51.100.0/24 geosite:example app:app.exe"}, "")
}

func TestDetectHysteria(t *testing.T) {
	if f := Detect("acl:\n  inline:\n    - proxy(geosite:example)\n    - direct(all)\n"); f != Hysteria {
		t.Fatalf("format %s", f)
	}
	if _, err := Convert("- direct(all)", Hysteria); err == nil {
		t.Fatal("hysteria converted here")
	}
}

func TestEmptyAndBad(t *testing.T) {
	if _, err := Convert("   \n\n", Auto); err == nil {
		t.Fatal("empty text converted")
	}
	if _, err := Convert("\xff\xfe", Auto); err == nil {
		t.Fatal("binary converted")
	}
	if _, err := Convert(`{"rules": [{"outboundTag": "proxy", "protocol": ["bittorrent"]}]}`, Auto); err == nil || !strings.Contains(err.Error(), "bittorrent") {
		t.Fatalf("nothing converted, err %v", err)
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"*.example.com": "suffix:example.com", "example.com": "exact:example.com", ".example.com": "suffix:example.com",
		"ex*ple.com": `regexp:^ex.*ple\.com$`, "192.0.2.1": "ip:192.0.2.1",
	} {
		it, _, ok := wildcardHost(in, true)
		if !ok || it.String() != want {
			t.Errorf("%s: %v %v", in, it, ok)
		}
	}
	for in, want := range map[string]string{
		`(?:^|\.)example\.com$`: "suffix:example.com", `^example\.com$`: "exact:example.com", `\.example\.com$`: "sub:example.com",
		`^ad[0-9]+\.example\.com$`: `regexp:^ad[0-9]+\.example\.com$`,
	} {
		it, err := jsHostRegex(in)
		if err != nil || it.String() != want {
			t.Errorf("%s: %v %v", in, it, err)
		}
	}
	if _, err := jsHostRegex(`(?<=x)y`); err == nil {
		t.Error("a lookbehind accepted")
	}
	for in, want := range map[string]string{"255.255.255.0": "198.51.100.0/24", "255.255.255.255": "198.51.100.0"} {
		if p, ok := maskPrefix("198.51.100.0", in); !ok || p != want {
			t.Errorf("%s: %s %v", in, p, ok)
		}
	}
	if _, ok := maskPrefix("198.51.100.0", "255.0.255.0"); ok {
		t.Error("a broken mask accepted")
	}
	for in, want := range map[string]string{"443": "443", "1000:2000": "1000-2000", "0-65535": "", "5-5": "5"} {
		p, _, ok := portItem(in)
		if !ok || p != want {
			t.Errorf("%s: %q %v", in, p, ok)
		}
	}
}
