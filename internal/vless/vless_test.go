package vless

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const testID = "5f0b7c1e-1234-4abc-9def-0123456789ab"

// A REALITY public key is 32 bytes, base64url without padding.
const testPBK = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"

func TestParseReality(t *testing.T) {
	l, warns, err := Parse("vless://" + testID + "@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.org&fp=Chrome&pbk=" + testPBK + "&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none&packetEncoding=xudp#NL%20Reality")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings %v", warns)
	}
	want := Link{Name: "NL Reality", Host: "example.com", Port: 443, Settings: Settings{
		ID: testID, Flow: FlowVision, Security: "reality", SNI: "www.example.org", Fingerprint: "chrome",
		PublicKey: testPBK, ShortID: "6ba85179e30d4fc2", SpiderX: "/",
	}}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("got %+v\nwant %+v", l, want)
	}
}

func TestParseTransports(t *testing.T) {
	cases := []struct {
		link string
		want Settings
	}{
		{"vless://" + testID + "@example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#ws",
			Settings{ID: testID, Network: "ws", Security: "tls", Path: "/ws?ed=2048", Host: "cdn.example.com", SNI: "cdn.example.com", ALPN: "h2,http/1.1"}},
		{"vless://" + testID + "@[2001:db8::1]:8443?type=grpc&security=tls&serviceName=svc&mode=multi&authority=a.example.com",
			Settings{ID: testID, Network: "grpc", Security: "tls", ServiceName: "svc", Mode: "multi", Authority: "a.example.com"}},
		{"vless://" + testID + "@example.com:443?type=splithttp&security=reality&sni=www.example.org&pbk=" + testPBK + "&path=%2Fx&mode=stream-one&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
			Settings{ID: testID, Network: "xhttp", Security: "reality", SNI: "www.example.org", PublicKey: testPBK, Path: "/x", Mode: "stream-one", Extra: `{"xPaddingBytes":"100-1000"}`}},
		{"vless://" + testID + "@example.com:80?type=httpupgrade&security=tls&path=%2Fup&host=example.com",
			Settings{ID: testID, Network: "httpupgrade", Security: "tls", Path: "/up", Host: "example.com"}},
		{"vless://" + testID + "@example.com:443?type=grpc&security=tls&path=legacy",
			Settings{ID: testID, Network: "grpc", Security: "tls", ServiceName: "legacy"}},
		{"vless://" + testID + "@192.168.1.10:2000?type=kcp&headerType=wechat-video",
			Settings{ID: testID, Network: "kcp", HeaderType: "wechat-video"}},
		{"vless://short-id@example.com:443?security=tls&pcs=" + strings.Repeat("ab", 32) + "&vcn=example.net",
			Settings{ID: "short-id", Security: "tls", PinSHA256: strings.Repeat("ab", 32), VerifyName: "example.net"}},
	}
	for _, c := range cases {
		l, _, err := Parse(c.link)
		if err != nil {
			t.Errorf("%s: %v", c.link, err)
			continue
		}
		if !reflect.DeepEqual(l.Settings, c.want) {
			t.Errorf("%s:\ngot  %+v\nwant %+v", c.link, l.Settings, c.want)
		}
	}
}

func TestParseWarnings(t *testing.T) {
	_, warns, err := Parse("vless://" + testID + "@example.com:443?security=tls&allowInsecure=1&foo=bar")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 2 || !strings.Contains(warns[0], "allowInsecure") || warns[1] != "ignored parameter foo" {
		t.Errorf("warnings %q", warns)
	}
}

func TestParseErrors(t *testing.T) {
	for _, link := range []string{
		"vmess://abc",
		"vless://example.com:443",
		"vless://" + testID + "@example.com",
		"vless://" + testID + "@example.com:0?security=tls",
		"vless://" + testID + "@:443?security=tls",
		"vless://not-a-uuid-but-much-longer-than-thirty-bytes@example.com:443?security=tls",
		"vless://" + testID + "@example.com:443?security=tls&type=h2",
		"vless://" + testID + "@example.com:443?security=tls&type=quic",
		"vless://" + testID + "@example.com:443?security=reality&sni=a.example",                     // no pbk
		"vless://" + testID + "@example.com:443?security=reality&pbk=" + testPBK,                    // no sni
		"vless://" + testID + "@example.com:443?security=reality&sni=a&pbk=" + testPBK + "&type=ws", // REALITY on ws
		"vless://" + testID + "@example.com:443?security=tls&flow=xtls-rprx-direct",                 // removed flow
		"vless://" + testID + "@example.com:443?flow=xtls-rprx-vision",                              // vision without tls
		"vless://" + testID + "@example.com:443?security=tls&flow=xtls-rprx-vision&type=ws",         // vision on ws
		"vless://" + testID + "@example.com:443?security=xtls",                                      // legacy XTLS
		"vless://" + testID + "@example.com:443?security=tls&type=xhttp&extra=notjson",              // extra
		"vless://" + testID + "@example.com:443?security=tls&pcs=abcd",                              // short pin
		"vless://" + testID + "@example.com:443?security=reality&sni=a&pbk=" + testPBK + "&sid=zz",  // sid
		"vless://" + testID + "@example.com:443?security=tls&encryption=aes-128-gcm",                // vmess-style
		"vless://" + testID + "@example.com:443?security=tls&type=grpc&mode=weird&serviceName=x",    // grpc mode
		"vless://" + testID + "@example.com:443?security=tls&fp=chrome%22",                          // fp
		"vless://" + testID + "@example.com:443?security=tls&host=a%0Ab",                            // newline
		"vless://" + testID + "@example.com:443?type=kcp&seed=s&headerType=dtls&security=tls",       // kcp seed+header
	} {
		if _, _, err := Parse(link); err == nil {
			t.Errorf("%s: no error", link)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, link := range []string{
		"vless://" + testID + "@example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.example.org&fp=chrome&pbk=" + testPBK + "&sid=6ba8&spx=%2F#NL",
		"vless://" + testID + "@[2001:db8::1]:8443?type=xhttp&security=tls&path=%2Fx&host=h.example&mode=auto&extra=%7B%7D&alpn=h2#v6",
		"vless://" + testID + "@example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com&sni=cdn.example.com&ech=AEX%2B",
		"vless://" + testID + "@10.0.0.1:443?type=kcp&seed=pw",
	} {
		a, _, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		b, _, err := Parse(a.String())
		if err != nil {
			t.Fatalf("%s: %v", a.String(), err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("round trip of %s:\n%+v\n%+v", link, a, b)
		}
	}
}

func TestTCPFragmentShareLink(t *testing.T) {
	want := TCPFragment{Packets: "tlshello", Length: "20-40", Interval: "0-2"}
	link := Link{Host: "example.org", Port: 443, Settings: Settings{
		ID: "fragment-test", Security: "tls", TCPFragment: want,
	}}
	got, warnings, err := Parse(link.String())
	if err != nil || len(warnings) != 0 || got.Settings.TCPFragment != want {
		t.Fatalf("fm round trip: %+v %v %v", got.Settings.TCPFragment, warnings, err)
	}
	for _, bad := range []string{
		`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"0-40","interval":"0-2"}}]}`,
		`{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"20-40","interval":"0-2","unknown":"value"}}]}`,
		`{"udp":[{"type":"unsupported"}]}`,
	} {
		u, err := url.Parse(link.String())
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("fm", bad)
		u.RawQuery = q.Encode()
		got, warnings, err := Parse(u.String())
		if err != nil || !slices.Contains(warnings, "finalmask не переносится") || got.Settings.TCPFragment != (TCPFragment{}) {
			t.Fatalf("unsupported fm: %+v %v %v", got.Settings.TCPFragment, warnings, err)
		}
	}
}

func TestPlainAllowed(t *testing.T) {
	for host, want := range map[string]bool{
		"192.168.1.1": true, "10.1.2.3": true, "127.0.0.1": true, "fe80::1": true, "fd00::1": true,
		"router.lan": true, "nas.local": true, "localhost": true,
		"203.0.113.5": false, "example.com": false, "2001:db8::1": false,
	} {
		if got := PlainAllowed(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
	plain := Settings{ID: testID}
	if err := plain.ValidateFor("example.com"); err == nil {
		t.Error("plain VLESS to a public name passed")
	}
	if err := plain.ValidateFor("192.168.1.10"); err != nil {
		t.Errorf("plain VLESS in the LAN: %v", err)
	}
	plain.Encryption = "mlkem768x25519plus.native.0rtt.abc"
	if err := plain.ValidateFor("example.com"); err != nil {
		t.Errorf("VLESS encryption: %v", err)
	}
}

func config(t *testing.T, s Settings, r Run) map[string]any {
	t.Helper()
	if r.SOCKSListen == "" {
		r.SOCKSListen = "127.0.0.1:20001"
	}
	b, err := Config(s, r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// at walks a decoded config: keys for objects, ints for arrays.
func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("%v: not an object at %q", path, k)
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("%v: no element %d", path, k)
			}
			v = a[k]
		}
	}
	return v
}

func TestConfigReality(t *testing.T) {
	s := Settings{ID: testID, Flow: FlowVision, Security: "reality", SNI: "www.example.org", PublicKey: testPBK, ShortID: "ab"}
	m := config(t, s, Run{Host: "example.com", Port: 443, Dial: netip.MustParseAddr("203.0.113.5"), SOCKSUsername: "u", SOCKSPassword: "p"})
	in := at(t, m, "inbounds", 0)
	if at(t, in, "protocol") != "socks" || at(t, in, "listen") != "127.0.0.1" || at(t, in, "port") != 20001.0 ||
		at(t, in, "settings", "auth") != "password" || at(t, in, "settings", "udp") != true ||
		at(t, in, "settings", "accounts", 0, "user") != "u" || at(t, in, "settings", "accounts", 0, "pass") != "p" {
		t.Errorf("inbound %v", in)
	}
	out := at(t, m, "outbounds", 0)
	if at(t, out, "protocol") != "vless" || at(t, out, "settings", "address") != "203.0.113.5" || at(t, out, "settings", "port") != 443.0 ||
		at(t, out, "settings", "id") != testID || at(t, out, "settings", "flow") != FlowVision || at(t, out, "settings", "encryption") != "none" {
		t.Errorf("outbound %v", out)
	}
	ss := at(t, out, "streamSettings")
	if at(t, ss, "network") != "raw" || at(t, ss, "security") != "reality" ||
		at(t, ss, "realitySettings", "serverName") != "www.example.org" || at(t, ss, "realitySettings", "fingerprint") != "chrome" ||
		at(t, ss, "realitySettings", "publicKey") != testPBK || at(t, ss, "realitySettings", "shortId") != "ab" {
		t.Errorf("stream %v", ss)
	}
	if len(at(t, m, "outbounds").([]any)) != 1 || m["routing"] != nil || m["dns"] != nil {
		t.Errorf("more than the one outbound: %v", m)
	}
}

func TestConfigTLSPinnedIP(t *testing.T) {
	// A pinned IP keeps the server's name for TLS and the WebSocket host.
	s := Settings{ID: testID, Network: "ws", Security: "tls", Path: "/ws", Fingerprint: "firefox", ALPN: "http/1.1"}
	m := config(t, s, Run{Host: "vpn.example.com", Port: 443, Dial: netip.MustParseAddr("203.0.113.5")})
	ss := at(t, m, "outbounds", 0, "streamSettings")
	if at(t, ss, "tlsSettings", "serverName") != "vpn.example.com" || at(t, ss, "wsSettings", "host") != "vpn.example.com" ||
		at(t, ss, "wsSettings", "path") != "/ws" || at(t, ss, "tlsSettings", "fingerprint") != "firefox" ||
		at(t, ss, "tlsSettings", "alpn", 0) != "http/1.1" {
		t.Errorf("stream %v", ss)
	}
	// An IP server without an SNI sends none.
	m = config(t, Settings{ID: testID, Security: "tls"}, Run{Host: "203.0.113.5", Port: 443})
	if _, has := at(t, m, "outbounds", 0, "streamSettings", "tlsSettings").(map[string]any)["serverName"]; has {
		t.Error("serverName for an IP server")
	}
}

func TestConfigTransports(t *testing.T) {
	run := Run{Host: "example.com", Port: 443}
	m := config(t, Settings{ID: testID, Network: "xhttp", Security: "tls", Path: "/x", Mode: "packet-up", Extra: `{"xmux":{"maxConcurrency":"16-32"}}`}, run)
	x := at(t, m, "outbounds", 0, "streamSettings", "xhttpSettings")
	if at(t, x, "mode") != "packet-up" || at(t, x, "extra", "xmux", "maxConcurrency") != "16-32" || at(t, x, "host") != "example.com" {
		t.Errorf("xhttp %v", x)
	}
	m = config(t, Settings{ID: testID, Network: "grpc", Security: "tls", ServiceName: "svc", Mode: "multi"}, run)
	if g := at(t, m, "outbounds", 0, "streamSettings", "grpcSettings"); at(t, g, "serviceName") != "svc" || at(t, g, "multiMode") != true {
		t.Errorf("grpc %v", g)
	}
	m = config(t, Settings{ID: testID, Security: "tls", HeaderType: "http", Host: "a.example,b.example", Path: "/p"}, run)
	if h := at(t, m, "outbounds", 0, "streamSettings", "rawSettings", "header"); at(t, h, "type") != "http" ||
		at(t, h, "request", "headers", "Host", 1) != "b.example" || at(t, h, "request", "path", 0) != "/p" {
		t.Errorf("raw http header %v", h)
	}
	m = config(t, Settings{ID: testID, Network: "kcp", Seed: "pw"}, Run{Host: "10.0.0.2", Port: 2000})
	if mask := at(t, m, "outbounds", 0, "streamSettings", "finalmask", "udp", 0); at(t, mask, "type") != "mkcp-legacy" || at(t, mask, "settings", "value") != "pw" {
		t.Errorf("kcp %v", mask)
	}
	m = config(t, Settings{ID: testID, Encryption: "mlkem768x25519plus.native.0rtt.key"}, run)
	if at(t, m, "outbounds", 0, "settings", "encryption") != "mlkem768x25519plus.native.0rtt.key" || at(t, m, "outbounds", 0, "streamSettings", "security") != "none" {
		t.Error("VLESS encryption")
	}
}

func TestConfigRefuses(t *testing.T) {
	if _, err := Config(Settings{ID: testID}, Run{Host: "example.com", Port: 443, SOCKSListen: "127.0.0.1:1"}); err == nil {
		t.Error("plain VLESS to a public server")
	}
	// The name is local, the pinned address is not.
	if _, err := Config(Settings{ID: testID}, Run{Host: "nas.lan", Port: 443, Dial: netip.MustParseAddr("203.0.113.9"), SOCKSListen: "127.0.0.1:1"}); err == nil {
		t.Error("plain VLESS to a public pinned IP")
	}
	if _, err := Config(Settings{ID: testID, Security: "tls"}, Run{Host: "example.com", Port: 0, SOCKSListen: "127.0.0.1:1"}); err == nil {
		t.Error("port 0")
	}
}
