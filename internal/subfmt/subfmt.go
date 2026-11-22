// Package subfmt reads subscriptions that come as client configs instead
// of a list of share links: Clash (Mihomo) YAML, sing-box JSON and Xray
// JSON (one config or a list of them). The servers HyRoute runs, VLESS and
// Hysteria 2, come back as share links, so that one parser
// (hysteria.ParseURI) checks every server whatever the format.
package subfmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/vless"
)

// Result is one converted subscription.
type Result struct {
	// Format names it: "Clash", "sing-box", "Xray".
	Format string
	// Links are the servers as vless:// and hysteria2:// links.
	Links []string
	// Balancers are Xray configs whose catch-all rule selects VLESS nodes.
	Balancers []XrayBalancer
	// Other counts the servers of other protocols by type ("vmess",
	// "trojan", …).
	Other map[string]int
	// Warnings: settings a server has that HyRoute leaves out
	// ("<name>: …").
	Warnings []string
	// Errors: servers that could not be converted ("<name>: …").
	Errors []string
}

func (r *Result) other(t string) {
	if t == "" {
		t = "?"
	}
	r.Other[strings.ToLower(t)]++
}

// Convert reads body as Clash, sing-box or Xray. ok is false when it is
// none of them (a list of links, a web page …).
func Convert(body []byte) (Result, bool) {
	body = bytes.TrimPrefix(bytes.TrimSpace(body), []byte("\ufeff"))
	r := Result{Other: map[string]int{}, Links: []string{}, Warnings: []string{}, Errors: []string{}}
	if len(body) == 0 {
		return r, false
	}
	switch body[0] {
	case '{', '[':
		return r, r.json(body)
	}
	return r, r.clash(body)
}

// ---- JSON: sing-box and Xray ----

func (r *Result) json(body []byte) bool {
	var list []json.RawMessage
	if body[0] == '[' {
		if json.Unmarshal(body, &list) != nil {
			return false
		}
	} else {
		list = []json.RawMessage{body}
	}
	found := false
	for _, raw := range list {
		var cfg struct {
			Remarks   string            `json:"remarks"`
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if json.Unmarshal(raw, &cfg) != nil || cfg.Outbounds == nil {
			continue
		}
		found = true
		if r.xrayBalancer(cfg.Remarks, raw, cfg.Outbounds) {
			if r.Format == "" {
				r.Format = "Xray"
			}
			continue
		}
		for _, ob := range cfg.Outbounds {
			var head struct {
				Type     string `json:"type"`     // sing-box
				Protocol string `json:"protocol"` // Xray
				Tag      string `json:"tag"`
			}
			if json.Unmarshal(ob, &head) != nil {
				continue
			}
			switch {
			case head.Type != "":
				if r.Format == "" {
					r.Format = "sing-box"
				}
				r.singbox(head.Type, head.Tag, ob)
			case head.Protocol != "":
				if r.Format == "" {
					r.Format = "Xray"
				}
				name := cfg.Remarks
				if name == "" || len(cfg.Outbounds) > 1 && countProxies(cfg.Outbounds) > 1 {
					name = firstNonEmpty(head.Tag, cfg.Remarks)
				}
				r.xray(head.Protocol, name, ob)
			}
		}
	}
	return found
}

// countProxies counts the outbounds of an Xray config that are servers.
func countProxies(obs []json.RawMessage) int {
	n := 0
	for _, ob := range obs {
		var h struct{ Protocol string }
		json.Unmarshal(ob, &h)
		if !service(h.Protocol) {
			n++
		}
	}
	return n
}

// service: an outbound that is no server (direct, block, DNS …).
func service(t string) bool {
	switch strings.ToLower(t) {
	case "", "direct", "freedom", "block", "blackhole", "dns", "selector", "urltest", "loopback", "tor":
		return true
	}
	return false
}

func (r *Result) add(link string) { r.Links = append(r.Links, link) }

func (r *Result) fail(name string, err error) {
	r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", orUnnamed(name), err))
}

func (r *Result) warn(name, w string) {
	r.Warnings = append(r.Warnings, orUnnamed(name)+": "+w)
}

func orUnnamed(name string) string {
	if name == "" {
		return "без имени"
	}
	return name
}

// vlessLink writes a VLESS server as a link, if Settings holds.
func (r *Result) vlessLink(name, host string, port int, s vless.Settings) {
	if host == "" || port < 1 || port > 65535 {
		r.fail(name, fmt.Errorf("нет адреса или порта сервера"))
		return
	}
	s.Network = vless.NormalizeNetwork(s.Network)
	if s.Encryption == "none" {
		s.Encryption = ""
	}
	if err := s.ValidateFor(host); err != nil {
		r.fail(name, err)
		return
	}
	r.add(vless.Link{Name: name, Host: host, Port: port, Settings: s}.String())
}

// ---- sing-box ----

type sbTLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name"`
	Insecure   bool     `json:"insecure"`
	ALPN       []string `json:"alpn"`
	UTLS       struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
	CertificatePublicKeySHA256 []string `json:"certificate_public_key_sha256"`
}

func (r *Result) singbox(typ, tag string, raw json.RawMessage) {
	switch strings.ToLower(typ) {
	case "vless":
		var o struct {
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			UUID       string `json:"uuid"`
			Flow       string `json:"flow"`
			TLS        *sbTLS `json:"tls"`
			Transport  *struct {
				Type        string          `json:"type"`
				Path        string          `json:"path"`
				Host        json.RawMessage `json:"host"`
				Headers     map[string]any  `json:"headers"`
				ServiceName string          `json:"service_name"`
			} `json:"transport"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			r.fail(tag, err)
			return
		}
		s := vless.Settings{ID: o.UUID, Flow: o.Flow}
		if t := o.TLS; t != nil && t.Enabled {
			s.Security, s.SNI, s.Fingerprint, s.ALPN = "tls", t.ServerName, strings.ToLower(t.UTLS.Fingerprint), strings.Join(t.ALPN, ",")
			if t.Reality.Enabled {
				s.Security, s.PublicKey, s.ShortID = "reality", t.Reality.PublicKey, t.Reality.ShortID
			}
			if t.Insecure {
				r.warn(tag, "insecure: Xray проверяет сертификат всегда")
			}
		}
		if tr := o.Transport; tr != nil {
			s.Network, s.Path, s.ServiceName = tr.Type, tr.Path, tr.ServiceName
			s.Host = firstNonEmpty(firstString(tr.Host), headerHost(tr.Headers))
		}
		r.vlessLink(tag, o.Server, o.ServerPort, s)
	case "hysteria2":
		var o struct {
			Server      string   `json:"server"`
			ServerPort  int      `json:"server_port"`
			ServerPorts []string `json:"server_ports"`
			HopInterval string   `json:"hop_interval"`
			Password    string   `json:"password"`
			Obfs        *struct {
				Type     string `json:"type"`
				Password string `json:"password"`
			} `json:"obfs"`
			TLS *sbTLS `json:"tls"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			r.fail(tag, err)
			return
		}
		var ports []string
		if o.ServerPort != 0 {
			ports = append(ports, strconv.Itoa(o.ServerPort))
		}
		for _, p := range o.ServerPorts {
			ports = append(ports, strings.ReplaceAll(p, ":", "-"))
		}
		l := hy2uri.Link{Name: tag, Auth: o.Password, Host: o.Server, Ports: strings.Join(ports, ","), HopInterval: o.HopInterval}
		if o.Obfs != nil {
			l.ObfsType, l.ObfsPassword = o.Obfs.Type, o.Obfs.Password
		}
		if t := o.TLS; t != nil {
			l.SNI, l.Insecure = t.ServerName, t.Insecure
		}
		r.hy2Link(l)
	default:
		if !service(typ) {
			r.other(typ)
		}
	}
}

// hy2Link writes a Hysteria 2 server. Compat keeps the hop interval.
func (r *Result) hy2Link(l hy2uri.Link) {
	if l.Host == "" || l.Ports == "" {
		r.fail(l.Name, fmt.Errorf("нет адреса или порта сервера"))
		return
	}
	r.add(l.Compat())
}

// ---- Xray ----

func (r *Result) xray(protocol, name string, raw json.RawMessage) {
	if strings.ToLower(protocol) != "vless" {
		if !service(protocol) {
			r.other(protocol)
		}
		return
	}
	var o struct {
		Settings struct {
			Address    string `json:"address"`
			Port       int    `json:"port"`
			ID         string `json:"id"`
			Flow       string `json:"flow"`
			Encryption string `json:"encryption"`
			Vnext      []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
				Users   []struct {
					ID         string `json:"id"`
					Flow       string `json:"flow"`
					Encryption string `json:"encryption"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
		Stream struct {
			Network  string `json:"network"`
			Security string `json:"security"`
			TLS      struct {
				ServerName    string   `json:"serverName"`
				Fingerprint   string   `json:"fingerprint"`
				ALPN          []string `json:"alpn"`
				ECH           string   `json:"echConfigList"`
				Pin           string   `json:"pinnedPeerCertSha256"`
				VerifyName    string   `json:"verifyPeerCertByName"`
				AllowInsecure bool     `json:"allowInsecure"`
			} `json:"tlsSettings"`
			Reality struct {
				ServerName    string `json:"serverName"`
				Fingerprint   string `json:"fingerprint"`
				PublicKey     string `json:"publicKey"`
				Password      string `json:"password"`
				ShortID       string `json:"shortId"`
				SpiderX       string `json:"spiderX"`
				MLDSA65Verify string `json:"mldsa65Verify"`
			} `json:"realitySettings"`
			WS   *xHTTPish `json:"wsSettings"`
			HU   *xHTTPish `json:"httpupgradeSettings"`
			GRPC *struct {
				ServiceName string `json:"serviceName"`
				MultiMode   bool   `json:"multiMode"`
				Authority   string `json:"authority"`
			} `json:"grpcSettings"`
			XHTTP     map[string]json.RawMessage `json:"xhttpSettings"`
			SplitHTTP map[string]json.RawMessage `json:"splithttpSettings"`
			Raw       *xRaw                      `json:"rawSettings"`
			TCP       *xRaw                      `json:"tcpSettings"`
			KCP       *struct {
				Seed   string `json:"seed"`
				Header struct {
					Type string `json:"type"`
				} `json:"header"`
			} `json:"kcpSettings"`
			Sockopt   map[string]json.RawMessage `json:"sockopt"`
			FinalMask json.RawMessage            `json:"finalmask"`
		} `json:"streamSettings"`
		Mux *struct {
			Enabled bool `json:"enabled"`
		} `json:"mux"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		r.fail(name, err)
		return
	}
	st := o.Settings
	host, port := st.Address, st.Port
	s := vless.Settings{ID: st.ID, Flow: st.Flow, Encryption: st.Encryption}
	if len(st.Vnext) > 0 {
		v := st.Vnext[0]
		host, port = v.Address, v.Port
		if len(v.Users) > 0 {
			s.ID, s.Flow, s.Encryption = v.Users[0].ID, v.Users[0].Flow, v.Users[0].Encryption
		}
	}
	ss := o.Stream
	s.Network, s.Security = ss.Network, strings.ToLower(ss.Security)
	if s.Security == "none" {
		s.Security = ""
	}
	switch s.Security {
	case "tls":
		t := ss.TLS
		s.SNI, s.Fingerprint, s.ALPN, s.ECH, s.PinSHA256, s.VerifyName = t.ServerName, t.Fingerprint, strings.Join(t.ALPN, ","), t.ECH, t.Pin, t.VerifyName
		if t.AllowInsecure {
			r.warn(name, "allowInsecure: Xray проверяет сертификат всегда")
		}
	case "reality":
		t := ss.Reality
		s.SNI, s.Fingerprint, s.PublicKey, s.ShortID, s.SpiderX, s.MLDSA65Verify = t.ServerName, t.Fingerprint, firstNonEmpty(t.PublicKey, t.Password), t.ShortID, t.SpiderX, t.MLDSA65Verify
	}
	switch vless.NormalizeNetwork(s.Network) {
	case "ws":
		if w := ss.WS; w != nil {
			s.Path, s.Host = w.Path, firstNonEmpty(w.Host, headerHost(w.Headers))
		}
	case "httpupgrade":
		if w := ss.HU; w != nil {
			s.Path, s.Host = w.Path, firstNonEmpty(w.Host, headerHost(w.Headers))
		}
	case "grpc":
		if g := ss.GRPC; g != nil {
			s.ServiceName, s.Authority = g.ServiceName, g.Authority
			if g.MultiMode {
				s.Mode = "multi"
			}
		}
	case "xhttp":
		x := ss.XHTTP
		if x == nil {
			x = ss.SplitHTTP
		}
		var err error
		if s.Path, s.Host, s.Mode, s.Extra, err = xhttpFields(x); err != nil {
			r.fail(name, err)
			return
		}
		var dropped []string
		if s.Extra, dropped, err = vless.CleanExtra(s.Extra); err != nil {
			r.fail(name, err)
			return
		}
		for _, d := range dropped {
			r.warn(name, "xhttp: «"+d+"» не переносится")
		}
	case "kcp":
		if k := ss.KCP; k != nil {
			s.Seed, s.HeaderType = k.Seed, k.Header.Type
		}
	case "":
		h := ss.Raw
		if h == nil {
			h = ss.TCP
		}
		if h != nil && h.Header.Type == "http" {
			s.HeaderType = "http"
			s.Path = strings.Join(h.Header.Request.Path, ",")
			s.Host = strings.Join(h.Header.Request.Headers["Host"], ",")
		}
	}
	if len(ss.Sockopt) > 0 {
		r.warn(name, "sockopt (цепочки, fragment и т. п.) не переносится")
	}
	if len(ss.FinalMask) > 0 && string(ss.FinalMask) != "null" {
		if fragment, err := vless.ParseTCPFragment(ss.FinalMask); err == nil && vless.NormalizeNetwork(s.Network) != "kcp" {
			s.TCPFragment = fragment
		} else {
			r.warn(name, "finalmask не переносится")
		}
	}
	if o.Mux != nil && o.Mux.Enabled {
		r.warn(name, "mux не переносится")
	}
	r.vlessLink(name, host, port, s)
}

type xHTTPish struct {
	Path    string         `json:"path"`
	Host    string         `json:"host"`
	Headers map[string]any `json:"headers"`
}

type xRaw struct {
	Header struct {
		Type    string `json:"type"`
		Request struct {
			Path    []string            `json:"path"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
	} `json:"header"`
}

// xhttpFields splits Xray's xhttpSettings into the link's path, host and
// mode, and extra: every other setting, as a share link carries them.
func xhttpFields(m map[string]json.RawMessage) (path, host, mode, extra string, err error) {
	str := func(k string) string {
		var s string
		json.Unmarshal(m[k], &s)
		delete(m, k)
		return s
	}
	path, host, mode = str("path"), str("host"), str("mode")
	if mode == "auto" {
		mode = ""
	}
	rest := map[string]json.RawMessage{}
	if e, ok := m["extra"]; ok {
		if err := json.Unmarshal(e, &rest); err != nil {
			return "", "", "", "", fmt.Errorf("xhttp extra: нужен JSON-объект")
		}
		delete(m, "extra")
	}
	for k, v := range m {
		rest[k] = v
	}
	if len(rest) > 0 {
		b, err := json.Marshal(rest)
		if err != nil {
			return "", "", "", "", err
		}
		extra = string(b)
	}
	return path, host, mode, extra, nil
}

// headerHost is the Host header of a headers object (a string or a list).
func headerHost(h map[string]any) string {
	for k, v := range h {
		if strings.EqualFold(k, "host") {
			switch x := v.(type) {
			case string:
				return x
			case []any:
				if len(x) > 0 {
					s, _ := x[0].(string)
					return s
				}
			}
		}
	}
	return ""
}

// firstString reads a string or the first of a list.
func firstString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var l []string
	if json.Unmarshal(raw, &l) == nil && len(l) > 0 {
		return l[0]
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// ---- Clash (Mihomo) ----

func (r *Result) clash(body []byte) bool {
	var cfg struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(body, &cfg) != nil || cfg.Proxies == nil {
		return false
	}
	r.Format = "Clash"
	for _, p := range cfg.Proxies {
		c := clashProxy(p)
		name := c.str("name")
		switch typ := strings.ToLower(c.str("type")); typ {
		case "vless":
			r.clashVLESS(name, c)
		case "hysteria2":
			l := hy2uri.Link{Name: name, Auth: c.str("password"), Host: c.str("server"),
				ObfsType: c.str("obfs"), ObfsPassword: c.str("obfs-password"), SNI: c.str("sni"),
				Insecure: c.bool("skip-cert-verify"), PinSHA256: c.str("fingerprint")}
			l.Ports = c.str("ports")
			if p := c.str("port"); p != "" && !strings.Contains(","+l.Ports+",", ","+p+",") {
				l.Ports = strings.Trim(p+","+l.Ports, ",")
			}
			if hi := c.str("hop-interval"); hi != "" {
				if _, err := strconv.Atoi(hi); err == nil {
					hi += "s"
				}
				l.HopInterval = hi
			}
			r.hy2Link(l)
		default:
			if !service(typ) {
				r.other(typ)
			}
		}
	}
	return true
}

type clashProxy map[string]any

// str reads a scalar as a string (ports come as numbers).
func (c clashProxy) str(k string) string {
	switch v := c[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func (c clashProxy) bool(k string) bool {
	v, _ := c[k].(bool)
	return v
}

func (c clashProxy) sub(k string) clashProxy {
	m, _ := c[k].(map[string]any)
	return m
}

func (c clashProxy) list(k string) []string {
	var out []string
	switch v := c[k].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = append(out, v)
	}
	return out
}

func (r *Result) clashVLESS(name string, c clashProxy) {
	port, _ := strconv.Atoi(c.str("port"))
	s := vless.Settings{ID: c.str("uuid"), Flow: c.str("flow"), Encryption: c.str("encryption"),
		Network: c.str("network"), Fingerprint: strings.ToLower(c.str("client-fingerprint")), ALPN: strings.Join(c.list("alpn"), ",")}
	if c.bool("tls") {
		s.Security, s.SNI = "tls", firstNonEmpty(c.str("servername"), c.str("sni"))
		if ro := c.sub("reality-opts"); ro != nil {
			s.Security, s.PublicKey, s.ShortID = "reality", ro.str("public-key"), ro.str("short-id")
		}
		if c.bool("skip-cert-verify") {
			r.warn(name, "skip-cert-verify: Xray проверяет сертификат всегда")
		}
	}
	switch vless.NormalizeNetwork(s.Network) {
	case "ws":
		o := c.sub("ws-opts")
		s.Path, s.Host = o.str("path"), headerHost(o.sub("headers"))
	case "grpc":
		s.ServiceName = c.sub("grpc-opts").str("grpc-service-name")
	case "xhttp":
		o := c.sub("xhttp-opts")
		s.Path, s.Host, s.Mode = o.str("path"), o.str("host"), o.str("mode")
	case "httpupgrade":
		o := c.sub("http-upgrade-opts")
		s.Path, s.Host = o.str("path"), o.str("host")
	}
	r.vlessLink(name, c.str("server"), port, s)
}
