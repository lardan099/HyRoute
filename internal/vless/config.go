package vless

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Run is what one start of xray.exe needs besides the settings.
type Run struct {
	// Host is the server's name or IP from the profile; Dial, when
	// valid, is the address Xray connects to instead (HyRoute pins the
	// IP it excluded from interception).
	Host string
	Port int
	Dial netip.Addr
	// SOCKS5 inbound on loopback with random credentials, so that other
	// local processes cannot use the tunnel.
	SOCKSListen   string // 127.0.0.1:port
	SOCKSUsername string
	SOCKSPassword string
	// LogLevel is Xray's: "warning" by default.
	LogLevel string
}

// Config is the xray.exe client config: a SOCKS5 inbound (with UDP) and
// one VLESS outbound, nothing else (no routing, DNS or geo files: HyRoute
// decides what goes into the tunnel).
func Config(s Settings, r Run) ([]byte, error) {
	out, err := outbound(s, r, "proxy")
	if err != nil {
		return nil, err
	}
	cfg, err := clientConfig(r, false)
	if err != nil {
		return nil, err
	}
	cfg["outbounds"] = []any{out}
	return json.MarshalIndent(cfg, "", "  ")
}

func outbound(s Settings, r Run, tag string) (map[string]any, error) {
	if err := s.ValidateFor(r.Host); err != nil {
		return nil, err
	}
	if r.Port < 1 || r.Port > 65535 {
		return nil, errors.New("порт сервера вне 1–65535")
	}
	address := r.Host
	if r.Dial.IsValid() {
		address = r.Dial.Unmap().String()
		if err := s.ValidateFor(address); err != nil {
			return nil, err
		}
	}
	// A name the TLS handshake and the HTTP transports need when Xray
	// dials a pinned IP: the server's own name, unless it is an IP.
	name := ""
	if a, err := netip.ParseAddr(r.Host); err != nil || !a.IsValid() {
		name = r.Host
	}
	enc := s.Encryption
	if enc == "" {
		enc = "none"
	}
	return map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{
			"address":    address,
			"port":       r.Port,
			"id":         s.ID,
			"flow":       s.Flow,
			"encryption": enc,
		},
		"streamSettings": stream(s, name),
	}, nil
}

func clientConfig(r Run, sniff bool) (map[string]any, error) {
	lhost, lport, err := net.SplitHostPort(r.SOCKSListen)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(lport)
	if err != nil {
		return nil, err
	}
	level := r.LogLevel
	if level == "" {
		level = "warning"
	}
	in := map[string]any{
		"tag":      "socks-in",
		"listen":   lhost,
		"port":     port,
		"protocol": "socks",
		"settings": map[string]any{
			"auth":     "password",
			"accounts": []any{map[string]any{"user": r.SOCKSUsername, "pass": r.SOCKSPassword}},
			"udp":      true,
			"ip":       lhost,
		},
	}
	if sniff {
		in["sniffing"] = map[string]any{"enabled": true, "routeOnly": true}
	}
	return map[string]any{
		"log":      map[string]any{"loglevel": level, "access": "none", "dnsLog": false},
		"inbounds": []any{in},
	}, nil
}

// stream is streamSettings. name is the server's domain ("" for an IP).
func stream(s Settings, name string) map[string]any {
	network := s.Network
	if network == "" {
		network = "raw"
	}
	st := map[string]any{"network": network}
	// The host the HTTP transports send: the link's, else the TLS name,
	// else the server's.
	host := firstNonEmpty(s.Host, s.SNI, name)
	switch s.Network {
	case "":
		if s.HeaderType == "http" {
			path := s.Path
			if path == "" {
				path = "/"
			}
			req := map[string]any{"path": splitList(path)}
			if hs := splitList(host); len(hs) > 0 {
				req["headers"] = map[string]any{"Host": hs}
			}
			st["rawSettings"] = map[string]any{"header": map[string]any{"type": "http", "request": req}}
		}
	case "ws":
		st["wsSettings"] = map[string]any{"path": orSlash(s.Path), "host": host}
	case "httpupgrade":
		st["httpupgradeSettings"] = map[string]any{"path": orSlash(s.Path), "host": host}
	case "grpc":
		g := map[string]any{"serviceName": s.ServiceName, "multiMode": s.Mode == "multi"}
		if s.Authority != "" {
			g["authority"] = s.Authority
		}
		st["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": orSlash(s.Path), "host": host}
		if s.Mode != "" {
			x["mode"] = s.Mode
		}
		// Again here: settings saved before CleanExtra or restored from a
		// backup.
		if extra, _, err := CleanExtra(s.Extra); err == nil && extra != "" {
			x["extra"] = json.RawMessage(extra)
		}
		st["xhttpSettings"] = x
	case "kcp":
		st["kcpSettings"] = map[string]any{}
		// The header and the seed are masks of their own since Xray v26
		// (finalmask, "mkcp-legacy"): nothing in it is the original
		// obfuscation.
		mask := map[string]any{}
		if s.HeaderType != "" && s.HeaderType != "none" {
			mask["header"] = s.HeaderType
		}
		if s.Seed != "" {
			mask["value"] = s.Seed
		}
		st["finalmask"] = map[string]any{"udp": []any{map[string]any{"type": "mkcp-legacy", "settings": mask}}}
	}
	switch s.Security {
	case "tls":
		st["security"] = "tls"
		t := map[string]any{}
		if sni := firstNonEmpty(s.SNI, s.Host, name); sni != "" {
			t["serverName"] = sni
		}
		if s.Fingerprint != "" {
			t["fingerprint"] = s.Fingerprint
		}
		if alpn := splitList(s.ALPN); len(alpn) > 0 {
			t["alpn"] = alpn
		}
		if s.ECH != "" {
			t["echConfigList"] = s.ECH
		}
		if s.PinSHA256 != "" {
			t["pinnedPeerCertSha256"] = s.PinSHA256
		}
		if s.VerifyName != "" {
			t["verifyPeerCertByName"] = s.VerifyName
		}
		st["tlsSettings"] = t
	case "reality":
		st["security"] = "reality"
		fp := s.Fingerprint
		if fp == "" {
			fp = "chrome" // REALITY needs one
		}
		r := map[string]any{
			"serverName":  s.SNI,
			"fingerprint": fp,
			"publicKey":   s.PublicKey,
			"shortId":     s.ShortID,
		}
		if s.SpiderX != "" {
			r["spiderX"] = s.SpiderX
		}
		if s.MLDSA65Verify != "" {
			r["mldsa65Verify"] = s.MLDSA65Verify
		}
		st["realitySettings"] = r
	default:
		st["security"] = "none"
	}
	return st
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func orSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// splitList splits a comma-separated value, dropping empty items.
func splitList(v string) []string {
	var out []string
	for p := range strings.SplitSeq(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
