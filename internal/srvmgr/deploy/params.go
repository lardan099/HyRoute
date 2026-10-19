// Package deploy installs Hysteria on a server as a job: download and
// verify the binary, system user, TLS, config, systemd unit, firewall,
// start and verify, with rollback, and without touching anything that is
// already as it should be.
package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
)

// Where HyRoute installs Hysteria: the places of the official installer.
const (
	BinaryPath = preflight.StdBinary
	ConfigPath = preflight.StdConfig
	Unit       = preflight.StdUnit
	UnitPath   = "/etc/systemd/system/" + preflight.StdUnit
	ConfigDir  = "/etc/hysteria"
	CertPath   = ConfigDir + "/server.crt"
	KeyPath    = ConfigDir + "/server.key"
	User       = "hysteria"
	Home       = "/var/lib/hysteria"
	// Backup is the suffix of the previous file kept while a deploy runs.
	Backup = ".hyroute-prev"
	// Original is the suffix of a file of the installation a deploy
	// replaced (Params.Replace): kept for good. Later jobs reuse
	// .hyroute-prev; nothing of HyRoute changes or removes this copy.
	Original = ".hyroute-orig"
)

// TLS modes.
const (
	TLSSelfSigned = "self-signed"
	TLSACME       = "acme"
)

// Download sources.
const (
	SourceAuto   = "auto"
	SourceDirect = "direct"
	SourceRelay  = "relay"
	// SourceNode: another managed server (Params.Via) provides the binary.
	SourceNode = "node"
)

// Params are the choices of a deploy (no secrets).
type Params struct {
	// Version: "" = the version of HyRoute's installation (Submit fills
	// it in), else hyrelease.DefaultVersion.
	Version string `json:"version,omitempty"`
	Port    int    `json:"port,omitempty"` // UDP port, default 443
	// HopPorts is a port-hopping range ("20000-50000"): the server listens
	// on the lowest port and redirects the others to it.
	HopPorts string `json:"hopPorts,omitempty"`
	TLS      string `json:"tls"`              // self-signed, acme
	Domain   string `json:"domain,omitempty"` // acme
	Email    string `json:"email,omitempty"`  // acme, optional
	// Challenge is the ACME challenge: http (TCP 80, default), tls (TCP
	// 443) or dns (a TXT record through the DNSProvider's API; no port).
	Challenge string `json:"challenge,omitempty"`
	// DNSProvider (dns challenge): a name of DNSProviders; its settings
	// are secrets (Input.DNS).
	DNSProvider string `json:"dnsProvider,omitempty"`
	// SNI is the name in the self-signed certificate and in client links;
	// empty: the masquerade site's name, else none.
	SNI  string `json:"sni,omitempty"`
	Obfs bool   `json:"obfs,omitempty"` // Salamander
	// Masquerade is the site shown to HTTP/3 visitors (reverse proxy);
	// empty: Masq says, by default "404 Not Found".
	Masquerade string `json:"masquerade,omitempty"`
	// Masq: the other kinds of masquerade and the answer on TCP.
	Masq Masq `json:"masq,omitzero"`
	// Auth: "" keeps the current config's auth section (a new server gets
	// a password), password, or userpass with Users (each user gets a
	// password and a link of their own).
	Auth  string   `json:"auth,omitempty"`
	Users []string `json:"users,omitempty"`
	// The advanced settings (advanced.go); zero values leave Hysteria's
	// defaults.
	Bandwidth Bandwidth `json:"bandwidth,omitzero"`
	QUIC      QUIC      `json:"quic,omitzero"`
	UDP       UDP       `json:"udp,omitzero"`
	Sniff     Sniff     `json:"sniff,omitzero"`
	Outbound  Outbound  `json:"outbound,omitzero"`
	// Preset: sections of a preset laid over the config the params make
	// (presets.go).
	Preset *Preset `json:"preset,omitempty"`
	Source string  `json:"source,omitempty"` // auto (default), direct, relay, node
	// Via is the server that provides the binary (source node).
	Via int64 `json:"via,omitempty"`
	// KeepFirewall: do not open ports in ufw or firewalld.
	KeepFirewall bool `json:"keepFirewall,omitempty"`
	// Replace an installation HyRoute did not make (its files are kept
	// with the .hyroute-orig suffix).
	Replace bool `json:"replace,omitempty"`
	// Overwrite a current config that no deploy made (edited, rolled back
	// or imported): the deploy builds the config from these params alone,
	// and what they do not cover (ACL, resolver, extra outbounds…) is lost.
	// Without it Submit refuses with ErrConfigChanged.
	Overwrite bool `json:"overwrite,omitempty"`
}

var (
	// domainRe: a host name in ASCII; the top-level label is letters or
	// punycode (xn--p1ai is .рф), never digits (an IP address).
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)
	// emailRe: the domain in any case (Admin@Example.com), as entered.
	emailRe = regexp.MustCompile(`^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$`)
)

// asciiName is a host name as entered, lower case, its international
// labels in punycode ("vpn.пример.рф" → "vpn.xn--e1afmkfd.xn--p1ai"): the
// form ACME, SNI and client links take.
func asciiName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if a, err := idna.Lookup.ToASCII(s); err == nil && s != "" {
		return a
	}
	return s
}

// Normalize fills the defaults and checks the params.
func (p *Params) Normalize() error {
	if p.Version == "" {
		p.Version = hyrelease.DefaultVersion
	}
	if err := hyrelease.CheckVersion(p.Version); err != nil {
		return err
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("неверный порт %d", p.Port)
	}
	if _, err := hyconfig.ParseListen(p.Listen()); err != nil {
		return fmt.Errorf("порты: %w", err)
	}
	if _, err := hy2uri.ParsePorts(p.Ports()); err != nil {
		return fmt.Errorf("порты: %w", err)
	}
	if _, err := (hopping.Spec{Ports: strings.Split(p.Ports(), ",")}).Parse(); err != nil {
		return fmt.Errorf("порты: %w", err)
	}
	p.Domain = asciiName(p.Domain)
	p.SNI = asciiName(p.SNI)
	switch p.TLS {
	case TLSSelfSigned:
		if p.SNI != "" && !domainRe.MatchString(p.SNI) {
			return fmt.Errorf("неверное имя для сертификата %q", p.SNI)
		}
	case TLSACME:
		if !domainRe.MatchString(p.Domain) {
			return errors.New("для сертификата Let's Encrypt нужен домен, который указывает на сервер")
		}
		if p.Email != "" && !emailRe.MatchString(p.Email) {
			return fmt.Errorf("неверный email %q", p.Email)
		}
		if p.Challenge == "" {
			p.Challenge = "http"
		}
		if p.Challenge != "http" && p.Challenge != "tls" && p.Challenge != "dns" {
			return fmt.Errorf("неизвестная проверка ACME %q", p.Challenge)
		}
	default:
		return fmt.Errorf("неизвестный режим TLS %q", p.TLS)
	}
	if err := p.normalizeAdvanced(); err != nil {
		return err
	}
	if err := p.normalizePreset(); err != nil {
		return err
	}
	return normalizeSource(&p.Source, &p.Via)
}

// normalizeSource checks a download source and its node.
func normalizeSource(source *string, via *int64) error {
	if *source == "" {
		*source = SourceAuto
	}
	switch *source {
	case SourceAuto, SourceDirect, SourceRelay:
		*via = 0
	case SourceNode:
		if *via <= 0 {
			return errors.New("выберите сервер, через который загружать Hysteria")
		}
	default:
		return fmt.Errorf("неизвестный источник загрузки %q", *source)
	}
	return nil
}

// Listen is the listen address for the config.
func (p *Params) Listen() string {
	if p.HopPorts == "" {
		return fmt.Sprintf(":%d", p.Port)
	}
	return fmt.Sprintf(":%d,%s", p.Port, p.HopPorts)
}

// Ports is what clients connect to.
func (p *Params) Ports() string { return strings.TrimPrefix(p.Listen(), ":") }

// CertName is the name in the self-signed certificate ("" when none).
func (p *Params) CertName() string {
	if p.SNI != "" {
		return p.SNI
	}
	if u, err := url.Parse(p.Masquerade); err == nil && p.Masquerade != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// TCPPorts are the TCP ports the deploy needs free and open: those of the
// ACME challenge or of the masquerade site.
func (p *Params) TCPPorts() []int {
	if ports := p.presetTCPPorts(); len(ports) > 0 {
		return ports
	}
	switch {
	case p.Masq.TCP && p.Masq.Type != "":
		return []int{80, 443}
	case p.TLS != TLSACME || p.Challenge == "dns":
		return nil
	case p.Challenge == "tls":
		return []int{443}
	}
	return []int{80}
}

// Secret names in the job's sealed secrets. The auth section is kept in
// one of four forms, as the server had it (a new server gets a password).
// Every password is a secret of its own, so the job log masks each one.
const (
	SecretAuth = "auth" // password auth
	// userpass auth: SecretUsers is the JSON list of the user names, and
	// SecretUserPrefix + name the password of each.
	SecretUsers      = "users"
	SecretUserPrefix = "user:"
	// http auth: the URL of the backend, and "1" when its certificate is
	// not checked.
	SecretAuthHTTP         = "authHTTP"
	SecretAuthHTTPInsecure = "authHTTPInsecure"
	SecretAuthCommand      = "authCommand" // command auth: the program
	SecretObfs             = "obfs"
	SecretCert             = "cert" // self-signed certificate (PEM; not secret, kept with the key)
	SecretKey              = "key"  // its private key (PEM)
)

// AuthSecrets are the secrets of an auth section, of any type: what a
// redeploy keeps so clients go on connecting as before. Empty when it has
// none.
func AuthSecrets(a hyconfig.Auth) map[string]string {
	out := map[string]string{}
	switch strings.ToLower(a.Type) {
	case "password":
		if a.Password != "" {
			out[SecretAuth] = a.Password
		}
	case "userpass":
		if len(a.UserPass) == 0 {
			break
		}
		names := slices.Sorted(maps.Keys(a.UserPass))
		b, _ := json.Marshal(names)
		out[SecretUsers] = string(b)
		for _, u := range names {
			out[SecretUserPrefix+u] = a.UserPass[u]
		}
	case "http", "https":
		if a.HTTP.URL != "" {
			out[SecretAuthHTTP] = a.HTTP.URL
			if a.HTTP.Insecure {
				out[SecretAuthHTTPInsecure] = "1"
			}
		}
	case "command", "cmd":
		if a.Command != "" {
			out[SecretAuthCommand] = a.Command
		}
	}
	return out
}

// authOf is the auth section kept in secrets s.
func authOf(s map[string]string) (hyconfig.Auth, error) {
	switch {
	case s[SecretUsers] != "":
		var names []string
		if err := json.Unmarshal([]byte(s[SecretUsers]), &names); err != nil {
			return hyconfig.Auth{}, fmt.Errorf("userpass users: %w", err)
		}
		up := make(map[string]string, len(names))
		for _, u := range names {
			up[u] = s[SecretUserPrefix+u]
		}
		return hyconfig.Auth{Type: "userpass", UserPass: up}, nil
	case s[SecretAuthHTTP] != "":
		return hyconfig.Auth{Type: "http", HTTP: hyconfig.AuthHTTP{URL: s[SecretAuthHTTP], Insecure: s[SecretAuthHTTPInsecure] == "1"}}, nil
	case s[SecretAuthCommand] != "":
		return hyconfig.Auth{Type: "command", Command: s[SecretAuthCommand]}, nil
	case s[SecretAuth] != "":
		return hyconfig.Auth{Type: "password", Password: s[SecretAuth]}, nil
	}
	return hyconfig.Auth{}, errors.New("no auth secret")
}

// secretsOf collects the secrets a config is built from; get reads one by
// name (a job's Env.Secret).
func secretsOf(get func(string) string) map[string]string {
	s := map[string]string{}
	keys := []string{SecretAuth, SecretUsers, SecretAuthHTTP, SecretAuthHTTPInsecure, SecretAuthCommand, SecretObfs, SecretOutPassword}
	for _, k := range dnsKeys() {
		keys = append(keys, SecretDNSPrefix+k)
	}
	for _, k := range keys {
		if v := get(k); v != "" {
			s[k] = v
		}
	}
	var names []string
	json.Unmarshal([]byte(s[SecretUsers]), &names)
	for _, u := range names {
		s[SecretUserPrefix+u] = get(SecretUserPrefix + u)
	}
	return s
}

// NewSecrets makes the passwords and, for a self-signed certificate, the
// certificate for a deploy (p normalized). host is the server's address
// (put in the certificate too). The secrets of an existing installation
// (CurrentSecrets) are passed in reuse so client links stay valid; in are
// the secrets the admin entered. Input that does not fit the params is an
// error.
func NewSecrets(p Params, host string, reuse map[string]string, in Input) (map[string]string, error) {
	s, err := authSecrets(p, reuse)
	if err != nil {
		return nil, err
	}
	if p.Obfs {
		if s[SecretObfs] = reuse[SecretObfs]; s[SecretObfs] == "" {
			if s[SecretObfs], err = password(); err != nil {
				return nil, err
			}
		}
	}
	if err := advancedSecrets(p, s, reuse, in); err != nil {
		return nil, err
	}
	if p.TLS == TLSSelfSigned {
		cert, key, err := SelfSigned(p.CertName(), host, time.Now())
		if err != nil {
			return nil, err
		}
		s[SecretCert], s[SecretKey] = string(cert), string(key)
	}
	return s, nil
}

// authSecrets are the secrets of the auth section p asks for, with the
// passwords of reuse where they are the same: a password for a password,
// a user's for the same user.
func authSecrets(p Params, reuse map[string]string) (map[string]string, error) {
	cur := map[string]string{}
	for k, v := range reuse {
		if k == SecretAuth || k == SecretUsers || k == SecretAuthHTTP || k == SecretAuthHTTPInsecure || k == SecretAuthCommand || strings.HasPrefix(k, SecretUserPrefix) {
			cur[k] = v
		}
	}
	kept, kerr := authOf(cur)
	s := map[string]string{}
	var err error
	switch p.Auth {
	case "":
		if kerr == nil {
			return cur, nil
		}
		s[SecretAuth], err = password()
	case AuthPassword:
		if kerr == nil && kept.Type == AuthPassword {
			s[SecretAuth] = kept.Password
		} else {
			s[SecretAuth], err = password()
		}
	case AuthUserPass:
		b, _ := json.Marshal(p.Users)
		s[SecretUsers] = string(b)
		for _, u := range p.Users {
			pw := kept.UserPass[u]
			if kerr != nil || kept.Type != AuthUserPass || pw == "" {
				if pw, err = password(); err != nil {
					return nil, err
				}
			}
			s[SecretUserPrefix+u] = pw
		}
	}
	return s, err
}

// password is 24 random bytes, URL-safe base64 (32 characters): safe in
// YAML, URIs and QR codes.
func password() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SelfSigned makes an ECDSA P-256 certificate valid for 10 years for name
// (may be empty) and host (a domain or an IP).
func SelfSigned(name, host string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	cn := name
	if cn == "" {
		cn = host
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range []string{name, host} {
		if n == "" {
			continue
		}
		if ip, err := netip.ParseAddr(n); err == nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip.AsSlice())
		} else if !containsFold(tpl.DNSNames, n) {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// Pin is the pinSHA256 of a PEM certificate: SHA-256 of its DER, hex.
func Pin(certPEM []byte) (string, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return "", errors.New("не сертификат PEM")
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return "", err
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// BuildConfig is the server config for params and secrets.
func BuildConfig(p Params, s map[string]string) (*hyconfig.Server, error) {
	auth, err := authOf(s)
	if err != nil {
		return nil, err
	}
	c := &hyconfig.Server{Listen: p.Listen(), Auth: auth}
	switch p.TLS {
	case TLSSelfSigned:
		// Clients may connect by IP without SNI: do not require the
		// certificate name.
		c.TLS = &hyconfig.TLS{Cert: CertPath, Key: KeyPath, SNIGuard: "disable"}
	case TLSACME:
		c.ACME = &hyconfig.ACME{Domains: []string{p.Domain}, Email: p.Email, Type: p.Challenge}
	}
	if p.Obfs {
		c.Obfs = hyconfig.Obfs{Type: "salamander", Salamander: hyconfig.Salamander{Password: s[SecretObfs]}}
	}
	buildAdvanced(c, p, s)
	if err := p.overlayPreset(c); err != nil {
		return nil, err
	}
	for _, pr := range c.Validate() {
		if !pr.Warning {
			return nil, fmt.Errorf("%s: %s", pr.Field, pr.Message)
		}
	}
	return c, nil
}

// Meta is the non-secret summary of a deployed config with a password
// (configYAML sets the auth type a redeploy kept).
func Meta(p Params, pin string) model.ConfigMeta {
	m := model.ConfigMeta{Version: p.Version, Listen: p.Listen(), Ports: p.Ports(), TLS: p.TLS, PinSHA256: pin, Auth: "password"}
	switch p.TLS {
	case TLSSelfSigned:
		m.SNI = p.CertName()
	case TLSACME:
		m.SNI = p.Domain
	}
	if p.Obfs {
		m.Obfs = "salamander"
	}
	return m
}

// UnitText is the systemd unit: the official installer's, plus a restart
// when Hysteria exits with an error.
const UnitText = `[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target

[Service]
Type=simple
ExecStart=` + BinaryPath + ` server --config ` + ConfigPath + `
WorkingDirectory=~
User=` + User + `
Group=` + User + `
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`
