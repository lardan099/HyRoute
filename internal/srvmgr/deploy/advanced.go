package deploy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
)

// The advanced settings of a deploy. A zero value leaves Hysteria's
// default, and the deploy writes nothing for it into the config.

// Bandwidth is the server's speed limit per client.
type Bandwidth struct {
	// UpMbps, DownMbps: what the server sends to and takes from one
	// client at most, in Mbit/s. Hysteria uses the lower of these and the
	// client's own numbers.
	UpMbps   int `json:"upMbps,omitempty"`
	DownMbps int `json:"downMbps,omitempty"`
	// IgnoreClient: the server does not take the clients' speeds and
	// always uses its own congestion control (BBR).
	IgnoreClient bool `json:"ignoreClient,omitempty"`
}

// QUIC are the QUIC transport settings.
type QUIC struct {
	// StreamWindowMB, ConnWindowMB: the receive windows of one stream and
	// of a whole connection, in MiB (Hysteria's defaults: 8 and 20).
	StreamWindowMB int `json:"streamWindowMB,omitempty"`
	ConnWindowMB   int `json:"connWindowMB,omitempty"`
	// IdleTimeout: seconds of silence before a connection is closed
	// (default 30).
	IdleTimeout int `json:"idleTimeout,omitempty"`
	// MaxStreams: TCP connections one client may have open at once
	// (default 1024).
	MaxStreams int `json:"maxStreams,omitempty"`
	// DisableMTUDiscovery: keep packets at the minimal size.
	DisableMTUDiscovery bool `json:"disableMTUDiscovery,omitempty"`
}

// UDP is the forwarding of the clients' UDP (games, calls, QUIC sites).
type UDP struct {
	Disable bool `json:"disable,omitempty"`
	// IdleTimeout: seconds an idle UDP session is kept (default 60).
	IdleTimeout int `json:"idleTimeout,omitempty"`
}

// Sniff makes the server read the site's name from the connection (TLS
// SNI, HTTP Host, QUIC) so the ACL and outbounds match it, not the IP.
type Sniff struct {
	Enable bool `json:"enable,omitempty"`
	// Timeout: seconds to wait for the first bytes (default 2).
	Timeout int `json:"timeout,omitempty"`
	// RewriteDomain: also replace a domain the client sent.
	RewriteDomain bool `json:"rewriteDomain,omitempty"`
	// TCPPorts, UDPPorts: ports to sniff ("80,443,8000-9000"; empty: all).
	TCPPorts string `json:"tcpPorts,omitempty"`
	UDPPorts string `json:"udpPorts,omitempty"`
}

// Outbound types.
const (
	OutDirect = "direct"
	OutSOCKS5 = "socks5"
	OutHTTP   = "http"
)

// Outbound is where the server sends the clients' traffic: the only
// outbound of the config, so the default one.
type Outbound struct {
	// Type: "" (Hysteria's own default: direct, IPv4 and IPv6), direct,
	// socks5 or http.
	Type string `json:"type,omitempty"`
	// Mode (direct): auto, 46 (IPv4 first), 64 (IPv6 first), 4, 6.
	Mode string `json:"mode,omitempty"`
	// BindIPv4, BindIPv6, BindDevice (direct): the local address or
	// interface to go out from.
	BindIPv4   string `json:"bindIPv4,omitempty"`
	BindIPv6   string `json:"bindIPv6,omitempty"`
	BindDevice string `json:"bindDevice,omitempty"`
	// Addr: the proxy, host:port (socks5) or http(s)://host:port (http).
	Addr string `json:"addr,omitempty"`
	// User of the proxy; its password is a secret (Input.OutPassword).
	User string `json:"user,omitempty"`
}

// Masquerade types.
const (
	MasqProxy  = "proxy"
	MasqFile   = "file"
	MasqString = "string"
)

// Masq is what the server shows to visitors who are not clients. The site
// of the proxy type is Params.Masquerade (it came first).
type Masq struct {
	// Type: "" (404 Not Found; proxy when Params.Masquerade is set),
	// proxy, file or string.
	Type string `json:"type,omitempty"`
	Dir  string `json:"dir,omitempty"`  // file: a folder on the server
	Text string `json:"text,omitempty"` // string: the page
	// Status (string): the HTTP status, default 200.
	Status int `json:"status,omitempty"`
	// TCP: answer on TCP 80 and 443 too (HTTP redirects to HTTPS), as an
	// ordinary site does; without it only HTTP/3 over UDP.
	TCP bool `json:"tcp,omitempty"`
}

// Input are the secret values of a deploy that only the admin knows: they
// go into the job's sealed secrets, never into its params. An empty value
// keeps the one of the current config.
type Input struct {
	// DNS: the settings of the DNS provider (ACME dns challenge), by the
	// key Hysteria reads (DNSProviders).
	DNS map[string]string `json:"dns,omitempty"`
	// OutPassword: the password of the outbound proxy.
	OutPassword string `json:"outPassword,omitempty"`
}

// DNSField is a setting of a DNS provider.
type DNSField struct {
	Key      string `json:"key"`
	Required bool   `json:"required"`
}

// DNSProviders are the DNS providers Hysteria issues ACME certificates
// with, and the keys of their settings (app/cmd/server.go).
var DNSProviders = map[string][]DNSField{
	"cloudflare": {{"cloudflare_api_token", true}},
	"duckdns":    {{"duckdns_api_token", true}, {"duckdns_override_domain", false}},
	"gandi":      {{"gandi_api_token", true}},
	"godaddy":    {{"godaddy_api_token", true}},
	"namecheap":  {{"namecheap_api_user", true}, {"namecheap_api_key", true}, {"namecheap_api_endpoint", false}, {"namecheap_client_ip", false}},
	"njalla":     {{"njalla_api_token", true}},
	"porkbun":    {{"porkbun_api_key", true}, {"porkbun_api_secret_key", true}},
	"vultr":      {{"vultr_api_token", true}},
}

// Auth types a deploy sets up.
const (
	AuthPassword = "password"
	AuthUserPass = "userpass"
)

// MaxUsers is the most userpass users a deploy makes.
const MaxUsers = 100

var (
	userRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	deviceRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,15}$`)
	dirRe    = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+/?$`)
	proxyRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// normalizeAdvanced checks the advanced settings and their combinations.
func (p *Params) normalizeAdvanced() error {
	for _, f := range []func() error{p.normalizeAuth, p.normalizeBandwidth, p.normalizeQUIC, p.normalizeSniff, p.normalizeUDP, p.normalizeOutbound, p.normalizeMasq, p.normalizeDNS} {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Params) normalizeAuth() error {
	switch p.Auth {
	case "", AuthPassword:
		if len(p.Users) > 0 {
			return errors.New("пользователи задаются только для входа по имени и паролю (userpass)")
		}
	case AuthUserPass:
		if len(p.Users) == 0 {
			return errors.New("для входа по имени и паролю нужен хотя бы один пользователь")
		}
		if len(p.Users) > MaxUsers {
			return fmt.Errorf("пользователей больше %d", MaxUsers)
		}
		seen := map[string]bool{}
		for i, u := range p.Users {
			u = strings.TrimSpace(u)
			if !userRe.MatchString(u) {
				return fmt.Errorf("имя пользователя %q: латинские буквы, цифры, точка, дефис и подчёркивание, до 64 символов", u)
			}
			// Hysteria compares the names case-insensitively.
			if seen[strings.ToLower(u)] {
				return fmt.Errorf("пользователь %q указан дважды", u)
			}
			seen[strings.ToLower(u)] = true
			p.Users[i] = u
		}
	default:
		return fmt.Errorf("неизвестный способ входа %q", p.Auth)
	}
	return nil
}

func (p *Params) normalizeBandwidth() error {
	b := p.Bandwidth
	for _, v := range []int{b.UpMbps, b.DownMbps} {
		if v < 0 || v > 100000 {
			return errors.New("скорость сервера: от 1 до 100000 Мбит/с")
		}
	}
	if b.IgnoreClient && (b.UpMbps > 0 || b.DownMbps > 0) {
		return errors.New("скорость сервера не действует, когда он не учитывает скорость клиентов: Hysteria тогда всегда использует BBR. Оставьте что-то одно")
	}
	return nil
}

func (p *Params) normalizeQUIC() error {
	q := p.QUIC
	if q.StreamWindowMB < 0 || q.StreamWindowMB > 256 || q.ConnWindowMB < 0 || q.ConnWindowMB > 1024 {
		return errors.New("окна QUIC: поток до 256 МиБ, соединение до 1024 МиБ")
	}
	// Either default stands for Hysteria's: 8 MiB a stream, 20 a
	// connection.
	stream, conn := q.StreamWindowMB, q.ConnWindowMB
	if stream == 0 {
		stream = 8
	}
	if conn == 0 {
		conn = 20
	}
	if stream > conn {
		return fmt.Errorf("окно потока (%d МиБ) больше окна соединения (%d МиБ): поток не получит больше, чем всё соединение", stream, conn)
	}
	if q.IdleTimeout != 0 && (q.IdleTimeout < 4 || q.IdleTimeout > 120) {
		return errors.New("тайм-аут простоя QUIC: от 4 до 120 секунд")
	}
	if q.MaxStreams != 0 && (q.MaxStreams < 8 || q.MaxStreams > 65535) {
		return errors.New("одновременных соединений на клиента: от 8 до 65535")
	}
	return nil
}

func (p *Params) normalizeUDP() error {
	u := p.UDP
	if u.IdleTimeout != 0 && (u.IdleTimeout < 2 || u.IdleTimeout > 600) {
		return errors.New("тайм-аут UDP: от 2 до 600 секунд")
	}
	if u.Disable && u.IdleTimeout != 0 {
		return errors.New("тайм-аут UDP задан, а пересылка UDP выключена")
	}
	if u.Disable && p.Sniff.UDPPorts != "" {
		return errors.New("порты UDP для определения сайтов заданы, а пересылка UDP выключена")
	}
	return nil
}

func (p *Params) normalizeSniff() error {
	s := &p.Sniff
	s.TCPPorts, s.UDPPorts = strings.TrimSpace(s.TCPPorts), strings.TrimSpace(s.UDPPorts)
	if !s.Enable {
		if s.Timeout != 0 || s.RewriteDomain || s.TCPPorts != "" || s.UDPPorts != "" {
			return errors.New("настройки определения сайтов заданы, а само оно выключено")
		}
		return nil
	}
	if s.Timeout < 0 || s.Timeout > 60 {
		return errors.New("тайм-аут определения сайтов: от 1 до 60 секунд")
	}
	for _, v := range []string{s.TCPPorts, s.UDPPorts} {
		if v != "" && !validPorts(v) {
			return fmt.Errorf("неверный список портов %q (пример: 80,443,8000-9000)", v)
		}
	}
	return nil
}

// validPorts: a list of ports and ranges, as sniff takes them.
func validPorts(s string) bool {
	for _, part := range strings.Split(s, ",") {
		lo, hi, rng := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return false
		}
		if rng {
			b, err := strconv.Atoi(hi)
			if err != nil || b < a || b > 65535 {
				return false
			}
		}
	}
	return true
}

func (p *Params) normalizeOutbound() error {
	o := &p.Outbound
	o.Addr, o.User = strings.TrimSpace(o.Addr), strings.TrimSpace(o.User)
	direct := o.Mode != "" || o.BindIPv4 != "" || o.BindIPv6 != "" || o.BindDevice != ""
	proxy := o.Addr != "" || o.User != ""
	switch o.Type {
	case "":
		if direct || proxy {
			return errors.New("настройки выхода заданы, а тип выхода не выбран")
		}
	case OutDirect:
		if proxy {
			return errors.New("адрес и пользователь прокси не нужны для прямого выхода")
		}
		if o.Mode != "" && !slices.Contains([]string{"auto", "46", "64", "4", "6"}, o.Mode) {
			return fmt.Errorf("неизвестный режим выхода %q", o.Mode)
		}
		if o.BindDevice != "" && (o.BindIPv4 != "" || o.BindIPv6 != "") {
			return errors.New("выход привязывается либо к интерфейсу, либо к адресам, не к обоим сразу")
		}
		if o.BindDevice != "" && !deviceRe.MatchString(o.BindDevice) {
			return fmt.Errorf("неверное имя интерфейса %q", o.BindDevice)
		}
		if a, err := netip.ParseAddr(o.BindIPv4); o.BindIPv4 != "" && (err != nil || !a.Is4()) {
			return fmt.Errorf("неверный IPv4-адрес выхода %q", o.BindIPv4)
		}
		if a, err := netip.ParseAddr(o.BindIPv6); o.BindIPv6 != "" && (err != nil || !a.Is6() || a.Is4In6()) {
			return fmt.Errorf("неверный IPv6-адрес выхода %q", o.BindIPv6)
		}
		if (o.Mode == "4" && o.BindIPv6 != "") || (o.Mode == "6" && o.BindIPv4 != "") {
			return errors.New("адрес выхода другой версии IP, чем выбранный режим")
		}
	case OutSOCKS5, OutHTTP:
		if direct {
			return errors.New("режим и привязка задаются только для прямого выхода")
		}
		if o.Type == OutSOCKS5 {
			if !validHostPort(o.Addr) {
				return errors.New("адрес SOCKS5-прокси: хост:порт")
			}
		} else {
			u, err := url.Parse(o.Addr)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !validHostPort(u.Host) || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
				return errors.New("адрес HTTP-прокси: http://хост:порт или https://хост:порт, без имени и пароля (они задаются отдельно)")
			}
			o.Addr = u.Scheme + "://" + u.Host
		}
		if o.User != "" && !proxyRe.MatchString(o.User) {
			return errors.New("имя пользователя прокси: латинские буквы, цифры, точка, дефис и подчёркивание, до 64 символов")
		}
	default:
		return fmt.Errorf("неизвестный тип выхода %q", o.Type)
	}
	return nil
}

// validHostPort: host:port with a name or an IP and a port.
func validHostPort(s string) bool {
	h, port, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return domainRe.MatchString(strings.ToLower(h)) || h == "localhost"
}

func (p *Params) normalizeMasq() error {
	m := &p.Masq
	if m.Type == "" && p.Masquerade != "" {
		m.Type = MasqProxy
	}
	m.Dir = strings.TrimSpace(m.Dir)
	if (m.Type != MasqProxy && p.Masquerade != "") || (m.Type != MasqFile && m.Dir != "") || (m.Type != MasqString && (m.Text != "" || m.Status != 0)) {
		return errors.New("заданы настройки другого вида сайта-маскировки")
	}
	switch m.Type {
	case "":
		if m.TCP {
			return errors.New("для ответа по TCP выберите сайт-маскировку")
		}
	case MasqProxy:
		u, err := url.Parse(p.Masquerade)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("сайт-маскировка: нужен адрес https://")
		}
	case MasqFile:
		if !dirRe.MatchString(m.Dir) || path.Clean(m.Dir) != strings.TrimSuffix(m.Dir, "/") || m.Dir == "/" {
			return errors.New("папка сайта-маскировки: полный путь на сервере, например /var/www/site")
		}
		m.Dir = path.Clean(m.Dir)
		for _, bad := range []string{"/etc", "/root", "/proc", "/sys", "/dev", "/boot"} {
			if m.Dir == bad || strings.HasPrefix(m.Dir, bad+"/") {
				return fmt.Errorf("папку %s нельзя показывать посетителям", m.Dir)
			}
		}
	case MasqString:
		if strings.TrimSpace(m.Text) == "" {
			return errors.New("текст страницы-маскировки пуст")
		}
		if len(m.Text) > 16<<10 {
			return errors.New("текст страницы-маскировки длиннее 16 КиБ")
		}
		if m.Status != 0 && (m.Status < 200 || m.Status > 599 || m.Status == 233) {
			return errors.New("код ответа страницы-маскировки: от 200 до 599, кроме 233")
		}
	default:
		return fmt.Errorf("неизвестный вид сайта-маскировки %q", m.Type)
	}
	if m.TCP && p.TLS == TLSACME && p.Challenge != "dns" {
		return fmt.Errorf("сайт-маскировка по TCP занимает порты 80 и 443, а они нужны Let's Encrypt для проверки %s. Выберите проверку через DNS или отключите ответ по TCP", p.Challenge)
	}
	return nil
}

func (p *Params) normalizeDNS() error {
	if p.TLS != TLSACME || p.Challenge != "dns" {
		if p.DNSProvider != "" {
			return errors.New("DNS-провайдер нужен только для проверки Let's Encrypt через DNS")
		}
		return nil
	}
	if _, ok := DNSProviders[p.DNSProvider]; !ok {
		return fmt.Errorf("неизвестный DNS-провайдер %q", p.DNSProvider)
	}
	return nil
}

// Secret names of the advanced settings.
const (
	SecretDNSPrefix   = "dns:"        // + key: a setting of the DNS provider
	SecretOutPassword = "outPassword" // the outbound proxy's password
)

// Markers in the secrets of the current config (CurrentSecrets) that say
// whose they are; NewSecrets reuses a secret only for the same owner.
const (
	reuseDNS = "reuse:dnsProvider"
	reuseOut = "reuse:outbound" // type and user: "socks5 alice"
)

// dnsKeys are the keys of every DNS provider.
func dnsKeys() []string {
	var out []string
	for _, fs := range DNSProviders {
		for _, f := range fs {
			out = append(out, f.Key)
		}
	}
	slices.Sort(out)
	return out
}

func outOwner(o Outbound) string { return o.Type + " " + o.User }

// advancedSecrets adds the DNS settings and the proxy password to s: what
// the admin entered, else the current config's.
func advancedSecrets(p Params, s, reuse map[string]string, in Input) error {
	if p.TLS == TLSACME && p.Challenge == "dns" {
		fields := DNSProviders[p.DNSProvider]
		known := map[string]bool{}
		for _, f := range fields {
			known[f.Key] = true
		}
		for k := range in.DNS {
			if !known[k] {
				return fmt.Errorf("у DNS-провайдера %s нет настройки %q", p.DNSProvider, k)
			}
		}
		same := reuse[reuseDNS] == p.DNSProvider
		for _, f := range fields {
			v := strings.TrimSpace(in.DNS[f.Key])
			if v == "" && same {
				v = reuse[SecretDNSPrefix+f.Key]
			}
			if strings.ContainsAny(v, "\r\n\x00") || len(v) > 1024 {
				return fmt.Errorf("неверное значение %s", f.Key)
			}
			if v == "" && f.Required {
				return fmt.Errorf("для %s нужно %s", p.DNSProvider, f.Key)
			}
			if v != "" {
				s[SecretDNSPrefix+f.Key] = v
			}
		}
	} else if len(in.DNS) > 0 {
		return errors.New("настройки DNS-провайдера нужны только для проверки Let's Encrypt через DNS")
	}

	o := p.Outbound
	pw := in.OutPassword
	switch {
	case pw != "" && (o.Type != OutSOCKS5 && o.Type != OutHTTP || o.User == ""):
		return errors.New("пароль прокси задаётся вместе с именем пользователя прокси")
	case strings.ContainsAny(pw, "\r\n\x00") || len(pw) > 255:
		return errors.New("неверный пароль прокси")
	case pw == "" && o.User != "" && reuse[reuseOut] == outOwner(o):
		pw = reuse[SecretOutPassword]
	}
	if pw != "" {
		s[SecretOutPassword] = pw
	}
	return nil
}

// reuseAdvanced adds the advanced secrets of a current config to out.
func reuseAdvanced(c *hyconfig.Server, out map[string]string) {
	if c.ACME != nil && strings.EqualFold(c.ACME.Type, "dns") && len(c.ACME.DNS.Config) > 0 {
		name := strings.ToLower(c.ACME.DNS.Name)
		out[reuseDNS] = name
		for _, f := range DNSProviders[name] {
			if v := c.ACME.DNS.Config[f.Key]; v != "" {
				out[SecretDNSPrefix+f.Key] = v
			}
		}
	}
	if len(c.Outbounds) == 0 {
		return
	}
	switch o := c.Outbounds[0]; strings.ToLower(o.Type) {
	case OutSOCKS5:
		if o.SOCKS5.Password != "" {
			out[reuseOut] = outOwner(Outbound{Type: OutSOCKS5, User: o.SOCKS5.Username})
			out[SecretOutPassword] = o.SOCKS5.Password
		}
	case OutHTTP:
		if u, err := url.Parse(o.HTTP.URL); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				out[reuseOut] = outOwner(Outbound{Type: OutHTTP, User: u.User.Username()})
				out[SecretOutPassword] = pw
			}
		}
	}
}

// buildAdvanced writes the advanced settings into c.
func buildAdvanced(c *hyconfig.Server, p Params, s map[string]string) {
	if b := p.Bandwidth; b.UpMbps > 0 || b.DownMbps > 0 {
		if b.UpMbps > 0 {
			c.Bandwidth.Up = fmt.Sprintf("%d mbps", b.UpMbps)
		}
		if b.DownMbps > 0 {
			c.Bandwidth.Down = fmt.Sprintf("%d mbps", b.DownMbps)
		}
	}
	c.IgnoreClientBandwidth = p.Bandwidth.IgnoreClient

	q := p.QUIC
	if q.StreamWindowMB > 0 {
		w := uint64(q.StreamWindowMB) << 20
		c.QUIC.InitStreamReceiveWindow, c.QUIC.MaxStreamReceiveWindow = w, w
	}
	if q.ConnWindowMB > 0 {
		w := uint64(q.ConnWindowMB) << 20
		c.QUIC.InitConnReceiveWindow, c.QUIC.MaxConnReceiveWindow = w, w
	}
	if q.IdleTimeout > 0 {
		c.QUIC.MaxIdleTimeout = seconds(q.IdleTimeout)
	}
	c.QUIC.MaxIncomingStreams = int64(q.MaxStreams)
	c.QUIC.DisablePathMTUDiscovery = q.DisableMTUDiscovery

	c.DisableUDP = p.UDP.Disable
	if p.UDP.IdleTimeout > 0 {
		c.UDPIdleTimeout = seconds(p.UDP.IdleTimeout)
	}

	if sn := p.Sniff; sn.Enable {
		c.Sniff = hyconfig.Sniff{Enable: true, RewriteDomain: sn.RewriteDomain, TCPPorts: sn.TCPPorts, UDPPorts: sn.UDPPorts}
		if sn.Timeout > 0 {
			c.Sniff.Timeout = seconds(sn.Timeout)
		}
	}

	switch o := p.Outbound; o.Type {
	case OutDirect:
		c.Outbounds = []hyconfig.Outbound{{Name: "default", Type: OutDirect, Direct: hyconfig.OutboundDirect{Mode: o.Mode, BindIPv4: o.BindIPv4, BindIPv6: o.BindIPv6, BindDevice: o.BindDevice}}}
	case OutSOCKS5:
		c.Outbounds = []hyconfig.Outbound{{Name: "default", Type: OutSOCKS5, SOCKS5: hyconfig.OutboundSOCKS5{Addr: o.Addr, Username: o.User, Password: s[SecretOutPassword]}}}
	case OutHTTP:
		u, _ := url.Parse(o.Addr)
		if o.User != "" {
			if pw := s[SecretOutPassword]; pw != "" {
				u.User = url.UserPassword(o.User, pw)
			} else {
				u.User = url.User(o.User)
			}
		}
		c.Outbounds = []hyconfig.Outbound{{Name: "default", Type: OutHTTP, HTTP: hyconfig.OutboundHTTP{URL: u.String()}}}
	}

	switch m := p.Masq; m.Type {
	case MasqProxy:
		c.Masquerade = hyconfig.Masquerade{Type: MasqProxy, Proxy: hyconfig.MasqueradeProxy{URL: p.Masquerade, RewriteHost: true}}
	case MasqFile:
		c.Masquerade = hyconfig.Masquerade{Type: MasqFile, File: hyconfig.MasqueradeFile{Dir: m.Dir}}
	case MasqString:
		ct := "text/plain; charset=utf-8"
		if strings.HasPrefix(strings.TrimSpace(m.Text), "<") {
			ct = "text/html; charset=utf-8"
		}
		c.Masquerade = hyconfig.Masquerade{Type: MasqString, String: hyconfig.MasqueradeString{Content: m.Text, StatusCode: m.Status, Headers: map[string]string{"content-type": ct}}}
	}
	if p.Masq.TCP && p.Masq.Type != "" {
		c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS, c.Masquerade.ForceHTTPS = ":80", ":443", true
	}

	if c.ACME != nil && p.Challenge == "dns" {
		cfg := map[string]string{}
		for _, f := range DNSProviders[p.DNSProvider] {
			if v := s[SecretDNSPrefix+f.Key]; v != "" {
				cfg[f.Key] = v
			}
		}
		c.ACME.DNS = hyconfig.ACMEDNS{Name: p.DNSProvider, Config: cfg}
	}
}

func seconds(n int) hyconfig.Duration { return hyconfig.Duration(strconv.Itoa(n) + "s") }
