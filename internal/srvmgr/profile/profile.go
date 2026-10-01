// Package profile makes the client side of a server: the share links
// (the official form and the one for URL-parsing importers), the client
// config and a QR code, from the server's current config revision.
package profile

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"rsc.io/qr"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Summary is what anyone who sees the server may see: no secrets.
type Summary struct {
	Name      string `json:"name"`
	Host      string `json:"host"`
	Ports     string `json:"ports"`
	SNI       string `json:"sni,omitempty"`
	Insecure  bool   `json:"insecure"`
	PinSHA256 string `json:"pinSHA256,omitempty"`
	Obfs      string `json:"obfs,omitempty"`
	Auth      string `json:"auth"`
	// Users are the userpass users (names only), sorted.
	Users    []string `json:"users,omitempty"`
	Warnings []string `json:"warnings"`
}

// Profile is the client profile with its secrets.
type Profile struct {
	Summary
	User string `json:"user,omitempty"`
	// URI is the official form (all ports in the authority): Hysteria,
	// HApp, Incy. Compat has the first port and mport for importers that
	// parse links with a URL library (v2rayN); the same for one port.
	URI    string `json:"uri"`
	Compat string `json:"compat"`
	// Config is the client config.yaml of the Hysteria client.
	Config string `json:"config"`
	// QR and QRCompat are the QR codes of the links: rows of "0" and "1".
	QR       []string `json:"qr"`
	QRCompat []string `json:"qrCompat"`
}

// ErrExternalAuth: the passwords are checked by an HTTP service or a
// command; the controller does not know them.
var ErrExternalAuth = errors.New("внешняя проверка паролей")

// ClientOptions are what a client of srv needs beyond its config c: the
// address and public ports, the hop interval, and how to check the
// certificate. user picks the userpass user.
func ClientOptions(srv model.Server, c *hyconfig.Server, meta model.ConfigMeta, user string) hyconfig.ClientOptions {
	o := hyconfig.ClientOptions{Host: srv.Host, Ports: meta.Ports, User: user}
	if srv.HopInterval > 0 {
		// ClientFor uses it only for a union of ports.
		o.HopInterval = hyconfig.Duration(strconv.Itoa(srv.HopInterval) + "s")
	}
	switch meta.TLS {
	case "self-signed":
		o.PinSHA256, o.SNI = meta.PinSHA256, meta.SNI
	case "file":
		o.SNI = meta.SNI
	}
	return o
}

// Summarize is the summary of a server's client profile.
func Summarize(srv model.Server, cfg []byte, meta model.ConfigMeta) (Summary, error) {
	c, err := hyconfig.ParseServer(cfg)
	if err != nil {
		return Summary{}, err
	}
	s := Summary{Name: srv.Name, Host: srv.Host, Ports: meta.Ports, Auth: strings.ToLower(c.Auth.Type), Obfs: strings.ToLower(c.Obfs.Type), Warnings: []string{}}
	if s.Ports == "" {
		if l, err := hyconfig.ParseListen(c.Listen); err == nil {
			s.Ports = l.Ports
		}
	}
	o := ClientOptions(srv, c, meta, "")
	s.SNI, s.PinSHA256, s.Insecure = o.SNI, o.PinSHA256, o.PinSHA256 != ""
	if c.ACME != nil && len(c.ACME.Domains) > 0 && s.SNI == "" && !strings.EqualFold(c.ACME.Domains[0], srv.Host) {
		s.SNI = c.ACME.Domains[0]
	}
	for u := range c.Auth.UserPass {
		s.Users = append(s.Users, u)
	}
	sort.Strings(s.Users)
	if s.PinSHA256 != "" {
		s.Warnings = append(s.Warnings, "Сертификат самоподписанный: клиенты проверяют его по pinSHA256. Клиент, который pin не поддерживает, подключится без проверки сертификата.")
	}
	if s.Auth == "http" || s.Auth == "command" {
		s.Warnings = append(s.Warnings, "Пароли клиентов проверяет внешний сервис: HyRoute их не знает, и ссылку нужно дополнить паролем вручную.")
	}
	if meta.TLS == "" && c.ACME == nil && c.TLS == nil {
		s.Warnings = append(s.Warnings, "В конфиге нет TLS: Hysteria с ним не запустится.")
	}
	return s, nil
}

// Build is the full profile; user picks the userpass user (may be empty
// when there is one).
func Build(srv model.Server, cfg []byte, meta model.ConfigMeta, user string) (Profile, error) {
	s, err := Summarize(srv, cfg, meta)
	if err != nil {
		return Profile{}, err
	}
	if s.Auth == "http" || s.Auth == "command" {
		return Profile{}, ErrExternalAuth
	}
	c, _ := hyconfig.ParseServer(cfg)
	cc, err := hyconfig.ClientFor(c, ClientOptions(srv, c, meta, user))
	if err != nil {
		return Profile{}, err
	}
	host, ports, err := hyconfig.SplitServer(cc.Server)
	if err != nil {
		return Profile{}, err
	}
	l := hy2uri.Link{
		Name: srv.Name, Auth: cc.Auth, Host: host, Ports: ports,
		SNI: cc.TLS.SNI, Insecure: cc.TLS.Insecure, PinSHA256: cc.TLS.PinSHA256,
		HopInterval: string(cc.Transport.UDP.HopInterval),
	}
	switch strings.ToLower(cc.Obfs.Type) {
	case "salamander":
		l.ObfsType, l.ObfsPassword = "salamander", cc.Obfs.Salamander.Password
	case "gecko":
		l.ObfsType, l.ObfsPassword = "gecko", cc.Obfs.Gecko.Password
	}
	if err := l.Validate(); err != nil {
		return Profile{}, err
	}
	yml, err := cc.Marshal()
	if err != nil {
		return Profile{}, err
	}
	p := Profile{Summary: s, URI: withHop(l.String(), srv.HopInterval, cc.Transport.UDP.HopInterval != ""), Compat: l.Compat(), Config: string(yml)}
	if s.Auth == "userpass" {
		p.User, _, _ = strings.Cut(cc.Auth, ":")
	}
	if p.QR, err = QR(p.URI); err != nil {
		return Profile{}, err
	}
	if p.QRCompat, err = QR(p.Compat); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// withHop adds the hop interval to an official link (hopping: the client
// config has it). The scheme does not define it, and the Hysteria client
// ignores it; HyRoute and Incy read mportHopInt, as Compat carries it.
func withHop(uri string, seconds int, hopping bool) string {
	if !hopping || seconds <= 0 {
		return uri
	}
	base, frag, hasFrag := strings.Cut(uri, "#")
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	base += sep + "mportHopInt=" + strconv.Itoa(seconds)
	if hasFrag {
		base += "#" + frag
	}
	return base
}

// QR is the QR code of text (error correction M) as rows of "0" and "1",
// without the quiet zone.
func QR(text string) ([]string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	rows := make([]string, code.Size)
	var b strings.Builder
	for y := 0; y < code.Size; y++ {
		b.Reset()
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[y] = b.String()
	}
	return rows, nil
}
