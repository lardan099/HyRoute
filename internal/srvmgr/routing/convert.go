package routing

import (
	"net/url"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Outbound is an outbound of the config. A password the editor got as
// apply.Hidden and sends back so keeps the current one.
type Outbound struct {
	Name string `json:"name"`
	// From is the outbound's name in the current config ("": a new one).
	// Rules naming it follow a rename.
	From   string  `json:"from,omitempty"`
	Type   string  `json:"type"` // direct, socks5, http
	Direct *Direct `json:"direct,omitempty"`
	SOCKS5 *SOCKS5 `json:"socks5,omitempty"`
	HTTP   *HTTP   `json:"http,omitempty"`
	// Locked: the outbound of a deployed cascade; it stays first and as
	// it is.
	Locked bool `json:"locked,omitempty"`
}

// Direct goes out from the server itself.
type Direct struct {
	Mode       string `json:"mode,omitempty"` // auto, 64, 46, 6, 4
	BindIPv4   string `json:"bindIPv4,omitempty"`
	BindIPv6   string `json:"bindIPv6,omitempty"`
	BindDevice string `json:"bindDevice,omitempty"`
	FastOpen   bool   `json:"fastOpen,omitempty"`
}

// SOCKS5 is a SOCKS5 proxy.
type SOCKS5 struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// HTTP is an HTTP or HTTPS proxy; the password is apart from the URL.
type HTTP struct {
	URL      string `json:"url"`
	Password string `json:"password,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

func hidden(s string) string {
	if s == "" {
		return ""
	}
	return apply.Hidden
}

// splitURL takes the password out of a proxy URL. A URL that does not
// parse is redacted whole.
func splitURL(raw string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil {
		return redact.String(raw), ""
	}
	if u.User == nil {
		return raw, ""
	}
	pw, ok := u.User.Password()
	if !ok {
		return raw, ""
	}
	u.User = url.User(u.User.Username())
	return u.String(), pw
}

// outboundOf is an outbound of the config, passwords hidden.
func outboundOf(o hyconfig.Outbound) Outbound {
	v := Outbound{Name: o.Name, From: o.Name, Type: strings.ToLower(o.Type)}
	switch v.Type {
	case "direct":
		d := o.Direct
		v.Direct = &Direct{Mode: d.Mode, BindIPv4: d.BindIPv4, BindIPv6: d.BindIPv6, BindDevice: d.BindDevice, FastOpen: d.FastOpen}
	case "socks5":
		v.SOCKS5 = &SOCKS5{Addr: o.SOCKS5.Addr, Username: o.SOCKS5.Username, Password: hidden(o.SOCKS5.Password)}
	case "http":
		u, pw := splitURL(o.HTTP.URL)
		v.HTTP = &HTTP{URL: u, Password: hidden(pw), Insecure: o.HTTP.Insecure}
	}
	return v
}

// outbounds turns the editor's outbounds into the config's: cur are the
// current ones, ref the cascade the server is the entry of. renames maps
// the lower-case old name of a renamed outbound to its new name.
func outbounds(cur []hyconfig.Outbound, in []Outbound, ref *ChainRef) (out []hyconfig.Outbound, renames map[string]string, err error) {
	renames = map[string]string{}
	var lock *hyconfig.Outbound
	if ref != nil {
		for i := range cur {
			if strings.EqualFold(cur[i].Name, cascade.OutboundName) {
				lock = &cur[i]
			}
		}
	}
	for i, o := range in {
		if lock != nil && (strings.EqualFold(o.From, lock.Name) || strings.EqualFold(o.Name, lock.Name)) {
			if i != 0 || !strings.EqualFold(o.From, lock.Name) || o.Name != lock.Name {
				return nil, nil, &model.FieldError{Field: "outbounds", Msg: "Outbound «" + lock.Name + "» ведёт в каскад «" + ref.Name + "»: он остаётся первым и без изменений. Чтобы убрать его, снимите связь на странице каскада."}
			}
			out = append(out, *lock)
			continue
		}
		c, err := o.config(cur)
		if err != nil {
			return nil, nil, err
		}
		if o.From != "" && !strings.EqualFold(o.From, c.Name) {
			renames[strings.ToLower(o.From)] = c.Name
		}
		out = append(out, c)
	}
	if lock != nil && (len(out) == 0 || out[0].Name != lock.Name) {
		return nil, nil, &model.FieldError{Field: "outbounds", Msg: "Outbound «" + lock.Name + "» ведёт в каскад «" + ref.Name + "»: он остаётся первым и без изменений. Чтобы убрать его, снимите связь на странице каскада."}
	}
	return out, renames, nil
}

// config is the editor's outbound in the config, from the current one of
// that name (unknown fields kept, hidden passwords put back).
func (o Outbound) config(cur []hyconfig.Outbound) (hyconfig.Outbound, error) {
	name := strings.TrimSpace(o.Name)
	var was hyconfig.Outbound
	if o.From != "" {
		found := false
		for _, c := range cur {
			if strings.EqualFold(c.Name, o.From) {
				was, found = c, true
			}
		}
		if !found {
			return was, &model.FieldError{Field: "outbounds", Msg: "В конфиге сервера нет outbound «" + o.From + "»: откройте маршрутизацию заново."}
		}
	}
	t := strings.ToLower(strings.TrimSpace(o.Type))
	c := hyconfig.Outbound{Name: name, Type: t}
	if o.From != "" && strings.EqualFold(was.Type, t) {
		c = was // unknown fields and the type's spelling stay
		c.Name = name
	}
	keep := func(field, pw, current string) (string, error) {
		if pw != apply.Hidden {
			return pw, nil
		}
		if current == "" {
			return "", &model.FieldError{Field: field, Msg: "Пароль outbound «" + name + "» не задан: введите его."}
		}
		return current, nil
	}
	var err error
	switch t {
	case "direct":
		d := Direct{}
		if o.Direct != nil {
			d = *o.Direct
		}
		c.Direct.Mode, c.Direct.BindIPv4, c.Direct.BindIPv6, c.Direct.BindDevice, c.Direct.FastOpen = d.Mode, d.BindIPv4, d.BindIPv6, d.BindDevice, d.FastOpen
	case "socks5":
		s := SOCKS5{}
		if o.SOCKS5 != nil {
			s = *o.SOCKS5
		}
		c.SOCKS5.Addr, c.SOCKS5.Username = s.Addr, s.Username
		if c.SOCKS5.Password, err = keep("outbounds.socks5.password", s.Password, was.SOCKS5.Password); err != nil {
			return c, err
		}
	case "http":
		h := HTTP{}
		if o.HTTP != nil {
			h = *o.HTTP
		}
		raw := h.URL
		if strings.Contains(raw, redact.Mask) {
			// A URL the view redacted whole: the current one.
			if was.HTTP.URL == "" {
				return c, &model.FieldError{Field: "outbounds.http.url", Msg: "Адрес HTTP-прокси outbound «" + name + "» не задан."}
			}
			raw = was.HTTP.URL
		} else {
			_, curPw := splitURL(was.HTTP.URL)
			pw, err := keep("outbounds.http.password", h.Password, curPw)
			if err != nil {
				return c, err
			}
			if pw != "" {
				u, err := url.Parse(raw)
				if err != nil || u.Host == "" {
					return c, &model.FieldError{Field: "outbounds.http.url", Msg: "Неверный адрес HTTP-прокси outbound «" + name + "»."}
				}
				user := ""
				if u.User != nil {
					user = u.User.Username()
				}
				u.User = url.UserPassword(user, pw)
				raw = u.String()
			}
		}
		c.HTTP.URL, c.HTTP.Insecure = raw, h.Insecure
	default:
		return c, &model.FieldError{Field: "outbounds.type", Msg: "Тип outbound «" + name + "» — direct, socks5 или http."}
	}
	return c, nil
}

// Resolver is the DNS server the server resolves client requests with.
type Resolver struct {
	Type     string `json:"type"` // system, udp, tcp, tls, https
	Addr     string `json:"addr,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

func resolverOf(r hyconfig.Resolver) Resolver {
	switch t := strings.ToLower(r.Type); t {
	case "", "system":
		return Resolver{Type: "system"}
	case "tcp":
		return Resolver{Type: t, Addr: r.TCP.Addr, Timeout: string(r.TCP.Timeout)}
	case "udp":
		return Resolver{Type: t, Addr: r.UDP.Addr, Timeout: string(r.UDP.Timeout)}
	case "tls", "tcp-tls":
		return Resolver{Type: "tls", Addr: r.TLS.Addr, Timeout: string(r.TLS.Timeout), SNI: r.TLS.SNI, Insecure: r.TLS.Insecure}
	case "https", "http":
		return Resolver{Type: "https", Addr: r.HTTPS.Addr, Timeout: string(r.HTTPS.Timeout), SNI: r.HTTPS.SNI, Insecure: r.HTTPS.Insecure}
	default:
		return Resolver{Type: t}
	}
}

// set writes the resolver into the config; an unchanged one keeps its
// spelling, the sections of other types stay.
func (in Resolver) set(r *hyconfig.Resolver) {
	in.Type = strings.ToLower(strings.TrimSpace(in.Type))
	if in == resolverOf(*r) || in.Type == "" {
		return
	}
	r.Type = in.Type
	switch in.Type {
	case "tcp":
		r.TCP.Addr, r.TCP.Timeout = in.Addr, hyconfig.Duration(in.Timeout)
	case "udp":
		r.UDP.Addr, r.UDP.Timeout = in.Addr, hyconfig.Duration(in.Timeout)
	case "tls":
		r.TLS.Addr, r.TLS.Timeout, r.TLS.SNI, r.TLS.Insecure = in.Addr, hyconfig.Duration(in.Timeout), in.SNI, in.Insecure
	case "https":
		r.HTTPS.Addr, r.HTTPS.Timeout, r.HTTPS.SNI, r.HTTPS.Insecure = in.Addr, hyconfig.Duration(in.Timeout), in.SNI, in.Insecure
	}
}
