// Package preset is a reusable part of a Hysteria server config: its
// sections (ports, speed, QUIC, UDP, sniff, resolver, ACL, outbounds,
// masquerade, obfuscation) without secrets and without the addresses of
// a server. A preset is made from a server's config, and its sections
// are laid over another config through the typed model; what cannot be
// carried over is left out with a note.
package preset

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Sections.
const (
	Ports      = "ports"      // listen ports (not the address)
	Speed      = "speed"      // bandwidth, ignoreClientBandwidth, congestion, speedTest
	QUIC       = "quic"       // quic
	UDP        = "udp"        // disableUDP, udpIdleTimeout
	Sniff      = "sniff"      // sniff
	Resolver   = "resolver"   // resolver
	ACL        = "acl"        // acl
	Outbounds  = "outbounds"  // outbounds (no credentials, local proxies only)
	Masquerade = "masquerade" // masquerade
	Obfs       = "obfs"       // obfs type (a password is made when applied)
)

// Sections are all sections in config order.
var Sections = []string{Ports, Obfs, Masquerade, Speed, QUIC, UDP, Resolver, Sniff, ACL, Outbounds}

// Valid reports whether s is a section name.
func Valid(s string) bool { return slices.Contains(Sections, s) }

// Extract is the preset of a server config: every section it has, without
// secrets (passwords, tokens, credentials in URLs) and without addresses
// of the server (listen and bind addresses, remote proxies). TLS, ACME,
// auth, the stats API and fields HyRoute does not know are never part of
// a preset. notes say what was left out.
func Extract(c *hyconfig.Server) (*hyconfig.Server, []string) {
	var notes []string
	p := &hyconfig.Server{}
	if l, err := hyconfig.ParseListen(c.Listen); err == nil && c.Listen != "" && !strings.Contains(c.Listen, "://") {
		p.Listen = ":" + l.Ports
	}
	p.Obfs = hyconfig.Obfs{Type: strings.ToLower(c.Obfs.Type)}
	if p.Obfs.Type == "gecko" {
		p.Obfs.Gecko = hyconfig.Gecko{MinPacketSize: c.Obfs.Gecko.MinPacketSize, MaxPacketSize: c.Obfs.Gecko.MaxPacketSize}
	}
	if p.Obfs.Type == "plain" {
		p.Obfs.Type = ""
	}
	p.Masquerade = c.Masquerade
	if u, err := url.Parse(p.Masquerade.Proxy.URL); err == nil && u.User != nil {
		u.User = nil
		p.Masquerade.Proxy.URL = u.String()
		notes = append(notes, "Из адреса сайта-маскировки убраны имя и пароль.")
	}
	if h := p.Masquerade.String.Headers; len(h) > 0 {
		p.Masquerade.String.Headers = map[string]string{}
		for k, v := range h {
			if redact.IsSecretKey(k) || strings.EqualFold(k, "authorization") || strings.EqualFold(k, "cookie") || strings.EqualFold(k, "set-cookie") {
				notes = append(notes, fmt.Sprintf("Заголовок маскировки %s не сохранён.", k))
				continue
			}
			p.Masquerade.String.Headers[k] = v
		}
	}
	p.Masquerade.ListenHTTP, p.Masquerade.ListenHTTPS = portOnly(p.Masquerade.ListenHTTP), portOnly(p.Masquerade.ListenHTTPS)
	p.Bandwidth, p.IgnoreClientBandwidth, p.Congestion, p.SpeedTest = c.Bandwidth, c.IgnoreClientBandwidth, c.Congestion, c.SpeedTest
	p.QUIC = c.QUIC
	p.DisableUDP, p.UDPIdleTimeout = c.DisableUDP, c.UDPIdleTimeout
	p.Resolver = c.Resolver
	p.Sniff = c.Sniff
	p.ACL = c.ACL
	for _, o := range c.Outbounds {
		o, note := outbound(o)
		if note != "" {
			notes = append(notes, note)
		}
		if o != nil {
			p.Outbounds = append(p.Outbounds, *o)
		}
	}
	clearUnknown(reflect.ValueOf(p).Elem())
	if len(hyconfig.UnknownFields(c)) > 0 {
		notes = append(notes, "Поля, которых HyRoute не знает, в пресет не входят.")
	}
	return p, notes
}

// portOnly is a listen address without its host (":443").
func portOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return ":" + port
	}
	return ""
}

// outbound is an outbound for a preset: no credentials, no addresses of
// the server (bind addresses), and a proxy only on the server itself.
func outbound(o hyconfig.Outbound) (*hyconfig.Outbound, string) {
	out := hyconfig.Outbound{Name: o.Name, Type: strings.ToLower(o.Type)}
	switch out.Type {
	case "direct":
		out.Direct = hyconfig.OutboundDirect{Mode: o.Direct.Mode, BindDevice: o.Direct.BindDevice, FastOpen: o.Direct.FastOpen}
		if o.Direct.BindIPv4 != "" || o.Direct.BindIPv6 != "" {
			return &out, fmt.Sprintf("У выхода %s убрана привязка к адресам сервера.", o.Name)
		}
		return &out, ""
	case "socks5":
		if !local(o.SOCKS5.Addr) {
			return nil, fmt.Sprintf("Выход %s (SOCKS5 на другом сервере) не сохранён: адреса других серверов в пресет не входят.", o.Name)
		}
		out.SOCKS5 = hyconfig.OutboundSOCKS5{Addr: o.SOCKS5.Addr}
		if o.SOCKS5.Username != "" || o.SOCKS5.Password != "" {
			return &out, fmt.Sprintf("У выхода %s убраны имя и пароль прокси.", o.Name)
		}
		return &out, ""
	case "http":
		u, err := url.Parse(o.HTTP.URL)
		if err != nil || !local(u.Host) {
			return nil, fmt.Sprintf("Выход %s (HTTP-прокси на другом сервере) не сохранён: адреса других серверов в пресет не входят.", o.Name)
		}
		note := ""
		if u.User != nil {
			u.User = nil
			note = fmt.Sprintf("У выхода %s убраны имя и пароль прокси.", o.Name)
		}
		out.HTTP = hyconfig.OutboundHTTP{URL: u.String(), Insecure: o.HTTP.Insecure}
		return &out, note
	}
	return nil, fmt.Sprintf("Выход %s неизвестного типа не сохранён.", o.Name)
}

// local: host:port on the server itself (a local proxy such as WARP).
func local(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

var unknownType = reflect.TypeOf(hyconfig.Unknown{})

// clearUnknown drops the fields HyRoute does not know, everywhere in v:
// they could hold anything.
func clearUnknown(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			clearUnknown(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.Type() == unknownType {
				f.Set(reflect.Zero(unknownType))
				continue
			}
			clearUnknown(f)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			clearUnknown(v.Index(i))
		}
	}
}

// Has lists the sections preset p carries.
func Has(p *hyconfig.Server) []string {
	var out []string
	for _, s := range Sections {
		if !empty(p, s) {
			out = append(out, s)
		}
	}
	return out
}

func empty(p *hyconfig.Server, section string) bool {
	switch section {
	case Ports:
		return p.Listen == ""
	case Speed:
		return reflect.ValueOf(p.Bandwidth).IsZero() && !p.IgnoreClientBandwidth && reflect.ValueOf(p.Congestion).IsZero() && !p.SpeedTest
	case QUIC:
		return reflect.ValueOf(p.QUIC).IsZero()
	case UDP:
		return !p.DisableUDP && p.UDPIdleTimeout == ""
	case Sniff:
		return reflect.ValueOf(p.Sniff).IsZero()
	case Resolver:
		return reflect.ValueOf(p.Resolver).IsZero()
	case ACL:
		return reflect.ValueOf(p.ACL).IsZero()
	case Outbounds:
		return len(p.Outbounds) == 0
	case Masquerade:
		return reflect.ValueOf(p.Masquerade).IsZero()
	case Obfs:
		return p.Obfs.Type == ""
	}
	return true
}

// ErrNoSection: the preset does not carry a section asked for.
var ErrNoSection = errors.New("preset: no such section")

// Overlay lays the sections of preset p over config c: each section of c
// becomes the preset's. The listen address keeps c's host; obfuscation
// keeps c's password when the type stays, else gets one from password().
// It reports whether the obfuscation password is new (client links
// change).
func Overlay(c, p *hyconfig.Server, sections []string, password func() string) (newObfs bool, err error) {
	for _, s := range sections {
		if !Valid(s) || empty(p, s) {
			return false, fmt.Errorf("%w %q", ErrNoSection, s)
		}
	}
	for _, s := range sections {
		switch s {
		case Ports:
			host := ""
			if h, _, err := net.SplitHostPort(c.Listen); err == nil && !strings.Contains(c.Listen, "://") {
				host = h
				if strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
			}
			c.Listen = host + p.Listen
		case Speed:
			c.Bandwidth, c.IgnoreClientBandwidth, c.Congestion, c.SpeedTest = p.Bandwidth, p.IgnoreClientBandwidth, p.Congestion, p.SpeedTest
		case QUIC:
			c.QUIC = p.QUIC
		case UDP:
			c.DisableUDP, c.UDPIdleTimeout = p.DisableUDP, p.UDPIdleTimeout
		case Sniff:
			c.Sniff = p.Sniff
		case Resolver:
			c.Resolver = p.Resolver
		case ACL:
			c.ACL = p.ACL
		case Outbounds:
			c.Outbounds = slices.Clone(p.Outbounds)
		case Masquerade:
			c.Masquerade = p.Masquerade
		case Obfs:
			o := hyconfig.Obfs{Type: p.Obfs.Type, Gecko: hyconfig.Gecko{MinPacketSize: p.Obfs.Gecko.MinPacketSize, MaxPacketSize: p.Obfs.Gecko.MaxPacketSize}}
			old := ""
			if strings.EqualFold(c.Obfs.Type, o.Type) {
				// The block of the type in use: Hysteria ignores the other.
				old = c.Obfs.Salamander.Password
				if strings.EqualFold(o.Type, "gecko") {
					old = c.Obfs.Gecko.Password
				}
			}
			pw := old
			if pw == "" {
				pw, newObfs = password(), true
			}
			if o.Type == "gecko" {
				o.Gecko.Password = pw
			} else {
				o.Salamander.Password = pw
			}
			c.Obfs = o
		}
	}
	return newObfs, nil
}
