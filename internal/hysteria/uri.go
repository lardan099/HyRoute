package hysteria

import (
	"strings"

	"github.com/lardan099/hyroute/internal/hy2uri"
)

// ParseURI parses hysteria2:// and hy2:// share links (see hy2uri.Parse
// for the accepted variants) into a profile.
func ParseURI(s string) (p Profile, warnings []string, err error) {
	l, warnings, err := hy2uri.Parse(s)
	if err != nil {
		return p, nil, err
	}
	p = Profile{
		Name:  l.Name,
		Host:  l.Host,
		Ports: l.Ports,
		Auth:  l.Auth,
		TLS:   TLS{SNI: l.SNI, Insecure: l.Insecure, PinSHA256: l.PinSHA256, ECH: l.ECH},
		Obfs:  Obfs{Type: l.ObfsType, Password: l.ObfsPassword},
		Hop:   Hop{Interval: l.HopInterval},
	}
	// Bandwidth switches the connection to Brutal; a speed a panel put in
	// the link is no reason to do that behind the user's back.
	for _, k := range []struct {
		name string
		v    int
	}{{"down", l.DownMbps}, {"up", l.UpMbps}} {
		if k.v != 0 {
			warnings = append(warnings, "ignored parameter "+k.name)
		}
	}
	p.PinServerIP = true
	return p, warnings, p.Validate()
}

// URI exports the profile in the official format. Only connection
// parameters are included (bandwidth, hop intervals etc. are not part of the
// share-link spec).
func (p *Profile) URI() string {
	return hy2uri.Link{
		Name:         p.Name,
		Auth:         p.Auth,
		Host:         p.Host,
		Ports:        p.Ports,
		ObfsType:     strings.ToLower(p.Obfs.Type),
		ObfsPassword: p.Obfs.Password,
		SNI:          p.TLS.SNI,
		Insecure:     p.TLS.Insecure,
		PinSHA256:    p.TLS.PinSHA256,
		ECH:          p.TLS.ECH,
	}.String()
}
