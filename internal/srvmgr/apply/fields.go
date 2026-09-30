package apply

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Fields are the main settings of a server config, as the structured
// editor shows them. Secrets are Hidden unless the admin typed new ones;
// an empty password asks for a generated one.
type Fields struct {
	Listen string `json:"listen"`
	// TLS: "file" (cert and key paths) or "acme".
	TLS         string   `json:"tls"`
	Cert        string   `json:"cert"`
	Key         string   `json:"key"`
	SNIGuard    string   `json:"sniGuard"`
	ACMEDomains []string `json:"acmeDomains"`
	ACMEEmail   string   `json:"acmeEmail"`
	// AuthType other than password is edited in the raw config only.
	AuthType     string `json:"authType"`
	AuthPassword string `json:"authPassword"`
	// Obfs: "" or "salamander" (other types: raw config only).
	Obfs         string `json:"obfs"`
	ObfsPassword string `json:"obfsPassword"`
	// Masquerade: "" (404), "proxy", "string" or "file" (the last two:
	// raw config only, kept as they are).
	Masquerade     string `json:"masquerade"`
	MasqueradeURL  string `json:"masqueradeUrl"`
	RewriteHost    bool   `json:"rewriteHost"`
	BandwidthUp    string `json:"bandwidthUp"`
	BandwidthDown  string `json:"bandwidthDown"`
	IgnoreClientBW bool   `json:"ignoreClientBandwidth"`
	SpeedTest      bool   `json:"speedTest"`
	DisableUDP     bool   `json:"disableUDP"`
	UDPIdleTimeout string `json:"udpIdleTimeout"`
}

// FieldsOf reads the fields from a config (masked or not).
func FieldsOf(c *hyconfig.Server) Fields {
	f := Fields{
		Listen: c.Listen, AuthType: strings.ToLower(c.Auth.Type), AuthPassword: c.Auth.Password,
		Obfs: strings.ToLower(c.Obfs.Type), ObfsPassword: c.Obfs.Salamander.Password,
		Masquerade: strings.ToLower(c.Masquerade.Type), MasqueradeURL: c.Masquerade.Proxy.URL, RewriteHost: c.Masquerade.Proxy.RewriteHost,
		BandwidthUp: c.Bandwidth.Up, BandwidthDown: c.Bandwidth.Down, IgnoreClientBW: c.IgnoreClientBandwidth,
		SpeedTest: c.SpeedTest, DisableUDP: c.DisableUDP, UDPIdleTimeout: string(c.UDPIdleTimeout),
		ACMEDomains: []string{},
	}
	switch {
	case c.ACME != nil:
		f.TLS, f.ACMEDomains, f.ACMEEmail = "acme", append([]string{}, c.ACME.Domains...), c.ACME.Email
	case c.TLS != nil:
		f.TLS, f.Cert, f.Key, f.SNIGuard = "file", c.TLS.Cert, c.TLS.Key, c.TLS.SNIGuard
	}
	return f
}

// SetFields writes the fields into the config; what the fields do not
// cover (other TLS options, ACME details, ACL, outbounds, unknown fields)
// stays as it was.
func SetFields(c *hyconfig.Server, f Fields) error {
	c.Listen = strings.TrimSpace(f.Listen)
	switch f.TLS {
	case "file":
		if c.TLS == nil {
			c.TLS = &hyconfig.TLS{}
		}
		c.TLS.Cert, c.TLS.Key, c.TLS.SNIGuard = strings.TrimSpace(f.Cert), strings.TrimSpace(f.Key), f.SNIGuard
		c.ACME = nil
	case "acme":
		if c.ACME == nil {
			c.ACME = &hyconfig.ACME{}
		}
		c.ACME.Domains = nil
		for _, d := range f.ACMEDomains {
			if d = strings.TrimSpace(d); d != "" {
				c.ACME.Domains = append(c.ACME.Domains, d)
			}
		}
		c.ACME.Email = strings.TrimSpace(f.ACMEEmail)
		c.TLS = nil
	}
	if strings.EqualFold(c.Auth.Type, "password") || c.Auth.Type == "" {
		c.Auth.Type = "password"
		if c.Auth.Password = f.AuthPassword; c.Auth.Password == "" {
			c.Auth.Password = generated()
		}
	}
	switch f.Obfs {
	case "":
		if strings.EqualFold(c.Obfs.Type, "salamander") {
			c.Obfs = hyconfig.Obfs{Unknown: c.Obfs.Unknown}
		}
	case "salamander":
		c.Obfs.Type = "salamander"
		if c.Obfs.Salamander.Password = f.ObfsPassword; c.Obfs.Salamander.Password == "" {
			c.Obfs.Salamander.Password = generated()
		}
	}
	switch f.Masquerade {
	case "":
		c.Masquerade = hyconfig.Masquerade{Unknown: c.Masquerade.Unknown}
	case "proxy":
		c.Masquerade.Type = "proxy"
		c.Masquerade.Proxy.URL, c.Masquerade.Proxy.RewriteHost = strings.TrimSpace(f.MasqueradeURL), f.RewriteHost
	}
	c.Bandwidth.Up, c.Bandwidth.Down = strings.TrimSpace(f.BandwidthUp), strings.TrimSpace(f.BandwidthDown)
	c.IgnoreClientBandwidth, c.SpeedTest, c.DisableUDP = f.IgnoreClientBW, f.SpeedTest, f.DisableUDP
	c.UDPIdleTimeout = hyconfig.Duration(strings.TrimSpace(f.UDPIdleTimeout))
	return nil
}

// generated is a new password: 24 random bytes, base64url.
func generated() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Check is what the editor shows about a candidate.
type Check struct {
	// YAML is the candidate as the editor shows it (secrets masked).
	YAML   string `json:"yaml"`
	Fields Fields `json:"fields"`
	// Problems are errors (apply refused) and warnings of the check.
	Problems []hyconfig.Problem `json:"problems"`
	// Diff is against the current revision, both masked.
	Diff []Line `json:"diff"`
	// Secrets are the paths of secrets that change (not in the diff).
	Secrets []string `json:"secrets"`
	// Unknown are fields HyRoute does not know (kept as they are).
	Unknown []string `json:"unknown"`
	OK      bool     `json:"ok"`
}

// Build turns the editor's text (and fields, when the structured editor
// changed them) into the candidate: current is the config of the base
// revision (secrets and all). It returns the unmasked candidate, nil when
// it cannot be built (the check says why).
func Build(current []byte, text string, fields *Fields) (Check, []byte, error) {
	ch := Check{Problems: []hyconfig.Problem{}, Diff: []Line{}, Secrets: []string{}, Unknown: []string{}}
	b := []byte(text)
	if fields != nil {
		c, err := hyconfig.ParseServer(b)
		if err != nil {
			return ch, nil, &model.FieldError{Field: "yaml", Msg: "Конфиг не разобрать: " + err.Error()}
		}
		if err := SetFields(c, *fields); err != nil {
			return ch, nil, err
		}
		if b, err = c.Marshal(); err != nil {
			return ch, nil, err
		}
	}
	cand, err := Unmask(b, current)
	var fe *model.FieldError
	if errors.As(err, &fe) {
		return ch, nil, err
	} else if err != nil {
		return ch, nil, &model.FieldError{Field: "yaml", Msg: "Конфиг не разобрать: " + err.Error()}
	}
	c, err := hyconfig.ParseServer(cand)
	if err != nil {
		return ch, nil, &model.FieldError{Field: "yaml", Msg: "Конфиг не разобрать: " + err.Error()}
	}
	masked, err := MaskUnchanged(cand, current)
	if err != nil {
		return ch, nil, err
	}
	curMasked, _, err := Mask(current)
	if err != nil {
		return ch, nil, err
	}
	mc, _ := hyconfig.ParseServer(masked)
	ch.YAML, ch.Fields = string(masked), FieldsOf(mc)
	ch.Problems = append(ch.Problems, c.Validate()...)
	ch.Unknown = append(ch.Unknown, hyconfig.UnknownFields(c)...)
	ch.Diff = Diff(string(curMasked), string(masked))
	ch.Secrets = append(ch.Secrets, ChangedSecrets(current, cand)...)
	ch.OK = !hyconfig.HasErrors(ch.Problems)
	return ch, cand, nil
}
