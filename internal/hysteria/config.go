package hysteria

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// RunOptions are the per-launch values that are not part of the profile.
type RunOptions struct {
	// ServerIP, when valid, replaces Host in the server field (pin IP mode).
	ServerIP string
	// SOCKS5 inbound on loopback, with random credentials so other local
	// processes cannot use the tunnel.
	SOCKSListen   string
	SOCKSUsername string
	SOCKSPassword string
}

type yConfig struct {
	Server     string       `yaml:"server"`
	Auth       string       `yaml:"auth,omitempty"`
	TLS        *yTLS        `yaml:"tls,omitempty"`
	Obfs       *yObfs       `yaml:"obfs,omitempty"`
	Transport  *yTransport  `yaml:"transport,omitempty"`
	QUIC       *yQUIC       `yaml:"quic,omitempty"`
	Congestion *yCongestion `yaml:"congestion,omitempty"`
	Bandwidth  *yBandwidth  `yaml:"bandwidth,omitempty"`
	FastOpen   bool         `yaml:"fastOpen,omitempty"`
	SOCKS5     ySOCKS5      `yaml:"socks5"`
}

type yTLS struct {
	SNI       string `yaml:"sni,omitempty"`
	Insecure  bool   `yaml:"insecure,omitempty"`
	PinSHA256 string `yaml:"pinSHA256,omitempty"`
	CA        string `yaml:"ca,omitempty"`
	ECH       string `yaml:"ech,omitempty"`
}

type yObfs struct {
	Type       string       `yaml:"type"`
	Salamander *ySalamander `yaml:"salamander,omitempty"`
	Gecko      *yGecko      `yaml:"gecko,omitempty"`
}

type ySalamander struct {
	Password string `yaml:"password"`
}

type yGecko struct {
	Password      string `yaml:"password"`
	MinPacketSize int    `yaml:"minPacketSize,omitempty"`
	MaxPacketSize int    `yaml:"maxPacketSize,omitempty"`
}

type yTransport struct {
	UDP yTransportUDP `yaml:"udp"`
}

type yTransportUDP struct {
	HopInterval    string `yaml:"hopInterval,omitempty"`
	MinHopInterval string `yaml:"minHopInterval,omitempty"`
	MaxHopInterval string `yaml:"maxHopInterval,omitempty"`
}

type yQUIC struct {
	InitStreamReceiveWindow uint64 `yaml:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64 `yaml:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64 `yaml:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64 `yaml:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          string `yaml:"maxIdleTimeout,omitempty"`
	KeepAlivePeriod         string `yaml:"keepAlivePeriod,omitempty"`
	DisablePathMTUDiscovery bool   `yaml:"disablePathMTUDiscovery,omitempty"`
	DisableChromeParrot     bool   `yaml:"disableChromeParrot,omitempty"`
}

type yCongestion struct {
	Type       string `yaml:"type,omitempty"`
	BBRProfile string `yaml:"bbrProfile,omitempty"`
}

type yBandwidth struct {
	Up   string `yaml:"up,omitempty"`
	Down string `yaml:"down,omitempty"`
}

type ySOCKS5 struct {
	Listen     string `yaml:"listen"`
	Username   string `yaml:"username,omitempty"`
	Password   string `yaml:"password,omitempty"`
	DisableUDP bool   `yaml:"disableUDP"`
}

// BuildConfig renders the client YAML for one launch.
func BuildConfig(p *Profile, o RunOptions) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	host := p.Host
	sni := p.TLS.SNI
	if o.ServerIP != "" {
		host = o.ServerIP
		if sni == "" && !p.HostIsIP() {
			// Keep the certificate check on the domain when we pin the IP.
			sni = p.Host
		}
	}
	c := yConfig{
		Server:   ServerString(host, p.Ports),
		Auth:     p.Auth,
		FastOpen: p.FastOpen,
		SOCKS5: ySOCKS5{
			Listen:   o.SOCKSListen,
			Username: o.SOCKSUsername,
			Password: o.SOCKSPassword,
		},
	}
	// Hysteria checks pinSHA256 in addition to the CA chain, so a pinned
	// self-signed certificate would still fail with "unknown authority".
	// Share links with a pin mean "trust this certificate": skip the chain
	// check and let the pin do the verification (Go calls
	// VerifyPeerCertificate even with InsecureSkipVerify).
	insecure := p.TLS.Insecure || p.TLS.PinSHA256 != ""
	if t := (yTLS{SNI: sni, Insecure: insecure, PinSHA256: p.TLS.PinSHA256, CA: p.TLS.CA, ECH: p.TLS.ECH}); t != (yTLS{}) {
		c.TLS = &t
	}
	switch strings.ToLower(p.Obfs.Type) { // any case, like Validate
	case "salamander":
		c.Obfs = &yObfs{Type: "salamander", Salamander: &ySalamander{Password: p.Obfs.Password}}
	case "gecko":
		c.Obfs = &yObfs{Type: "gecko", Gecko: &yGecko{Password: p.Obfs.Password, MinPacketSize: p.Obfs.MinPacketSize, MaxPacketSize: p.Obfs.MaxPacketSize}}
	}
	if p.Hop != (Hop{}) {
		c.Transport = &yTransport{UDP: yTransportUDP{HopInterval: p.Hop.Interval, MinHopInterval: p.Hop.MinInterval, MaxHopInterval: p.Hop.MaxInterval}}
	}
	if q := yQUIC(p.QUIC); q != (yQUIC{}) {
		c.QUIC = &q
	}
	if p.Congestion != (Congestion{}) {
		c.Congestion = &yCongestion{Type: p.Congestion.Type, BBRProfile: p.Congestion.BBRProfile}
	}
	if p.Bandwidth != (Bandwidth{}) {
		c.Bandwidth = &yBandwidth{Up: p.Bandwidth.Up, Down: p.Bandwidth.Down}
	}
	return yaml.Marshal(&c)
}
