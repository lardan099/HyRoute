package hyconfig

// Client is the Hysteria client config. Forwarding, TProxy, redirect and
// TUN modes are not modelled: they stay in Unknown as written.
type Client struct {
	Server     string     `yaml:"server,omitempty"`
	Auth       string     `yaml:"auth,omitempty"`
	TLS        ClientTLS  `yaml:"tls,omitempty"`
	Obfs       Obfs       `yaml:"obfs,omitempty"`
	Transport  Transport  `yaml:"transport,omitempty"`
	QUIC       ClientQUIC `yaml:"quic,omitempty"`
	Congestion Congestion `yaml:"congestion,omitempty"`
	Bandwidth  Bandwidth  `yaml:"bandwidth,omitempty"`
	FastOpen   bool       `yaml:"fastOpen,omitempty"`
	Lazy       bool       `yaml:"lazy,omitempty"`
	Mimic      Mimic      `yaml:"mimic,omitempty"`
	Realm      Realm      `yaml:"realm,omitempty"`
	SOCKS5     *SOCKS5    `yaml:"socks5,omitempty"`
	HTTP       *HTTPProxy `yaml:"http,omitempty"`
	Unknown    Unknown    `yaml:"-"`
}

// ParseClient reads a client config.
func ParseClient(b []byte) (*Client, error) {
	var c Client
	if err := parseDoc(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Marshal writes the config as YAML.
func (c *Client) Marshal() ([]byte, error) { return marshalDoc(c) }

// ClientTLS is how the client checks the server certificate.
type ClientTLS struct {
	SNI               string  `yaml:"sni,omitempty"`
	Insecure          bool    `yaml:"insecure,omitempty"`
	PinSHA256         string  `yaml:"pinSHA256,omitempty"`
	CA                string  `yaml:"ca,omitempty"`
	ClientCertificate string  `yaml:"clientCertificate,omitempty"`
	ClientKey         string  `yaml:"clientKey,omitempty"`
	ECH               string  `yaml:"ech,omitempty"`
	Unknown           Unknown `yaml:"-"`
}

// Transport is the client transport; port hopping lives here.
type Transport struct {
	Type    string       `yaml:"type,omitempty"` // udp
	UDP     TransportUDP `yaml:"udp,omitempty"`
	Unknown Unknown      `yaml:"-"`
}

// TransportUDP is the hop interval for port hopping.
type TransportUDP struct {
	HopInterval    Duration `yaml:"hopInterval,omitempty"`
	MinHopInterval Duration `yaml:"minHopInterval,omitempty"`
	MaxHopInterval Duration `yaml:"maxHopInterval,omitempty"`
	Unknown        Unknown  `yaml:"-"`
}

// ClientQUIC is the client's QUIC tuning.
type ClientQUIC struct {
	InitStreamReceiveWindow uint64   `yaml:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64   `yaml:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64   `yaml:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64   `yaml:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          Duration `yaml:"maxIdleTimeout,omitempty"`
	KeepAlivePeriod         Duration `yaml:"keepAlivePeriod,omitempty"`
	DisablePathMTUDiscovery bool     `yaml:"disablePathMTUDiscovery,omitempty"`
	DisableChromeParrot     bool     `yaml:"disableChromeParrot,omitempty"`
	Sockopts                Sockopts `yaml:"sockopts,omitempty"`
	Unknown                 Unknown  `yaml:"-"`
}

// Sockopts are socket options (Linux, Android).
type Sockopts struct {
	BindInterface       string  `yaml:"bindInterface,omitempty"`
	FirewallMark        uint32  `yaml:"fwmark,omitempty"`
	FdControlUnixSocket string  `yaml:"fdControlUnixSocket,omitempty"`
	Unknown             Unknown `yaml:"-"`
}

// SOCKS5 is the client's SOCKS5 inbound.
type SOCKS5 struct {
	Listen     string  `yaml:"listen,omitempty"`
	Username   string  `yaml:"username,omitempty"`
	Password   string  `yaml:"password,omitempty"`
	DisableUDP bool    `yaml:"disableUDP,omitempty"`
	Unknown    Unknown `yaml:"-"`
}

// HTTPProxy is the client's HTTP proxy inbound.
type HTTPProxy struct {
	Listen   string  `yaml:"listen,omitempty"`
	Username string  `yaml:"username,omitempty"`
	Password string  `yaml:"password,omitempty"`
	Realm    string  `yaml:"realm,omitempty"`
	Unknown  Unknown `yaml:"-"`
}
