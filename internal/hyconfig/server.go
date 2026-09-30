package hyconfig

// Server is the Hysteria server config. Field order is the order the
// config is written in.
type Server struct {
	Listen                string       `yaml:"listen,omitempty"`
	TLS                   *TLS         `yaml:"tls,omitempty"`
	ACME                  *ACME        `yaml:"acme,omitempty"`
	ECH                   ECH          `yaml:"ech,omitempty"`
	Auth                  Auth         `yaml:"auth,omitempty"`
	Obfs                  Obfs         `yaml:"obfs,omitempty"`
	Masquerade            Masquerade   `yaml:"masquerade,omitempty"`
	Bandwidth             Bandwidth    `yaml:"bandwidth,omitempty"`
	IgnoreClientBandwidth bool         `yaml:"ignoreClientBandwidth,omitempty"`
	Congestion            Congestion   `yaml:"congestion,omitempty"`
	QUIC                  ServerQUIC   `yaml:"quic,omitempty"`
	SpeedTest             bool         `yaml:"speedTest,omitempty"`
	DisableUDP            bool         `yaml:"disableUDP,omitempty"`
	UDPIdleTimeout        Duration     `yaml:"udpIdleTimeout,omitempty"`
	Resolver              Resolver     `yaml:"resolver,omitempty"`
	Sniff                 Sniff        `yaml:"sniff,omitempty"`
	ACL                   ACL          `yaml:"acl,omitempty"`
	Outbounds             []Outbound   `yaml:"outbounds,omitempty"`
	TrafficStats          TrafficStats `yaml:"trafficStats,omitempty"`
	Mimic                 Mimic        `yaml:"mimic,omitempty"`
	Realm                 Realm        `yaml:"realm,omitempty"`
	Unknown               Unknown      `yaml:"-"`
}

// ParseServer reads a server config.
func ParseServer(b []byte) (*Server, error) {
	var s Server
	if err := parseDoc(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Marshal writes the config as YAML.
func (s *Server) Marshal() ([]byte, error) { return marshalDoc(s) }

// TLS is a certificate and key from files.
type TLS struct {
	Cert     string  `yaml:"cert,omitempty"`
	Key      string  `yaml:"key,omitempty"`
	SNIGuard string  `yaml:"sniGuard,omitempty"` // dns-san (default), strict, disable
	ClientCA string  `yaml:"clientCA,omitempty"`
	Unknown  Unknown `yaml:"-"`
}

// ACME obtains the certificate automatically.
type ACME struct {
	Domains    []string `yaml:"domains,omitempty"`
	Email      string   `yaml:"email,omitempty"`
	CA         string   `yaml:"ca,omitempty"` // letsencrypt (default), zerossl
	ListenHost string   `yaml:"listenHost,omitempty"`
	Dir        string   `yaml:"dir,omitempty"`
	Type       string   `yaml:"type,omitempty"` // http, tls, dns
	HTTP       ACMEAlt  `yaml:"http,omitempty"`
	TLS        ACMEAlt  `yaml:"tls,omitempty"`
	DNS        ACMEDNS  `yaml:"dns,omitempty"`
	// Before acme.type existed.
	DisableHTTP    bool    `yaml:"disableHTTP,omitempty"`
	DisableTLSALPN bool    `yaml:"disableTLSALPN,omitempty"`
	AltHTTPPort    int     `yaml:"altHTTPPort,omitempty"`
	AltTLSALPNPort int     `yaml:"altTLSALPNPort,omitempty"`
	Unknown        Unknown `yaml:"-"`
}

// ACMEAlt is the listening port of an ACME challenge.
type ACMEAlt struct {
	AltPort int     `yaml:"altPort,omitempty"`
	Unknown Unknown `yaml:"-"`
}

// ACMEDNS is the DNS challenge provider.
type ACMEDNS struct {
	Name    string            `yaml:"name,omitempty"`
	Config  map[string]string `yaml:"config,omitempty"`
	Unknown Unknown           `yaml:"-"`
}

// ECH is the Encrypted Client Hello key.
type ECH struct {
	KeyPath string  `yaml:"keyPath,omitempty"`
	Unknown Unknown `yaml:"-"`
}

// Auth is how clients authenticate.
type Auth struct {
	Type     string            `yaml:"type,omitempty"` // password, userpass, http, command
	Password string            `yaml:"password,omitempty"`
	UserPass map[string]string `yaml:"userpass,omitempty"`
	HTTP     AuthHTTP          `yaml:"http,omitempty"`
	Command  string            `yaml:"command,omitempty"`
	Unknown  Unknown           `yaml:"-"`
}

// AuthHTTP is an authentication backend.
type AuthHTTP struct {
	URL      string  `yaml:"url,omitempty"`
	Insecure bool    `yaml:"insecure,omitempty"`
	Unknown  Unknown `yaml:"-"`
}

// Obfs is packet obfuscation; the same on server and client.
type Obfs struct {
	Type       string     `yaml:"type,omitempty"` // salamander, gecko
	Salamander Salamander `yaml:"salamander,omitempty"`
	Gecko      Gecko      `yaml:"gecko,omitempty"`
	Unknown    Unknown    `yaml:"-"`
}

// Salamander obfuscation.
type Salamander struct {
	Password string  `yaml:"password,omitempty"`
	Unknown  Unknown `yaml:"-"`
}

// Gecko obfuscation (Salamander plus handshake fragmentation).
type Gecko struct {
	Password      string  `yaml:"password,omitempty"`
	MinPacketSize int     `yaml:"minPacketSize,omitempty"`
	MaxPacketSize int     `yaml:"maxPacketSize,omitempty"`
	Unknown       Unknown `yaml:"-"`
}

// Masquerade is what the server shows to plain HTTP/3 visitors.
type Masquerade struct {
	Type        string           `yaml:"type,omitempty"` // file, proxy, string
	File        MasqueradeFile   `yaml:"file,omitempty"`
	Proxy       MasqueradeProxy  `yaml:"proxy,omitempty"`
	String      MasqueradeString `yaml:"string,omitempty"`
	ListenHTTP  string           `yaml:"listenHTTP,omitempty"`
	ListenHTTPS string           `yaml:"listenHTTPS,omitempty"`
	ForceHTTPS  bool             `yaml:"forceHTTPS,omitempty"`
	Unknown     Unknown          `yaml:"-"`
}

// MasqueradeFile serves a directory.
type MasqueradeFile struct {
	Dir     string  `yaml:"dir,omitempty"`
	Unknown Unknown `yaml:"-"`
}

// MasqueradeProxy is a reverse proxy to another site.
type MasqueradeProxy struct {
	URL         string  `yaml:"url,omitempty"`
	RewriteHost bool    `yaml:"rewriteHost,omitempty"`
	XForwarded  bool    `yaml:"xForwarded,omitempty"`
	Insecure    bool    `yaml:"insecure,omitempty"`
	Unknown     Unknown `yaml:"-"`
}

// MasqueradeString answers with a fixed body.
type MasqueradeString struct {
	Content    string            `yaml:"content,omitempty"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	StatusCode int               `yaml:"statusCode,omitempty"`
	Unknown    Unknown           `yaml:"-"`
}

// Bandwidth is a speed limit ("100 mbps"); the same on server and client.
type Bandwidth struct {
	Up                      string  `yaml:"up,omitempty"`
	Down                    string  `yaml:"down,omitempty"`
	DisableLossCompensation bool    `yaml:"disableLossCompensation,omitempty"`
	Unknown                 Unknown `yaml:"-"`
}

// Congestion is the non-Brutal congestion controller.
type Congestion struct {
	Type       string  `yaml:"type,omitempty"`       // bbr (default), reno
	BBRProfile string  `yaml:"bbrProfile,omitempty"` // standard, conservative, aggressive
	Unknown    Unknown `yaml:"-"`
}

// ServerQUIC is the server's QUIC tuning.
type ServerQUIC struct {
	InitStreamReceiveWindow uint64   `yaml:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64   `yaml:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64   `yaml:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64   `yaml:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          Duration `yaml:"maxIdleTimeout,omitempty"`
	MaxIncomingStreams      int64    `yaml:"maxIncomingStreams,omitempty"`
	DisablePathMTUDiscovery bool     `yaml:"disablePathMTUDiscovery,omitempty"`
	DisableStatelessReset   bool     `yaml:"disableStatelessReset,omitempty"`
	Unknown                 Unknown  `yaml:"-"`
}

// Resolver is the DNS server for client requests.
type Resolver struct {
	Type    string        `yaml:"type,omitempty"` // system (default), udp, tcp, tls, https
	TCP     ResolverPlain `yaml:"tcp,omitempty"`
	UDP     ResolverPlain `yaml:"udp,omitempty"`
	TLS     ResolverTLS   `yaml:"tls,omitempty"`
	HTTPS   ResolverTLS   `yaml:"https,omitempty"`
	Unknown Unknown       `yaml:"-"`
}

// ResolverPlain is a plain DNS server.
type ResolverPlain struct {
	Addr    string   `yaml:"addr,omitempty"`
	Timeout Duration `yaml:"timeout,omitempty"`
	Unknown Unknown  `yaml:"-"`
}

// ResolverTLS is a DNS-over-TLS or DNS-over-HTTPS server.
type ResolverTLS struct {
	Addr     string   `yaml:"addr,omitempty"`
	Timeout  Duration `yaml:"timeout,omitempty"`
	SNI      string   `yaml:"sni,omitempty"`
	Insecure bool     `yaml:"insecure,omitempty"`
	Unknown  Unknown  `yaml:"-"`
}

// Sniff is protocol sniffing of client requests.
type Sniff struct {
	Enable        bool     `yaml:"enable,omitempty"`
	Timeout       Duration `yaml:"timeout,omitempty"`
	RewriteDomain bool     `yaml:"rewriteDomain,omitempty"`
	TCPPorts      string   `yaml:"tcpPorts,omitempty"`
	UDPPorts      string   `yaml:"udpPorts,omitempty"`
	Unknown       Unknown  `yaml:"-"`
}

// ACL is the server's routing rules.
type ACL struct {
	File              string   `yaml:"file,omitempty"`
	Inline            []string `yaml:"inline,omitempty"`
	GeoIP             string   `yaml:"geoip,omitempty"`
	GeoSite           string   `yaml:"geosite,omitempty"`
	GeoUpdateInterval Duration `yaml:"geoUpdateInterval,omitempty"`
	Unknown           Unknown  `yaml:"-"`
}

// Outbound is an exit for client connections.
type Outbound struct {
	Name    string         `yaml:"name,omitempty"`
	Type    string         `yaml:"type,omitempty"` // direct, socks5, http
	Direct  OutboundDirect `yaml:"direct,omitempty"`
	SOCKS5  OutboundSOCKS5 `yaml:"socks5,omitempty"`
	HTTP    OutboundHTTP   `yaml:"http,omitempty"`
	Unknown Unknown        `yaml:"-"`
}

// OutboundDirect is the local interface.
type OutboundDirect struct {
	Mode       string  `yaml:"mode,omitempty"` // auto, 64, 46, 6, 4
	BindIPv4   string  `yaml:"bindIPv4,omitempty"`
	BindIPv6   string  `yaml:"bindIPv6,omitempty"`
	BindDevice string  `yaml:"bindDevice,omitempty"`
	FastOpen   bool    `yaml:"fastOpen,omitempty"`
	Unknown    Unknown `yaml:"-"`
}

// OutboundSOCKS5 is a SOCKS5 proxy.
type OutboundSOCKS5 struct {
	Addr     string  `yaml:"addr,omitempty"`
	Username string  `yaml:"username,omitempty"`
	Password string  `yaml:"password,omitempty"`
	Unknown  Unknown `yaml:"-"`
}

// OutboundHTTP is an HTTP or HTTPS proxy.
type OutboundHTTP struct {
	URL      string  `yaml:"url,omitempty"`
	Insecure bool    `yaml:"insecure,omitempty"`
	Unknown  Unknown `yaml:"-"`
}

// TrafficStats is the HTTP statistics API.
type TrafficStats struct {
	Listen  string  `yaml:"listen,omitempty"`
	Secret  string  `yaml:"secret,omitempty"`
	Unknown Unknown `yaml:"-"`
}

// Mimic disguises the connection as TCP (Linux); must match on both ends.
type Mimic struct {
	Enabled   bool     `yaml:"enabled,omitempty"`
	Interface string   `yaml:"interface,omitempty"`
	XDPMode   string   `yaml:"xdpMode,omitempty"` // native, skb
	Path      string   `yaml:"path,omitempty"`
	ExtraArgs []string `yaml:"extraArgs,omitempty"`
	Unknown   Unknown  `yaml:"-"`
}

// Realm tunes the P2P mode (listen: realm://…).
type Realm struct {
	STUNServers       []string    `yaml:"stunServers,omitempty"`
	STUNTimeout       Duration    `yaml:"stunTimeout,omitempty"`
	PunchTimeout      Duration    `yaml:"punchTimeout,omitempty"`
	HeartbeatInterval Duration    `yaml:"heartbeatInterval,omitempty"` // server only
	Insecure          bool        `yaml:"insecure,omitempty"`
	IPMode            string      `yaml:"ipMode,omitempty"` // dual, v4, v6
	PortMapping       PortMapping `yaml:"portMapping,omitempty"`
	Unknown           Unknown     `yaml:"-"`
}

// PortMapping is UPnP/NAT-PMP on the gateway.
type PortMapping struct {
	Enabled  bool     `yaml:"enabled,omitempty"`
	Timeout  Duration `yaml:"timeout,omitempty"`
	Lifetime Duration `yaml:"lifetime,omitempty"`
	Unknown  Unknown  `yaml:"-"`
}
