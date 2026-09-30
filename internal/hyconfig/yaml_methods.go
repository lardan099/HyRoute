package hyconfig

import "gopkg.in/yaml.v3"

// One pattern for every model type (keep the list in step with server.go
// and client.go): decode the known keys through a method-less twin type,
// keep the rest in Unknown, and write them back after the known ones.

func (x *Server) UnmarshalYAML(n *yaml.Node) error {
	type p Server
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Server) MarshalYAML() (any, error) {
	type p Server
	return encodeKnown(p(x), x.Unknown)
}

func (x *TLS) UnmarshalYAML(n *yaml.Node) error {
	type p TLS
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x TLS) MarshalYAML() (any, error) {
	type p TLS
	return encodeKnown(p(x), x.Unknown)
}

func (x *ACME) UnmarshalYAML(n *yaml.Node) error {
	type p ACME
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ACME) MarshalYAML() (any, error) {
	type p ACME
	return encodeKnown(p(x), x.Unknown)
}

func (x *ACMEAlt) UnmarshalYAML(n *yaml.Node) error {
	type p ACMEAlt
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ACMEAlt) MarshalYAML() (any, error) {
	type p ACMEAlt
	return encodeKnown(p(x), x.Unknown)
}

func (x *ACMEDNS) UnmarshalYAML(n *yaml.Node) error {
	type p ACMEDNS
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ACMEDNS) MarshalYAML() (any, error) {
	type p ACMEDNS
	return encodeKnown(p(x), x.Unknown)
}

func (x *ECH) UnmarshalYAML(n *yaml.Node) error {
	type p ECH
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ECH) MarshalYAML() (any, error) {
	type p ECH
	return encodeKnown(p(x), x.Unknown)
}

func (x *Auth) UnmarshalYAML(n *yaml.Node) error {
	type p Auth
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Auth) MarshalYAML() (any, error) {
	type p Auth
	return encodeKnown(p(x), x.Unknown)
}

func (x *AuthHTTP) UnmarshalYAML(n *yaml.Node) error {
	type p AuthHTTP
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x AuthHTTP) MarshalYAML() (any, error) {
	type p AuthHTTP
	return encodeKnown(p(x), x.Unknown)
}

func (x *Obfs) UnmarshalYAML(n *yaml.Node) error {
	type p Obfs
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Obfs) MarshalYAML() (any, error) {
	type p Obfs
	return encodeKnown(p(x), x.Unknown)
}

func (x *Salamander) UnmarshalYAML(n *yaml.Node) error {
	type p Salamander
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Salamander) MarshalYAML() (any, error) {
	type p Salamander
	return encodeKnown(p(x), x.Unknown)
}

func (x *Gecko) UnmarshalYAML(n *yaml.Node) error {
	type p Gecko
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Gecko) MarshalYAML() (any, error) {
	type p Gecko
	return encodeKnown(p(x), x.Unknown)
}

func (x *Masquerade) UnmarshalYAML(n *yaml.Node) error {
	type p Masquerade
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Masquerade) MarshalYAML() (any, error) {
	type p Masquerade
	return encodeKnown(p(x), x.Unknown)
}

func (x *MasqueradeFile) UnmarshalYAML(n *yaml.Node) error {
	type p MasqueradeFile
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x MasqueradeFile) MarshalYAML() (any, error) {
	type p MasqueradeFile
	return encodeKnown(p(x), x.Unknown)
}

func (x *MasqueradeProxy) UnmarshalYAML(n *yaml.Node) error {
	type p MasqueradeProxy
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x MasqueradeProxy) MarshalYAML() (any, error) {
	type p MasqueradeProxy
	return encodeKnown(p(x), x.Unknown)
}

func (x *MasqueradeString) UnmarshalYAML(n *yaml.Node) error {
	type p MasqueradeString
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x MasqueradeString) MarshalYAML() (any, error) {
	type p MasqueradeString
	return encodeKnown(p(x), x.Unknown)
}

func (x *Bandwidth) UnmarshalYAML(n *yaml.Node) error {
	type p Bandwidth
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Bandwidth) MarshalYAML() (any, error) {
	type p Bandwidth
	return encodeKnown(p(x), x.Unknown)
}

func (x *Congestion) UnmarshalYAML(n *yaml.Node) error {
	type p Congestion
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Congestion) MarshalYAML() (any, error) {
	type p Congestion
	return encodeKnown(p(x), x.Unknown)
}

func (x *ServerQUIC) UnmarshalYAML(n *yaml.Node) error {
	type p ServerQUIC
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ServerQUIC) MarshalYAML() (any, error) {
	type p ServerQUIC
	return encodeKnown(p(x), x.Unknown)
}

func (x *Resolver) UnmarshalYAML(n *yaml.Node) error {
	type p Resolver
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Resolver) MarshalYAML() (any, error) {
	type p Resolver
	return encodeKnown(p(x), x.Unknown)
}

func (x *ResolverPlain) UnmarshalYAML(n *yaml.Node) error {
	type p ResolverPlain
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ResolverPlain) MarshalYAML() (any, error) {
	type p ResolverPlain
	return encodeKnown(p(x), x.Unknown)
}

func (x *ResolverTLS) UnmarshalYAML(n *yaml.Node) error {
	type p ResolverTLS
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ResolverTLS) MarshalYAML() (any, error) {
	type p ResolverTLS
	return encodeKnown(p(x), x.Unknown)
}

func (x *Sniff) UnmarshalYAML(n *yaml.Node) error {
	type p Sniff
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Sniff) MarshalYAML() (any, error) {
	type p Sniff
	return encodeKnown(p(x), x.Unknown)
}

func (x *ACL) UnmarshalYAML(n *yaml.Node) error {
	type p ACL
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ACL) MarshalYAML() (any, error) {
	type p ACL
	return encodeKnown(p(x), x.Unknown)
}

func (x *Outbound) UnmarshalYAML(n *yaml.Node) error {
	type p Outbound
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Outbound) MarshalYAML() (any, error) {
	type p Outbound
	return encodeKnown(p(x), x.Unknown)
}

func (x *OutboundDirect) UnmarshalYAML(n *yaml.Node) error {
	type p OutboundDirect
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x OutboundDirect) MarshalYAML() (any, error) {
	type p OutboundDirect
	return encodeKnown(p(x), x.Unknown)
}

func (x *OutboundSOCKS5) UnmarshalYAML(n *yaml.Node) error {
	type p OutboundSOCKS5
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x OutboundSOCKS5) MarshalYAML() (any, error) {
	type p OutboundSOCKS5
	return encodeKnown(p(x), x.Unknown)
}

func (x *OutboundHTTP) UnmarshalYAML(n *yaml.Node) error {
	type p OutboundHTTP
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x OutboundHTTP) MarshalYAML() (any, error) {
	type p OutboundHTTP
	return encodeKnown(p(x), x.Unknown)
}

func (x *TrafficStats) UnmarshalYAML(n *yaml.Node) error {
	type p TrafficStats
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x TrafficStats) MarshalYAML() (any, error) {
	type p TrafficStats
	return encodeKnown(p(x), x.Unknown)
}

func (x *Mimic) UnmarshalYAML(n *yaml.Node) error {
	type p Mimic
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Mimic) MarshalYAML() (any, error) {
	type p Mimic
	return encodeKnown(p(x), x.Unknown)
}

func (x *Realm) UnmarshalYAML(n *yaml.Node) error {
	type p Realm
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Realm) MarshalYAML() (any, error) {
	type p Realm
	return encodeKnown(p(x), x.Unknown)
}

func (x *PortMapping) UnmarshalYAML(n *yaml.Node) error {
	type p PortMapping
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x PortMapping) MarshalYAML() (any, error) {
	type p PortMapping
	return encodeKnown(p(x), x.Unknown)
}

func (x *Client) UnmarshalYAML(n *yaml.Node) error {
	type p Client
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Client) MarshalYAML() (any, error) {
	type p Client
	return encodeKnown(p(x), x.Unknown)
}

func (x *ClientTLS) UnmarshalYAML(n *yaml.Node) error {
	type p ClientTLS
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ClientTLS) MarshalYAML() (any, error) {
	type p ClientTLS
	return encodeKnown(p(x), x.Unknown)
}

func (x *Transport) UnmarshalYAML(n *yaml.Node) error {
	type p Transport
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Transport) MarshalYAML() (any, error) {
	type p Transport
	return encodeKnown(p(x), x.Unknown)
}

func (x *TransportUDP) UnmarshalYAML(n *yaml.Node) error {
	type p TransportUDP
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x TransportUDP) MarshalYAML() (any, error) {
	type p TransportUDP
	return encodeKnown(p(x), x.Unknown)
}

func (x *ClientQUIC) UnmarshalYAML(n *yaml.Node) error {
	type p ClientQUIC
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x ClientQUIC) MarshalYAML() (any, error) {
	type p ClientQUIC
	return encodeKnown(p(x), x.Unknown)
}

func (x *Sockopts) UnmarshalYAML(n *yaml.Node) error {
	type p Sockopts
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x Sockopts) MarshalYAML() (any, error) {
	type p Sockopts
	return encodeKnown(p(x), x.Unknown)
}

func (x *SOCKS5) UnmarshalYAML(n *yaml.Node) error {
	type p SOCKS5
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x SOCKS5) MarshalYAML() (any, error) {
	type p SOCKS5
	return encodeKnown(p(x), x.Unknown)
}

func (x *HTTPProxy) UnmarshalYAML(n *yaml.Node) error {
	type p HTTPProxy
	return decodeKnown(n, (*p)(x), &x.Unknown)
}

func (x HTTPProxy) MarshalYAML() (any, error) {
	type p HTTPProxy
	return encodeKnown(p(x), x.Unknown)
}
