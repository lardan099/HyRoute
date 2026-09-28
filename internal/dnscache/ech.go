package dnscache

import (
	"encoding/binary"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/rules"
)

// knownPublicNames are ECH public names in use whether or not their HTTPS
// records pass by: Cloudflare's, by far the largest ECH deployment (a
// browser on DoH never shows its HTTPS queries).
var knownPublicNames = map[string]bool{"cloudflare-ech.com": true}

// maxPublicNames bounds the public names learned from HTTPS/SVCB answers.
const maxPublicNames = 4096

// maxPublicTTL bounds how long a learned public name is kept, well below
// MaxTTL: any zone may name any site as its public name, and while it is
// kept, GREASE hellos to that site are no longer taken at their word.
const maxPublicTTL = time.Hour

// PublicName reports whether name is known as the public (outer) name of
// real ECH: a known provider's, or one learned from the ECH configs of
// HTTPS/SVCB answers. Any other outer SNI of a hello with
// encrypted_client_hello is the site itself: browsers send GREASE ECH to
// every site without an ECH config.
func (c *Cache) PublicName(name string) bool {
	name = rules.NormalizeDomain(name)
	if name == "" {
		return false
	}
	if knownPublicNames[name] {
		return true
	}
	now := c.now()
	c.mu.RLock()
	exp, ok := c.public[name]
	c.mu.RUnlock()
	return ok && now.Before(exp)
}

// KnownPublicName reports whether name is on the built-in list of ECH
// public names (knownPublicNames), without the names a cache learned:
// what HyRoute knows without a running session (conn-rules).
func KnownPublicName(name string) bool {
	return knownPublicNames[rules.NormalizeDomain(name)]
}

// addPublicLocked remembers a public name learned from an answer.
func (c *Cache) addPublicLocked(name string, exp time.Time) {
	if name == "" || knownPublicNames[name] {
		return
	}
	if c.public == nil {
		c.public = make(map[string]time.Time)
	}
	old, ok := c.public[name]
	if !ok && len(c.public) >= maxPublicNames {
		for n := range c.public {
			delete(c.public, n)
			break
		}
	}
	if exp.After(old) {
		c.public[name] = exp
	}
}

// echPublicNames returns the public names of the ECH configs in the "ech"
// parameter of an HTTPS or SVCB record.
func echPublicNames(r *dnsmessage.SVCBResource) []string {
	v, ok := r.GetParam(dnsmessage.SVCParamECH)
	if !ok || len(v) < 2 || int(binary.BigEndian.Uint16(v)) != len(v)-2 {
		return nil
	}
	var out []string
	// ECHConfigList: ECHConfig{version, length, contents}...
	for b := v[2:]; len(b) >= 4 && len(out) < 8; {
		version, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+n {
			break
		}
		if version == 0xfe0d {
			if name := configPublicName(b[4 : 4+n]); name != "" {
				out = append(out, name)
			}
		}
		b = b[4+n:]
	}
	return out
}

// configPublicName returns the public_name of ECHConfigContents
// (draft-ietf-tls-esni, version 0xfe0d): key_config {config_id, kem_id,
// public_key<2>, cipher_suites<2>}, maximum_name_length, public_name<1>.
func configPublicName(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	b = b[3:]     // config_id, kem_id
	for range 2 { // public_key, cipher_suites
		if len(b) < 2 || len(b) < 2+int(binary.BigEndian.Uint16(b)) {
			return ""
		}
		b = b[2+int(binary.BigEndian.Uint16(b)):]
	}
	if len(b) < 2 || len(b) < 2+int(b[1]) {
		return ""
	}
	return rules.NormalizeDomain(string(b[2 : 2+int(b[1])]))
}
