package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// dns.json holds the DNS policies of «Настройки» → «DNS». It is written
// only when the user saves that card: a user who never did has no such
// file, and every option is off. A custom server's URL may carry an
// account ID: it is sealed like the subscription URLs.
const dnsFile = "dns.json"

// maxDNSFile bounds dns.json (a few custom URLs of at most 2 KB).
const maxDNSFile = 64 << 10

// storedDNS is dns.json on disk. Decoding is lenient: a newer HyRoute may
// add fields, an older one ignores them.
type storedDNS struct {
	BlockBrowserDoH bool           `json:"blockBrowserDoH,omitempty"`
	StripECH        bool           `json:"stripECH,omitempty"`
	ByRules         bool           `json:"byRules,omitempty"`
	IgnoreAddrRules bool           `json:"ignoreAddrRules,omitempty"`
	Tunnel          storedUpstream `json:"tunnel,omitzero"`
	Direct          storedUpstream `json:"direct,omitzero"`
}

type storedUpstream struct {
	Preset    string `json:"preset,omitempty"`
	SealedURL string `json:"sealedURL,omitempty"` // seal([]byte(url)), base64; only with preset "custom"
}

// LoadDNS reads dns.json. A missing file is every option off. Any other
// problem (bad JSON, a URL that does not unseal, e.g. a file from another
// Windows account, a setting that does not validate) is an error: the
// caller keeps every option off and never overwrites the file.
func (s *Store) LoadDNS() (dnspolicy.Config, error) {
	b, err := s.readRegular(dnsFile, maxDNSFile)
	if errors.Is(err, os.ErrNotExist) {
		return dnspolicy.Config{}, nil
	}
	if err != nil {
		return dnspolicy.Config{}, fmt.Errorf("dns.json: %w", err)
	}
	var st storedDNS
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &st); err != nil {
		return dnspolicy.Config{}, fmt.Errorf("dns.json: %w", err)
	}
	c := dnspolicy.Config{BlockBrowserDoH: st.BlockBrowserDoH, StripECH: st.StripECH, ByRules: st.ByRules, IgnoreAddrRules: st.IgnoreAddrRules}
	for _, u := range []struct {
		in  storedUpstream
		out *dnspolicy.Upstream
	}{{st.Tunnel, &c.Tunnel}, {st.Direct, &c.Direct}} {
		u.out.Preset = u.in.Preset
		if u.in.Preset != dnspolicy.Custom {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(u.in.SealedURL)
		if err == nil {
			raw, err = unseal(raw)
		}
		if err != nil {
			return dnspolicy.Config{}, fmt.Errorf("dns.json: адрес своего DNS-сервера не расшифровывается (файл другой учётной записи Windows?): %w", err)
		}
		u.out.URL = string(raw)
	}
	if err := c.Validate(); err != nil {
		return dnspolicy.Config{}, fmt.Errorf("dns.json: %w", err)
	}
	return c, nil
}

// SaveDNS validates c and writes dns.json (custom URLs sealed).
func (s *Store) SaveDNS(c dnspolicy.Config) error {
	c.Normalize()
	if err := c.Validate(); err != nil {
		return err
	}
	st := storedDNS{BlockBrowserDoH: c.BlockBrowserDoH, StripECH: c.StripECH, ByRules: c.ByRules, IgnoreAddrRules: c.IgnoreAddrRules}
	for _, u := range []struct {
		in  dnspolicy.Upstream
		out *storedUpstream
	}{{c.Tunnel, &st.Tunnel}, {c.Direct, &st.Direct}} {
		u.out.Preset = u.in.Preset
		if u.in.Preset != dnspolicy.Custom {
			continue
		}
		sealed, err := seal([]byte(u.in.URL))
		if err != nil {
			return fmt.Errorf("seal DNS server URL: %w", err)
		}
		u.out.SealedURL = base64.StdEncoding.EncodeToString(sealed)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path(dnsFile), b)
}
