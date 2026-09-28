package sysdns

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/rules"
)

// Info is a snapshot of the machine's DNS setup (dns): which addresses
// are DNS servers of the adapters that are up, and the namespaces that
// belong to the local network.
type Info struct {
	// Primary: DNS servers of up adapters with a default gateway.
	Primary map[netip.Addr]bool
	// All: every up adapter's DNS servers.
	All map[netip.Addr]bool
	// Suffixes are local namespaces: the adapters' DNS suffixes and
	// search lists, and the NRPT namespaces; normalized, deduplicated.
	Suffixes []string
}

// Local reports whether name equals or is under a local namespace. A nil
// Info has none.
func (i *Info) Local(name string) bool {
	if i == nil || len(i.Suffixes) == 0 {
		return false
	}
	name = rules.NormalizeDomain(name)
	if name == "" {
		return false
	}
	for _, s := range i.Suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// LocalSuffixes combines the adapters' DNS suffixes and search lists with
// the registry's names (search list, primary domain, NRPT) into
// Info.Suffixes. A network sets the adapters' names through DHCP (options
// 15 and 119), so a public suffix among them ("com", "ru", "co.uk",
// "com.ru", "github.io"; rules.Registrable refuses them) is not trusted: it
// would make a whole namespace local, and its names would bypass every DNS
// policy. The single-label names a home network really uses (lan, home,
// local, …) are local names of dnspolicy anyway. The registry's names only
// an administrator sets, and they are kept. Residual: a network can still
// name a registrable domain (say "example.com"), and its names then go to
// the network's server like any local name.
func LocalSuffixes(adapter, registry []string) []string {
	var trusted []string
	for _, a := range adapter {
		if _, ok := rules.Registrable(strings.Trim(strings.TrimSpace(a), ". ")); ok {
			trusted = append(trusted, a)
		}
	}
	return ParseNames(append(trusted, registry...))
}

// maxNames bounds the local namespaces kept.
const maxNames = 256

// ParseNames normalizes local namespaces as Windows lists them: leading
// and trailing dots and spaces trimmed, lower case, IDN as punycode.
// Invalid and empty entries are dropped, and so is "." (an NRPT rule for
// every name, which would make every name local). The result is
// deduplicated and has at most 256 entries.
func ParseNames(raw []string) []string {
	var out []string
	for _, r := range raw {
		n := strings.Trim(strings.TrimSpace(r), ". ")
		if n == "" {
			continue
		}
		n = rules.NormalizeDomain(n)
		if !validName(n) || slices.Contains(out, n) {
			continue
		}
		out = append(out, n)
		if len(out) == maxNames {
			break
		}
	}
	return out
}

func validName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
