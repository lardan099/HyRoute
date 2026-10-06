//go:build windows

// Package sysdns reads the DNS servers Windows uses: the packet engine
// recognizes the DNS client's encrypted queries to them, and the kill
// switch lets those queries through.
package sysdns

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Servers lists the DNS servers of the adapters that are up.
func Servers() (map[netip.Addr]bool, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		out := map[netip.Addr]bool{}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
					out[ip.Unmap()] = true
				}
			}
		}
		return out, nil
	}
}

// dns

// Snapshot reads the adapters (their DNS servers, which have a default
// gateway, their DNS suffixes) and the local namespaces of the registry
// (search list, primary domain, NRPT); single-label adapter suffixes are
// dropped (LocalSuffixes). A registry read failure only drops
// those names; the error is for the caller's log.
func Snapshot() (Info, error) {
	info, suffixes, err := adapters()
	if err != nil {
		return Info{}, err
	}
	names, rerr := localNames()
	info.Suffixes = LocalSuffixes(suffixes, names)
	return info, rerr
}

// adapters walks the up adapters: All = their DNS servers, Primary = the
// DNS servers of those with a default gateway, and their DNS suffixes.
func adapters() (Info, []string, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return Info{}, nil, err
		}
		info := Info{Primary: map[netip.Addr]bool{}, All: map[netip.Addr]bool{}}
		var suffixes []string
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			gateway := a.FirstGatewayAddress != nil
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
					ip = ip.Unmap()
					info.All[ip] = true
					if gateway {
						info.Primary[ip] = true
					}
				}
			}
			if a.DnsSuffix != nil {
				suffixes = append(suffixes, windows.UTF16PtrToString(a.DnsSuffix))
			}
			for s := a.FirstDnsSuffix; s != nil; s = s.Next {
				suffixes = append(suffixes, windows.UTF16ToString(s.String[:]))
			}
		}
		return info, suffixes, nil
	}
}

// NRPT rule keys: group policy, then local policy.
var nrptKeys = []string{
	`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`,
	`SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`,
}

// localNames reads the search list, the primary domain and the NRPT
// namespaces from the registry, read-only.
func localNames() ([]string, error) {
	var out []string
	var first error
	note := func(err error) {
		if err != nil && first == nil && err != registry.ErrNotExist {
			first = err
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err == nil {
		for _, v := range []string{"SearchList", "Domain", "NV Domain"} {
			s, _, err := k.GetStringValue(v)
			if err == nil {
				out = append(out, strings.Split(s, ",")...)
			} else if err != registry.ErrNotExist {
				note(err)
			}
		}
		k.Close()
	} else {
		note(err)
	}
	for _, path := range nrptKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			note(err)
			continue
		}
		rules, err := k.ReadSubKeyNames(256)
		k.Close()
		if !errors.Is(err, io.EOF) { // io.EOF: fewer than 256, all read
			note(err)
		}
		for _, r := range rules {
			rk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+r, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			names, _, err := rk.GetStringsValue("Name")
			rk.Close()
			if err == nil {
				// ".corp.example" is a namespace, "host.corp.example" one
				// name; "." (every name) is dropped by ParseNames.
				out = append(out, names...)
			}
		}
	}
	return out, first
}

// FlushCache empties the Windows DNS client cache (what ipconfig /flushdns
// does).
func FlushCache() error {
	r, _, err := procFlush.Call()
	if r == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			return errFlush
		}
		return err
	}
	return nil
}

var (
	procFlush = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
	errFlush  = errors.New("DnsFlushResolverCache failed")
)
