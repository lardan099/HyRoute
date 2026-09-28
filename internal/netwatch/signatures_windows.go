//go:build windows

package netwatch

import (
	"io"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/lardan099/hyroute/internal/netmode"
)

// Windows writes a network's signature (with the gateway's MAC for an
// unmanaged network) exactly when it identifies the network. A network
// still «Идентификация…» and «Неопознанная сеть» have none, and the GUID NLM
// gives them may be shared by every unidentified connection: such an ID
// must never match «Именно эта сеть» nor settle a relaxing action.
const signaturesKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\`

// identified: Windows identified network id (a domain network, or a
// signature with ProfileGuid id). Read-only.
func identified(id, category string) (bool, error) {
	if id == "" {
		return false, nil
	}
	if category == netmode.Domain {
		return true, nil
	}
	var firstErr error
	for _, kind := range []string{"Unmanaged", "Managed"} {
		ok, err := hasSignature(signaturesKey+kind, id)
		if ok {
			return true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return false, firstErr
}

func hasSignature(path, id string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(4096) // io.EOF: fewer than that
	if err != nil && err != io.EOF && len(names) == 0 {
		return false, err
	}
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		v, typ, err := sk.GetStringValue("ProfileGuid")
		sk.Close()
		if err == nil && typ == registry.SZ && len(v) <= 64 && strings.EqualFold(strings.TrimSpace(v), id) {
			return true, nil
		}
	}
	return false, nil
}
