//go:build windows

package store

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// seal encrypts with DPAPI for the current user: another account or
// machine cannot decrypt profiles.json.
func seal(b []byte) ([]byte, error) {
	return dpapi(b, true)
}

func unseal(b []byte) ([]byte, error) {
	return dpapi(b, false)
}

var entropy = []byte("HyRoute profile secrets v1")

func dpapi(b []byte, protect bool) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(b))}
	if len(b) > 0 {
		in.Data = &b[0]
	}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	const uiForbidden = 0x1 // CRYPTPROTECT_UI_FORBIDDEN
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, &ent, 0, nil, uiForbidden, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &ent, 0, nil, uiForbidden, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
