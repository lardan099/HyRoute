package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// HyRoute 1.2.0 wrote backups as .hyroute files (its internal/app/backup.go):
//
//	{format: "hyroute-backup", version: 1, kind: "full"|"rules", created, app,
//	 sealed: {kdf: "pbkdf2-sha256", iter, salt, nonce, box} | data: {...}}
//
// full is always sealed (PBKDF2-SHA256 → AES-256-GCM, AAD
// "format/version/kind"); rules is plain. Their payload
// ({settings, profiles, subscriptions, proxies, prefs}) is handed to the
// app raw (Payload.LegacyData), which maps it into sections. New files are
// never written in this format.

const (
	LegacyExt     = ".hyroute"
	legacyKDF     = "pbkdf2-sha256"
	legacyMaxSize = 32 << 20
)

type legacyFile struct {
	Format  string          `json:"format"`
	Version int             `json:"version"`
	Kind    string          `json:"kind"`
	Created time.Time       `json:"created"`
	App     string          `json:"app,omitempty"`
	Sealed  *legacySeal     `json:"sealed,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type legacySeal struct {
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Box   []byte `json:"box"`
}

func parseLegacy(b []byte) (*File, error) {
	if len(b) > legacyMaxSize {
		return nil, ErrTooLarge
	}
	var l legacyFile
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, ErrDamaged
	}
	if l.Version > 1 {
		return nil, &NewerError{l.Version}
	}
	switch {
	case l.Version < 1:
		return nil, ErrDamaged
	case l.Kind == "full" && l.Sealed != nil:
	case l.Kind == "rules" && (l.Data != nil || l.Sealed != nil):
	default:
		return nil, ErrDamaged
	}
	if s := l.Sealed; s != nil && (s.KDF != legacyKDF || s.Iter < 1000 || s.Iter > 10_000_000 || len(s.Salt) < 8 || len(s.Salt) > 64 || len(s.Nonce) != 12) {
		return nil, ErrDamaged
	}
	return &File{Format: l.Format, Version: l.Version, Encrypted: l.Sealed != nil, legacy: &l}, nil
}

func (l *legacyFile) open(password string) (*Payload, error) {
	data := []byte(l.Data)
	if s := l.Sealed; s != nil {
		kdfMu.Lock()
		if kdfHook != nil {
			kdfHook()
		}
		key, err := pbkdf2.Key(sha256.New, password, s.Salt, s.Iter, 32)
		kdfMu.Unlock()
		if err != nil {
			return nil, ErrDamaged
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrDamaged
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrDamaged
		}
		data, err = gcm.Open(nil, s.Nonce, s.Box, fmt.Appendf(nil, "%s/%d/%s", l.Format, l.Version, l.Kind))
		if err != nil {
			return nil, ErrPassword
		}
	}
	if !json.Valid(data) {
		return nil, ErrDamaged
	}
	return &Payload{App: l.App, Created: l.Created, Secrets: l.Kind == "full", Sections: map[string]json.RawMessage{},
		Legacy: l.Kind, LegacyData: data}, nil
}
