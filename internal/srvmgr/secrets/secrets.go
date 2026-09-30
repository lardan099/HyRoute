// Package secrets encrypts credentials and configs at rest with envelope
// encryption: every value gets its own random data key (DEK), the value is
// sealed with the DEK (AES-256-GCM) and the DEK is sealed with a version of
// the master key (AES-256-GCM). The version travels in the sealed blob, so
// the master key can be rotated: old versions stay loaded to open old
// values, Rewrap moves a value to the current version.
//
// A context string (like "server/12/ssh_password") is bound to both layers
// as additional data: a sealed value moved to another row does not open.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// KeySize is the size of master and data keys.
const KeySize = 32

var magic = [4]byte{'H', 'R', 'S', '1'}

// header: magic, key version, DEK nonce, sealed DEK, data nonce.
const (
	nonceSize  = 12
	tagSize    = 16
	sealedDEK  = KeySize + tagSize
	headerSize = len(magic) + 4 + nonceSize + sealedDEK + nonceSize
)

var (
	// ErrWrongKey: the value does not open with this key and context
	// (another master key, another row, or tampering).
	ErrWrongKey = errors.New("secret does not decrypt: wrong master key or context")
	// ErrCorrupt: not a sealed value of this format.
	ErrCorrupt = errors.New("sealed secret is corrupt")
)

// UnknownVersionError: the value was sealed with a master key version the
// keyring does not have.
type UnknownVersionError struct{ Version uint32 }

func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("sealed with master key version %d, which is not loaded", e.Version)
}

// Keyring holds the master key versions; Current seals new values.
type Keyring struct {
	current uint32
	keys    map[uint32][]byte
}

// NewKeyring builds a keyring; the highest version is current.
func NewKeyring(keys map[uint32][]byte) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("no master key")
	}
	k := &Keyring{keys: map[uint32][]byte{}}
	for v, key := range keys {
		if v == 0 {
			return nil, errors.New("master key version 0 is reserved")
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("master key version %d: %d bytes, want %d", v, len(key), KeySize)
		}
		k.keys[v] = append([]byte(nil), key...)
		k.current = max(k.current, v)
	}
	return k, nil
}

// Current is the version new values are sealed with.
func (k *Keyring) Current() uint32 { return k.current }

// Versions lists the loaded versions, ascending.
func (k *Keyring) Versions() []uint32 {
	vs := make([]uint32, 0, len(k.keys))
	for v := range k.keys {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	return vs
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aad(layer, context string, version uint32) []byte {
	b := make([]byte, 0, len(layer)+len(context)+8)
	b = append(b, layer...)
	b = binary.BigEndian.AppendUint32(b, version)
	b = append(b, context...)
	return b
}

// Seal encrypts plaintext for context with the current master key.
func (k *Keyring) Seal(plaintext []byte, context string) ([]byte, error) {
	dek := make([]byte, KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	out := make([]byte, 0, headerSize+len(plaintext)+tagSize)
	out = append(out, magic[:]...)
	out = binary.BigEndian.AppendUint32(out, k.current)
	wrapped, err := wrap(k.keys[k.current], dek, context, k.current)
	if err != nil {
		return nil, err
	}
	out = append(out, wrapped...)
	data, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return data.Seal(out, nonce, plaintext, aad("data", context, k.current)), nil
}

// wrap seals the DEK: nonce + sealed DEK.
func wrap(kek, dek []byte, context string, version uint32) ([]byte, error) {
	a, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, dek, aad("dek", context, version)), nil
}

type parsed struct {
	version uint32
	wrapped []byte // nonce + sealed DEK
	nonce   []byte
	sealed  []byte
}

func parse(b []byte) (parsed, error) {
	if len(b) < headerSize+tagSize || [4]byte(b[:4]) != magic {
		return parsed{}, ErrCorrupt
	}
	p := parsed{version: binary.BigEndian.Uint32(b[4:8])}
	p.wrapped = b[8 : 8+nonceSize+sealedDEK]
	p.nonce = b[8+nonceSize+sealedDEK : headerSize]
	p.sealed = b[headerSize:]
	return p, nil
}

func (k *Keyring) unwrap(p parsed, context string) ([]byte, error) {
	kek, ok := k.keys[p.version]
	if !ok {
		return nil, &UnknownVersionError{p.version}
	}
	a, err := gcm(kek)
	if err != nil {
		return nil, err
	}
	dek, err := a.Open(nil, p.wrapped[:nonceSize], p.wrapped[nonceSize:], aad("dek", context, p.version))
	if err != nil {
		return nil, ErrWrongKey
	}
	return dek, nil
}

// Open decrypts a value sealed for context.
func (k *Keyring) Open(sealed []byte, context string) ([]byte, error) {
	p, err := parse(sealed)
	if err != nil {
		return nil, err
	}
	dek, err := k.unwrap(p, context)
	if err != nil {
		return nil, err
	}
	data, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	pt, err := data.Open(nil, p.nonce, p.sealed, aad("data", context, p.version))
	if err != nil {
		return nil, ErrWrongKey
	}
	return pt, nil
}

// SealString and OpenString are Seal and Open for text.
func (k *Keyring) SealString(s, context string) ([]byte, error) { return k.Seal([]byte(s), context) }

func (k *Keyring) OpenString(sealed []byte, context string) (string, error) {
	b, err := k.Open(sealed, context)
	return string(b), err
}

// Version is the master key version a sealed value uses.
func Version(sealed []byte) (uint32, error) {
	p, err := parse(sealed)
	return p.version, err
}

// NeedsRewrap reports whether the value is sealed with an older version.
func (k *Keyring) NeedsRewrap(sealed []byte) bool {
	v, err := Version(sealed)
	return err == nil && v != k.current
}

// Rewrap re-seals a value with the current master key version (after a
// rotation), with a fresh data key.
func (k *Keyring) Rewrap(sealed []byte, context string) ([]byte, error) {
	pt, err := k.Open(sealed, context)
	if err != nil {
		return nil, err
	}
	return k.Seal(pt, context)
}
