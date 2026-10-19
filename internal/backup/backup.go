// Package backup is the .hyroute-backup file format: an envelope with an
// Argon2id + AES-256-GCM encrypted (or, without secrets, plain) payload of
// named sections. It knows nothing about the sections' contents.
//
// It also reads the .hyroute files of HyRoute 1.2.0 (legacy.go): their
// payload is handed over raw, the app maps it into sections.
package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	Ext         = ".hyroute-backup"
	Format      = "hyroute-backup"
	Version     = 1
	MaxFile     = 96 << 20 // envelope: base64 of gzip, or plain JSON
	MaxPayload  = 64 << 20 // decompressed payload: configuration + stats.MaxExport (32 MiB)
	MinPassword = 8

	cipherName = "aes-256-gcm"
	kdfName    = "argon2id"
	// maxTargets bounds Payload.Targets (and each value's fields).
	maxTargets     = 10000
	maxTargetField = 255
)

// kdfMu serializes Argon2 runs: each may take up to 128 MiB in the
// elevated process.
var kdfMu sync.Mutex

// kdfHook (tests) runs inside kdfMu around every key derivation.
var kdfHook func()

type KDF struct {
	Name      string `json:"name"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memoryKiB"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF is used for new files (tests lower it).
var DefaultKDF = KDF{Name: kdfName, Time: 3, MemoryKiB: 64 << 10, Threads: 4}

type File struct {
	Format    string          `json:"format"`
	Version   int             `json:"version"`
	Encrypted bool            `json:"encrypted"`
	KDF       *KDF            `json:"kdf,omitempty"`
	Cipher    string          `json:"cipher,omitempty"`
	Nonce     []byte          `json:"nonce,omitempty"`
	Data      []byte          `json:"data,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`

	// legacy is a HyRoute 1.2.0 .hyroute file (nil for ours).
	legacy *legacyFile
}

// Target describes a server a section refers to (secret-free), so a
// restore can find the same server on another machine. A group is
// {name, group: true}.
type Target struct {
	Name  string `json:"name"`
	Host  string `json:"host,omitempty"`
	Ports string `json:"ports,omitempty"`
	Sub   string `json:"sub,omitempty"` // subscription display name
	Group bool   `json:"group,omitempty"`
}

type Payload struct {
	App      string                     `json:"app"`
	Created  time.Time                  `json:"created"`
	Secrets  bool                       `json:"secrets"`
	Targets  map[string]Target          `json:"targets,omitempty"`
	Sections map[string]json.RawMessage `json:"sections"`
	// Unknown lists top-level fields this version does not know (a newer
	// HyRoute wrote them); they are ignored. Not serialized.
	Unknown []string `json:"-"`
	// Legacy is the kind ("full" or "rules") of a HyRoute 1.2.0 file and
	// LegacyData its payload, which the app maps into Sections. Not
	// serialized.
	Legacy     string          `json:"-"`
	LegacyData json.RawMessage `json:"-"`
	// Errors: sections of a legacy file the app could not map (key → why
	// they cannot be imported); the other sections stay usable. Not
	// serialized.
	Errors map[string]string `json:"-"`
}

var (
	ErrForeign  = message("Это не резервная копия HyRoute")
	ErrDamaged  = message("Файл резервной копии повреждён")
	ErrPassword = message("Неверный пароль или файл повреждён")
	ErrTooLarge = message("Файл слишком большой для резервной копии HyRoute (больше 96 МБ)")
	ErrTooBig   = message("Копия получилась больше 96 МБ: снимите «Статистика» и повторите") // Encode
	// ErrPayloadBig: the data inside (unpacked) is over MaxPayload, though
	// the file itself may be small.
	ErrPayloadBig  = message("Данные копии больше 64 МБ: снимите крупные разделы (статистику, правила с большими списками) и повторите") // Encode
	ErrPayloadOpen = message("Данные в этой копии больше 64 МБ: HyRoute их не откроет")
	ErrSecrets     = message("Без пароля нельзя сохранить пароли, ссылки подписок и статистику")
	ErrShort       = message("Пароль — не меньше 8 символов")
)

// message is an error text for the user (a sentence, capital first).
type message string

func (m message) Error() string { return string(m) }

// NewerError: the file's format version is newer than this build reads.
type NewerError struct{ Version int }

func (e *NewerError) Error() string {
	return fmt.Sprintf("Копия сделана более новой версией HyRoute (формат %d). Обновите HyRoute и повторите", e.Version)
}

// damaged is ErrDamaged with a detail (JSON errors of a plain file).
func damaged(detail error) error {
	if detail == nil {
		return ErrDamaged
	}
	return fmt.Errorf("%w: %v", ErrDamaged, detail)
}

// NeedsPassword reports whether Open needs a password.
func (f *File) NeedsPassword() bool {
	if f.legacy != nil {
		return f.legacy.Sealed != nil
	}
	return f.Encrypted
}

// IsLegacy: a HyRoute 1.2.0 .hyroute file.
func (f *File) IsLegacy() bool { return f.legacy != nil }

// Encode: password "" → plain envelope, refused when p.Secrets.
func Encode(p *Payload, password string) ([]byte, error) {
	if password == "" && p.Secrets {
		return nil, ErrSecrets
	}
	if password != "" && len([]rune(password)) < MinPassword {
		return nil, ErrShort
	}
	if p.Sections == nil {
		p.Sections = map[string]json.RawMessage{}
	}
	if password == "" {
		body, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		f := File{Format: Format, Version: Version, Payload: body}
		b, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		if err := json.Indent(&out, b, "", "  "); err != nil {
			return nil, err
		}
		if out.Len() > MaxFile {
			return nil, ErrTooBig
		}
		return out.Bytes(), nil
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxPayload {
		return nil, ErrPayloadBig // Open would refuse it, however small the file
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	k := DefaultKDF
	k.Salt = make([]byte, 16)
	if _, err := rand.Read(k.Salt); err != nil {
		return nil, err
	}
	f := File{Format: Format, Version: Version, Encrypted: true, KDF: &k, Cipher: cipherName, Nonce: make([]byte, 12)}
	if _, err := rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(password, &k)
	if err != nil {
		return nil, err
	}
	f.Data = gcm.Seal(nil, f.Nonce, z.Bytes(), aad(&f))
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFile {
		return nil, ErrTooBig
	}
	return b, nil
}

// aad binds the header to the ciphertext: any change fails authentication.
func aad(f *File) []byte {
	k := f.KDF
	return fmt.Appendf(nil, "hyroute-backup/%d/%s/%s/%d/%d/%d/%x", f.Version, f.Cipher, k.Name, k.Time, k.MemoryKiB, k.Threads, k.Salt)
}

func newGCM(password string, k *KDF) (cipher.AEAD, error) {
	kdfMu.Lock()
	if kdfHook != nil {
		kdfHook()
	}
	key := argon2.IDKey([]byte(password), k.Salt, k.Time, k.MemoryKiB, k.Threads, 32)
	kdfMu.Unlock()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// kdfOK checks the header bounds before any Argon2 run.
func kdfOK(k *KDF) bool {
	return k != nil && k.Name == kdfName && len(k.Salt) >= 16 && len(k.Salt) <= 64 &&
		k.Time >= 1 && k.Time <= 8 && k.MemoryKiB >= 8192 && k.MemoryKiB <= 131072 &&
		uint64(k.Time)*uint64(k.MemoryKiB) <= 786432 && k.Threads >= 1 && k.Threads <= 16
}

// Parse checks the envelope (size, format, version, header bounds) without
// decrypting.
func Parse(b []byte) (*File, error) {
	if len(b) > MaxFile {
		return nil, ErrTooLarge
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil || top == nil {
		return nil, ErrForeign
	}
	var format string
	if json.Unmarshal(top["format"], &format) != nil || format != Format {
		return nil, ErrForeign
	}
	if _, ok := top["kind"]; ok {
		return parseLegacy(b)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, damaged(nil)
	}
	if f.Version > Version {
		return nil, &NewerError{f.Version}
	}
	if f.Version < 1 {
		return nil, ErrDamaged
	}
	if f.Encrypted {
		if !kdfOK(f.KDF) || f.Cipher != cipherName || len(f.Nonce) != 12 || len(f.Data) == 0 || f.Payload != nil {
			return nil, ErrDamaged
		}
	} else if f.Payload == nil || f.KDF != nil || f.Data != nil {
		return nil, ErrDamaged
	}
	return &f, nil
}

// Open decrypts (password ignored for a plain file), gunzips with the
// MaxPayload limit and decodes the payload; unknown top-level fields are
// ignored and listed in Payload.Unknown (sections stay raw: the app
// decodes them strictly).
func (f *File) Open(password string) (*Payload, error) {
	if f.legacy != nil {
		return f.legacy.open(password)
	}
	body := []byte(f.Payload)
	if f.Encrypted {
		gcm, err := newGCM(password, f.KDF)
		if err != nil {
			return nil, ErrDamaged
		}
		z, err := gcm.Open(nil, f.Nonce, f.Data, aad(f))
		if err != nil {
			return nil, ErrPassword
		}
		zr, err := gzip.NewReader(bytes.NewReader(z))
		if err != nil {
			return nil, ErrDamaged
		}
		body, err = io.ReadAll(io.LimitReader(zr, MaxPayload+1))
		if err != nil {
			return nil, ErrDamaged
		}
		if len(body) > MaxPayload {
			return nil, ErrPayloadOpen
		}
	}
	return decodePayload(body, !f.Encrypted)
}

func decodePayload(body []byte, plain bool) (*Payload, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		if plain {
			return nil, damaged(err)
		}
		return nil, ErrDamaged
	}
	p := &Payload{}
	fields := map[string]any{"app": &p.App, "created": &p.Created, "secrets": &p.Secrets, "targets": &p.Targets, "sections": &p.Sections}
	for k, raw := range top {
		dst, ok := fields[k]
		if !ok {
			p.Unknown = append(p.Unknown, k)
			continue
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			if plain {
				return nil, damaged(fmt.Errorf("%s: %v", k, err))
			}
			return nil, ErrDamaged
		}
	}
	slices.Sort(p.Unknown)
	if plain && p.Secrets {
		// Anyone can write a plain file: it never unlocks the sections
		// only a password-protected copy carries (Encode refuses one).
		return nil, damaged(errors.New("secrets в копии без пароля"))
	}
	if p.Sections == nil {
		p.Sections = map[string]json.RawMessage{}
	}
	if len(p.Targets) > maxTargets {
		return nil, ErrDamaged
	}
	for id, t := range p.Targets {
		if len(id) > maxTargetField || len(t.Name) > maxTargetField || len(t.Host) > maxTargetField ||
			len(t.Ports) > maxTargetField || len(t.Sub) > maxTargetField {
			return nil, ErrDamaged
		}
	}
	return p, nil
}
