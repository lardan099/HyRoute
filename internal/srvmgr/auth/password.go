package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the argon2id parameters; they travel in the PHC string, so
// changing the defaults rehashes passwords on the next login.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultParams follow the OWASP recommendation for argon2id with room to
// spare: 64 MiB, 3 passes, 2 lanes.
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

var b64 = base64.RawStdEncoding

// idKey is argon2.IDKey; tests wrap it to see how many runs overlap.
var idKey = argon2.IDKey

// HashPassword returns the PHC string
// $argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>.
func HashPassword(password string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := idKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// parseHash reads a PHC argon2id string.
func parseHash(encoded string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, errBadHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return p, nil, nil, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, errBadHash
	}
	// Bounds keep a planted hash from making verification a DoS.
	if p.Memory == 0 || p.Memory > 1<<21 || p.Time == 0 || p.Time > 64 || p.Threads == 0 {
		return p, nil, nil, errBadHash
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil || len(salt) < 8 {
		return p, nil, nil, errBadHash
	}
	if key, err = b64.DecodeString(parts[5]); err != nil || len(key) < 16 || len(key) > 128 {
		return p, nil, nil, errBadHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}

// VerifyPassword checks password against a PHC string in constant time.
// stale is true when the hash uses other parameters than want: the caller
// should store a fresh hash.
func VerifyPassword(encoded, password string, want Params) (ok, stale bool, err error) {
	p, salt, key, err := parseHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := idKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(key)))
	ok = subtle.ConstantTimeCompare(got, key) == 1
	return ok, p != want, nil
}
