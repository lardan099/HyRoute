package secrets

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Samples is what checking a key without writing needs from a database.
type Samples interface {
	Setting(ctx context.Context, key string) (string, error)
	// SealedSamples are one sealed value of every key version in use.
	SealedSamples(ctx context.Context) ([]store.SealedValue, error)
}

// samples are the database's sealed values to try a key on: the check
// value and one value of every version in use.
func samples(ctx context.Context, db Samples) ([]store.SealedValue, error) {
	out, err := db.SealedSamples(ctx)
	if err != nil {
		return nil, err
	}
	switch check, err := db.Setting(ctx, checkSetting); {
	case err == nil:
		b, err := base64.StdEncoding.DecodeString(check)
		if err != nil {
			return nil, fmt.Errorf("проверочное значение мастер-ключа в базе (settings, %s) повреждено: %w", checkSetting, err)
		}
		v, err := Version(b)
		if err != nil {
			return nil, fmt.Errorf("проверочное значение мастер-ключа в базе (settings, %s): %w", checkSetting, err)
		}
		out = append(out, store.SealedValue{Version: v, Sealed: b, Context: checkContext})
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	return out, nil
}

// Verify checks that keys open the database: the check value and a value
// of every key version in use. Unlike Open it writes nothing: it is for a
// database that is not the controller's yet (a backup being restored) or
// that the controller uses now (doctor). from names where the key came
// from, for the error.
func Verify(ctx context.Context, keys *Keyring, db Samples, from string) error {
	ss, err := samples(ctx, db)
	if err != nil {
		return err
	}
	for _, s := range ss {
		if _, err := keys.Open(s.Sealed, s.Context); err != nil {
			return mismatch(err, from)
		}
	}
	return nil
}

// NeedsKey reports whether the database holds anything only the master
// key opens: the check value or sealed values.
func NeedsKey(ctx context.Context, db Samples) (bool, error) {
	ss, err := samples(ctx, db)
	return len(ss) > 0, err
}

// Key check results of one version.
const (
	KeyOK      = "ok"      // the text has the version and it opens the values
	KeyWrong   = "wrong"   // the text has the version, but it does not open them
	KeyMissing = "missing" // the database needs the version, the text lacks it
)

// VersionCheck is the result of one key version the database uses.
type VersionCheck struct {
	Version uint32 `json:"version"`
	Status  string `json:"status"`
}

// KeyReport answers whether a copy of the master key opens the database.
type KeyReport struct {
	// Versions are the versions the database uses, ascending.
	Versions []VersionCheck `json:"versions"`
	// Unused are versions of the text the database does not use.
	Unused []uint32 `json:"unused"`
}

// OK reports whether the text opens everything in the database.
func (r KeyReport) OK() bool {
	for _, v := range r.Versions {
		if v.Status != KeyOK {
			return false
		}
	}
	return true
}

// ErrNotKeyText: the text is not in the master key format.
var ErrNotKeyText = errors.New("текст не похож на мастер-ключ: нужен формат файла ключа, «1:<32 байта в base64>», по строке на версию")

// CheckKeyText tries a copy of the master key (the text of a key file)
// on the database's sealed values, version by version, so an admin can
// tell a copy in a password manager is right before it is needed. The
// text is not kept, and errors do not quote it.
func CheckKeyText(ctx context.Context, text string, db Samples) (KeyReport, error) {
	parsed, err := parseKeys(text)
	if err != nil {
		return KeyReport{}, ErrNotKeyText
	}
	keys, err := NewKeyring(parsed)
	if err != nil {
		return KeyReport{}, ErrNotKeyText
	}
	ss, err := samples(ctx, db)
	if err != nil {
		return KeyReport{}, err
	}
	status := map[uint32]string{}
	for _, s := range ss {
		st := KeyOK
		if _, ok := parsed[s.Version]; !ok {
			st = KeyMissing
		} else if _, err := keys.Open(s.Sealed, s.Context); err != nil {
			st = KeyWrong
		}
		if status[s.Version] == "" || status[s.Version] == KeyOK {
			status[s.Version] = st
		}
	}
	var r KeyReport
	for v, st := range status {
		r.Versions = append(r.Versions, VersionCheck{Version: v, Status: st})
	}
	slices.SortFunc(r.Versions, func(a, b VersionCheck) int { return cmp.Compare(a.Version, b.Version) })
	for _, v := range keys.Versions() {
		if _, used := status[v]; !used {
			r.Unused = append(r.Unused, v)
		}
	}
	return r, nil
}

// RekeyDB is what rekey needs from a database.
type RekeyDB interface {
	Samples
	SetSetting(ctx context.Context, key, value string, at time.Time) error
	SealedVersions(ctx context.Context) ([]uint32, error)
	// RewrapSealed seals again every value not sealed with current, in
	// small transactions (an interrupted run is safe to repeat).
	RewrapSealed(ctx context.Context, current uint32, rewrap func(sealed []byte, context string) ([]byte, error)) (int, error)
}

// Rekey seals every stored value and the check value with the current
// key version, after Verify accepted keys. It returns how many values it
// rewrapped and the loaded versions nothing needs any more: their lines
// can go from the key file.
func Rekey(ctx context.Context, keys *Keyring, db RekeyDB) (n int, unused []uint32, err error) {
	n, err = db.RewrapSealed(ctx, keys.Current(), keys.Rewrap)
	if err != nil {
		return n, nil, err
	}
	if err := storeCheck(ctx, db, keys); err != nil {
		return n, nil, err
	}
	used, err := db.SealedVersions(ctx)
	if err != nil {
		return n, nil, err
	}
	for _, v := range keys.Versions() {
		if v != keys.Current() && !slices.Contains(used, v) {
			unused = append(unused, v)
		}
	}
	return n, unused, nil
}

// AddVersion appends a new key version (the highest loaded one plus one)
// to the key file and returns the keyring with it: rekey -rotate. The
// file is replaced in one rename and keeps its other lines.
func AddVersion(file string, keys *Keyring) (*Keyring, error) {
	b, err := readKeyFile(file)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, KeySize)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	v := keys.Current() + 1
	text := string(b)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += fmt.Sprintf("%d:%s\n", v, base64.StdEncoding.EncodeToString(raw))
	parsed, err := parseKeys(text)
	if err != nil {
		return nil, err
	}
	next, err := NewKeyring(parsed)
	if err != nil {
		return nil, err
	}
	tmp := file + ".new"
	os.Remove(tmp)
	if err := writeKeyFile(tmp, text); err != nil {
		return nil, err
	}
	if err := datadir.Replace(tmp, file); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return next, nil
}
