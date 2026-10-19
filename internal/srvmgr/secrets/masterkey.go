package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
)

// EnvMasterKey holds the master key when it is not in a file.
const EnvMasterKey = "HYROUTE_MASTER_KEY"

// Master key text: one key per line or comma-separated, each
// "<version>:<base64 of 32 bytes>" or just the base64 (version 1); a
// line starting with "#" is a comment, commas and all.
// The highest version seals new values; the others open old ones.
func parseKeys(text string) (map[uint32][]byte, error) {
	keys := map[uint32][]byte{}
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, item := range strings.Split(line, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			v, name := uint64(1), "master key"
			if ver, b, ok := strings.Cut(item, ":"); ok {
				n, err := strconv.ParseUint(ver, 10, 32)
				if err != nil || n == 0 {
					return nil, fmt.Errorf("master key version %q: want a positive number", ver)
				}
				v, item, name = n, b, fmt.Sprintf("master key version %d", n)
			}
			key, err := decodeKey(item)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if _, dup := keys[uint32(v)]; dup {
				return nil, fmt.Errorf("master key version %d given twice", v)
			}
			keys[uint32(v)] = key
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no master key in the text")
	}
	return keys, nil
}

func decodeKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != KeySize {
				return nil, fmt.Errorf("%d bytes, want %d", len(b), KeySize)
			}
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// NewKeyText is a fresh version-1 master key in the file format.
func NewKeyText() (string, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "1:" + base64.StdEncoding.EncodeToString(b) + "\n", nil
}

// Source says where the master key came from.
type Source int

const (
	FromEnv Source = iota
	FromFile
	// Created: there was no key and the database had nothing sealed, a new
	// file was written. Losing it loses every stored credential, so the
	// caller tells the admin to back it up.
	Created
)

// KeyInEnv reports whether Load takes the key from EnvMasterKey rather
// than from the file: the variable holds more than white space.
func KeyInEnv(getenv func(string) string) bool {
	return strings.TrimSpace(getenv(EnvMasterKey)) != ""
}

// Load reads the master key from the environment (getenv(EnvMasterKey))
// or from file. The file must not be readable by group or others. With
// neither, the error wraps fs.ErrNotExist: only Open, which sees the
// database, may create a key.
func Load(getenv func(string) string, file string) (*Keyring, Source, error) {
	if KeyInEnv(getenv) {
		keys, err := parseKeys(getenv(EnvMasterKey))
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", EnvMasterKey, err)
		}
		k, err := NewKeyring(keys)
		return k, FromEnv, err
	}
	b, err := readKeyFile(file)
	if err != nil {
		return nil, 0, err
	}
	keys, err := parseKeys(string(b))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	k, err := NewKeyring(keys)
	return k, FromFile, err
}

func readKeyFile(file string) ([]byte, error) {
	st, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("master key file %s is not a regular file", file)
	}
	// Windows has no Unix modes: the controller sets the file's ACL
	// (package datadir).
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key file %s has mode %v: allow only its owner (chmod 600)", file, st.Mode().Perm())
	}
	return os.ReadFile(file)
}

// createKeyFile writes a new version-1 key to file (0600) in an existing
// directory; an existing file is never overwritten.
func createKeyFile(file string) (*Keyring, error) {
	text, err := NewKeyText()
	if err != nil {
		return nil, err
	}
	if err := writeKeyFile(file, text); err != nil {
		return nil, err
	}
	keys, err := parseKeys(text)
	if err != nil {
		return nil, err
	}
	return NewKeyring(keys)
}

func writeKeyFile(file, text string) error {
	if _, err := os.Stat(filepath.Dir(file)); err != nil {
		return fmt.Errorf("master key directory: %w", err)
	}
	f, err := datadir.Create(file)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(file)
		return err
	}
	return datadir.SyncDir(filepath.Dir(file))
}
