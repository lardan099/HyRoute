package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func ring(t *testing.T, keys map[uint32][]byte) *Keyring {
	t.Helper()
	k, err := NewKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const fakeSecret = "fake-ssh-password-for-tests"

func TestRoundTrip(t *testing.T) {
	k := ring(t, map[uint32][]byte{1: key(1)})
	for _, pt := range []string{"", fakeSecret, strings.Repeat("x", 100000)} {
		s, err := k.SealString(pt, "server/1/ssh_password")
		if err != nil {
			t.Fatal(err)
		}
		if pt != "" && bytes.Contains(s, []byte(pt)) {
			t.Fatal("plaintext visible in the sealed value")
		}
		got, err := k.OpenString(s, "server/1/ssh_password")
		if err != nil || got != pt {
			t.Fatalf("open: %q %v", got, err)
		}
	}
	a, _ := k.SealString(fakeSecret, "c")
	b, _ := k.SealString(fakeSecret, "c")
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same value are equal: nonces or DEKs repeat")
	}
}

func TestWrongKeyContextAndTampering(t *testing.T) {
	k := ring(t, map[uint32][]byte{1: key(1)})
	s, _ := k.SealString(fakeSecret, "server/1/ssh_password")

	other := ring(t, map[uint32][]byte{1: key(2)})
	if _, err := other.Open(s, "server/1/ssh_password"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := k.Open(s, "server/2/ssh_password"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong context: %v", err)
	}
	for i := 8; i < len(s); i += 7 {
		bad := append([]byte(nil), s...)
		bad[i] ^= 1
		if _, err := k.Open(bad, "server/1/ssh_password"); err == nil {
			t.Fatalf("flipped byte %d accepted", i)
		}
	}
	for _, bad := range [][]byte{nil, []byte("HRS1"), []byte("plain text value, not sealed at all......................................")} {
		if _, err := k.Open(bad, "x"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestRotation(t *testing.T) {
	old := ring(t, map[uint32][]byte{1: key(1)})
	s1, _ := old.SealString(fakeSecret, "ctx")

	k := ring(t, map[uint32][]byte{1: key(1), 2: key(2)})
	if k.Current() != 2 {
		t.Fatalf("current %d", k.Current())
	}
	if got, err := k.OpenString(s1, "ctx"); err != nil || got != fakeSecret {
		t.Fatalf("old value with the new keyring: %q %v", got, err)
	}
	if !k.NeedsRewrap(s1) {
		t.Fatal("old version not reported")
	}
	s2, err := k.Rewrap(s1, "ctx")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Version(s2); v != 2 || k.NeedsRewrap(s2) {
		t.Fatalf("rewrapped version %d", v)
	}
	// After version 1 is dropped, rewrapped values still open.
	only2 := ring(t, map[uint32][]byte{2: key(2)})
	if got, err := only2.OpenString(s2, "ctx"); err != nil || got != fakeSecret {
		t.Fatalf("%q %v", got, err)
	}
	var uv *UnknownVersionError
	if _, err := only2.Open(s1, "ctx"); !errors.As(err, &uv) || uv.Version != 1 {
		t.Fatalf("unknown version: %v", err)
	}
}

func TestNewKeyringErrors(t *testing.T) {
	for _, keys := range []map[uint32][]byte{nil, {1: key(1)[:16]}, {0: key(1)}} {
		if _, err := NewKeyring(keys); err == nil {
			t.Errorf("%v: no error", keys)
		}
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadFromEnv(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(key(7))
	k, src, err := Load(env(map[string]string{EnvMasterKey: b64}), filepath.Join(t.TempDir(), "master.key"))
	if err != nil || src != FromEnv || k.Current() != 1 {
		t.Fatalf("%v %v", src, err)
	}
	k, _, err = Load(env(map[string]string{EnvMasterKey: "1:" + b64 + ",3:" + base64.RawURLEncoding.EncodeToString(key(8))}), "")
	if err != nil || k.Current() != 3 || len(k.Versions()) != 2 {
		t.Fatalf("%v %v", k.Versions(), err)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString(key(1)[:10]), "0:" + b64, "x:" + b64, "1:" + b64 + "\n1:" + b64} {
		if _, _, err := Load(env(map[string]string{EnvMasterKey: bad}), ""); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// A variable of white space is no key: Load reads the file, and KeyInEnv,
// by which main decides to check the file, agrees.
func TestBlankEnvKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "master.key")
	text, _ := NewKeyText()
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", " ", "\n", " \r\n\t"} {
		e := env(map[string]string{EnvMasterKey: v})
		if _, src, err := Load(e, file); err != nil || src != FromFile || KeyInEnv(e) {
			t.Errorf("%q: %v %v in env %v", v, src, err, KeyInEnv(e))
		}
	}
	e := env(map[string]string{EnvMasterKey: " " + strings.TrimSpace(text) + "\n"})
	if _, src, err := Load(e, file); err != nil || src != FromEnv || !KeyInEnv(e) {
		t.Errorf("%v %v", src, err)
	}
}

// A comment line is skipped whole, commas included.
func TestParseKeysComments(t *testing.T) {
	k1, k2 := base64.StdEncoding.EncodeToString(key(1)), base64.StdEncoding.EncodeToString(key(2))
	keys, err := parseKeys("# старый ключ, удалить после ротации\n1:" + k1 + "\n")
	if err != nil || len(keys) != 1 || keys[1] == nil {
		t.Fatalf("%v %v", keys, err)
	}
	keys, err = parseKeys("  # 1:" + k1 + ",2:" + k2 + "\r\n1:" + k1)
	if err != nil || len(keys) != 1 || keys[2] != nil {
		t.Fatalf("a commented key is in use: %v %v", keys, err)
	}
	// A key without a version is not named version 1 in the error.
	if _, err := parseKeys("not base64!"); err == nil || strings.Contains(err.Error(), "version") {
		t.Fatalf("%v", err)
	}
}

func TestCreateAndLoadKeyFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "master.key")
	if _, _, err := Load(env(nil), file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("Load created a key file")
	}
	k1, err := createKeyFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createKeyFile(file); err == nil {
		t.Fatal("an existing key file overwritten")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(file)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("created with mode %v", st.Mode())
		}
	}
	s, _ := k1.SealString(fakeSecret, "c")
	k2, src, err := Load(env(nil), file)
	if err != nil || src != FromFile {
		t.Fatalf("%v %v", src, err)
	}
	if got, err := k2.OpenString(s, "c"); err != nil || got != fakeSecret {
		t.Fatal("reloaded key does not open values")
	}
	if runtime.GOOS != "windows" {
		os.Chmod(file, 0o644)
		if _, _, err := Load(env(nil), file); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("world-readable key accepted: %v", err)
		}
		os.Chmod(file, 0o600)
		link := filepath.Join(dir, "link.key")
		os.Symlink(file, link)
		if _, _, err := Load(env(nil), link); err == nil {
			t.Fatal("symlinked key file accepted")
		}
	}
	if _, err := createKeyFile(filepath.Join(dir, "missing-dir", "master.key")); err == nil {
		t.Fatal("key created in a missing directory")
	}
}
