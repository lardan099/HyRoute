package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// fakeDB is the settings table and the sealed values of a database.
type fakeDB struct {
	settings  map[string]string
	sealed    bool   // some row holds a sealed value
	sample    []byte // one of them, with its context
	sampleCtx string
}

func (d *fakeDB) Setting(_ context.Context, key string) (string, error) {
	v, ok := d.settings[key]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (d *fakeDB) SetSetting(_ context.Context, key, value string, _ time.Time) error {
	if d.settings == nil {
		d.settings = map[string]string{}
	}
	d.settings[key] = value
	return nil
}

func (d *fakeDB) HasSealed(context.Context) (bool, error) { return d.sealed, nil }

func (d *fakeDB) SealedSample(context.Context) ([]byte, string, error) {
	if d.sample == nil {
		return nil, "", store.ErrNotFound
	}
	return d.sample, d.sampleCtx, nil
}

func keyText(v uint32, b byte) string {
	return fmt.Sprintf("%d:%s\n", v, base64.StdEncoding.EncodeToString(key(b)))
}

func writeKey(t *testing.T, file, text string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkVersion(t *testing.T, db *fakeDB) uint32 {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(db.settings[checkSetting])
	if err != nil {
		t.Fatal(err)
	}
	v, err := Version(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// An empty database gets a new key and remembers it; the next start
// loads the same key.
func TestOpenCreatesKeyOnEmptyDB(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "master.key")
	db := &fakeDB{}
	k, src, err := Open(ctx, env(nil), file, db)
	if err != nil || src != Created {
		t.Fatalf("%v %v", src, err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
	if db.settings[checkSetting] == "" {
		t.Fatal("no check value stored")
	}
	s, _ := k.SealString(fakeSecret, "c")
	db.sealed, db.sample, db.sampleCtx = true, s, "c"
	k2, src, err := Open(ctx, env(nil), file, db)
	if err != nil || src != FromFile {
		t.Fatalf("restart: %v %v", src, err)
	}
	if got, err := k2.OpenString(s, "c"); err != nil || got != fakeSecret {
		t.Fatalf("restart key does not open values: %v", err)
	}
}

// Without a key, a database that has anything sealed refuses to start,
// and no key file appears.
func TestOpenWithoutKeyOnUsedDB(t *testing.T) {
	ctx := context.Background()
	bound := &fakeDB{}
	if _, _, err := Open(ctx, env(nil), filepath.Join(t.TempDir(), "master.key"), bound); err != nil {
		t.Fatal(err)
	}
	for name, db := range map[string]*fakeDB{
		"check value":             bound,
		"sealed values, no check": {sealed: true},
	} {
		file := filepath.Join(t.TempDir(), "master.key")
		_, _, err := Open(ctx, env(nil), file, db)
		if !errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), file) || !strings.Contains(err.Error(), EnvMasterKey) || !strings.Contains(err.Error(), "-master-key-file") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: a key file was created", name)
		}
	}
}

// Another key is refused before anything is written: by the check
// value, or, in a database from before it, by a sealed value.
func TestOpenWrongKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	right, wrong := filepath.Join(dir, "right.key"), filepath.Join(dir, "wrong.key")
	writeKey(t, right, keyText(1, 1))
	writeKey(t, wrong, keyText(1, 2))

	db := &fakeDB{}
	if _, src, err := Open(ctx, env(nil), right, db); err != nil || src != FromFile {
		t.Fatalf("%v %v", src, err)
	}
	check := db.settings[checkSetting]
	_, _, err := Open(ctx, env(nil), wrong, db)
	if !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), wrong) {
		t.Fatalf("wrong key file: %v", err)
	}
	_, _, err = Open(ctx, env(map[string]string{EnvMasterKey: keyText(1, 2)}), right, db)
	if !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), "переменной "+EnvMasterKey) {
		t.Fatalf("wrong key in the environment: %v", err)
	}
	if db.settings[checkSetting] != check {
		t.Fatal("check value changed by a wrong key")
	}
	if _, src, err := Open(ctx, env(map[string]string{EnvMasterKey: keyText(1, 1)}), wrong, db); err != nil || src != FromEnv {
		t.Fatalf("right key in the environment: %v %v", src, err)
	}

	// A database from a build without the check value.
	k := ring(t, map[uint32][]byte{1: key(1)})
	s, _ := k.SealString(fakeSecret, "server/1/ssh_password")
	old := &fakeDB{sealed: true, sample: s, sampleCtx: "server/1/ssh_password"}
	if _, _, err := Open(ctx, env(nil), wrong, old); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong key, old database: %v", err)
	}
	if _, ok := old.settings[checkSetting]; ok {
		t.Fatal("check value stored for a wrong key")
	}
	if _, _, err := Open(ctx, env(nil), right, old); err != nil {
		t.Fatalf("right key, old database: %v", err)
	}
	if _, _, err := Open(ctx, env(nil), wrong, old); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong key after the check value was stored: %v", err)
	}

	db.settings[checkSetting] = "not base64!"
	if _, _, err := Open(ctx, env(nil), right, db); err == nil {
		t.Fatal("corrupt check value accepted")
	}
}

// After a rotation the check value moves to the new version, so the old
// one can go once the data has moved too; a key without the version the
// database needs is refused with that version in the message.
func TestOpenRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	file := filepath.Join(dir, "master.key")
	writeKey(t, file, keyText(1, 1))
	db := &fakeDB{}
	if _, _, err := Open(ctx, env(nil), file, db); err != nil {
		t.Fatal(err)
	}
	writeKey(t, file, keyText(1, 1)+keyText(2, 2))
	if _, _, err := Open(ctx, env(nil), file, db); err != nil {
		t.Fatal(err)
	}
	if v := checkVersion(t, db); v != 2 {
		t.Fatalf("check value version %d after rotation", v)
	}
	writeKey(t, file, keyText(2, 2))
	if _, _, err := Open(ctx, env(nil), file, db); err != nil {
		t.Fatalf("new version only: %v", err)
	}
	writeKey(t, file, keyText(1, 1))
	if _, _, err := Open(ctx, env(nil), file, db); !errors.Is(err, ErrKeyMismatch) || !strings.Contains(err.Error(), "версией 2") {
		t.Fatalf("old version only: %v", err)
	}
}
