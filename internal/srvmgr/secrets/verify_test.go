package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// dbSealedWith is a database whose values use versions 1 and 2 of keys
// and whose check value is sealed with the current one.
func dbSealedWith(t *testing.T, keys *Keyring) *fakeDB {
	t.Helper()
	db := &fakeDB{}
	for _, v := range []uint32{1, 2} {
		one, err := NewKeyring(map[uint32][]byte{v: keys.keys[v]})
		if err != nil {
			t.Fatal(err)
		}
		ctx := "server/1/config/" + string(rune('0'+v))
		b, err := one.SealString("config", ctx)
		if err != nil {
			t.Fatal(err)
		}
		db.samples = append(db.samples, store.SealedValue{Version: v, Sealed: b, Context: ctx})
	}
	if err := storeCheck(context.Background(), db, keys); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	keys := ring(t, map[uint32][]byte{1: key(1), 2: key(2)})
	db := dbSealedWith(t, keys)
	before := db.settings[checkSetting]
	if err := Verify(ctx, keys, db, "файла x"); err != nil {
		t.Fatal(err)
	}
	if db.settings[checkSetting] != before {
		t.Fatal("Verify wrote the check value")
	}
	// Without version 1, or with another version 2, it does not open.
	for name, k := range map[string]*Keyring{
		"no v1":    ring(t, map[uint32][]byte{2: key(2)}),
		"wrong v1": ring(t, map[uint32][]byte{1: key(9), 2: key(2)}),
		"wrong v2": ring(t, map[uint32][]byte{1: key(1), 2: key(9)}),
	} {
		if err := Verify(ctx, k, db, "файла x"); !errors.Is(err, ErrKeyMismatch) {
			t.Errorf("%s: %v, want ErrKeyMismatch", name, err)
		}
	}
	// An empty database: anything goes.
	if err := Verify(ctx, ring(t, map[uint32][]byte{1: key(5)}), &fakeDB{}, "файла x"); err != nil {
		t.Fatalf("empty database: %v", err)
	}
}

func TestCheckKeyText(t *testing.T) {
	ctx := context.Background()
	keys := ring(t, map[uint32][]byte{1: key(1), 2: key(2)})
	db := dbSealedWith(t, keys)
	cases := []struct {
		name, text string
		want       []VersionCheck
		unused     []uint32
	}{
		{"right", keyText(1, 1) + keyText(2, 2), []VersionCheck{{1, KeyOK}, {2, KeyOK}}, nil},
		{"comments and order", "# copy\n" + keyText(2, 2) + keyText(1, 1), []VersionCheck{{1, KeyOK}, {2, KeyOK}}, nil},
		{"old version lost", keyText(2, 2), []VersionCheck{{1, KeyMissing}, {2, KeyOK}}, nil},
		{"wrong current", keyText(1, 1) + keyText(2, 7), []VersionCheck{{1, KeyOK}, {2, KeyWrong}}, nil},
		{"extra version", keyText(1, 1) + keyText(2, 2) + keyText(3, 3), []VersionCheck{{1, KeyOK}, {2, KeyOK}}, []uint32{3}},
	}
	for _, c := range cases {
		r, err := CheckKeyText(ctx, c.text, db)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !slices.Equal(r.Versions, c.want) || !slices.Equal(r.Unused, c.unused) {
			t.Errorf("%s: %+v, want %+v unused %v", c.name, r, c.want, c.unused)
		}
		if r.OK() != (c.name == "right" || c.name == "comments and order" || c.name == "extra version") {
			t.Errorf("%s: OK %v", c.name, r.OK())
		}
	}

	// Not a key: the error does not quote the text.
	secret := base64.StdEncoding.EncodeToString(key(4))[:20]
	for _, text := range []string{"", "hello", "1:" + secret, secret + ":" + secret} {
		_, err := CheckKeyText(ctx, text, db)
		if !errors.Is(err, ErrNotKeyText) {
			t.Errorf("%q: %v, want ErrNotKeyText", text, err)
		}
		if err != nil && text != "" && strings.Contains(err.Error(), secret) {
			t.Errorf("%q: the error quotes the text", text)
		}
	}
}
