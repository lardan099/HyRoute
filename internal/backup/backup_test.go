package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	DefaultKDF = KDF{Name: kdfName, Time: 1, MemoryKiB: 8 << 10, Threads: 1}
	os.Exit(m.Run())
}

func sample(secrets bool) *Payload {
	return &Payload{
		App: "1.3.0", Created: time.Date(2026, 9, 28, 9, 30, 0, 0, time.UTC), Secrets: secrets,
		Targets:  map[string]Target{"a1b2c3d4e5f6": {Name: "NL-1", Host: "nl.example.net", Ports: "443", Sub: "Provider"}},
		Sections: map[string]json.RawMessage{"servers": json.RawMessage(`{"main":"a1b2c3d4e5f6","list":[]}`)},
	}
}

func roundTrip(t *testing.T, p *Payload, password string) *Payload {
	t.Helper()
	b, err := Encode(p, password)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.NeedsPassword() != (password != "") {
		t.Fatal("encrypted flag")
	}
	got, err := f.Open(password)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRoundTripEncrypted(t *testing.T) {
	p := sample(true)
	if got := roundTrip(t, p, "correct horse"); !reflect.DeepEqual(got, p) {
		t.Fatalf("%+v\n%+v", got, p)
	}
}

func TestRoundTripPlain(t *testing.T) {
	p := sample(false)
	got := roundTrip(t, p, "")
	for k, v := range got.Sections {
		var c bytes.Buffer
		json.Compact(&c, v)
		got.Sections[k] = c.Bytes()
	}
	if !reflect.DeepEqual(got, p) {
		t.Fatalf("%+v\n%+v", got, p)
	}
	b, _ := Encode(p, "")
	if !bytes.Contains(b, []byte(`"encrypted": false`)) || !bytes.Contains(b, []byte("nl.example.net")) {
		t.Fatalf("plain envelope: %s", b)
	}
}

func TestWrongPassword(t *testing.T) {
	b, _ := Encode(sample(true), "password1")
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Open("password2"); !errors.Is(err, ErrPassword) {
		t.Fatal(err)
	}
}

func TestTamperHeader(t *testing.T) {
	b, _ := Encode(sample(true), "password1")
	var orig File
	if err := json.Unmarshal(b, &orig); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(f *File){
		"salt":    func(f *File) { f.KDF.Salt[0] ^= 1 },
		"time":    func(f *File) { f.KDF.Time = 2 },
		"memory":  func(f *File) { f.KDF.MemoryKiB = 9 << 10 },
		"threads": func(f *File) { f.KDF.Threads = 2 },
		"nonce":   func(f *File) { f.Nonce[0] ^= 1 },
		"data":    func(f *File) { f.Data[len(f.Data)/2] ^= 1 },
	}
	for name, mod := range cases {
		var f File
		json.Unmarshal(b, &f)
		mod(&f)
		nb, _ := json.Marshal(f)
		pf, err := Parse(nb)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := pf.Open("password1"); !errors.Is(err, ErrPassword) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestPlainRefusesSecrets(t *testing.T) {
	if _, err := Encode(sample(true), ""); !errors.Is(err, ErrSecrets) {
		t.Fatal(err)
	}
	if _, err := Encode(sample(false), "short"); !errors.Is(err, ErrShort) {
		t.Fatal(err)
	}
	// Eight characters count as runes, not bytes.
	if _, err := Encode(sample(true), "пароль1"); !errors.Is(err, ErrShort) {
		t.Fatal(err)
	}
	if _, err := Encode(sample(true), "пароль12"); err != nil {
		t.Fatal(err)
	}
}

func TestForeign(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("{}"), []byte("PK\x03\x04zip"), []byte(`{"format":"other","version":1}`), []byte(`[1,2]`)} {
		if _, err := Parse(b); !errors.Is(err, ErrForeign) {
			t.Fatalf("%q: %v", b, err)
		}
	}
}

func TestNewer(t *testing.T) {
	_, err := Parse([]byte(`{"format":"hyroute-backup","version":2,"encrypted":false,"payload":{}}`))
	var ne *NewerError
	if !errors.As(err, &ne) || ne.Version != 2 || !strings.Contains(err.Error(), "формат 2") {
		t.Fatal(err)
	}
}

func TestKDFBounds(t *testing.T) {
	b, _ := Encode(sample(true), "password1")
	cases := []func(k *KDF){
		func(k *KDF) { k.MemoryKiB = 4 << 20 },
		func(k *KDF) { k.MemoryKiB = 256 << 10 },
		func(k *KDF) { k.Time = 100 },
		func(k *KDF) { k.Time, k.MemoryKiB = 8, 128<<10 },
		func(k *KDF) { k.Threads = 0 },
		func(k *KDF) { k.Name = "scrypt" },
		func(k *KDF) { k.Salt = k.Salt[:8] },
	}
	for i, mod := range cases {
		var f File
		json.Unmarshal(b, &f)
		mod(f.KDF)
		nb, _ := json.Marshal(f)
		start := time.Now()
		if _, err := Parse(nb); !errors.Is(err, ErrDamaged) {
			t.Fatalf("%d: %v", i, err)
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Fatalf("%d: slow", i)
		}
	}
}

func TestKDFSerialized(t *testing.T) {
	b, _ := Encode(sample(true), "password1")
	f, _ := Parse(b)
	var in, max atomic.Int32
	kdfHook = func() {
		n := in.Add(1)
		if n > max.Load() {
			max.Store(n)
		}
		time.Sleep(10 * time.Millisecond)
		in.Add(-1)
	}
	defer func() { kdfHook = nil }()
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if _, err := f.Open("password1"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if max.Load() != 1 {
		t.Fatalf("overlap %d", max.Load())
	}
}

func TestLimits(t *testing.T) {
	if _, err := Parse(make([]byte, MaxFile+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	// A gzip bomb inside a valid envelope.
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write([]byte(`{"app":"`))
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for range MaxPayload>>20 + 1 {
		zw.Write(chunk)
	}
	zw.Write([]byte(`"}`))
	zw.Close()
	k := DefaultKDF
	k.Salt = bytes.Repeat([]byte{1}, 16)
	f := &File{Format: Format, Version: Version, Encrypted: true, KDF: &k, Cipher: cipherName, Nonce: make([]byte, 12)}
	gcm, _ := newGCM("password1", &k)
	f.Data = gcm.Seal(nil, f.Nonce, z.Bytes(), aad(f))
	nb, _ := json.Marshal(f)
	pf, err := Parse(nb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pf.Open("password1"); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestPayloadUnknownTopLevel(t *testing.T) {
	env := func(payload string) *File {
		f, err := Parse([]byte(`{"format":"hyroute-backup","version":1,"encrypted":false,"payload":` + payload + `}`))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	p, err := env(`{"app":"9.0.0","secrets":false,"sections":{"rules":{}},"future":1,"alpha":{}}`).Open("")
	if err != nil || p.App != "9.0.0" || !reflect.DeepEqual(p.Unknown, []string{"alpha", "future"}) || p.Sections["rules"] == nil {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := env(`{"secrets":"x","sections":{}}`).Open(""); !errors.Is(err, ErrDamaged) {
		t.Fatal(err)
	}
	// A plain file never claims secrets: the envelope and the payload
	// would disagree (the subscriptions and statistics are password-only).
	if _, err := env(`{"secrets":true,"sections":{"subscriptions":[]}}`).Open(""); !errors.Is(err, ErrDamaged) || !strings.Contains(err.Error(), "secrets") {
		t.Fatal(err)
	}
	var many strings.Builder
	many.WriteString(`{"sections":{},"targets":{`)
	for i := range maxTargets + 1 {
		if i > 0 {
			many.WriteByte(',')
		}
		fmt.Fprintf(&many, `"%012x":{"name":"x"}`, i)
	}
	many.WriteString("}}")
	if _, err := env(many.String()).Open(""); !errors.Is(err, ErrDamaged) {
		t.Fatal(err)
	}
}

// legacyEncode writes a file the way HyRoute 1.2.0 did.
func legacyEncode(t *testing.T, kind, password string, payload []byte) []byte {
	t.Helper()
	f := legacyFile{Format: Format, Version: 1, Kind: kind, Created: time.Now().UTC(), App: "1.2.0"}
	if password == "" {
		f.Data = payload
	} else {
		s := &legacySeal{KDF: legacyKDF, Iter: 1000, Salt: bytes.Repeat([]byte{7}, 16), Nonce: bytes.Repeat([]byte{3}, 12)}
		key, _ := pbkdf2.Key(sha256.New, password, s.Salt, s.Iter, 32)
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		s.Box = gcm.Seal(nil, s.Nonce, payload, fmt.Appendf(nil, "%s/%d/%s", f.Format, f.Version, f.Kind))
		f.Sealed = s
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return b
}

func TestLegacy(t *testing.T) {
	payload := []byte(`{"settings":{"defaultAction":"direct","rules":[]}}`)
	f, err := Parse(legacyEncode(t, "full", "password1", payload))
	if err != nil || !f.IsLegacy() || !f.NeedsPassword() {
		t.Fatalf("%v", err)
	}
	if _, err := f.Open("wrong-pass"); !errors.Is(err, ErrPassword) {
		t.Fatal(err)
	}
	p, err := f.Open("password1")
	if err != nil || p.Legacy != "full" || !p.Secrets || !bytes.Equal(p.LegacyData, payload) || p.App != "1.2.0" {
		t.Fatalf("%+v %v", p, err)
	}
	f, err = Parse(legacyEncode(t, "rules", "", payload))
	if err != nil || f.NeedsPassword() {
		t.Fatal(err)
	}
	if p, err := f.Open(""); err != nil || p.Legacy != "rules" || p.Secrets {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := Parse([]byte(`{"format":"hyroute-backup","version":1,"kind":"full","data":{}}`)); !errors.Is(err, ErrDamaged) {
		t.Fatal("full without seal", err)
	}
}
