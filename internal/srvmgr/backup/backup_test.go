package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

func init() {
	// Fast key derivation: the tests are about the format.
	kdfParams.time, kdfParams.memory, kdfParams.threads = 1, 64, 1
}

func TestCryptRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3 * chunkSize, 3*chunkSize + 17} {
		plain := make([]byte, size)
		rand.Read(plain)
		var sealed bytes.Buffer
		if err := encrypt(&sealed, bytes.NewReader(plain), "correct horse"); err != nil {
			t.Fatal(err)
		}
		if !Encrypted(sealed.Bytes()) {
			t.Fatalf("%d: no magic", size)
		}
		if size > 64 && bytes.Contains(sealed.Bytes(), plain[:64]) {
			t.Fatalf("%d: the plaintext is in the output", size)
		}
		var out bytes.Buffer
		if err := decrypt(&out, bytes.NewReader(sealed.Bytes()), "correct horse"); err != nil {
			t.Fatalf("%d: %v", size, err)
		}
		if !bytes.Equal(out.Bytes(), plain) {
			t.Fatalf("%d: round trip differs", size)
		}
		if err := decrypt(io.Discard, bytes.NewReader(sealed.Bytes()), "wrong horse"); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("%d: wrong passphrase: %v", size, err)
		}
	}
}

// Cut, extended or changed copies do not decrypt.
func TestCryptTamper(t *testing.T) {
	plain := make([]byte, 2*chunkSize+100)
	rand.Read(plain)
	var b bytes.Buffer
	if err := encrypt(&b, bytes.NewReader(plain), "pw"); err != nil {
		t.Fatal(err)
	}
	sealed := b.Bytes()
	full := chunkSize + tagSize
	cases := map[string][]byte{
		"cut at a chunk":      sealed[:headerSize+2*full],
		"cut in a chunk":      sealed[:len(sealed)-10],
		"no chunks":           sealed[:headerSize],
		"extra bytes":         append(append([]byte(nil), sealed...), 0),
		"chunks swapped":      append(append(append(append([]byte(nil), sealed[:headerSize]...), sealed[headerSize+full:headerSize+2*full]...), sealed[headerSize:headerSize+full]...), sealed[headerSize+2*full:]...),
		"flipped data byte":   flip(sealed, headerSize+5),
		"flipped header salt": flip(sealed, len(cryptMagic)+12),
	}
	for name, c := range cases {
		if err := decrypt(io.Discard, bytes.NewReader(c), "pw"); err == nil {
			t.Errorf("%s: decrypted", name)
		}
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 1
	return c
}

// fixture is a controller database with a master key and sealed values.
type fixture struct {
	dir, dbPath, keyFile string
	db                   *sqlite.DB
	keys                 *secrets.Keyring
	keyText              string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{dir: t.TempDir()}
	f.dbPath = filepath.Join(f.dir, "hyroute-server.db")
	f.keyFile = filepath.Join(f.dir, "master.key")
	db, err := sqlite.Open(ctx, f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f.db = db
	noEnv := func(string) string { return "" }
	if f.keys, _, err = secrets.Open(ctx, noEnv, f.keyFile, db); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.keyFile)
	f.keyText = string(b)
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	err = db.CreateServer(ctx, &srv, func(id int64) ([]model.Credential, error) {
		s, err := f.keys.SealString("canary-ssh-password", model.CredContext(id, model.CredSSHPassword))
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: s}}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// keysFrom loads the key the way the controller does.
func keysFrom(file string) func() (*secrets.Keyring, string, error) {
	return func() (*secrets.Keyring, string, error) {
		k, _, err := secrets.Load(func(string) string { return "" }, file)
		return k, "файла " + file, err
	}
}

func TestMakeListPrune(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	m := &Manager{DB: f.db, Dir: filepath.Join(f.dir, "backups"), Keep: 2, Now: func() time.Time { return now }}
	var names []string
	for range 3 {
		info, err := m.Make(ctx)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, info.Name)
		if runtime.GOOS != "windows" {
			st, _ := os.Stat(filepath.Join(m.Dir, info.Name))
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("copy mode %v", st.Mode().Perm())
			}
		}
	}
	// The same second: -2, -3 tell them apart; the oldest one is dropped.
	if names[0] != "hyroute-server-20261008-120000.db" || names[1] != "hyroute-server-20261008-120000-2.db" || names[2] != "hyroute-server-20261008-120000-3.db" {
		t.Fatalf("names %q", names)
	}
	os.WriteFile(filepath.Join(m.Dir, "notes.txt"), []byte("mine"), 0o600)
	list, err := m.List()
	if err != nil || len(list) != 2 || list[0].Name != names[2] || list[1].Name != names[1] {
		t.Fatalf("list %+v %v", list, err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "notes.txt")); err != nil {
		t.Fatal("prune removed a file of another name")
	}
	entries, _ := os.ReadDir(m.Dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover %s", e.Name())
		}
	}
	if last := m.Last(); last.Name != names[2] || last.Error != "" {
		t.Fatalf("last %+v", last)
	}

	for _, bad := range []string{"../hyroute-server.db", "notes.txt", "hyroute-server-20261008-120000.db/../x", names[0]} {
		if _, _, err := m.Open(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("open %q: %v", bad, err)
		}
	}
	r, info, err := m.Open(names[2])
	if err != nil || info.Name != names[2] {
		t.Fatal(err)
	}
	r.Close()
}

// Round makes a copy when none is there or the newest is Interval old.
func TestRound(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	m := &Manager{DB: f.db, Dir: filepath.Join(f.dir, "backups"), Keep: 5, Interval: 24 * time.Hour, Now: func() time.Time { return now }}
	count := func() int {
		l, _ := m.List()
		return len(l)
	}
	m.Round(ctx)
	if count() != 1 {
		t.Fatal("no first copy")
	}
	now = now.Add(23 * time.Hour)
	m.Round(ctx)
	if count() != 1 {
		t.Fatal("a copy before it was due")
	}
	now = now.Add(time.Hour)
	m.Round(ctx)
	if count() != 2 {
		t.Fatal("no copy when due")
	}
}

// Neither the copy nor the log holds the master key or the passphrase.
func TestNoKeyInCopy(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	var logs bytes.Buffer
	const pass = "canary-backup-passphrase"
	for _, p := range []string{"", pass} {
		m := &Manager{DB: f.db, Dir: filepath.Join(f.dir, "backups"), Passphrase: p, Interval: time.Hour,
			Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
		m.Round(ctx)
		list, _ := m.List()
		if len(list) == 0 {
			t.Fatal("no copy")
		}
		b, err := os.ReadFile(filepath.Join(m.Dir, list[0].Name))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f.keyText), "1:")))
		for _, needle := range [][]byte{[]byte(strings.TrimSpace(f.keyText)), raw, []byte(pass), []byte("canary-ssh-password")} {
			if bytes.Contains(b, needle) {
				t.Errorf("passphrase %q: the copy holds %q", p, needle)
			}
		}
		os.RemoveAll(m.Dir)
	}
	if strings.Contains(logs.String(), pass) || strings.Contains(logs.String(), strings.TrimSpace(f.keyText)) {
		t.Errorf("the log holds a secret: %s", logs.String())
	}
}

func TestRestore(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	m := &Manager{DB: src.db, Dir: filepath.Join(src.dir, "backups"), Passphrase: "pw"}
	info, err := m.Make(ctx)
	if err != nil {
		t.Fatal(err)
	}
	copyFile := filepath.Join(m.Dir, info.Name)

	target := func(t *testing.T, key string) (dir, dbPath, keyFile string) {
		dir = t.TempDir()
		keyFile = filepath.Join(dir, "master.key")
		if key != "" {
			os.WriteFile(keyFile, []byte(key), 0o600)
		}
		return dir, filepath.Join(dir, "hyroute-server.db"), keyFile
	}
	opts := func(dbPath, keyFile string) RestoreOptions {
		return RestoreOptions{File: copyFile, DB: dbPath, Passphrase: "pw", Keys: keysFrom(keyFile)}
	}
	noFiles := func(t *testing.T, dir string) {
		t.Helper()
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != "master.key" {
				t.Errorf("left %s", e.Name())
			}
		}
	}

	t.Run("right key", func(t *testing.T) {
		_, dbPath, keyFile := target(t, src.keyText)
		r, err := Restore(ctx, opts(dbPath, keyFile))
		if err != nil {
			t.Fatal(err)
		}
		if r.Schema != sqlite.KnownSchema() || len(r.Versions) != 1 || r.Versions[0] != 1 || r.Previous != "" {
			t.Fatalf("%+v", r)
		}
		db, err := sqlite.Open(ctx, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		keys, _, err := secrets.Open(ctx, func(string) string { return "" }, keyFile, db)
		if err != nil {
			t.Fatalf("the controller would not start: %v", err)
		}
		srvs, err := db.ListServers(ctx)
		if err != nil || len(srvs) != 1 {
			t.Fatalf("servers %v %v", srvs, err)
		}
		creds, err := db.ServerCredentials(ctx, srvs[0].ID)
		if err != nil || len(creds) != 1 {
			t.Fatalf("creds %v %v", creds, err)
		}
		if p, err := keys.OpenString(creds[0].Sealed, model.CredContext(srvs[0].ID, creds[0].Kind)); err != nil || p != "canary-ssh-password" {
			t.Fatalf("credential %q %v", p, err)
		}
		if runtime.GOOS != "windows" {
			st, _ := os.Stat(dbPath)
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("restored mode %v", st.Mode().Perm())
			}
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, _ := secrets.NewKeyText()
		dir, dbPath, keyFile := target(t, other)
		if _, err := Restore(ctx, opts(dbPath, keyFile)); !errors.Is(err, secrets.ErrKeyMismatch) {
			t.Fatalf("%v, want ErrKeyMismatch", err)
		}
		noFiles(t, dir)
	})

	t.Run("no key", func(t *testing.T) {
		dir, dbPath, keyFile := target(t, "")
		if _, err := Restore(ctx, opts(dbPath, keyFile)); !errors.Is(err, secrets.ErrNoKey) {
			t.Fatalf("%v, want ErrNoKey", err)
		}
		noFiles(t, dir)
	})

	t.Run("passphrase", func(t *testing.T) {
		dir, dbPath, keyFile := target(t, src.keyText)
		o := opts(dbPath, keyFile)
		o.Passphrase = ""
		if _, err := Restore(ctx, o); !errors.Is(err, ErrNeedPassphrase) {
			t.Fatalf("no passphrase: %v", err)
		}
		o.Passphrase = "nope"
		if _, err := Restore(ctx, o); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("wrong passphrase: %v", err)
		}
		noFiles(t, dir)
	})

	t.Run("database in use", func(t *testing.T) {
		_, dbPath, keyFile := target(t, src.keyText)
		cur, err := sqlite.Open(ctx, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		u := model.User{Username: "someone", PasswordHash: "h", Role: model.RoleOwner, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := cur.CreateUser(ctx, &u); err != nil {
			t.Fatal(err)
		}
		cur.Close()
		before, _ := os.ReadFile(dbPath)
		if _, err := Restore(ctx, opts(dbPath, keyFile)); !errors.Is(err, ErrInUse) {
			t.Fatalf("%v, want ErrInUse", err)
		}
		if after, _ := os.ReadFile(dbPath); !bytes.Equal(before, after) {
			t.Fatal("the database in use changed")
		}
		o := opts(dbPath, keyFile)
		o.Force = true
		o.Now = func() time.Time { return time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC) }
		r, err := Restore(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		if r.Previous != dbPath+".before-restore-20261008-093000" {
			t.Fatalf("previous %q", r.Previous)
		}
		prev, err := sqlite.OpenExisting(ctx, r.Previous)
		if err != nil {
			t.Fatal(err)
		}
		defer prev.Close()
		if u2, err := prev.UserByName(ctx, "someone"); err != nil || u2.ID != u.ID {
			t.Fatalf("the previous database lost its user: %v", err)
		}
	})

	t.Run("an unused database is replaced", func(t *testing.T) {
		_, dbPath, keyFile := target(t, src.keyText)
		cur, err := sqlite.Open(ctx, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		cur.Close()
		if r, err := Restore(ctx, opts(dbPath, keyFile)); err != nil || r.Previous != "" {
			t.Fatalf("%+v %v", r, err)
		}
	})
}

// A copy of a newer schema or a damaged one is refused before anything
// is written.
func TestRestoreRefusesNewerAndDamaged(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "master.key")
	os.WriteFile(keyFile, []byte(src.keyText), 0o600)
	dbPath := filepath.Join(dir, "hyroute-server.db")

	plain := filepath.Join(src.dir, "copy.db")
	if err := Write(ctx, src.db, src.dir, plain, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(plain)
	damaged := filepath.Join(src.dir, "damaged.db")
	// Every page after the first: the header stays readable, the tables
	// do not.
	for i := 4096; i < len(b); i++ {
		b[i] ^= 0x5a
	}
	os.WriteFile(damaged, b, 0o600)
	if _, err := Restore(ctx, RestoreOptions{File: damaged, DB: dbPath, Keys: keysFrom(keyFile)}); err == nil {
		t.Fatal("a damaged copy was restored")
	}

	raw, err := sql.Open("sqlite", src.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, 'future', 0)`, sqlite.KnownSchema()+1); err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(src.dir, "newer.db")
	if err := Write(ctx, src.db, src.dir, newer, ""); err != nil {
		t.Fatal(err)
	}
	_, err = Restore(ctx, RestoreOptions{File: newer, DB: dbPath, Keys: keysFrom(keyFile)})
	if !sqlite.IsNewerSchema(err) {
		t.Fatalf("%v, want the newer schema refused", err)
	}
	if _, err := os.Stat(dbPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a database appeared")
	}
}
