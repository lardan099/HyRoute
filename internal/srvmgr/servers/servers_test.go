package servers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// Fake credentials made for these tests.
const (
	fakePass       = "fake-ssh-password-7Q2x"
	fakePassphrase = "fake-key-passphrase-9Z"
)

func newService(t *testing.T) (*Service, *sqlite.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sqlite.Open(context.Background(), filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, err := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	s := New(db, keys)
	s.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return s, db, dir
}

func genKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var blk *pem.Block
	var err error
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(blk))
}

func ptr(s string) *string { return &s }

func base() Input {
	return Input{Name: "Frankfurt 1", Host: "vps.example.com", AuthType: model.AuthPassword, Password: ptr(fakePass), Tags: []string{"de", "DE", " prod "}, Country: "de"}
}

func fieldOf(err error) string {
	var fe *model.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestCreateDefaultsAndValidation(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	info, err := s.Create(ctx, 1, base())
	if err != nil {
		t.Fatal(err)
	}
	if info.SSHPort != 22 || info.SSHUser != "root" || info.Role != model.RoleStandalone || info.State != model.StateNew || info.Country != "DE" {
		t.Fatalf("defaults: %+v", info.Server)
	}
	if len(info.Tags) != 2 || info.Tags[1] != "prod" {
		t.Fatalf("tags %q", info.Tags)
	}
	if !info.HasPassword || info.HasKey {
		t.Fatalf("credential flags %+v", info)
	}
	c, err := s.Credentials(ctx, info.ID)
	if err != nil || c.Password != fakePass {
		t.Fatalf("credentials %v", err)
	}

	bad := map[string]func(*Input){
		"name":     func(in *Input) { in.Name = "Frankfurt 1" }, // duplicate
		"host":     func(in *Input) { in.Host = "https://vps.example.com:22" },
		"sshPort":  func(in *Input) { in.SSHPort = 70000 },
		"sshUser":  func(in *Input) { in.SSHUser = "root; rm -rf /" },
		"country":  func(in *Input) { in.Country = "Germany" },
		"authType": func(in *Input) { in.AuthType = "telnet" },
		"password": func(in *Input) { in.Password = nil },
		"key":      func(in *Input) { in.AuthType, in.Password, in.Key = model.AuthKey, nil, ptr("not a key") },
	}
	for field, mut := range bad {
		in := base()
		if field != "name" {
			in.Name = "other " + field
		}
		mut(&in)
		if _, err := s.Create(ctx, 1, in); fieldOf(err) != field {
			t.Errorf("%s: got %v", field, err)
		}
	}
	for _, h := range []string{"203.0.113.10", "2001:db8::1", "[2001:db8::2]", "a.b-c.example"} {
		in := base()
		in.Name, in.Host = "ok "+h, h
		if _, err := s.Create(ctx, 1, in); err != nil {
			t.Errorf("host %q: %v", h, err)
		}
	}
}

func TestKeyAuth(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	in := base()
	in.AuthType, in.Password = model.AuthKey, nil

	in.Key = ptr(genKey(t, fakePassphrase))
	if _, err := s.Create(ctx, 1, in); fieldOf(err) != "keyPassphrase" {
		t.Fatalf("encrypted key without passphrase: %v", err)
	}
	in.KeyPassphrase = ptr("wrong passphrase")
	if _, err := s.Create(ctx, 1, in); fieldOf(err) != "keyPassphrase" {
		t.Fatalf("wrong passphrase: %v", err)
	}
	in.KeyPassphrase = ptr(fakePassphrase)
	info, err := s.Create(ctx, 1, in)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasKey || !info.HasKeyPassphrase || info.HasPassword {
		t.Fatalf("%+v", info)
	}
	c, _ := s.Credentials(ctx, info.ID)
	if _, err := ssh.ParsePrivateKeyWithPassphrase(c.Key, []byte(c.KeyPassphrase)); err != nil {
		t.Fatalf("stored key does not parse: %v", err)
	}
}

func TestUpdateCredentials(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	info, _ := s.Create(ctx, 1, base())

	// Fields change, the password stays when not sent.
	in := base()
	in.Password, in.Notes, in.SSHPort = nil, "reinstalled", 2222
	got, err := s.Update(ctx, 1, info.ID, in)
	if err != nil || got.Notes != "reinstalled" || got.SSHPort != 2222 || !got.HasPassword {
		t.Fatalf("%+v %v", got, err)
	}
	if c, _ := s.Credentials(ctx, info.ID); c.Password != fakePass {
		t.Fatal("password lost")
	}
	// Switching to a key drops the password; a key is required.
	in.AuthType = model.AuthKey
	if _, err := s.Update(ctx, 1, info.ID, in); fieldOf(err) != "key" {
		t.Fatalf("switch without key: %v", err)
	}
	in.Key = ptr(genKey(t, ""))
	got, err = s.Update(ctx, 1, info.ID, in)
	if err != nil || !got.HasKey || got.HasPassword {
		t.Fatalf("%+v %v", got, err)
	}
	// Keeping the key, adding nothing: still valid.
	in.Key = nil
	if _, err := s.Update(ctx, 1, info.ID, in); err != nil {
		t.Fatal(err)
	}
	// Back to a password: required again.
	in.AuthType = model.AuthPassword
	if _, err := s.Update(ctx, 1, info.ID, in); fieldOf(err) != "password" {
		t.Fatalf("switch without password: %v", err)
	}
	if _, err := s.Update(ctx, 1, 999, in); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing server: %v", err)
	}
}

func TestDelete(t *testing.T) {
	s, db, _ := newService(t)
	ctx := context.Background()
	info, _ := s.Create(ctx, 1, base())
	if err := s.Delete(ctx, 1, info.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, info.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("server still there")
	}
	if cs, _ := db.ServerCredentials(ctx, info.ID); len(cs) != 0 {
		t.Fatal("credentials left after delete")
	}
	if err := s.Delete(ctx, 1, info.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if es, _ := db.ListAudit(ctx, 10); len(es) < 2 || es[0].Action != "server_deleted" {
		t.Fatalf("audit %+v", es)
	}
}

// Credentials are sealed: no file of the database (main, WAL, SHM) holds
// them in the clear, and a sealed value does not open for another server.
func TestNoPlaintextSecretsInDatabase(t *testing.T) {
	s, db, dir := newService(t)
	ctx := context.Background()
	key := genKey(t, fakePassphrase)
	in := base()
	s.Create(ctx, 1, in)
	in2 := base()
	in2.Name, in2.AuthType, in2.Password, in2.Key, in2.KeyPassphrase = "Key server", model.AuthKey, nil, ptr(key), ptr(fakePassphrase)
	info2, err := s.Create(ctx, 1, in2)
	if err != nil {
		t.Fatal(err)
	}
	keyBody := key[40:80] // a piece of the base64 body
	files, _ := filepath.Glob(filepath.Join(dir, "t.db*"))
	if len(files) == 0 {
		t.Fatal("no database files")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, secret := range []string{fakePass, fakePassphrase, keyBody} {
			if bytes.Contains(b, []byte(secret)) {
				t.Fatalf("%s holds %q in the clear", filepath.Base(f), secret)
			}
		}
	}
	cs, _ := db.ServerCredentials(ctx, info2.ID)
	for _, c := range cs {
		if _, err := s.Keys.Open(c.Sealed, model.CredContext(info2.ID+1, c.Kind)); err == nil {
			t.Fatal("sealed credential opens for another server")
		}
	}
}

func TestAddressChangeForgetsHostKey(t *testing.T) {
	s, db, _ := newService(t)
	ctx := context.Background()
	info, _ := s.Create(ctx, 1, base())
	db.SetHostKey(ctx, model.HostKey{ServerID: info.ID, Type: "ssh-ed25519", Key: []byte{1}, Fingerprint: "SHA256:fake", TrustedAt: time.Unix(1, 0)})
	in := base()
	in.Password, in.Notes = nil, "same address"
	got, _ := s.Update(ctx, 1, info.ID, in)
	if got.HostKey == nil || got.HostKey.Fingerprint != "SHA256:fake" {
		t.Fatal("host key dropped without an address change")
	}
	in.Host = "other.example.com"
	got, _ = s.Update(ctx, 1, info.ID, in)
	if got.HostKey != nil {
		t.Fatal("host key kept for another address")
	}
}

// An edit keeps the state a job wrote meanwhile: the copy Update read
// before it may be stale.
func TestUpdateKeepsState(t *testing.T) {
	s, db, _ := newService(t)
	ctx := context.Background()
	info, _ := s.Create(ctx, 1, base())
	if err := db.SetServerState(ctx, info.ID, model.StateDeploying, time.Now()); err != nil {
		t.Fatal(err)
	}
	stale, _ := db.ServerByID(ctx, info.ID)
	db.SetServerState(ctx, info.ID, model.StateHealthy, time.Now()) // the job ended
	stale.Notes = "edited"
	if err := db.UpdateServer(ctx, &stale, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ServerByID(ctx, info.ID); got.State != model.StateHealthy || got.Notes != "edited" {
		t.Fatalf("%s %q", got.State, got.Notes)
	}
}
