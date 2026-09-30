package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// selfSigned writes a certificate for 127.0.0.1 and its key.
func selfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hyroute-server test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	c, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(c)
	return certFile, keyFile, pool
}

func start(t *testing.T, args []string, dataDir string) (string, context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	env := func(k string) string {
		if k == "HYROUTE_SERVER_DATA_DIR" {
			return dataDir
		}
		return ""
	}
	go func() { done <- run(ctx, args, env, io.Discard, ready) }()
	select {
	case addr := <-ready:
		t.Cleanup(func() { cancel(); <-done })
		return addr, cancel, done
	case err := <-done:
		cancel()
		return "", nil, chanOf(err)
	case <-time.After(10 * time.Second):
		t.Fatal("not started")
	}
	return "", nil, nil
}

func chanOf(err error) chan error {
	c := make(chan error, 1)
	c <- err
	return c
}

func TestRunServesTLS(t *testing.T) {
	certFile, keyFile, pool := selfSigned(t, t.TempDir())
	addr, _, _ := start(t, []string{"-listen", "127.0.0.1:0", "-tls-cert", certFile, "-tls-key", keyFile}, filepath.Join(t.TempDir(), "data"))
	if addr == "" {
		t.Fatal("not started")
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	res, err := c.Get("https://" + addr + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("health %d", res.StatusCode)
	}
	// Plaintext on the TLS port gets nothing useful.
	if res, err := http.Get("http://" + addr + "/api/v1/health"); err == nil {
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Fatal("plaintext served")
		}
	}
}

func TestRunRefusesBadTLSFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not a certificate"), 0o644)
	_, _, done := start(t, []string{"-listen", "127.0.0.1:0", "-tls-cert", filepath.Join(dir, "cert.pem"), "-tls-key", filepath.Join(dir, "key.pem")}, filepath.Join(t.TempDir(), "data"))
	if err := <-done; err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("%v", err)
	}
}

// A data directory others can read is refused before anything is read
// from it.
func TestRunRefusesOpenDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows gets an ACL instead")
	}
	dir := filepath.Join(t.TempDir(), "data")
	os.Mkdir(dir, 0o700)
	os.Chmod(dir, 0o755)
	_, _, done := start(t, []string{"-listen", "127.0.0.1:0"}, dir)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("a master key was created in an open directory")
	}
	os.Chmod(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "master.key"), []byte("fake"), 0o644)
	_, _, done = start(t, []string{"-listen", "127.0.0.1:0"}, dir)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("%v", err)
	}
}
