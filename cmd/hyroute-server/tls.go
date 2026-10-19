package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// certFiles serves the admin's certificate from its PEM files and reads
// them again when they change: a renewed certificate needs no restart.
type certFiles struct {
	cert, key string
	log       *slog.Logger

	mu      sync.Mutex
	c       *tls.Certificate
	mod     time.Time // of the files loaded
	checked time.Time
}

// recheck is how often the files are looked at, at most.
const recheck = 30 * time.Second

func loadCert(cert, key string, log *slog.Logger) (*certFiles, error) {
	f := &certFiles{cert: cert, key: key, log: log}
	if _, err := f.get(); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return f, nil
}

func (f *certFiles) modTime() (time.Time, error) {
	var mod time.Time
	for _, p := range []string{f.cert, f.key} {
		st, err := os.Stat(p)
		if err != nil {
			return mod, err
		}
		if st.ModTime().After(mod) {
			mod = st.ModTime()
		}
	}
	return mod, nil
}

func (f *certFiles) get() (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.c != nil && now.Sub(f.checked) < recheck {
		return f.c, nil
	}
	f.checked = now
	mod, err := f.modTime()
	if f.c != nil && (err != nil || mod.Equal(f.mod)) {
		return f.c, nil
	}
	c, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		if f.c != nil {
			// A renewal half-written: keep serving the old pair.
			f.log.Warn("tls certificate not reloaded", "err", err)
			return f.c, nil
		}
		return nil, err
	}
	if f.c != nil {
		f.log.Info("tls certificate reloaded", "file", f.cert)
	}
	f.c, f.mod = &c, mod
	return f.c, nil
}

func (f *certFiles) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) { return f.get() }
