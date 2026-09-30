package hyrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sync"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// A Source puts a verified binary on the server. Phase 3 adds a source
// through another managed node; the deploy only sees this interface.
type Source interface {
	// Name is how the log calls the source ("direct", "relay").
	Name() string
	// Fetch leaves the asset at path (inside a temporary directory the
	// caller made), checked against a.SHA256 on the server.
	Fetch(ctx context.Context, ex remote.Executor, a Asset, path string, sudo bool) error
}

// ErrChecksum means the file does not match the release hash.
var ErrChecksum = errors.New("SHA-256 файла не совпадает с хешем релиза")

// Direct: the server downloads the file itself.
type Direct struct{}

func (Direct) Name() string { return "direct" }

func (Direct) Fetch(ctx context.Context, ex remote.Executor, a Asset, path string, sudo bool) error {
	if err := remote.Download(ctx, ex, a.URL, path, sudo); err != nil {
		return fmt.Errorf("сервер не скачал %s: %w", a.Name, err)
	}
	return verify(ctx, ex, a, path, sudo)
}

// Relay: the controller downloads and checks the file and uploads it over
// SFTP. For servers that cannot reach GitHub.
type Relay struct {
	R *Resolver

	mu sync.Mutex
	// last keeps the latest verified binary: deploying a fleet downloads
	// it once.
	last    []byte
	lastSum string
}

// NewRelay is a relay source downloading through r.
func NewRelay(r *Resolver) *Relay { return &Relay{R: r} }

func (r *Relay) binary(ctx context.Context, a Asset) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastSum == a.SHA256 {
		return r.last, nil
	}
	b, err := r.R.get(ctx, a.URL, maxBinary)
	if err != nil {
		return nil, fmt.Errorf("controller не скачал %s: %w", a.Name, err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, fmt.Errorf("%w (%s)", ErrChecksum, a.Name)
	}
	r.last, r.lastSum = b, a.SHA256
	return b, nil
}

func (*Relay) Name() string { return "relay" }

// maxBinary bounds a download (Hysteria binaries are about 20 MB).
const maxBinary = 200 << 20

func (r *Relay) Fetch(ctx context.Context, ex remote.Executor, a Asset, path string, sudo bool) error {
	b, err := r.binary(ctx, a)
	if err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, path, b, remote.FileSpec{Mode: fs.FileMode(0o600), Sudo: sudo}); err != nil {
		return fmt.Errorf("не удалось загрузить %s на сервер: %w", a.Name, err)
	}
	// The upload is checked on the server too.
	return verify(ctx, ex, a, path, sudo)
}

func verify(ctx context.Context, ex remote.Executor, a Asset, path string, sudo bool) error {
	sum, err := remote.FileSHA256(ctx, ex, path, sudo)
	if err != nil {
		return err
	}
	if sum != a.SHA256 {
		return fmt.Errorf("%w (%s)", ErrChecksum, a.Name)
	}
	return nil
}
