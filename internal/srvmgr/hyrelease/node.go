package hyrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Node: another managed server provides the binary (P3-05), for a server
// that cannot reach GitHub when the controller cannot either. The node
// gives its installed binary when it is this release's file (the same
// version and architecture: the hash says so), or downloads the asset
// itself into a temporary directory and checks it; the controller moves
// it to the target in memory, never to disk, and the target checks it
// again.
type Node struct {
	// Server names the node for the log.
	Server string
	// Open connects to the node; sudo: its SSH user is not root.
	Open func(ctx context.Context) (ex remote.Executor, sudo bool, err error)
	// Installed is where Hysteria is on the node ("": nowhere known).
	Installed string
}

func (n *Node) Name() string { return "node" }

func (n *Node) Fetch(ctx context.Context, ex remote.Executor, a Asset, path string, sudo bool) error {
	b, err := n.binary(ctx, a)
	if err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, path, b, remote.FileSpec{Mode: fs.FileMode(0o600), Sudo: sudo}); err != nil {
		return fmt.Errorf("не удалось загрузить %s на сервер: %w", a.Name, err)
	}
	return verify(ctx, ex, a, path, sudo)
}

// binary is the asset as the node has it or downloads it, checked.
func (n *Node) binary(ctx context.Context, a Asset) ([]byte, error) {
	nx, su, err := n.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("нет подключения к серверу «%s»: %w", n.Server, err)
	}
	defer nx.Close()
	if n.Installed != "" {
		if sum, err := remote.FileSHA256(ctx, nx, n.Installed, su); err == nil && sum == a.SHA256 {
			if b, err := read(ctx, nx, n.Installed, su, a); err == nil {
				return b, nil
			}
		}
	}
	dir, err := remote.TempDir(ctx, nx, su)
	if err != nil {
		return nil, fmt.Errorf("сервер «%s» не создал временный каталог: %w", n.Server, err)
	}
	defer remote.RemoveTempDir(context.WithoutCancel(ctx), nx, dir, su)
	tmp := dir + "/hysteria"
	if err := remote.Download(ctx, nx, a.URL, tmp, su); err != nil {
		return nil, fmt.Errorf("сервер «%s» не скачал %s: %w", n.Server, a.Name, err)
	}
	if err := verify(ctx, nx, a, tmp, su); err != nil {
		return nil, err
	}
	return read(ctx, nx, tmp, su, a)
}

// read reads a binary of the node and checks it in memory. The executor
// bounds the read (sshexec stops at 32 MB with remote.ErrFileTooLarge);
// maxBinary is for one that does not.
func read(ctx context.Context, ex remote.Executor, path string, sudo bool, a Asset) ([]byte, error) {
	b, err := ex.ReadFile(ctx, path, sudo)
	if err != nil {
		return nil, err
	}
	if len(b) > maxBinary {
		return nil, fmt.Errorf("%s больше %d МБ", path, maxBinary>>20)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, fmt.Errorf("%w (%s)", ErrChecksum, a.Name)
	}
	return b, nil
}
