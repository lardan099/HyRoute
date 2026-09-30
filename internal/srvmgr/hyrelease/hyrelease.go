// Package hyrelease finds a Hysteria server binary for a machine and puts
// it on the machine verified: the asset for the architecture, its SHA-256
// (pinned in HyRoute for the default version, else from the release's
// hashes.txt) and a Source that gets the file onto the server.
package hyrelease

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DefaultVersion is the Hysteria version deployed unless another is asked
// for. Its hashes are pinned (pinned.go).
const DefaultVersion = "v2.12.3"

// GitHub is where releases come from.
const GitHub = "https://github.com/apernet/hysteria/releases/download"

var versionRe = regexp.MustCompile(`^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// CheckVersion validates a version tag ("v2.12.3").
func CheckVersion(v string) error {
	if !versionRe.MatchString(v) {
		return fmt.Errorf("неверная версия %q (нужно вида v2.12.3)", v)
	}
	return nil
}

// Asset is one binary of a release.
type Asset struct {
	Version string `json:"version"`
	Name    string `json:"name"` // hysteria-linux-amd64
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// AssetName is the Linux binary for a release-asset architecture (as in
// the preflight report: amd64, arm64, arm, 386…). The plain amd64 build is
// used, not amd64-avx: it runs on every x86-64 CPU.
func AssetName(arch string) (string, error) {
	switch arch {
	case "amd64", "arm64", "arm", "armv5", "386", "s390x", "riscv64", "mipsle", "mipsle-sf", "loong64":
		return "hysteria-linux-" + arch, nil
	}
	return "", fmt.Errorf("для архитектуры %q нет сборки Hysteria", arch)
}

// ParseHashes reads a release's hashes.txt ("<sha256>  build/<name>").
func ParseHashes(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		sum := strings.ToLower(f[0])
		if !hexRe.MatchString(sum) {
			continue
		}
		name := f[1][strings.LastIndex(f[1], "/")+1:]
		out[strings.TrimPrefix(name, "*")] = sum
	}
	if len(out) == 0 {
		return nil, errors.New("hashes.txt: нет ни одной строки с хешем")
	}
	return out, nil
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Resolver finds assets and their hashes.
type Resolver struct {
	HTTP *http.Client
	// Base replaces GitHub (tests).
	Base string
}

func (r *Resolver) base() string {
	if r.Base != "" {
		return r.Base
	}
	return GitHub
}

func (r *Resolver) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

// URL is the download URL of a release file.
func (r *Resolver) URL(version, name string) string {
	return r.base() + "/app/" + version + "/" + name
}

// Resolve returns the asset for a version and architecture with its
// SHA-256. The default version uses the pinned hashes and needs no
// network; others read hashes.txt of the release.
func (r *Resolver) Resolve(ctx context.Context, version, arch string) (Asset, error) {
	if version == "" {
		version = DefaultVersion
	}
	if err := CheckVersion(version); err != nil {
		return Asset{}, err
	}
	name, err := AssetName(arch)
	if err != nil {
		return Asset{}, err
	}
	a := Asset{Version: version, Name: name, URL: r.URL(version, name)}
	if sums, ok := pinned[version]; ok {
		if a.SHA256 = sums[name]; a.SHA256 == "" {
			return Asset{}, fmt.Errorf("в релизе %s нет %s", version, name)
		}
		return a, nil
	}
	b, err := r.get(ctx, r.URL(version, "hashes.txt"), 1<<20)
	if err != nil {
		return Asset{}, fmt.Errorf("не удалось получить хеши релиза %s: %w", version, err)
	}
	sums, err := ParseHashes(b)
	if err != nil {
		return Asset{}, err
	}
	if a.SHA256 = sums[name]; a.SHA256 == "" {
		return Asset{}, fmt.Errorf("в релизе %s нет %s", version, name)
	}
	return a, nil
}

// Fetch downloads a release file to memory (at most limit bytes).
func (r *Resolver) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("файл слишком большой")
	}
	return b, nil
}
