// Package update downloads and verifies HyRoute releases and swaps the
// program files with a rollback. The swap runs in hyroute-updater.exe
// after HyRoute has exited; see docs/ARCHITECTURE.md §15.6.
package update

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/release"
)

const (
	SumsName     = "SHA256SUMS"
	ManifestName = "manifest.json"
	// Required files of a release package.
	MainExe    = "HyRoute.exe"
	UpdaterExe = "hyroute-updater.exe"
)

// ZipName is the release asset for a version ("v0.5.0").
func ZipName(version string) string {
	return "HyRoute-" + strings.TrimPrefix(version, "v") + "-windows-amd64.zip"
}

// Manifest lists the package files and their SHA256 (inside the zip,
// whose own hash is in SHA256SUMS).
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

// Available is a newer HyRoute release.
type Available struct {
	Version   string    `json:"version"`
	Notes     string    `json:"notes"`
	Published time.Time `json:"published"`
	Page      string    `json:"page"`
	Size      int64     `json:"size"`
	zipURL    string
	sums      []string
}

// Check looks for a release newer than current. channel "beta" also
// accepts prereleases.
func Check(ctx context.Context, c *release.Client, repo, current, channel string) (Available, bool, error) {
	list, err := c.Releases(ctx, repo)
	if err != nil {
		return Available{}, false, err
	}
	r, ok := release.Latest(list, channel == "beta", func(tag string) bool { return strings.HasPrefix(tag, "v") })
	if !ok || release.Compare(r.Tag, current) <= 0 {
		return Available{}, false, nil
	}
	a, has := r.Asset(ZipName(r.Tag))
	if !has {
		return Available{}, false, fmt.Errorf("в релизе %s нет пакета %s", r.Tag, ZipName(r.Tag))
	}
	av := Available{Version: r.Tag, Notes: r.Body, Published: r.Published, Page: r.Page, Size: a.Size, zipURL: a.URL}
	if s, has := r.Asset(SumsName); has {
		if b, err := c.Fetch(ctx, s.URL); err == nil {
			if sum := release.SumFor(b, a.Name); sum != "" {
				av.sums = append(av.sums, sum)
			}
		}
	}
	if d := a.SHA256(); d != "" {
		av.sums = append(av.sums, d)
	}
	if len(av.sums) == 0 {
		return av, false, errors.New("у релиза нет контрольных сумм (SHA256SUMS): обновление небезопасно")
	}
	return av, true, nil
}

// Stage downloads the package into root\<version>, verifies it and
// extracts it into root\<version>\files. It returns that directory.
func Stage(ctx context.Context, c *release.Client, a Available, root string, progress func(done, total int64)) (string, error) {
	dir := filepath.Join(root, a.Version)
	os.RemoveAll(dir)
	zipPath := filepath.Join(dir, "package.zip")
	if _, err := c.Download(ctx, a.zipURL, zipPath, 300<<20, progress, a.sums...); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	files := filepath.Join(dir, "files")
	if err := extract(zipPath, files); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("пакет повреждён: %w", err)
	}
	m, err := Verify(files)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if release.Compare(m.Version, a.Version) != 0 {
		os.RemoveAll(dir)
		return "", fmt.Errorf("пакет версии %s вместо %s", m.Version, a.Version)
	}
	return files, nil
}

func extract(zipPath, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// Flat package only: no paths, no traversal.
		name := f.Name
		if name != filepath.Base(name) || strings.ContainsAny(name, `\/:`) || name == ".." {
			return fmt.Errorf("недопустимое имя в пакете: %q", name)
		}
		if f.UncompressedSize64 > 300<<20 {
			return fmt.Errorf("%s: слишком большой", name)
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(filepath.Join(dst, name))
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 300<<20))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Verify checks every file of the manifest in dir.
func Verify(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return m, errors.New("в пакете нет manifest.json")
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("manifest.json: %w", err)
	}
	for _, need := range []string{MainExe, UpdaterExe} {
		if _, ok := m.Files[need]; !ok {
			return m, fmt.Errorf("в пакете нет %s", need)
		}
	}
	for name, want := range m.Files {
		if name != filepath.Base(name) || name == ManifestName {
			return m, fmt.Errorf("недопустимое имя %q", name)
		}
		got, err := FileSHA256(filepath.Join(dir, name))
		if err != nil {
			return m, fmt.Errorf("%s: %w", name, err)
		}
		if !strings.EqualFold(got, want) {
			return m, fmt.Errorf("%s: контрольная сумма не совпала", name)
		}
	}
	return m, nil
}

func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Swap is an applied update that can still be undone.
type Swap struct {
	Target   string
	Replaced []string // names whose old version is <name>.old
	Added    []string // names that did not exist before
	journal  string   // removed on Commit and Undo (ApplyJournaled)
}

// Apply copies the manifest files from staging into target. Each replaced
// file is first renamed to <name>.old; identical files are skipped. On any
// error everything done so far is undone.
func Apply(staging, target string) (*Swap, error) {
	m, err := Verify(staging)
	if err != nil {
		return nil, err
	}
	sw := &Swap{Target: target}
	for name, sum := range m.Files {
		dst := filepath.Join(target, name)
		if cur, err := FileSHA256(dst); err == nil && strings.EqualFold(cur, sum) {
			continue
		}
		if err := sw.put(filepath.Join(staging, name), dst, name); err != nil {
			sw.Undo()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return sw, nil
}

func (sw *Swap) put(src, dst, name string) error {
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		os.Remove(dst + ".old")
		if err := os.Rename(dst, dst+".old"); err != nil {
			os.Remove(tmp)
			return err
		}
		sw.Replaced = append(sw.Replaced, name)
	} else {
		sw.Added = append(sw.Added, name)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	return nil
}

// Undo restores the previous files. The journal is removed only when
// everything was restored, so a failed undo is retried on the next start.
func (sw *Swap) Undo() error {
	var errs []error
	for _, n := range sw.Added {
		if err := removeOrSetAside(filepath.Join(sw.Target, n)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, n := range sw.Replaced {
		dst := filepath.Join(sw.Target, n)
		if err := removeOrSetAside(dst); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Rename(dst+".old", dst); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 && sw.journal != "" {
		os.Remove(sw.journal)
	}
	return errors.Join(errs...)
}

// Commit deletes the .old copies and the journal.
func (sw *Swap) Commit() {
	for _, n := range sw.Replaced {
		os.Remove(filepath.Join(sw.Target, n+".old"))
	}
	if sw.journal != "" {
		os.Remove(sw.journal)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
