// Package browser holds the HyRoute browser extension (extension/, a
// Chromium MV3 extension) and what installs it: the files HyRoute puts
// next to itself for «Загрузить распакованное», and the native messaging
// host manifest that lets the extension start hyroutectl.exe.
package browser

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lardan099/hyroute/internal/ctl"
)

//go:embed extension
var files embed.FS

// DirName is the extension's folder next to HyRoute.exe, HostFile its
// native messaging host manifest.
const (
	DirName  = "browser-extension"
	HostFile = "browser-host.json"
)

// ExtensionID is the ID Chromium gives an extension with this manifest
// "key" (base64 of the public key): the first 32 hex digits of its
// SHA-256, written with the letters a-p.
func ExtensionID(key string) string {
	der, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	id := make([]byte, 32)
	for i, b := range sum[:16] {
		id[2*i], id[2*i+1] = 'a'+b>>4, 'a'+b&15
	}
	return string(id)
}

// Version is the embedded extension's version (its manifest).
func Version() string {
	b, err := files.ReadFile("extension/manifest.json")
	if err != nil {
		return ""
	}
	var m struct {
		Version string `json:"version"`
	}
	json.Unmarshal(b, &m)
	return m.Version
}

// DiskVersion is the version of the extension in dir ("" when there is
// none).
func DiskVersion(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return ""
	}
	var m struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return m.Version
}

// Write puts the extension into dir: every file written anew, files of an
// older version that this one no longer has removed. Only files the
// extension could have had are touched (no subfolders but its own).
func Write(dir string) error {
	keep := map[string]bool{}
	err := fs.WalkDir(files, "extension", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, "extension"), "/")
		target := filepath.Join(dir, filepath.FromSlash(rel))
		keep[filepath.Clean(target)] = true
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		return writeFile(target, b)
	})
	if err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || keep[filepath.Clean(p)] {
			return err
		}
		if d.IsDir() {
			os.RemoveAll(p)
			return fs.SkipDir
		}
		return os.Remove(p)
	})
}

// writeFile replaces path through a temporary file next to it.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// HostManifest is the native messaging host manifest for hyroutectl at
// exe.
func HostManifest(exe string) []byte {
	b, _ := json.MarshalIndent(map[string]any{
		"name":            ctl.BrowserHost,
		"description":     "HyRoute",
		"path":            exe,
		"type":            "stdio",
		"allowed_origins": ctl.BrowserOrigins,
	}, "", "  ")
	return append(b, '\n')
}

// WriteHostManifest writes HostManifest(exe) to path unless it already
// says exactly that.
func WriteHostManifest(path, exe string) error {
	want := HostManifest(exe)
	if b, err := os.ReadFile(path); err == nil && string(b) == string(want) {
		return nil
	}
	return writeFile(path, want)
}

// Remove deletes the extension's folder and the host manifest.
func Remove(dir, manifest string) error {
	err := os.RemoveAll(dir)
	if e := os.Remove(manifest); e != nil && !errors.Is(e, fs.ErrNotExist) {
		err = errors.Join(err, e)
	}
	return err
}
