//go:build !windows

package store

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// Not elevated elsewhere: the user's own rights apply. The writes still
// never follow a link at the target (the temp file is renamed over it).

// WriteUserFile writes b to path, a file the user picked.
func WriteUserFile(path string, b []byte) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return sentencef("«%s»: нужен полный путь", path)
	}
	dir, name := filepath.Split(path)
	if checkUserName(name) != nil {
		return sentencef("Недопустимое имя файла: «%s»", path) // the whole path: masked in Privacy mode
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if fi, err := root.Lstat(name); err == nil && fi.IsDir() {
		return sentencef("«%s» — это папка", path)
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	tmp := ".hyroute-" + hex.EncodeToString(rnd[:]) + ".tmp" // short: any valid name fits
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		root.Remove(tmp)
	}
	return err
}

// ReadUserFile reads at most max bytes of path, a regular file.
func ReadUserFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, sentencef("«%s» — не обычный файл", path)
	}
	if fi.Size() > max {
		return nil, ErrUserFileTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrUserFileTooLarge
	}
	return b, nil
}
