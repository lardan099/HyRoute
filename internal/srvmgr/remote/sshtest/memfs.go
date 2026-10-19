package sshtest

import (
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// memFS is the SFTP view of SetFiles: those files only, read-only. Code
// that reads /proc or /etc of the server then sees the same Linux files on
// any machine the tests run on, not the files of that machine.
type memFS map[string]string

func (m memFS) handlers() sftp.Handlers {
	return sftp.Handlers{FileGet: m, FilePut: m, FileCmd: m, FileList: m}
}

func (m memFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	b, ok := m[r.Filepath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return strings.NewReader(b), nil
}

func (m memFS) Filewrite(*sftp.Request) (io.WriterAt, error) { return nil, os.ErrPermission }

func (m memFS) Filecmd(*sftp.Request) error { return os.ErrPermission }

func (m memFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	b, ok := m[r.Filepath]
	if !ok || (r.Method != "Stat" && r.Method != "Lstat") {
		return nil, os.ErrNotExist
	}
	return memList{memInfo{name: path.Base(r.Filepath), size: int64(len(b))}}, nil
}

type memList []fs.FileInfo

func (l memList) ListAt(f []fs.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return 0o444 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }
