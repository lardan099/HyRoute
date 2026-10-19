package remote

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// Typed file operations for installing software. Paths are checked with
// CheckPath; the only URLs are https ones built by the caller from fixed
// hosts.

var tempDirRe = regexp.MustCompile(`^/tmp/hyroute\.[A-Za-z0-9]{10}$`)

// TempDir creates a private temporary directory (/tmp/hyroute.XXXXXXXXXX).
// It first removes the ones older than a day: a job removes its own when
// it ends, so those are of a controller that died during a job (no job
// runs that long).
func TempDir(ctx context.Context, ex Executor, sudo bool) (string, error) {
	// Best effort: a find without -mmin (old BusyBox) only leaves them.
	ex.Run(ctx, Cmd{Args: []string{"find", "/tmp", "-maxdepth", "1", "-type", "d", "-name", "hyroute.??????????", "-mmin", "+1440",
		"-exec", "rm", "-rf", "--", "{}", "+"}, Sudo: sudo})
	out, err := run(ctx, ex, "mktemp", Cmd{Args: []string{"mktemp", "-d", "/tmp/hyroute.XXXXXXXXXX"}, Sudo: sudo})
	if err != nil {
		return "", err
	}
	if !tempDirRe.MatchString(out) {
		return "", fmt.Errorf("mktemp: unexpected path %q", out)
	}
	return out, nil
}

// RemoveTempDir deletes a directory made by TempDir (and nothing else).
func RemoveTempDir(ctx context.Context, ex Executor, dir string, sudo bool) error {
	if !tempDirRe.MatchString(dir) {
		return fmt.Errorf("not a temporary directory: %q", dir)
	}
	_, err := run(ctx, ex, "rm", Cmd{Args: []string{"rm", "-rf", "--", dir}, Sudo: sudo})
	return err
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FileSHA256 is the SHA-256 of a remote file, lowercase hex; "" when the
// file does not exist.
func FileSHA256(ctx context.Context, ex Executor, path string, sudo bool) (string, error) {
	if err := CheckPath(path); err != nil {
		return "", err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"sha256sum", "--", path}, Sudo: sudo})
	if err != nil {
		return "", err
	}
	if !res.OK() {
		if strings.Contains(string(res.Stderr), "No such file") {
			return "", nil
		}
		return "", &ExitError{Op: "sha256sum", Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	sum, _, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), " ")
	sum = strings.TrimPrefix(strings.ToLower(sum), `\`)
	if !hexRe.MatchString(sum) {
		return "", fmt.Errorf("sha256sum: unexpected output %q", res.Stdout)
	}
	return sum, nil
}

// Absent is the FileState of a missing file.
const Absent = "absent"

// ErrBackupMismatch: the backup of a file is not the file it was made
// from; RestoreFile left everything as it is.
var ErrBackupMismatch = errors.New("the backup does not match the recorded file")

// FileState is the SHA-256 of the file at path, or Absent. A job records
// it before changing the file, so a rollback knows what to go back to.
func FileState(ctx context.Context, ex Executor, path string, sudo bool) (string, error) {
	sum, err := FileSHA256(ctx, ex, path, sudo)
	if err != nil {
		return "", err
	}
	if sum == "" {
		return Absent, nil
	}
	return sum, nil
}

// RestoreFile brings path back to state (its FileState before the change)
// from backup, the copy made then. Nothing happens when path is in that
// state already; a state of Absent removes path. When backup is not the
// recorded file (the copy never finished, or it is from another run) it
// fails with ErrBackupMismatch and changes nothing. It reports whether it
// changed path.
func RestoreFile(ctx context.Context, ex Executor, path, backup, state string, sudo bool) (bool, error) {
	if state == "" {
		return false, errors.New("no recorded state")
	}
	cur, err := FileState(ctx, ex, path, sudo)
	if err != nil {
		return false, err
	}
	if cur == state {
		return false, nil
	}
	if state == Absent {
		return true, RemoveFile(ctx, ex, path, sudo)
	}
	b, err := FileState(ctx, ex, backup, sudo)
	if err != nil {
		return false, err
	}
	if b != state {
		return false, fmt.Errorf("%s: %w", path, ErrBackupMismatch)
	}
	return true, Rename(ctx, ex, backup, path, sudo)
}

// Download fetches an https URL to dest with curl, or wget when there is
// no curl.
func Download(ctx context.Context, ex Executor, url, dest string, sudo bool) error {
	if !strings.HasPrefix(url, "https://") || strings.ContainsAny(url, " \n\r\t'\"") {
		return errors.New("bad url")
	}
	if err := CheckPath(dest); err != nil {
		return err
	}
	curl, err := HasCommand(ctx, ex, "curl")
	if err != nil {
		return err
	}
	if curl {
		_, err = run(ctx, ex, "curl", Cmd{Args: []string{"curl", "-fsSL", "--retry", "2", "--connect-timeout", "20", "--max-time", "600", "-o", dest, "--", url}, Sudo: sudo})
		return err
	}
	wget, err := HasCommand(ctx, ex, "wget")
	if err != nil {
		return err
	}
	if !wget {
		return errors.New("на сервере нет ни curl, ни wget")
	}
	_, err = run(ctx, ex, "wget", Cmd{Args: []string{"wget", "-q", "-T", "60", "-t", "3", "-O", dest, "--", url}, Sudo: sudo})
	return err
}

var nameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// InstallFile copies src over dst atomically (a temporary file next to dst
// renamed over it), with mode and owner. A running program at dst keeps
// its old file.
func InstallFile(ctx context.Context, ex Executor, src, dst string, mode fs.FileMode, owner, group string, sudo bool) error {
	for _, p := range []string{src, dst} {
		if err := CheckPath(p); err != nil {
			return err
		}
	}
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	if !nameRe.MatchString(owner) || !nameRe.MatchString(group) {
		return errors.New("bad owner")
	}
	tmp := dst + ".hyroute-new"
	if _, err := run(ctx, ex, "install", Cmd{Args: []string{"install", "-m", fmt.Sprintf("%04o", mode.Perm()), "-o", owner, "-g", group, "--", src, tmp}, Sudo: sudo}); err != nil {
		return err
	}
	return Rename(ctx, ex, tmp, dst, sudo)
}

// Rename moves src over dst (same filesystem: atomic). dst is always the
// name itself (-T): a symlink there to a directory is replaced, never
// moved into.
func Rename(ctx context.Context, ex Executor, src, dst string, sudo bool) error {
	for _, p := range []string{src, dst} {
		if err := CheckPath(p); err != nil {
			return err
		}
	}
	_, err := run(ctx, ex, "mv", Cmd{Args: []string{"mv", "-fT", "--", src, dst}, Sudo: sudo})
	return err
}

// CopyFile copies src to dst keeping mode and owner (a backup). Whatever
// is at dst is removed first and dst made anew: a symlink there is never
// written through, so a backup next to a file in a directory the
// service's user can write cannot change another file.
func CopyFile(ctx context.Context, ex Executor, src, dst string, sudo bool) error {
	for _, p := range []string{src, dst} {
		if err := CheckPath(p); err != nil {
			return err
		}
	}
	_, err := run(ctx, ex, "cp", Cmd{Args: []string{"cp", "-p", "--remove-destination", "--", src, dst}, Sudo: sudo})
	return err
}

// RemoveFile deletes a file; a missing file is not an error.
func RemoveFile(ctx context.Context, ex Executor, path string, sudo bool) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	_, err := run(ctx, ex, "rm", Cmd{Args: []string{"rm", "-f", "--", path}, Sudo: sudo})
	return err
}

// MakeDir creates a directory (and parents) with mode and owner.
func MakeDir(ctx context.Context, ex Executor, path string, mode fs.FileMode, owner, group string, sudo bool) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	if !nameRe.MatchString(owner) || !nameRe.MatchString(group) {
		return errors.New("bad owner")
	}
	_, err := run(ctx, ex, "install", Cmd{Args: []string{"install", "-d", "-m", fmt.Sprintf("%04o", mode.Perm()), "-o", owner, "-g", group, "--", path}, Sudo: sudo})
	return err
}

// SetOwnerMode gives an existing file (or directory) an owner, a group
// and permission bits.
func SetOwnerMode(ctx context.Context, ex Executor, path string, mode fs.FileMode, owner, group string, sudo bool) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = "root"
	}
	if !nameRe.MatchString(owner) || !nameRe.MatchString(group) {
		return errors.New("bad owner")
	}
	if _, err := run(ctx, ex, "chown", Cmd{Args: []string{"chown", "--", owner + ":" + group, path}, Sudo: sudo}); err != nil {
		return err
	}
	_, err := run(ctx, ex, "chmod", Cmd{Args: []string{"chmod", "--", fmt.Sprintf("%04o", mode.Perm()), path}, Sudo: sudo})
	return err
}

// FileInfo is what stat tells about a file.
type FileInfo struct {
	Mode  fs.FileMode // permission bits
	Owner string
	Group string
	Size  int64
}

// Stat describes a file (symlinks followed); ok is false when it does not
// exist.
func Stat(ctx context.Context, ex Executor, path string, sudo bool) (fi FileInfo, ok bool, err error) {
	if err := CheckPath(path); err != nil {
		return fi, false, err
	}
	res, err := ex.Run(ctx, Cmd{Args: []string{"stat", "-L", "-c", "%a %U %G %s", "--", path}, Sudo: sudo})
	if err != nil {
		return fi, false, err
	}
	if !res.OK() {
		if strings.Contains(string(res.Stderr), "No such file") {
			return fi, false, nil
		}
		return fi, false, &ExitError{Op: "stat", Code: res.ExitCode, Stderr: strings.TrimSpace(string(res.Stderr))}
	}
	f := strings.Fields(string(res.Stdout))
	if len(f) != 4 {
		return fi, false, fmt.Errorf("stat: unexpected output %q", res.Stdout)
	}
	mode, err1 := strconv.ParseUint(f[0], 8, 32)
	size, err2 := strconv.ParseInt(f[3], 10, 64)
	if err1 != nil || err2 != nil {
		return fi, false, fmt.Errorf("stat: unexpected output %q", res.Stdout)
	}
	return FileInfo{Mode: fs.FileMode(mode) & fs.ModePerm, Owner: f[1], Group: f[2], Size: size}, true, nil
}
