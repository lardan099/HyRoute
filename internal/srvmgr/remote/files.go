package remote

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// Typed file operations for installing software. Paths are checked with
// CheckPath; the only URLs are https ones built by the caller from fixed
// hosts.

var tempDirRe = regexp.MustCompile(`^/tmp/hyroute\.[A-Za-z0-9]{10}$`)

// TempDir creates a private temporary directory (/tmp/hyroute.XXXXXXXXXX).
func TempDir(ctx context.Context, ex Executor, sudo bool) (string, error) {
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

// Rename moves src over dst (same filesystem: atomic).
func Rename(ctx context.Context, ex Executor, src, dst string, sudo bool) error {
	for _, p := range []string{src, dst} {
		if err := CheckPath(p); err != nil {
			return err
		}
	}
	_, err := run(ctx, ex, "mv", Cmd{Args: []string{"mv", "-f", "--", src, dst}, Sudo: sudo})
	return err
}

// CopyFile copies src to dst keeping mode and owner (a backup).
func CopyFile(ctx context.Context, ex Executor, src, dst string, sudo bool) error {
	for _, p := range []string{src, dst} {
		if err := CheckPath(p); err != nil {
			return err
		}
	}
	_, err := run(ctx, ex, "cp", Cmd{Args: []string{"cp", "-p", "--", src, dst}, Sudo: sudo})
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
