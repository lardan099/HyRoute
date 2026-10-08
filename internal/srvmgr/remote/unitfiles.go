package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// UnitFiles are the files systemd builds a unit from: its unit file
// (FragmentPath) and its drop-ins (DropInPaths, systemctl edit), in
// systemd's order; nil when systemd has no such unit.
func UnitFiles(ctx context.Context, ex Executor, name string) ([]string, error) {
	if err := CheckUnitName(name); err != nil {
		return nil, err
	}
	out, err := run(ctx, ex, "systemctl show", Cmd{Args: []string{"systemctl", "show", "--no-pager", "-p", "LoadState,FragmentPath,DropInPaths", "--", name}})
	if err != nil {
		return nil, err
	}
	var load, fragment, dropIns string
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "LoadState":
			load = v
		case "FragmentPath":
			fragment = v
		case "DropInPaths":
			dropIns = v
		}
	}
	if load == "not-found" || fragment == "" {
		return nil, nil
	}
	files := append([]string{fragment}, strings.Fields(dropIns)...)
	for _, f := range files {
		if err := CheckPath(f); err != nil {
			return nil, fmt.Errorf("systemctl show %s: %w", name, err)
		}
	}
	return files, nil
}

// UnitSHA256 is the fingerprint of a unit a reconciliation compares
// (P4-06): the SHA-256 of its unit file, or with drop-ins the SHA-256 of
// the lines "<sha256>  <path>" of the file and each drop-in in order (a
// missing file has an empty sum). A unit HyRoute wrote without drop-ins
// has the SHA-256 of the text it wrote. "" when systemd has no such unit.
// files are the unit's files.
func UnitSHA256(ctx context.Context, ex Executor, name string, sudo bool) (sum string, files []string, err error) {
	files, err = UnitFiles(ctx, ex, name)
	if err != nil || len(files) == 0 {
		return "", files, err
	}
	sums := make([]string, len(files))
	for i, f := range files {
		if sums[i], err = FileSHA256(ctx, ex, f, sudo); err != nil {
			return "", files, err
		}
	}
	if len(files) == 1 {
		return sums[0], files, nil
	}
	var b strings.Builder
	for i, f := range files {
		fmt.Fprintf(&b, "%s  %s\n", sums[i], f)
	}
	s := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(s[:]), files, nil
}
