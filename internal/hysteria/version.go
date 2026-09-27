package hysteria

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"time"
)

var versionRe = regexp.MustCompile(`(?m)^Version:\s*(\S+)`)

// ExeVersion runs "hysteria version" and returns the version ("v2.12.3").
// A binary that does not answer like Hysteria is an error: this doubles as
// the "does the new core start at all" check.
func ExeVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = append(cmd.Environ(), "HYSTERIA_DISABLE_UPDATE_CHECK=1")
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	m := versionRe.FindSubmatch(out)
	if m == nil {
		return "", errors.New("не похоже на hysteria: нет строки Version")
	}
	return string(m[1]), nil
}
