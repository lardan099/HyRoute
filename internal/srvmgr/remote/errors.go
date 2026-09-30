package remote

import (
	"errors"
	"fmt"
)

// HostKeyUnknownError: the server has no trusted host key yet. The admin
// compares Fingerprint with the server (ssh-keygen -lf) and trusts it.
type HostKeyUnknownError struct {
	KeyType     string
	Fingerprint string // SHA256:… as ssh-keygen prints it
}

func (e *HostKeyUnknownError) Error() string {
	return fmt.Sprintf("host key %s %s is not trusted yet", e.KeyType, e.Fingerprint)
}

// HostKeyChangedError: the server presented another key than the trusted
// one. It may be a reinstall or a man in the middle; nothing connects
// until the admin explicitly trusts the new key.
type HostKeyChangedError struct {
	KeyType        string
	Fingerprint    string
	OldKeyType     string
	OldFingerprint string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("host key changed: trusted %s %s, got %s %s", e.OldKeyType, e.OldFingerprint, e.KeyType, e.Fingerprint)
}

var (
	// ErrAuthFailed: the server refused the SSH credentials.
	ErrAuthFailed = errors.New("ssh authentication failed")
	// ErrSudoRequired: the SSH user is not root and cannot sudo without a
	// password.
	ErrSudoRequired = errors.New("root or passwordless sudo required")
)

// UnreachableError: no SSH connection (DNS, refused, timeout).
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return "ssh unreachable: " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// ExitError: a typed operation's program failed.
type ExitError struct {
	Op     string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s: exit code %d: %s", e.Op, e.Code, e.Stderr)
}
