//go:build !windows

package store

// Outside Windows (tests) secrets are stored as is.
func seal(b []byte) ([]byte, error)   { return b, nil }
func unseal(b []byte) ([]byte, error) { return b, nil }
