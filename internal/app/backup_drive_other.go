//go:build !windows

package app

// driveType: no drive letters here; a restored path is taken as local
// (tests fake it).
func driveType(string) uint32 { return driveFixed }
