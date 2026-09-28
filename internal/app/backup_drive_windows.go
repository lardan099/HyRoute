//go:build windows

package app

import "golang.org/x/sys/windows"

// driveType is GetDriveTypeW of a root like "C:\": the path is not opened.
func driveType(root string) uint32 {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0
	}
	return windows.GetDriveType(p)
}
