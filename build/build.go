// Package build holds the build inputs HyRoute.exe embeds: the pinned
// runtime dependencies and the app icon. build/windows also has the
// go-winres configs for the exe resources (scripts/build.ps1).
package build

import _ "embed"

// Deps is deps.json: versions and SHA-256 of hysteria.exe and WinDivert.
// The copies in the program folder are checked against it before they run
// elevated; scripts/fetch-deps.ps1 downloads by it.
//
//go:embed deps.json
var Deps []byte

// Icon is the app icon (PNG), also the source of the tray icons.
//
//go:embed windows/icon.png
var Icon []byte
