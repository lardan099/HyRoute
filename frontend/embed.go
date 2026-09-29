// Package frontend embeds the built UI (frontend/dist, committed) for the
// Wails asset server.
package frontend

import "embed"

// Dist holds dist/: the asset server serves the directory with index.html.
//
//go:embed all:dist
var Dist embed.FS
