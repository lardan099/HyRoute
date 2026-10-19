// Package admin embeds the built web admin (web/admin/dist, committed) of
// hyroute-server.
package admin

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS is the admin app: a directory with index.html and assets/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the pattern above guarantees the directory
	}
	return sub
}
