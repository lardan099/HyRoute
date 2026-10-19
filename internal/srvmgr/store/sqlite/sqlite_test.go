package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileURI(t *testing.T) {
	cases := map[string]string{
		"/var/lib/hyroute-server/hyroute-server.db": "file:///var/lib/hyroute-server/hyroute-server.db",
		"/srv/a#b/c%41 d?.db":                       "file:///srv/a%23b/c%2541 d%3F.db",
	}
	if runtime.GOOS == "windows" {
		cases = map[string]string{
			`C:\ProgramData\HyRoute Server\hyroute-server.db`: "file:///C:/ProgramData/HyRoute Server/hyroute-server.db",
			`D:\a#b\c%41.db`: "file:///D:/a%23b/c%2541.db",
		}
	}
	for path, want := range cases {
		if got, err := fileURI(path); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", path, got, err, want)
		}
	}
}

// A path with characters that mean something in a URI opens that very
// file, the one Open created owner-only, and no other.
func TestOpenPathWithURICharacters(t *testing.T) {
	names := []string{"a#b.db", "a%41.db", "a b%.db"}
	if runtime.GOOS != "windows" {
		names = append(names, "a?mode=memory.db")
	}
	for _, name := range names {
		root := t.TempDir()
		dir := filepath.Join(root, "data#1")
		path := filepath.Join(dir, name)
		d, err := Open(context.Background(), path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v, err := d.SchemaVersion(context.Background()); err != nil || v == 0 {
			t.Fatalf("%s: schema version %d %v", name, v, err)
		}
		d.Close()
		if st, err := os.Stat(path); err != nil || st.Size() == 0 {
			t.Errorf("%s: the database is not in its file: %v", name, err)
		}
		for _, d := range []string{root, dir} {
			entries, _ := os.ReadDir(d)
			for _, e := range entries {
				if e.Name() != "data#1" && e.Name() != name {
					t.Errorf("%s: another file %s", name, filepath.Join(d, e.Name()))
				}
			}
		}
	}
}
