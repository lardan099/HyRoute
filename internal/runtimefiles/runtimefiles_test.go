package runtimefiles

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromRepoDeps(t *testing.T) {
	b, err := os.ReadFile("../../deps.json")
	if err != nil {
		t.Fatal(err)
	}
	files, err := FromDeps(b)
	if err != nil {
		t.Fatal(err)
	}
	names := ""
	for _, f := range files {
		names += f.Name + " "
		if len(f.SHA256) != 64 || !strings.HasPrefix(f.URL, "https://github.com/") {
			t.Fatalf("%+v", f)
		}
		if f.Member != "" && len(f.ArchiveSHA256) != 64 {
			t.Fatalf("%+v", f)
		}
	}
	if names != "WinDivert.dll WinDivert64.sys hysteria.exe " {
		t.Fatalf("%q", names)
	}
}

func TestStage(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(src, "a.exe"), []byte("good"), 0o644)
	files := []File{{Name: "a.exe", SHA256: sum([]byte("good"))}}
	if _, err := Stage(src, dst, files, nil); err != nil {
		t.Fatal(err)
	}
	if err := Verify(dst, files); err != nil {
		t.Fatal(err)
	}
	// The program folder copy is replaced: the verified copy stays and is
	// used; staging does not pick up the new file.
	os.WriteFile(filepath.Join(src, "a.exe"), []byte("evil"), 0o644)
	if _, err := Stage(src, dst, files, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "a.exe")); string(b) != "good" {
		t.Fatal("staged copy changed")
	}
	// Without a good copy, a replaced file is refused.
	os.Remove(filepath.Join(dst, "a.exe"))
	var me *MismatchError
	if _, err := Stage(src, dst, files, nil); !errors.As(err, &me) {
		t.Fatalf("replaced file accepted: %v", err)
	}
	// A tampered staged copy fails verification.
	os.WriteFile(filepath.Join(dst, "a.exe"), []byte("evil"), 0o644)
	if err := Verify(dst, files); !errors.As(err, &me) {
		t.Fatal("tampered copy passed")
	}
	os.Remove(filepath.Join(src, "a.exe"))
	os.Remove(filepath.Join(dst, "a.exe"))
	if _, err := Stage(src, dst, files, nil); err == nil {
		t.Fatal("missing file accepted")
	}
}

func zipOf(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestStageDownloads(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	zb := zipOf(t, map[string]string{"pkg/x64/b.dll": "bee", "pkg/x64/c.sys": "sea", "pkg/readme": "r"})
	served := map[string][]byte{"https://h/a.exe": []byte("good"), "https://h/pkg.zip": zb}
	hits := map[string]int{}
	get := func(url string, max int64) ([]byte, error) {
		hits[url]++
		if b, ok := served[url]; ok {
			return b, nil
		}
		return nil, errors.New("404")
	}
	files := []File{
		{Name: "a.exe", SHA256: sum([]byte("good")), URL: "https://h/a.exe"},
		{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "https://h/pkg.zip", Member: "pkg/x64/b.dll", ArchiveSHA256: sum(zb)},
		{Name: "c.sys", SHA256: sum([]byte("sea")), URL: "https://h/pkg.zip", Member: "pkg/x64/c.sys", ArchiveSHA256: sum(zb)},
	}
	// The program folder has a replaced b.dll and nothing else.
	os.WriteFile(filepath.Join(src, "b.dll"), []byte("evil"), 0o644)
	res, err := Stage(src, dst, files, get)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Downloaded, ",") != "a.exe,c.sys" || strings.Join(res.Replaced, ",") != "b.dll" {
		t.Fatalf("%+v", res)
	}
	if hits["https://h/pkg.zip"] != 1 {
		t.Fatalf("archive fetched %d times", hits["https://h/pkg.zip"])
	}
	if err := Verify(dst, files); err != nil {
		t.Fatal(err)
	}
	// Staged copies are kept: nothing is fetched again.
	res, err = Stage(src, dst, files, get)
	if err != nil || len(res.Downloaded)+len(res.Replaced) != 0 || len(hits) != 2 {
		t.Fatalf("%+v %v %v", res, err, hits)
	}
}

func TestStageDownloadChecked(t *testing.T) {
	zb := zipOf(t, map[string]string{"x/b.dll": "bee"})
	cases := map[string]struct {
		f     File
		serve []byte
	}{
		"file hash":    {File{Name: "a.exe", SHA256: sum([]byte("good")), URL: "u"}, []byte("evil")},
		"archive hash": {File{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "u", Member: "x/b.dll", ArchiveSHA256: sum([]byte("other"))}, zb},
		"member hash":  {File{Name: "b.dll", SHA256: sum([]byte("wasp")), URL: "u", Member: "x/b.dll", ArchiveSHA256: sum(zb)}, zb},
		"no member":    {File{Name: "b.dll", SHA256: sum([]byte("bee")), URL: "u", Member: "y/b.dll", ArchiveSHA256: sum(zb)}, zb},
	}
	for name, c := range cases {
		dst := t.TempDir()
		get := func(string, int64) ([]byte, error) { return c.serve, nil }
		if _, err := Stage(t.TempDir(), dst, []File{c.f}, get); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dst, c.f.Name)); err == nil {
			t.Errorf("%s: file written", name)
		}
	}
}
