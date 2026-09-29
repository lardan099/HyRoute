package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/stats"
)

func TestValidStatsName(t *testing.T) {
	for name, ok := range map[string]bool{
		"day-2026-09-28": true, "month-2026-09": true, "mode": true,
		"day-2026-13-01": false, "day-2026-09-28.json": false, "Mode": false, "../mode": false,
		"month-2026-9": false, "day-2026-09-28.json.tmp": false, "": false, `..\day-2026-09-28`: false,
	} {
		if ValidStatsName(name) != ok {
			t.Errorf("%q: %v", name, !ok)
		}
	}
}

func TestStatsFiles(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := s.StatsFiles()
	dir := filepath.Join(s.Dir, "stats")
	absent := func(what string) {
		t.Helper()
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s created the folder: %v", what, err)
		}
	}
	// An absent folder is never created by reading.
	if l, err := f.List(); err != nil || len(l) != 0 {
		t.Fatalf("%v %v", l, err)
	}
	absent("List")
	if _, err := f.Read("mode"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	absent("Read")
	if err := f.Remove("day-2026-09-28"); err != nil {
		t.Fatal(err)
	}
	absent("Remove")
	if n, err := f.SweepTemp(time.Now()); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	absent("SweepTemp")
	if ok, err := f.present(); ok || err != nil {
		t.Fatal(ok, err)
	}
	// An upgraded folder: its default is written with the first
	// statistics file, so nothing creates the folder before.
	if err := os.WriteFile(filepath.Join(s.Dir, "prefs.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := stats.New(nil)
	c.Configure(f)
	if c.Mode() != stats.ModeOn {
		t.Fatal(c.Mode())
	}
	if _, err := c.Report(time.Now(), "30d"); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	absent("Configure, Report and an empty Flush")
	// A new install writes its mode at once.
	s2, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c2 := stats.New(nil)
	c2.Configure(s2.StatsFiles())
	if b, err := os.ReadFile(filepath.Join(s2.Dir, "stats", "mode.json")); c2.Mode() != stats.ModeOn || err != nil || !bytes.Contains(b, []byte(`"mode":"no-sites"`)) {
		t.Fatalf("new install: %v, %s %v", c2.Mode(), b, err)
	}

	// Write creates it; round trip.
	if err := f.Write("day-2026-09-28", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := f.Write("mode", []byte(`{"v":1,"mode":"off"}`)); err != nil {
		t.Fatal(err)
	}
	if b, err := f.Read("day-2026-09-28"); err != nil || string(b) != `{"v":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if ok, _ := f.present(); !ok {
		t.Fatal("folder")
	}
	// Foreign names, mode.json, leftovers and folders are not listed.
	for _, n := range []string{"notes.txt", "day-2026-13-01.json", ".tmp-123", "month-2026-09.json.bak"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600)
	}
	os.Mkdir(filepath.Join(dir, "month-2026-08.json"), 0o700)
	if err := f.Write("month-2026-09", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	l, err := f.List()
	slices.Sort(l)
	if err != nil || !slices.Equal(l, []string{"day-2026-09-28", "month-2026-09"}) {
		t.Fatalf("%v %v", l, err)
	}
	if err := f.Remove("month-2026-09"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read("month-2026-09"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	// Invalid names touch nothing.
	for _, n := range []string{"../x", "notes", "day-2026-13-01"} {
		if err := f.Remove(n); err == nil {
			t.Errorf("Remove(%q)", n)
		}
		if _, err := f.Read(n); err == nil {
			t.Errorf("Read(%q)", n)
		}
		if err := f.Write(n, nil); err == nil {
			t.Errorf("Write(%q)", n)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("a foreign file was touched")
	}

	// Too large, a hard link: corrupt, the target never read.
	big := bytes.Repeat([]byte(" "), 4<<20+1)
	os.WriteFile(filepath.Join(dir, "day-2026-09-01.json"), big, 0o600)
	if _, err := f.Read("day-2026-09-01"); !errors.Is(err, stats.ErrCorrupt) {
		t.Fatalf("big: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "mode.json"), bytes.Repeat([]byte(" "), 4<<10+1), 0o600)
	if _, err := f.Read("mode"); !errors.Is(err, stats.ErrCorrupt) {
		t.Fatalf("big mode: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "secret.json")
	os.WriteFile(secret, []byte(`{"v":1}`), 0o600)
	if err := os.Link(secret, filepath.Join(dir, "day-2026-09-02.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read("day-2026-09-02"); !errors.Is(err, stats.ErrCorrupt) {
		t.Fatalf("hard link: %v", err)
	}
	// A symbolic link (needs a privilege on Windows).
	if err := os.Symlink(secret, filepath.Join(dir, "day-2026-09-03.json")); err == nil {
		if _, err := f.Read("day-2026-09-03"); !errors.Is(err, stats.ErrCorrupt) {
			t.Fatalf("symlink: %v", err)
		}
	} else {
		t.Logf("symlink not created: %v", err)
	}
	// traffic.json of HyRoute 1.2.0 is read the same way.
	os.WriteFile(filepath.Join(s.Dir, "traffic.json"), []byte(`{"version":1}`), 0o600)
	if b, err := f.ReadLegacy(); err != nil || string(b) != `{"version":1}` {
		t.Fatalf("%q %v", b, err)
	}
	os.Remove(filepath.Join(s.Dir, "traffic.json"))
	if err := os.Link(secret, filepath.Join(s.Dir, "traffic.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadLegacy(); !errors.Is(err, ErrNotRegular) || !errors.Is(err, stats.ErrCorrupt) {
		t.Fatalf("legacy hard link: %v", err)
	}
}

// A statistics folder that is a link to another folder is refused before
// anything in it is read.
func TestStatsFolderLink(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "day-2026-09-28.json"), []byte(`{"v":1}`), 0o600)
	if err := os.Symlink(other, filepath.Join(s.Dir, "stats")); err != nil {
		t.Skipf("symlink not created: %v", err)
	}
	f := s.StatsFiles()
	if _, err := f.List(); err == nil {
		t.Fatal("List through a link")
	}
	if _, err := f.Read("day-2026-09-28"); err == nil {
		t.Fatal("Read through a link")
	}
	if err := f.Write("day-2026-09-28", []byte("x")); err == nil {
		t.Fatal("Write through a link")
	}
	if b, _ := os.ReadFile(filepath.Join(other, "day-2026-09-28.json")); string(b) != `{"v":1}` {
		t.Fatal("target changed")
	}
}

func TestStatsSweepTemp(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := s.StatsFiles()
	if err := f.Write("day-2026-09-28", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Dir, "stats")
	old := time.Now().Add(-2 * time.Hour)
	for _, n := range []string{".tmp-abc", "notes.txt"} {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, old, old)
	}
	os.WriteFile(filepath.Join(dir, ".tmp-fresh"), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(dir, ".tmp-dir"), 0o700)
	os.Chtimes(filepath.Join(dir, ".tmp-dir"), old, old)
	os.Chtimes(filepath.Join(dir, "day-2026-09-28.json"), old, old)
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	linked := os.Symlink(target, filepath.Join(dir, ".tmp-link")) == nil
	n, err := f.SweepTemp(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	exists := func(n string) bool { _, err := os.Lstat(filepath.Join(dir, n)); return err == nil }
	if exists(".tmp-abc") || !exists(".tmp-fresh") || !exists(".tmp-dir") || !exists("notes.txt") || !exists("day-2026-09-28.json") {
		t.Fatal("wrong files swept")
	}
	if n != 1 {
		t.Fatalf("swept %d", n)
	}
	// Everything is old now: the link goes, not its target.
	n, err = f.SweepTemp(time.Now().Add(time.Minute))
	want := 1
	if linked {
		want = 2
		if exists(".tmp-link") {
			t.Fatal("link kept")
		}
		if b, _ := os.ReadFile(target); string(b) != "keep" {
			t.Fatal("link target touched")
		}
	}
	if err != nil || n != want || exists(".tmp-fresh") || !exists(".tmp-dir") {
		t.Fatalf("swept %d %v", n, err)
	}
}

// A folder Guard refuses: what the statistics show and log names no path
// (Guard's own texts do, with the Windows user name).
func TestStatsGuardRefusalNoPath(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Dir, "stats")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []error{
		fmt.Errorf("%s — ссылка на другое место, а не обычная папка", dir),
		fmt.Errorf("папка %s: %w", dir, syscall.Errno(5)),
	} {
		old := statsGuard
		statsGuard = func(string) error { return refusal }
		c := stats.New(nil)
		c.Configure(s.StatsFiles())
		now := time.Now()
		_, rerr := c.Report(now, "today")
		shown := c.StoreError()
		serr := c.SetMode(now, stats.ModeOn)
		xerr := c.Reset(now)
		statsGuard = old
		if rerr != nil || serr == nil || xerr == nil {
			t.Fatalf("%v %v %v", rerr, serr, xerr)
		}
		for _, text := range []string{shown, serr.Error(), xerr.Error()} {
			if text == "" || strings.Contains(text, s.Dir) || strings.Contains(text, filepath.Base(filepath.Dir(s.Dir))) {
				t.Errorf("a path in %q", text)
			}
		}
	}
}
