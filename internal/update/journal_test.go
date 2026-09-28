package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stagingDir writes a verified staging directory (files + manifest).
func stagingDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	m := Manifest{Version: "v0.6.0", Files: map[string]string{}}
	for n, c := range files {
		os.WriteFile(filepath.Join(dir, n), []byte(c), 0o755)
		s := sha256.Sum256([]byte(c))
		m.Files[n] = hex.EncodeToString(s[:])
	}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, ManifestName), b, 0o644)
	return dir
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func TestJournalRecoverAfterCrash(t *testing.T) {
	staging := stagingDir(t, map[string]string{MainExe: "new main", UpdaterExe: "new upd", "extra.dll": "new extra"})
	target := t.TempDir()
	os.WriteFile(filepath.Join(target, MainExe), []byte("old main"), 0o755)
	os.WriteFile(filepath.Join(target, UpdaterExe), []byte("old upd"), 0o755)
	jp := filepath.Join(t.TempDir(), "journal.json")

	// Applied, then the updater "died" before commit.
	if _, err := ApplyJournaled(staging, target, "", jp, "v0.5.0", "v0.6.0", true); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(target, MainExe)) != "new main" {
		t.Fatal("not applied")
	}
	j, err := ReadJournal(jp)
	if err != nil || j == nil || len(j.Replaced) != 2 || len(j.Added) != 1 || j.To != "v0.6.0" || !j.Reconnect {
		t.Fatalf("%v %+v", err, j)
	}
	if _, err := Recover(jp); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(target, MainExe)) != "old main" || read(t, filepath.Join(target, UpdaterExe)) != "old upd" {
		t.Fatal("old files not restored")
	}
	if read(t, filepath.Join(target, "extra.dll")) != "<missing>" {
		t.Fatal("added file left")
	}
	if j, _ := ReadJournal(jp); j != nil {
		t.Fatal("journal left after recovery")
	}
}

func TestJournalRecoverHalfway(t *testing.T) {
	target := t.TempDir()
	jp := filepath.Join(t.TempDir(), "journal.json")
	// The plan names three files; only the first was swapped when the
	// power went out, the second was being copied (.new).
	os.WriteFile(filepath.Join(target, "a.exe"), []byte("new a"), 0o755)
	os.WriteFile(filepath.Join(target, "a.exe.old"), []byte("old a"), 0o755)
	os.WriteFile(filepath.Join(target, "b.exe"), []byte("old b"), 0o755)
	os.WriteFile(filepath.Join(target, "b.exe.new"), []byte("half"), 0o755)
	writeJournal(jp, &Journal{Target: target, Replaced: []string{"a.exe", "b.exe"}, Added: []string{"c.dll"}})
	if _, err := Recover(jp); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a.exe": "old a", "b.exe": "old b", "b.exe.new": "<missing>", "a.exe.old": "<missing>", "c.dll": "<missing>"} {
		if got := read(t, filepath.Join(target, name)); got != want {
			t.Errorf("%s: %q want %q", name, got, want)
		}
	}
}

func TestJournalCommit(t *testing.T) {
	staging := stagingDir(t, map[string]string{MainExe: "new", UpdaterExe: "upd"})
	target := t.TempDir()
	os.WriteFile(filepath.Join(target, MainExe), []byte("old"), 0o755)
	jp := filepath.Join(t.TempDir(), "journal.json")
	sw, err := ApplyJournaled(staging, target, "", jp, "a", "b", false)
	if err != nil {
		t.Fatal(err)
	}
	sw.Commit()
	if j, _ := ReadJournal(jp); j != nil || read(t, filepath.Join(target, MainExe+".old")) != "<missing>" {
		t.Fatal("commit left the journal or the backup")
	}
	if j, err := Recover(jp); j != nil || err != nil {
		t.Fatal("nothing to recover after commit")
	}
}

// A renamed HyRoute.exe is updated and restored under its own name: a
// HyRoute.exe added next to it would be removed by a rollback, leaving
// nothing to start.
func TestJournalRenamedExe(t *testing.T) {
	staging := stagingDir(t, map[string]string{MainExe: "new main", UpdaterExe: "new upd"})
	target := t.TempDir()
	const exe = "HyRoute-0.5.exe"
	os.WriteFile(filepath.Join(target, exe), []byte("old main"), 0o755)
	jp := filepath.Join(t.TempDir(), "journal.json")
	if _, err := ApplyJournaled(staging, target, exe, jp, "v0.5.0", "", false); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(target, exe)) != "new main" || read(t, filepath.Join(target, MainExe)) != "<missing>" {
		t.Fatal("the renamed exe was not updated in place")
	}
	j, err := ReadJournal(jp)
	if err != nil || j.ExeName() != exe || len(j.Replaced) != 1 || j.Replaced[0] != exe {
		t.Fatalf("%v %+v", err, j)
	}
	if _, err := Recover(jp); err != nil {
		t.Fatal(err)
	}
	if read(t, filepath.Join(target, exe)) != "old main" {
		t.Fatal("renamed exe not restored")
	}
	// Two package files never land on one name.
	if _, err := ApplyJournaled(staging, target, "HYROUTE-UPDATER.exe", jp, "", "", false); err == nil {
		t.Fatal("exe named like the updater accepted")
	}
}

// Recovery runs elevated before its folder is protected: a journal
// naming files outside the program folder is refused, and nothing is
// touched.
func TestReadJournalRejectsOtherFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "app")
	os.MkdirAll(target, 0o755)
	victim := filepath.Join(root, "victim.dll")
	os.WriteFile(victim, []byte("keep"), 0o644)
	jp := filepath.Join(t.TempDir(), "journal.json")
	for _, j := range []*Journal{
		{Target: target, Added: []string{`..\victim.dll`}},
		{Target: target, Added: []string{"../victim.dll"}},
		{Target: target, Replaced: []string{"C:victim.dll"}},
		{Target: target, Exe: `..\evil.exe`},
		{Target: target, Added: []string{""}},
		{Target: "app"},
	} {
		writeJournal(jp, j)
		if _, err := ReadJournal(jp); err == nil {
			t.Errorf("accepted %+v", j)
		}
		if _, err := Recover(jp); err == nil {
			t.Errorf("recovered %+v", j)
		}
	}
	if read(t, victim) != "keep" {
		t.Fatal("a file outside the program folder was removed")
	}
	j := &Journal{Target: target}
	if !j.For(filepath.Join(root, "APP", ".")) || j.For(root) {
		t.Fatal("For")
	}
}

// CleanAside removes what an undo set aside, and nothing else of the
// folder's .bad files.
func TestCleanAsideOnlyOwnFiles(t *testing.T) {
	dir := t.TempDir()
	own := fmt.Sprintf("%s.%d.bad", MainExe, time.Now().UnixNano())
	for _, n := range []string{own, "dump.bad", "disk.2024.bad", "x.123456789012345678a.bad", MainExe} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644)
	}
	CleanAside(dir)
	if read(t, filepath.Join(dir, own)) != "<missing>" {
		t.Fatal("set-aside file kept")
	}
	for _, n := range []string{"dump.bad", "disk.2024.bad", "x.123456789012345678a.bad", MainExe} {
		if read(t, filepath.Join(dir, n)) != "x" {
			t.Fatalf("%s removed", n)
		}
	}
}

// The swap knows the version it installs (for --update-failed).
func TestApplyJournaledTarget(t *testing.T) {
	staging := stagingDir(t, map[string]string{MainExe: "new main", UpdaterExe: "new upd"})
	jp := filepath.Join(t.TempDir(), "journal.json")
	sw, err := ApplyJournaled(staging, t.TempDir(), "", jp, "v0.5.0", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if sw.To != "v0.6.0" {
		t.Fatalf("to %q", sw.To)
	}
}
