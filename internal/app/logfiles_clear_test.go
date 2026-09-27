package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClearLogsEmptiesCrashLog(t *testing.T) {
	c, _ := newCtl(t)
	dir := t.TempDir()
	c.SetLogDir(dir)
	crash := filepath.Join(dir, "crash.log")
	os.WriteFile(crash, []byte("panic: x"), 0o600)
	os.WriteFile(filepath.Join(dir, "hysteria-a.log.1"), []byte("old"), 0o600)
	if err := c.ClearLogs(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(crash); err != nil || fi.Size() != 0 {
		t.Fatalf("crash.log: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hysteria-a.log.1")); err == nil {
		t.Fatal("old log kept")
	}
}

// TestLateWriteAfterClearDoesNotReopen: a Hysteria line whose writer was
// fetched just before the logs were cleared must not bring the file back
// through an orphaned handle.
func TestLateWriteAfterClearDoesNotReopen(t *testing.T) {
	c, _ := newCtl(t)
	dir := t.TempDir()
	c.SetLogDir(dir)
	w := c.hysteriaFile("p1", "one")
	if w == nil {
		t.Fatal("no log file")
	}
	fmt.Fprintln(w, "before")
	if err := c.ClearLogs(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(w, "late")
	if _, err := os.Stat(filepath.Join(dir, "hysteria-p1.log")); !os.IsNotExist(err) {
		t.Fatalf("log file recreated by a closed writer: %v", err)
	}
	// A writer fetched now works as before.
	fmt.Fprintln(c.hysteriaFile("p1", "one"), "after")
	if b, err := os.ReadFile(filepath.Join(dir, "hysteria-p1.log")); err != nil || !strings.Contains(string(b), "after") || strings.Contains(string(b), "late") {
		t.Fatalf("%q %v", b, err)
	}
	c.SetLogDir("") // close the file before TempDir cleanup
}

// TestExportLogWholeJournal: "Сохранить лог" writes every entry the journal
// holds, not only the 2000 the UI polls.
func TestExportLogWholeJournal(t *testing.T) {
	c, _ := newCtl(t)
	c.EngineLog.Clear()
	for i := range 2500 {
		c.EngineLog.Add(time.Now(), "info", fmt.Sprintf("line %d", i))
	}
	out := c.ExportLog("engine", false)
	if n := strings.Count(out, "\r\n"); n != 2500 || !strings.Contains(out, "line 0\r\n") {
		t.Fatalf("%d lines", n)
	}
	if n := len(c.Logs("engine", 0)); n != 2000 {
		t.Fatalf("UI poll: %d", n)
	}
}
