package app

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
)

// TestClearLogsWhileHysteriaWrites: "Очистить логи" while Hysteria keeps
// writing. A line arriving between closing the files and deleting them
// must not open the profile's file again (an open log cannot be deleted
// on Windows), and new limits reach the files being written without a
// data race.
func TestClearLogsWhileHysteriaWrites(t *testing.T) {
	c, _ := newCtl(t)
	c.SetLogDir(t.TempDir())
	defer c.SetLogDir("") // close the files before TempDir cleanup
	line := func() { c.hysteriaLine("p1", hysteria.LogLine{Level: "warn", Msg: "TCP error"}) }
	line()

	// A line right after the files are closed: it must wait for the
	// deletion (it gets a moment to open its file if it does not).
	wrote := make(chan struct{})
	clearLogsHook = func() {
		go func() {
			line()
			close(wrote)
		}()
		select {
		case <-wrote:
		case <-time.After(200 * time.Millisecond):
		}
	}
	err := c.ClearLogs()
	clearLogsHook = nil
	<-wrote
	if err != nil {
		t.Fatal(err)
	}

	// The same with Hysteria writing all the time.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				line()
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()
	for range 100 {
		if err := c.ClearLogs(); err != nil {
			t.Fatal(err)
		}
		c.applyLogPrefs()
	}
}

// A deleted server's journal and log file go with it: the file is closed
// (it can be deleted) and the ring freed.
func TestDeletedServerLogsFreed(t *testing.T) {
	c, _ := newCtl(t)
	dir := t.TempDir()
	c.SetLogDir(dir)
	defer c.SetLogDir("")
	res, err := c.ImportURIs("hy2://a@one.example:443#ONE")
	if err != nil || len(res.Added) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	id := res.Added[0].ID
	c.hysteriaLine(id, hysteria.LogLine{Level: "info", Msg: "connected to server"})
	if err := c.DeleteProfile(id); err != nil {
		t.Fatal(err)
	}
	c.hyMu.Lock()
	_, journal := c.hyLogs[id]
	c.hyMu.Unlock()
	c.files.mu.Lock()
	_, file := c.files.hy[id]
	c.files.mu.Unlock()
	if journal || file {
		t.Fatalf("journal %v, file %v", journal, file)
	}
	if err := os.Remove(filepath.Join(dir, "hysteria-"+safeName(id)+".log")); err != nil {
		t.Fatal(err) // still open on Windows
	}
}
