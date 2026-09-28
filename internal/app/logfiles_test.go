package app

import (
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
