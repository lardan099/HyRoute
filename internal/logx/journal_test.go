package logx

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJournalSince(t *testing.T) {
	j := NewJournal(3)
	for i := 0; i < 5; i++ {
		j.Add(time.Now(), "info", string(rune('a'+i)))
	}
	all := j.Since(0, 0)
	if len(all) != 3 || all[0].Msg != "c" || all[2].Seq != 5 {
		t.Fatalf("%+v", all)
	}
	if got := j.Since(4, 0); len(got) != 1 || got[0].Msg != "e" {
		t.Fatalf("%+v", got)
	}
	if got := j.Since(0, 2); len(got) != 2 || got[0].Msg != "d" {
		t.Fatalf("%+v", got)
	}
	if j.Last() != 5 {
		t.Fatal(j.Last())
	}
}

// TestJournalOrderUnderConcurrentAdds: entries are stored in Seq order even
// when many goroutines log at once, so a poll never skips or repeats one.
func TestJournalOrderUnderConcurrentAdds(t *testing.T) {
	j := NewJournal(50000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				j.Add(time.Now(), "info", "x")
			}
		}()
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	var last uint64
	poll := func() {
		for _, e := range j.Since(last, 0) {
			if e.Seq != last+1 {
				t.Fatalf("after %d got %d", last, e.Seq)
			}
			last = e.Seq
		}
	}
	for running := true; running; {
		select {
		case <-finished:
			running = false
		default:
		}
		poll()
	}
	if last != 40000 {
		t.Fatalf("saw up to %d", last)
	}
}

func TestHandlerRedactsAndFormats(t *testing.T) {
	j := NewJournal(10)
	r := &Redactor{}
	r.Set("supersecret")
	var buf bytes.Buffer
	log := slog.New(NewHandler(j, r, slog.LevelInfo, &buf)).With("comp", "x")
	log.Debug("hidden")
	log.Info("auth failed", "auth", "supersecret", "note", "two words")
	e := j.Since(0, 0)
	if len(e) != 1 || e[0].Level != "info" {
		t.Fatalf("%+v", e)
	}
	if strings.Contains(e[0].Msg, "supersecret") || !strings.Contains(e[0].Msg, `note="two words"`) || !strings.Contains(e[0].Msg, "comp=x") {
		t.Fatal(e[0].Msg)
	}
	if strings.Contains(buf.String(), "supersecret") || !strings.Contains(buf.String(), "INFO") {
		t.Fatal(buf.String())
	}
}

func TestJournalTail(t *testing.T) {
	j := NewJournal(10)
	if got := j.Tail(5); got == nil || len(got) != 0 {
		t.Fatalf("empty journal: %#v", got)
	}
	for i := 0; i < 15; i++ {
		j.Add(time.Now(), "info", fmt.Sprint(i))
	}
	got := j.Tail(3)
	if len(got) != 3 || got[0].Msg != "12" || got[2].Msg != "14" {
		t.Fatalf("Tail(3) = %v", got)
	}
	if got := j.Tail(100); len(got) != 10 || got[0].Msg != "5" {
		t.Fatalf("Tail(100) = %v", got)
	}
}
