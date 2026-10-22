package uirpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type item struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

type target struct{ hidden int }

func (target) Sum(a, b int) int                  { return a + b }
func (target) Items(prefix string, n int) []item { return []item{{prefix + "x", n}} }
func (target) Fail(msg string) error             { return errors.New(msg) }
func (target) Pair(ok bool) (item, error)        { return item{"p", 1}, nil }
func (target) Nothing()                          {}
func (target) Ptr(p *item) string {
	if p == nil {
		return "nil"
	}
	return p.Name
}
func (target) Boom() int                         { panic("boom") }
func (target) Many(xs ...int) int                { return len(xs) }
func (t *target) private()                       {}
func (target) Context(ctx context.Context) error { return nil }

// pair connects two peers over pipes, as the two processes are.
func pair(t *testing.T) (a, b *Peer) {
	t.Helper()
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	a, b = New(ar, aw), New(br, bw)
	t.Cleanup(func() { aw.Close(); bw.Close() })
	return a, b
}

func TestCallsAndEvents(t *testing.T) {
	main, win := pair(t)
	main.OnCall = Dispatch(target{})
	var mu sync.Mutex
	var events []string
	got := make(chan struct{}, 4)
	win.OnEvent = func(name string, args []json.RawMessage) {
		mu.Lock()
		e := name
		if len(args) > 0 {
			e += ":" + string(args[0])
		}
		events = append(events, e)
		mu.Unlock()
		got <- struct{}{}
	}
	// The main process calls the window too (dialogs, the clipboard).
	win.OnCall = func(m string, a []json.RawMessage) (any, error) {
		if m == "clipboard.get" {
			return "текст", nil
		}
		return nil, errors.New("нет")
	}
	go main.Run()
	go win.Run()
	ctx := context.Background()

	cases := []struct {
		m    string
		args []any
		want string
		err  string
	}{
		{"Sum", []any{2, 3}, "5", ""},
		{"Items", []any{"a", 7}, `[{"name":"ax","n":7}]`, ""},
		{"Fail", []any{"нельзя"}, "", "нельзя"},
		{"Pair", []any{true}, `{"name":"p","n":1}`, ""},
		{"Nothing", nil, "null", ""},
		{"Ptr", []any{nil}, `"nil"`, ""},
		{"Ptr", []any{item{Name: "q"}}, `"q"`, ""},
		{"Sum", []any{4}, "4", ""}, // a missing argument is zero
		{"Boom", nil, "", "внутренняя ошибка в Boom: boom"},
		{"Many", []any{1, 2}, "", "не поддерживается"},
		{"private", nil, "", "нет такого вызова"},
		{"Gone", nil, "", "нет такого вызова"},
		{"Sum", []any{1, 2, 3}, "", "3 аргументов"},
		{"Sum", []any{"x", 1}, "", "аргумент 1"},
	}
	for _, c := range cases {
		r, err := win.Call(ctx, c.m, c.args...)
		switch {
		case c.err != "":
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want error %q", c.m, err, c.err)
			}
		case err != nil || string(r) != c.want:
			t.Errorf("%s: %s %v, want %s", c.m, r, err, c.want)
		}
	}
	if r, err := main.Call(ctx, "clipboard.get"); err != nil || string(r) != `"текст"` {
		t.Fatalf("%s %v", r, err)
	}
	main.Notify("status")
	main.Notify("settings", 42)
	for range 2 {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[1] != "settings:42" {
		t.Fatal(events)
	}
}

// Calls run side by side: a slow one (a file dialog) holds no other up.
func TestConcurrent(t *testing.T) {
	main, win := pair(t)
	release := make(chan struct{})
	main.OnCall = func(m string, a []json.RawMessage) (any, error) {
		if m == "slow" {
			<-release
		}
		return m, nil
	}
	go main.Run()
	go win.Run()
	slow := make(chan error, 1)
	go func() {
		_, err := win.Call(context.Background(), "slow")
		slow <- err
	}()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := win.Call(context.Background(), "fast"); err != nil || string(r) != `"fast"` {
				t.Errorf("%s %v", r, err)
			}
		}()
	}
	wg.Wait()
	close(release)
	if err := <-slow; err != nil {
		t.Fatal(err)
	}
}

// The window closes: calls waiting for it fail, later ones too.
func TestClosed(t *testing.T) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	main, win := New(ar, aw), New(br, bw)
	hang := make(chan struct{})
	win.OnCall = func(string, []json.RawMessage) (any, error) { <-hang; return nil, nil }
	go win.Run()
	done := make(chan error, 1)
	go func() { done <- main.Run() }()
	waiting := make(chan error, 1)
	go func() {
		_, err := main.Call(context.Background(), "dialog")
		waiting <- err
	}()
	time.Sleep(50 * time.Millisecond)
	bw.Close() // the window process ends
	if err := <-waiting; !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := main.Call(context.Background(), "x"); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	<-main.Done()
	close(hang)
	aw.Close()
}

func TestContextAndLimits(t *testing.T) {
	main, win := pair(t)
	main.OnCall = func(string, []json.RawMessage) (any, error) { select {} }
	go main.Run()
	go win.Run()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := win.Call(ctx, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if _, err := readFrame(strings.NewReader("\xff\xff\xff\xff")); err == nil {
		t.Fatal("huge frame read")
	}
	if _, err := readFrame(strings.NewReader("\x02\x00\x00\x00{x")); err == nil {
		t.Fatal("bad json read")
	}
}
