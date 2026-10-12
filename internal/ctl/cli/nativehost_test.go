package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/ctl"
)

func nativeIn(msgs ...string) *bytes.Buffer {
	var b bytes.Buffer
	for _, m := range msgs {
		binary.Write(&b, binary.LittleEndian, uint32(len(m)))
		b.WriteString(m)
	}
	return &b
}

func nativeOut(t *testing.T, b *bytes.Buffer) []nativeReply {
	t.Helper()
	var out []nativeReply
	for b.Len() > 0 {
		var n uint32
		if err := binary.Read(b, binary.LittleEndian, &n); err != nil {
			t.Fatal(err)
		}
		var r nativeReply
		if err := json.Unmarshal(b.Next(int(n)), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestNativeHost(t *testing.T) {
	r := newRig(func(req ctl.Request) []ctl.Frame {
		switch req.Cmd {
		case "browser-info":
			return result(map[string]any{"args": json.RawMessage(req.Args)})
		case "browser-add":
			return failFrames(ctl.CodeBrowserOff, "Расширение для браузера выключено")
		}
		return failFrames(ctl.CodeUnknown, "?")
	})
	origin := ctl.BrowserOrigins[0]
	if !IsNativeHost([]string{origin, "--parent-window=0"}) || IsNativeHost([]string{"status"}) || IsNativeHost(nil) {
		t.Fatal("IsNativeHost")
	}
	in := nativeIn(
		`{"id":1,"cmd":"browser-info","args":{"hosts":["a.example"],"app":"evil.exe"}}`,
		`{"id":"x","cmd":"connect"}`,
		`{"id":2,"cmd":"browser-add","args":{"sites":[".a.example"],"to":"vpn"}}`,
		`not json`,
	)
	var out bytes.Buffer
	if code := NativeHost(context.Background(), []string{origin}, in, &out, "chrome.exe", r.d); code != 0 {
		t.Fatal(code)
	}
	reps := nativeOut(t, &out)
	if len(reps) != 4 {
		t.Fatalf("%+v", reps)
	}
	if !reps[0].OK || string(reps[0].ID) != "1" || !strings.Contains(string(reps[0].Result), `"app":"chrome.exe"`) || strings.Contains(string(reps[0].Result), "evil") {
		t.Fatalf("%+v %s", reps[0], reps[0].Result)
	}
	if reps[1].OK || reps[1].Code != ctl.CodeUnknown || string(reps[1].ID) != `"x"` {
		t.Fatalf("%+v", reps[1])
	}
	if reps[2].OK || reps[2].Code != ctl.CodeBrowserOff {
		t.Fatalf("%+v", reps[2])
	}
	if reps[3].OK || reps[3].Code != ctl.CodeUsage {
		t.Fatalf("%+v", reps[3])
	}
	// Only the two browser commands reached HyRoute.
	if len(r.hy.reqs) != 2 || r.hy.reqs[0].Cmd != "browser-info" || r.hy.reqs[1].Cmd != "browser-add" {
		t.Fatalf("%+v", r.hy.reqs)
	}
	if r.stdout.Len() != 0 || r.stderr.Len() != 0 {
		t.Fatal("printed outside the protocol")
	}

	// Another extension: refused at once.
	out.Reset()
	if code := NativeHost(context.Background(), []string{"chrome-extension://abcdefghijklmnopabcdefghijklmnop/"}, nativeIn(`{"cmd":"browser-info"}`), &out, "", r.d); code != ctl.ExitCode(ctl.CodeDenied) {
		t.Fatal(code)
	}
	if reps = nativeOut(t, &out); len(reps) != 1 || reps[0].Code != ctl.CodeDenied {
		t.Fatalf("%+v", reps)
	}
	// The pipe up for neither the command line nor the extension.
	r.hy.first = &failFrames(ctl.CodeOff, "Командная строка выключена")[0]
	out.Reset()
	NativeHost(context.Background(), []string{origin}, nativeIn(`{"id":4,"cmd":"browser-info","args":{}}`), &out, "", r.d)
	if reps = nativeOut(t, &out); len(reps) != 1 || reps[0].Code != ctl.CodeBrowserOff || !strings.Contains(reps[0].Error, "Расширение для браузера") {
		t.Fatalf("%+v", reps)
	}
	r.hy.first = nil
	// HyRoute not running.
	r.hy.dialErr = map[string]error{}
	out.Reset()
	NativeHost(context.Background(), []string{origin}, nativeIn(`{"id":3,"cmd":"browser-info","args":{}}`), &out, "", r.d)
	if reps = nativeOut(t, &out); len(reps) != 1 || reps[0].Code != ctl.CodeNotRunning || reps[0].Error != "HyRoute не запущен" {
		t.Fatalf("%+v", reps)
	}
	// A frame cut short or too big: a usage error, then the host exits.
	for _, in := range []*bytes.Buffer{bytes.NewBuffer([]byte{5, 0, 0, 0, '{'}), bytes.NewBuffer([]byte{0, 0, 0, 2})} {
		out.Reset()
		if code := NativeHost(context.Background(), []string{origin}, in, &out, "", r.d); code != ctl.ExitCode(ctl.CodeUsage) {
			t.Fatal(code)
		}
	}
}
