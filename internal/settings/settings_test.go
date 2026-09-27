package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
)

func TestParseDefaults(t *testing.T) {
	s, set, err := Parse([]byte(`{"defaultAction":"direct","rules":[{"name":"c","app":{"pattern":"curl.exe"},"action":"tunnel"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !s.QUICBlocked() || !s.IPv6TunnelBlocked() || !s.RemoteDNS() || s.SniffTimeout() != 800*time.Millisecond {
		t.Fatalf("%+v", s)
	}
	if set == nil {
		t.Fatal("no set")
	}
	s, _, err = Parse([]byte(`{"defaultAction":"tunnel","blockQUIC":false,"sniffTimeoutMs":300,"rules":[]}`))
	if err != nil || s.QUICBlocked() || s.SniffTimeout() != 300*time.Millisecond || s.DefaultAction != rules.Tunnel {
		t.Fatalf("%+v %v", s, err)
	}
	if _, _, err := Parse([]byte("\xef\xbb\xbf" + `{"defaultAction":"direct","rules":[]}`)); err != nil {
		t.Fatalf("BOM: %v", err)
	}
	if _, _, err := Parse([]byte(`{"defaultAction":"direct","typo":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, _, err := Parse([]byte(`{"rules":[{"name":"x"}]}`)); err == nil {
		t.Fatal("invalid rule accepted")
	}
}

// A hand-edited file without rules loads as an empty list, never null.
func TestParseNoRules(t *testing.T) {
	for _, in := range []string{`{"defaultAction":"tunnel"}`, `{"defaultAction":"tunnel","rules":null}`} {
		s, _, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if s.Rules == nil {
			t.Fatalf("%s: rules nil", in)
		}
		b, _ := json.Marshal(s)
		if !strings.Contains(string(b), `"rules":[]`) {
			t.Fatalf("%s: %s", in, b)
		}
	}
}

func TestWatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(p, []byte(`{"defaultAction":"direct","rules":[]}`), 0o644)
	stop := make(chan struct{})
	defer close(stop)
	changes := make(chan *Settings, 4)
	errs := make(chan error, 4)
	go Watch(p, 10*time.Millisecond, stop, func(s *Settings, _ *rules.Set) { changes <- s }, func(e error) { errs <- e })
	time.Sleep(30 * time.Millisecond)
	future := time.Now().Add(time.Second)
	os.WriteFile(p, []byte(`{"defaultAction":"broken"`), 0o644)
	os.Chtimes(p, future, future)
	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Fatal("no error for broken file")
	}
	os.WriteFile(p, []byte(`{"defaultAction":"tunnel","rules":[]}`), 0o644)
	future = future.Add(time.Second)
	os.Chtimes(p, future, future)
	select {
	case s := <-changes:
		if s.DefaultAction != rules.Tunnel {
			t.Fatal("wrong settings")
		}
	case <-time.After(time.Second):
		t.Fatal("no change")
	}
}

func TestExactWebDefault(t *testing.T) {
	_, set, err := Parse([]byte(`{"defaultAction":"direct","rules":[]}`))
	if err != nil || !set.ExactWeb {
		t.Fatalf("default must be on: %v %v", set, err)
	}
	_, set, err = Parse([]byte(`{"defaultAction":"direct","rules":[],"exactWebDomains":false}`))
	if err != nil || set.ExactWeb {
		t.Fatalf("off: %v", err)
	}
}
