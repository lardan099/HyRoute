package hyrelease

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

// donor is a node: curl and a temporary directory, files as given.
func donor(t *testing.T, downloads map[string][]byte, files map[string][]byte) *fake.Executor {
	t.Helper()
	ex := machine(t, downloads, "curl")
	ex.On("mktemp").Reply("/tmp/hyroute.donor12345\n", 0)
	ex.On("rm").Reply("", 0)
	for p, b := range files {
		ex.SetFile(p, b)
	}
	return ex
}

func node(ex *fake.Executor, installed string) *Node {
	return &Node{Server: "NL", Installed: installed, Open: func(context.Context) (remote.Executor, bool, error) { return ex, false, nil }}
}

func TestNode(t *testing.T) {
	ctx := context.Background()
	bin := []byte("fake hysteria arm64")
	a := Asset{Name: "hysteria-linux-arm64", URL: "https://github.example/hysteria-linux-arm64", SHA256: sum(bin)}
	const installed = "/usr/local/bin/hysteria"

	// The node runs this very file: it gives it, downloads nothing.
	d := donor(t, nil, map[string][]byte{installed: bin})
	target := machine(t, nil)
	if err := node(d, installed).Fetch(ctx, target, a, tmp, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := target.File(tmp); string(got) != string(bin) {
		t.Fatalf("target has %q", got)
	}
	for _, c := range d.Commands() {
		if strings.HasPrefix(c, "curl") {
			t.Fatalf("the node downloaded although it had the file: %v", d.Commands())
		}
	}
	if !d.Closed() {
		t.Fatal("the node's connection left open")
	}

	// Another architecture (or version) installed: the node downloads the
	// asset into a temporary directory.
	d = donor(t, map[string][]byte{a.URL: bin}, map[string][]byte{installed: []byte("fake hysteria amd64")})
	target = machine(t, nil)
	if err := node(d, installed).Fetch(ctx, target, a, tmp, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := target.File(tmp); string(got) != string(bin) {
		t.Fatalf("target has %q", got)
	}

	// A file that is not the release's never reaches the target.
	d = donor(t, map[string][]byte{a.URL: []byte("tampered")}, nil)
	target = machine(t, nil)
	if err := node(d, "").Fetch(ctx, target, a, tmp, true); !errors.Is(err, ErrChecksum) || len(target.Writes()) != 0 {
		t.Fatalf("%v, writes %d", err, len(target.Writes()))
	}

	// The node cannot be reached.
	n := &Node{Server: "NL", Open: func(context.Context) (remote.Executor, bool, error) {
		return nil, false, errors.New("connection refused")
	}}
	if err := n.Fetch(ctx, machine(t, nil), a, tmp, true); err == nil || !strings.Contains(err.Error(), "нет подключения к серверу «NL»") {
		t.Fatalf("%v", err)
	}
}
