package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/rules"
)

// dns: a DNS entry's connection goes to ServeDNS; the connection its pass
// dial opens is tracked, so Abort resets it; without ServeDNS the
// connection is reset.
func TestServeDNSMode(t *testing.T) {
	f := newFixture(t)
	upc := make(chan net.Conn, 1)
	served := make(chan *nat.Entry, 1)
	f.relay.ServeDNS = func(ctx context.Context, e *nat.Entry, c net.Conn, pass func(context.Context, rules.Result) (net.Conn, error)) {
		served <- e
		if _, err := pass(ctx, rules.Result{Action: rules.Block}); err == nil {
			t.Error("a Block pass dialled")
		}
		up, err := pass(ctx, rules.Result{Action: rules.Tunnel, Profile: "p"})
		if err != nil {
			t.Error(err)
			return
		}
		upc <- up
		io.Copy(io.Discard, c) // until Abort
	}
	e := &nat.Entry{Mode: nat.DNS, DNSDest: 1}
	c := f.dialEntry(t, e)
	defer c.Close()
	if got := <-served; got != e {
		t.Fatal("ServeDNS got another entry")
	}
	up := <-upc
	f.relay.Abort()
	expectReset(t, c)
	up.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := up.Read(make([]byte, 1)); err == nil {
		t.Fatal("the pass-through connection survived Abort")
	}
	if r := <-f.done; r.Stage != "dns" || r.Route != "tunnel" || r.Profile != "p" {
		t.Fatalf("result %+v", r)
	}

	g := newFixture(t)
	c2 := g.dialEntry(t, &nat.Entry{Mode: nat.DNS})
	defer c2.Close()
	expectReset(t, c2)
}

// AbortWhere resets only the connections whose entry matches, both sides.
func TestAbortWhere(t *testing.T) {
	f := newFixture(t)
	upc := make(chan net.Conn, 1)
	f.relay.ServeDNS = func(ctx context.Context, e *nat.Entry, c net.Conn, pass func(context.Context, rules.Result) (net.Conn, error)) {
		up, err := pass(ctx, rules.Result{Action: rules.Tunnel})
		if err != nil {
			t.Error(err)
			return
		}
		upc <- up
		io.Copy(io.Discard, c)
	}
	dnsC := f.dialEntry(t, &nat.Entry{Mode: nat.DNS})
	defer dnsC.Close()
	up := <-upc
	other := f.dialEntry(t, &nat.Entry{Mode: nat.NoSniff})
	defer other.Close()
	echo := func(s string) error {
		other.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := other.Write([]byte(s)); err != nil {
			return err
		}
		_, err := io.ReadFull(other, make([]byte, len(s)))
		return err
	}
	if err := echo("hello"); err != nil {
		t.Fatal(err)
	}
	f.relay.AbortWhere(func(e *nat.Entry) bool { return e.Mode == nat.DNS })
	expectReset(t, dnsC)
	up.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := up.Read(make([]byte, 1)); err == nil {
		t.Fatal("the DNS upstream survived")
	}
	if err := echo("again"); err != nil {
		t.Fatalf("another connection was reset: %v", err)
	}
}
