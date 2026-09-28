package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/geodata"
	"github.com/lardan099/hyroute/internal/release"
)

// dns: every direct fetch of HyRoute registers its host (a redirect's
// too) before dialling, session or not; IP literals do not. Every session
// is started with the controller's set.
func TestOwnDialRegisters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://second.example/sub", http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	// Every host dials the loopback test server; the names are only
	// registered.
	oldDial, oldDefault, oldDirect := ownDial, http.DefaultTransport, directTransport.DialContext
	ownDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}
	t.Cleanup(func() { ownDial, http.DefaultTransport, directTransport.DialContext = oldDial, oldDefault, oldDirect })

	d := newDNSCtl(t, nil)
	d.InstallOwnDial()
	ctx := context.Background()
	// No session yet: the name is registered all the same.
	if _, err := d.httpFetch(ctx, "http://nosession.example/sub"); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveDNS(dnspolicy.Config{ByRules: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.Connect(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.httpFetch(ctx, "http://sub.example/redirect"); err != nil {
		t.Fatal(err)
	}
	resp, err := d.geoDownload(ctx, "http://geo.example/geosite.dat", 0)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := (&release.Client{}).Fetch(ctx, "http://release.example/checksums.txt"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://geodata-default.example/x", nil)
	if resp, err := (&http.Client{CheckRedirect: geodata.NoDowngrade}).Do(req); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if _, err := d.httpFetch(ctx, "http://127.0.0.1:1/ip"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nosession.example", "sub.example", "second.example", "geo.example", "release.example", "geodata-default.example"} {
		if !d.ownNames.Has(want) {
			t.Errorf("%s not registered", want)
		}
	}
	if d.ownNames.Has("127.0.0.1") || d.ownNames.Len() != 6 {
		t.Fatalf("%d registered", d.ownNames.Len())
	}
	// The session reads the controller's set: a name registered after it
	// started counts at once.
	own := d.sess().cfg.OwnName
	if own == nil || !own("sub.example") || own("late.example") {
		t.Fatal("the session does not read the controller's names")
	}
	d.httpFetch(ctx, "http://late.example/sub")
	if !own("late.example") {
		t.Fatal("a name registered after the start")
	}
}
