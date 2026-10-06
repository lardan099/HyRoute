package profile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

var srv = model.Server{Name: "Франкфурт 1", Host: "192.0.2.70"}

func TestDeployedServerLinksParseInHyRoute(t *testing.T) {
	p := deploy.Params{TLS: deploy.TLSSelfSigned, Masquerade: "https://www.example.com", HopPorts: "20000-50000", Obfs: true}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	sec, _ := deploy.NewSecrets(p, srv.Host, nil, deploy.Input{})
	c, _ := deploy.BuildConfig(p, sec)
	cfg, _ := c.Marshal()
	pin, _ := deploy.Pin([]byte(sec[deploy.SecretCert]))
	meta := deploy.Meta(p, pin)

	pr, err := Build(srv, cfg, meta, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pr.URI, "hysteria2://") || !strings.Contains(pr.URI, "@192.0.2.70:443,20000-50000/") || !strings.Contains(pr.Compat, "@192.0.2.70:443/") {
		t.Fatalf("%s\n%s", pr.URI, pr.Compat)
	}
	// Both forms are the same server for the HyRoute client (the shared
	// parser of P1-09).
	for _, link := range []string{pr.URI, pr.Compat} {
		hp, warns, err := hysteria.ParseURI(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if hp.Name != "Франкфурт 1" || hp.Host != "192.0.2.70" || hp.Ports != "443,20000-50000" || hp.Auth != sec[deploy.SecretAuth] ||
			hp.Obfs.Type != "salamander" || hp.Obfs.Password != sec[deploy.SecretObfs] || !hp.TLS.Insecure || hp.TLS.PinSHA256 != pin || hp.TLS.SNI != "www.example.com" {
			t.Fatalf("%s → %+v", link, hp)
		}
		if len(warns) != 0 {
			t.Fatalf("%s: warnings %q", link, warns)
		}
	}
	// The client config is a valid Hysteria client config for the same.
	cc, err := hyconfig.ParseClient([]byte(pr.Config))
	if err != nil || hyconfig.HasErrors(cc.Validate()) || cc.Server != "192.0.2.70:443,20000-50000" || cc.TLS.PinSHA256 != pin || cc.Obfs.Salamander.Password != sec[deploy.SecretObfs] {
		t.Fatalf("%v\n%s", err, pr.Config)
	}
	if len(pr.QR) < 21 || len(pr.QR) != len(pr.QR[0]) || len(pr.QRCompat) < 21 || strings.Trim(strings.Join(pr.QR, ""), "01") != "" {
		t.Fatalf("QR %d×%d", len(pr.QR), len(pr.QR[0]))
	}
	if len(pr.Warnings) != 1 || !strings.Contains(pr.Warnings[0], "pinSHA256") {
		t.Fatalf("%q", pr.Warnings)
	}

	// The summary has no secrets.
	s, _ := Summarize(srv, cfg, meta, nil)
	b, _ := json.Marshal(s)
	for _, secret := range []string{sec[deploy.SecretAuth], sec[deploy.SecretObfs]} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("secret in the summary: %s", b)
		}
	}
	if s.PinSHA256 != pin || s.Ports != "443,20000-50000" || s.Obfs != "salamander" || s.Auth != "password" {
		t.Fatalf("%+v", s)
	}
}

func TestACMEServer(t *testing.T) {
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-profile-pass\n")
	pr, err := Build(srv, cfg, model.ConfigMeta{TLS: "acme", Ports: "443", SNI: "vpn.example.com"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	l, _, err := hy2uri.Parse(pr.URI)
	if err != nil || l.SNI != "vpn.example.com" || l.Insecure || l.PinSHA256 != "" || pr.URI != pr.Compat || len(pr.Warnings) != 0 {
		t.Fatalf("%s %+v %v %q", pr.URI, l, err, pr.Warnings)
	}
}

func TestUserPass(t *testing.T) {
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: userpass\n  userpass:\n    bob: fake-bob-pass\n    alice: fake-alice-pass\n")
	meta := model.ConfigMeta{TLS: "acme", Ports: "443"}
	s, _ := Summarize(srv, cfg, meta, nil)
	if strings.Join(s.Users, ",") != "alice,bob" {
		t.Fatalf("%q", s.Users)
	}
	if _, err := Build(srv, cfg, meta, "", nil); err == nil {
		t.Fatal("no user picked among two")
	}
	pr, err := Build(srv, cfg, meta, "bob", nil)
	if err != nil || pr.User != "bob" {
		t.Fatal(err)
	}
	l, _, _ := hy2uri.Parse(pr.URI)
	if l.Auth != "bob:fake-bob-pass" {
		t.Fatalf("%q", l.Auth)
	}
}

// The user of a cascade link is no client: it is listed apart and gets
// no link; without a name the one client is taken.
func TestLinkUser(t *testing.T) {
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: userpass\n  userpass:\n    phone: fake-phone-pass\n    link-3-0: fake-link-pass\n")
	meta := model.ConfigMeta{TLS: "acme", Ports: "443"}
	links := []string{"link-3-0", "link-4-1"}
	s, _ := Summarize(srv, cfg, meta, links)
	if strings.Join(s.Users, ",") != "phone" || strings.Join(s.Links, ",") != "link-3-0" {
		t.Fatalf("users %q, links %q", s.Users, s.Links)
	}
	for _, u := range []string{"link-3-0", "LINK-3-0"} {
		if _, err := Build(srv, cfg, meta, u, links); !errors.Is(err, ErrLinkUser) {
			t.Fatalf("%s: %v", u, err)
		}
	}
	pr, err := Build(srv, cfg, meta, "", links)
	if err != nil || pr.User != "phone" || strings.Contains(pr.URI, "fake-link-pass") {
		t.Fatalf("%v %q", err, pr.User)
	}
	only := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: userpass\n  userpass:\n    link-3-0: fake-link-pass\n")
	if _, err := Build(srv, only, meta, "", links); !errors.Is(err, ErrLinkUser) {
		t.Fatalf("only the link: %v", err)
	}
}

func TestExternalAuth(t *testing.T) {
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: http\n  http:\n    url: http://127.0.0.1:8081/auth\n")
	if _, err := Build(srv, cfg, model.ConfigMeta{TLS: "acme"}, "", nil); !errors.Is(err, ErrExternalAuth) {
		t.Fatalf("%v", err)
	}
	s, err := Summarize(srv, cfg, model.ConfigMeta{TLS: "acme"}, nil)
	if err != nil || len(s.Warnings) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
}

// The hop interval of the server reaches both links and the client config
// of a hopping server, and the HyRoute client reads it from either link;
// one port gets none.
func TestHopInterval(t *testing.T) {
	hop := srv
	hop.HopInterval = 45
	p := deploy.Params{TLS: deploy.TLSSelfSigned, HopPorts: "20000-50000"}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	sec, _ := deploy.NewSecrets(p, hop.Host, nil, deploy.Input{})
	c, _ := deploy.BuildConfig(p, sec)
	cfg, _ := c.Marshal()
	pin, _ := deploy.Pin([]byte(sec[deploy.SecretCert]))
	pr, err := Build(hop, cfg, deploy.Meta(p, pin), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{pr.URI, pr.Compat} {
		if !strings.Contains(link, "mportHopInt=45") {
			t.Fatalf("no interval: %s", link)
		}
		hp, warns, err := hysteria.ParseURI(link)
		if err != nil || len(warns) != 0 || hp.Ports != "443,20000-50000" || hp.Hop.Interval != "45s" {
			t.Fatalf("%s → %+v %q %v", link, hp.Hop, warns, err)
		}
	}
	if !strings.Contains(pr.URI, "@192.0.2.70:443,20000-50000/?") {
		t.Fatal(pr.URI)
	}
	cc, _ := hyconfig.ParseClient([]byte(pr.Config))
	if cc.Transport.UDP.HopInterval != "45s" {
		t.Fatalf("%s", pr.Config)
	}

	one := deploy.Params{TLS: deploy.TLSSelfSigned}
	one.Normalize()
	sec, _ = deploy.NewSecrets(one, hop.Host, nil, deploy.Input{})
	c, _ = deploy.BuildConfig(one, sec)
	cfg, _ = c.Marshal()
	pin, _ = deploy.Pin([]byte(sec[deploy.SecretCert]))
	if pr, _ = Build(hop, cfg, deploy.Meta(one, pin), "", nil); strings.Contains(pr.URI+pr.Compat, "mportHopInt") || strings.Contains(pr.Config, "hopInterval") {
		t.Fatalf("interval for one port:\n%s\n%s", pr.URI, pr.Config)
	}
}
