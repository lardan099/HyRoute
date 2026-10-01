package remote_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func TestParsePortSpec(t *testing.T) {
	for _, s := range []string{"443/udp", "20000-50000/udp", "80/tcp"} {
		p, err := remote.ParsePortSpec(s)
		if err != nil || p.String() != s {
			t.Errorf("%q: %+v %v", s, p, err)
		}
	}
	for _, s := range []string{"", "443", "443/icmp", "0/udp", "50000-20000/udp", "70000/udp", "a/udp", "1-/udp"} {
		if _, err := remote.ParsePortSpec(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestPortAllowedUFW(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("ufw", "show", "added").Reply("Added user rules (see 'ufw status' for running firewall):\n"+
		"ufw allow 22/tcp\n"+
		"ufw allow 443/udp comment 'mine'\n"+
		"ufw allow in 20000:50000/udp\n"+
		"ufw allow 4430/udp\n", 0)
	for spec, want := range map[remote.PortSpec]bool{
		{From: 443, To: 443, Proto: "udp"}:     true,
		{From: 20000, To: 50000, Proto: "udp"}: true,
		{From: 443, To: 443, Proto: "tcp"}:     false,
		{From: 44, To: 44, Proto: "udp"}:       false,
		// Inside a range is not the rule HyRoute would add.
		{From: 30000, To: 30000, Proto: "udp"}: false,
	} {
		got, err := remote.PortAllowed(ctx, ex, "ufw", spec, false)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", spec, got, err)
		}
	}
	ex.On("ufw").Reply("Rule deleted\n", 0)
	if err := remote.ClosePort(ctx, ex, "ufw", remote.PortSpec{From: 20000, To: 50000, Proto: "udp"}, true); err != nil {
		t.Fatal(err)
	}
	if c := ex.Commands(); c[len(c)-1] != "ufw --force delete allow 20000:50000/udp" {
		t.Fatalf("%q", c)
	}
}

func TestPortAllowedFirewalld(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("firewall-cmd", "--permanent", "--query-port=443/udp").Reply("yes\n", 0)
	ex.On("firewall-cmd", "--permanent", "--query-port=8443/udp").Reply("no\n", 1)
	ex.On("firewall-cmd", "--permanent", "--query-port=9443/udp").Fail("FirewallD is not running", 252)
	if ok, err := remote.PortAllowed(ctx, ex, "firewalld", remote.PortSpec{From: 443, To: 443, Proto: "udp"}, false); !ok || err != nil {
		t.Fatalf("443: %v %v", ok, err)
	}
	if ok, err := remote.PortAllowed(ctx, ex, "firewalld", remote.PortSpec{From: 8443, To: 8443, Proto: "udp"}, false); ok || err != nil {
		t.Fatalf("8443: %v %v", ok, err)
	}
	if _, err := remote.PortAllowed(ctx, ex, "firewalld", remote.PortSpec{From: 9443, To: 9443, Proto: "udp"}, false); err == nil {
		t.Fatal("an error read as an answer")
	}
	ex.On("firewall-cmd").Reply("success\n", 0)
	if err := remote.ClosePort(ctx, ex, "firewalld", remote.PortSpec{From: 8443, To: 8443, Proto: "udp"}, false); err != nil {
		t.Fatal(err)
	}
	c := ex.Commands()
	if !slices.Equal(c[len(c)-2:], []string{"firewall-cmd --permanent --remove-port=8443/udp", "firewall-cmd --remove-port=8443/udp"}) {
		t.Fatalf("%q", c)
	}
}

// debianUser is a fake Debian server seen by a non-root user with sudo:
// the programs in tools live in /usr/sbin, which only a lookup that adds
// the sbin directories finds.
func debianUser(tools ...string) *fake.Executor {
	ex := fake.New()
	ex.On("sh", "-c").Do(func(c remote.Cmd) (remote.Result, error) {
		if strings.Contains(c.Args[2], "/usr/sbin") && slices.Contains(tools, c.Args[len(c.Args)-1]) {
			return remote.Result{}, nil
		}
		return remote.Result{ExitCode: 1}, nil
	})
	return ex
}

func TestReadFirewallSbin(t *testing.T) {
	ex := debianUser("ufw", "iptables")
	ex.On("ufw", "status").Reply("Status: active\n\nTo Action From\n", 0)
	fw, err := remote.ReadFirewall(context.Background(), ex, true)
	if err != nil || !fw.UFW || fw.Tool != "ufw" {
		t.Fatalf("%+v %v", fw, err)
	}
	if c := ex.Calls(); !c[len(c)-1].Sudo {
		t.Fatalf("ufw status without sudo: %+v", c[len(c)-1])
	}
}
