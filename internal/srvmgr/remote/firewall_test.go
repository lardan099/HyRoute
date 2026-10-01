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

// Rules as iptables -S INPUT and nft list ruleset print them.
const (
	iptablesOracle = `-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p udp -m udp --sport 123 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -m comment --comment "reject the rest" -j REJECT --reject-with icmp-host-prohibited
`
	iptablesDropPolicy = "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
	// fail2ban's jump comes first, the last rule only drops one address.
	iptablesOpen = "-P INPUT ACCEPT\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n-A INPUT -s 203.0.113.9/32 -j DROP\n"
	nftFinal     = `table inet filter {
	set blocked {
		type ipv4_addr
		elements = { 198.51.100.1, 198.51.100.2,
			     198.51.100.3 }
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept
		iif "lo" accept
		ip saddr {
			203.0.113.1,
			203.0.113.2
		} drop
		tcp dport { 22, 80 } accept
		counter packets 12 bytes 720 log prefix "nft input: " reject with icmpx admin-prohibited
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}
`
	nftPolicy = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
	}
}
`
	// Drops only in forward and output; input ends with a conditional
	// drop.
	nftOpen = `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state invalid drop
		tcp dport 22 ct state new limit rate 10/minute accept
		ip saddr { 203.0.113.1, 203.0.113.2 } drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		drop
	}

	chain output {
		type filter hook output priority filter; policy drop;
	}
}
`
)

func TestReadFirewall(t *testing.T) {
	for _, tc := range []struct {
		name      string
		iptables  string // "": not installed
		nft       string
		tool      string
		deny, end bool
	}{
		{"oracle cloud", iptablesOracle, "", "iptables", true, true},
		{"iptables drop policy", iptablesDropPolicy, "", "iptables", true, false},
		{"iptables open", iptablesOpen, "", "none", false, false},
		// The nftables backend shows the same rules in nft: named iptables.
		{"iptables-nft", iptablesOracle, nftFinal, "iptables", true, true},
		{"nft final reject", "-P INPUT ACCEPT\n", nftFinal, "nftables", true, true},
		{"nft drop policy", "", nftPolicy, "nftables", true, false},
		{"nft open", "-P INPUT ACCEPT\n", nftOpen, "none", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tools []string
			ex := fake.New()
			if tc.iptables != "" {
				tools = append(tools, "iptables")
				ex.On("iptables", "-S", "INPUT").Reply(tc.iptables, 0)
			}
			if tc.nft != "" {
				tools = append(tools, "nft")
				ex.On("nft", "list", "ruleset").Reply(tc.nft, 0)
			}
			ex.On("sh", "-c").Do(func(c remote.Cmd) (remote.Result, error) {
				if slices.Contains(tools, c.Args[len(c.Args)-1]) {
					return remote.Result{}, nil
				}
				return remote.Result{ExitCode: 1}, nil
			})
			fw, err := remote.ReadFirewall(context.Background(), ex, false)
			if err != nil || fw.Tool != tc.tool || fw.DropPolicy != tc.deny || fw.FinalRule != tc.end || fw.UFW || fw.Firewalld {
				t.Fatalf("%+v %v", fw, err)
			}
		})
	}
}
