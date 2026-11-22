package vless

import (
	"encoding/json"
	"testing"

	"github.com/lardan099/hyroute/internal/socks5"
)

func TestVPNChainBalanceUsesIngressForEveryNode(t *testing.T) {
	b := Balance{Nodes: []Node{
		{Host: "first.example", Port: 443, Settings: Settings{ID: "a", Security: "tls"}},
		{Host: "second.example", Port: 8443, Settings: Settings{ID: "b", Security: "tls"}},
	}}
	r := Run{SOCKSListen: "127.0.0.1:12345", Via: &socks5.Client{
		Server: "127.0.0.1:12346", Username: "ingress", Password: "secret",
	}}
	raw, err := BalanceConfig(b, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Outbounds []struct {
			Tag      string
			Protocol string
			Settings struct{ Address, User, Pass string }
			Stream   struct {
				Sockopt struct{ DialerProxy string }
			} `json:"streamSettings"`
		}
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Outbounds) != 3 {
		t.Fatalf("want two exit nodes and one ingress, got %d outbounds", len(got.Outbounds))
	}
	via := got.Outbounds[2]
	if via.Protocol != "socks" || via.Settings.Address != "127.0.0.1" ||
		via.Settings.User != r.Via.Username || via.Settings.Pass != r.Via.Password {
		t.Fatal("missing authenticated ingress")
	}
	for i, n := range b.Nodes {
		out := got.Outbounds[i]
		if out.Settings.Address != n.Host || out.Stream.Sockopt.DialerProxy != via.Tag {
			t.Fatalf("exit node %d did not keep its host and use the first VPN", i)
		}
	}
}
