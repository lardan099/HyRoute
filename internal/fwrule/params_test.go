package fwrule

import (
	"slices"
	"strings"
	"testing"
)

func TestProxyParams(t *testing.T) {
	udp := proxyParams(`C:\HyRoute\HyRoute.exe`, "UDP", []int{10801, 10802})
	for _, want := range []string{"protocol=UDP", "localport=10801,10802", "remoteip=localsubnet", "profile=private,domain", "dir=in", "action=allow", `program=C:\HyRoute\HyRoute.exe`} {
		if !slices.Contains(udp, want) {
			t.Errorf("UDP rule lacks %s: %v", want, udp)
		}
	}
	if !strings.Contains(udp[len(udp)-1], proxyRuleMark) {
		t.Error("no mark")
	}
	if tcp := proxyParams("x", "TCP", []int{1}); !slices.Contains(tcp, "protocol=TCP") || !slices.Contains(tcp, "localport=1") {
		t.Error(tcp)
	}
	if ProxyName == ProxyUDPName {
		t.Error("one name for both rules")
	}
}
