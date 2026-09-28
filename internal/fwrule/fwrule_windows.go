//go:build windows

package fwrule

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/relay"
)

// Name is what the user sees in "Windows Defender Firewall with Advanced
// Security".
const Name = "HyRoute relay (TCP)"

const createNoWindow = 0x08000000

// netsh runs %SystemRoot%\System32\netsh.exe by its full path: we run
// elevated, and a netsh.exe found through PATH could be anyone's.
func netsh(args ...string) ([]byte, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(filepath.Join(sys, "netsh.exe"), append([]string{"advfirewall", "firewall"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.CombinedOutput()
}

func params(exe string) []string {
	return []string{
		"dir=in", "action=allow", "program=" + exe, "protocol=TCP",
		fmt.Sprintf("localport=%d-%d", relay.PortMin, relay.PortMax),
		"profile=any", "enable=yes",
	}
}

// Ensure is called on every Connect: it creates the rule if it is missing
// and otherwise rewrites its parameters (the exe may have moved, the user
// may have disabled or edited it). netsh output is localized, so only exit
// codes are used.
func Ensure(exe string) error {
	if _, err := netsh("show", "rule", "name="+Name); err != nil {
		out, err := netsh(append([]string{"add", "rule", "name=" + Name}, params(exe)...)...)
		if err != nil {
			return fmt.Errorf("netsh add rule: %v: %s", err, out)
		}
		return nil
	}
	out, err := netsh(append([]string{"set", "rule", "name=" + Name, "new"}, params(exe)...)...)
	if err != nil {
		return fmt.Errorf("netsh set rule: %v: %s", err, out)
	}
	return nil
}

// Exists reports whether the rule is present.
func Exists() bool {
	_, err := netsh("show", "rule", "name="+Name)
	return err == nil
}

// Remove deletes the rule and both proxy rules (uninstaller, "Remove
// firewall rule" button).
func Remove() error {
	if err := SetProxyPorts("", nil, nil); err != nil {
		return err
	}
	if _, err := netsh("show", "rule", "name="+Name); err != nil {
		return nil
	}
	out, err := netsh("delete", "rule", "name="+Name)
	if err != nil {
		return fmt.Errorf("netsh delete rule: %v: %s", err, out)
	}
	return nil
}

// SetProxyPorts makes the proxy rules allow exactly these TCP and UDP
// ports; an empty list removes that rule.
func SetProxyPorts(exe string, tcp, udp []int) error {
	if err := setProxyRule(ProxyName, "TCP", exe, tcp); err != nil {
		return err
	}
	return setProxyRule(ProxyUDPName, "UDP", exe, udp)
}

func setProxyRule(name, proto, exe string, ports []int) error {
	_, err := netsh("show", "rule", "name="+name)
	exists := err == nil
	if len(ports) == 0 {
		if !exists {
			return nil
		}
		if out, err := netsh("delete", "rule", "name="+name); err != nil {
			return fmt.Errorf("netsh delete rule: %v: %s", err, out)
		}
		return nil
	}
	params := proxyParams(exe, proto, ports)
	var out []byte
	if exists {
		out, err = netsh(append([]string{"set", "rule", "name=" + name, "new"}, params...)...)
	} else {
		out, err = netsh(append([]string{"add", "rule", "name=" + name}, params...)...)
	}
	if err != nil {
		return fmt.Errorf("netsh: %v: %s", err, out)
	}
	return nil
}

// ProxyRules lists the proxy rules that exist (System page, diagnostics).
func ProxyRules() []string {
	out := []string{}
	for _, name := range []string{ProxyName, ProxyUDPName} {
		if _, err := netsh("show", "rule", "name="+name); err == nil {
			out = append(out, name)
		}
	}
	return out
}

// LegacyProxyUDP reports a UDP proxy rule written by v1.2.0, which served
// UDP on every LAN proxy (its rule has no description; ours carries
// proxyRuleMark). The labels of netsh's output are localized; the mark is
// ours, so only it is looked for.
func LegacyProxyUDP() bool {
	out, err := netsh("show", "rule", "name="+ProxyUDPName, "verbose")
	return err == nil && !strings.Contains(string(out), proxyRuleMark)
}
