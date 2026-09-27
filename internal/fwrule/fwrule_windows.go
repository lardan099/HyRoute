//go:build windows

// Package fwrule manages the inbound Windows Firewall rule the relay needs:
// reflected SYNs arrive as inbound packets and pass ALE_AUTH_RECV_ACCEPT,
// where the firewall would otherwise prompt or block.
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

// Remove deletes the rule and the proxy rule (uninstaller, "Remove
// firewall rule" button).
func Remove() error {
	if err := SetProxyPorts("", nil); err != nil {
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

// ProxyName is the rule that lets devices of the local network reach
// HyRoute's local proxies (private and domain networks only, never public
// Wi-Fi; and only from the subnets of this PC, not from the internet over
// a global IPv6 address or a public IPv4 one).
const ProxyName = "HyRoute local proxies (TCP)"

// SetProxyPorts makes the proxy rule allow exactly ports; no ports removes
// it.
func SetProxyPorts(exe string, ports []int) error {
	_, err := netsh("show", "rule", "name="+ProxyName)
	exists := err == nil
	if len(ports) == 0 {
		if !exists {
			return nil
		}
		if out, err := netsh("delete", "rule", "name="+ProxyName); err != nil {
			return fmt.Errorf("netsh delete rule: %v: %s", err, out)
		}
		return nil
	}
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = fmt.Sprint(p)
	}
	params := []string{"dir=in", "action=allow", "program=" + exe, "protocol=TCP",
		"localport=" + strings.Join(list, ","), "remoteip=localsubnet", "profile=private,domain", "enable=yes"}
	var out []byte
	if exists {
		out, err = netsh(append([]string{"set", "rule", "name=" + ProxyName, "new"}, params...)...)
	} else {
		out, err = netsh(append([]string{"add", "rule", "name=" + ProxyName}, params...)...)
	}
	if err != nil {
		return fmt.Errorf("netsh: %v: %s", err, out)
	}
	return nil
}
