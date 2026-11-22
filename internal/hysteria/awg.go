package hysteria

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/lardan099/hyroute/internal/awg"
)

// An AmneziaWG profile runs in HyRoute itself ("HyRoute --awg <config>",
// internal/awg): amneziawg-go over a userspace network stack behind a
// SOCKS5 port. Like Xray it is up once a request went through the server
// (watchVLESS); its log lines are JSON like Hysteria's.

// awgArgs are the child's arguments.
func awgArgs(cfgPath string) []string { return []string{"--awg", cfgPath} }

// InterpretAWG reports a line that ends the run: the child could not
// start (the device refused the settings, the SOCKS5 port is taken).
func InterpretAWG(l LogLine) (Event, bool) {
	if l.Level != "fatal" {
		return Event{}, false
	}
	kind := ErrOther
	switch l.Str("kind") {
	case awg.KindConfig:
		kind = ErrConfig
	case awg.KindPort:
		kind = ErrPortBusy
	}
	return Event{Fatal: true, Kind: kind, Message: "AmneziaWG не запустилась: " + l.Msg}, true
}

// ClassifyAWG explains a failed probe: a server that never completed a
// handshake (the address, the keys, the obfuscation, or UDP blocked on
// the way), one whose DNS does not answer through the tunnel (dnsFailing:
// the child said so lately), or one that lets nothing through.
func ClassifyAWG(probeErr error, handshake, dnsFailing bool) (ErrorKind, string) {
	if !handshake {
		return ErrTimeout, "Сервер не ответил на рукопожатие AmneziaWG: проверьте адрес и порт, ключи и параметры обфускации " +
			"(Jc, Jmin, Jmax, S1–S4, H1–H4 должны быть как на сервере). Ещё сеть может не пропускать UDP до сервера"
	}
	if dnsFailing {
		return ErrOther, "Рукопожатие с сервером прошло, но DNS через туннель не отвечает: проверьте DNS в настройках сервера"
	}
	text := "нет ответа"
	if probeErr != nil {
		text = probeErr.Error()
	}
	return ErrOther, "Рукопожатие с сервером прошло, но трафик через него не идёт (" + text + "): сервер не выпускает клиентов в интернет или Address не тот, что выдал сервер"
}

// awgEndpoint is where the child sends its UDP: the server's IP (pinned,
// or the host when it is one), or the loopback bridge through the first
// VPN of a chain (udpRelay).
func (s *Supervisor) awgEndpoint(pinned netip.Addr, udpRelay string) (netip.AddrPort, error) {
	if udpRelay != "" {
		return netip.ParseAddrPort(udpRelay)
	}
	port, err := VLESSPort(s.Profile.Ports)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip := pinned
	if !ip.IsValid() {
		if ip, err = netip.ParseAddr(s.Profile.Host); err != nil {
			return netip.AddrPort{}, errors.New("адрес сервера " + net.JoinHostPort(s.Profile.Host, strconv.Itoa(port)) + " не разрешён")
		}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
}
