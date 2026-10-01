// Package preflight inspects a server before Hysteria is deployed on it:
// OS and architecture, systemd, resources, firewall, DNS, the ports
// Hysteria needs, access to GitHub releases and an existing Hysteria
// installation. It only reads; the result is a report with checks rated
// ok, warn or fail, explained in Russian for the admin.
package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Level rates a check.
type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	// Fail blocks a deploy.
	Fail Level = "fail"
)

// Check is one line of the report.
type Check struct {
	ID      string `json:"id"`
	Level   Level  `json:"level"`
	Title   string `json:"title"`
	Details string `json:"details,omitempty"`
}

// Hysteria is an installation found on the server.
type Hysteria struct {
	Installed bool   `json:"installed"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Active    bool   `json:"active,omitempty"`
}

// Report is the result of a preflight.
type Report struct {
	User         string    `json:"user"`
	Root         bool      `json:"root"`
	OS           string    `json:"os"` // PRETTY_NAME
	OSID         string    `json:"osId"`
	OSVersion    string    `json:"osVersion"`
	Kernel       string    `json:"kernel"`
	Arch         string    `json:"arch"`         // uname -m
	HysteriaArch string    `json:"hysteriaArch"` // release asset suffix, "" if none
	Systemd      bool      `json:"systemd"`
	CPUs         int       `json:"cpus"`
	MemoryMiB    int       `json:"memoryMiB"`
	DiskFreeMiB  int       `json:"diskFreeMiB"`
	Firewall     string    `json:"firewall"`
	DNS          bool      `json:"dns"`
	GitHub       bool      `json:"github"`
	Hysteria     Hysteria  `json:"hysteria"`
	Checks       []Check   `json:"checks"`
	Blocked      bool      `json:"blocked"` // some check failed
	Ports        []PortUse `json:"ports,omitempty"`
}

// PortUse is a needed port found in use.
type PortUse struct {
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// Options are what the deploy will need.
type Options struct {
	// UDPPort is the Hysteria listen port (default 443).
	UDPPort int `json:"udpPort"`
	// TCPPorts must be free too (ACME http/tls challenges: 80, 443).
	TCPPorts []int `json:"tcpPorts,omitempty"`
}

func (r *Report) add(id string, l Level, title, details string) {
	r.Checks = append(r.Checks, Check{ID: id, Level: l, Title: title, Details: details})
	if l == Fail {
		r.Blocked = true
	}
}

// ReleaseURL is fetched to learn whether the server reaches GitHub
// releases (the direct download source).
const ReleaseURL = "https://github.com/apernet/hysteria/releases/latest"

// hysteriaArch maps uname -m to the suffix of Hysteria's Linux release
// assets (hysteria-linux-<arch>).
func hysteriaArch(m string) string {
	switch m {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv7", "armv6l":
		return "arm"
	case "i386", "i686":
		return "386"
	case "s390x":
		return "s390x"
	case "riscv64":
		return "riscv64"
	case "mips", "mipsel":
		return "mipsle"
	}
	return ""
}

// Run inspects the server. probe is remote.RunProbe of the same
// connection.
func Run(ctx context.Context, ex remote.Executor, probe remote.Probe, opt Options) (Report, error) {
	if opt.UDPPort == 0 {
		opt.UDPPort = 443
	}
	sudo := probe.NeedSudo()
	r := Report{User: probe.User, Root: probe.Root, Kernel: probe.Kernel, Arch: probe.Arch, HysteriaArch: hysteriaArch(probe.Arch)}

	if !probe.Privileged() {
		r.add("privileges", Fail, "Нет прав администратора", "Пользователь SSH не root и не может выполнять sudo без пароля.")
	} else if probe.Root {
		r.add("privileges", OK, "Права администратора: root", "")
	} else {
		r.add("privileges", OK, "Права администратора: sudo без пароля", "")
	}

	osr, err := remote.ReadOSRelease(ctx, ex)
	if err != nil {
		return r, err
	}
	r.OS, r.OSID, r.OSVersion = osr.PrettyName, osr.ID, osr.VersionID
	l, details := rateOS(osr)
	r.add("os", l, "Система: "+orUnknown(osr.PrettyName), details)

	if r.HysteriaArch == "" {
		r.add("arch", Fail, "Архитектура "+probe.Arch+" не поддерживается", "Для неё нет сборки Hysteria для Linux.")
	} else {
		r.add("arch", OK, "Архитектура: "+probe.Arch, "")
	}

	if r.Systemd, err = remote.HasSystemd(ctx, ex); err != nil {
		return r, err
	}
	if r.Systemd {
		r.add("systemd", OK, "systemd есть", "")
	} else {
		r.add("systemd", Fail, "Нет systemd", "HyRoute Server запускает Hysteria как службу systemd.")
	}

	if n, err := remote.CPUCount(ctx, ex); err == nil {
		r.CPUs = n
	}
	total, _, err := remote.Memory(ctx, ex)
	if err != nil {
		return r, err
	}
	r.MemoryMiB = total
	switch {
	case total > 0 && total < 128:
		r.add("memory", Fail, fmt.Sprintf("Памяти %d МБ", total), "Нужно хотя бы 128 МБ.")
	case total > 0 && total < 256:
		r.add("memory", Warn, fmt.Sprintf("Памяти %d МБ", total), "Hysteria запустится, но при нагрузке памяти может не хватить.")
	default:
		r.add("memory", OK, fmt.Sprintf("Процессоров: %d, памяти: %d МБ", r.CPUs, total), "")
	}

	if free, err := remote.DiskFree(ctx, ex, "/usr/local/bin"); err == nil {
		r.DiskFreeMiB = free
		switch {
		case free < 50:
			r.add("disk", Fail, fmt.Sprintf("Свободно %d МБ на диске", free), "Для Hysteria нужно около 50 МБ.")
		case free < 200:
			r.add("disk", Warn, fmt.Sprintf("Свободно %d МБ на диске", free), "Места мало: журналы и обновления могут его занять.")
		default:
			r.add("disk", OK, fmt.Sprintf("Свободно на диске: %d МБ", free), "")
		}
	}

	fw, err := remote.ReadFirewall(ctx, ex, sudo)
	if err != nil {
		return r, err
	}
	r.Firewall = fw.Tool
	switch {
	case fw.UFW || fw.Firewalld:
		r.add("firewall", OK, "Брандмауэр: "+fw.Tool, "Порты Hysteria откроются его средствами.")
	case fw.DropPolicy:
		r.add("firewall", Warn, "Брандмауэр: "+fw.Tool+" с запретом по умолчанию", "HyRoute Server не пишет правила iptables/nftables сам: откройте UDP-порт Hysteria вручную или включите ufw/firewalld.")
	default:
		r.add("firewall", OK, "Входящие соединения не ограничены брандмауэром", "")
	}

	if r.DNS, err = remote.Resolves(ctx, ex, "github.com"); err != nil {
		return r, err
	}
	if !r.DNS {
		r.add("dns", Warn, "Сервер не разрешает имена (github.com)", "Проверьте /etc/resolv.conf. Бинарник Hysteria можно загрузить через controller.")
	}
	code, err := remote.HTTPStatus(ctx, ex, ReleaseURL)
	if err != nil {
		return r, err
	}
	r.GitHub = code >= 200 && code < 400
	if r.GitHub {
		r.add("github", OK, "GitHub доступен", "Hysteria загрузится прямо на сервер.")
	} else {
		r.add("github", Warn, "GitHub недоступен с сервера", "Hysteria загрузит controller и передаст на сервер по SFTP.")
	}

	if err := r.inspectHysteria(ctx, ex); err != nil {
		return r, err
	}

	hasSS, err := remote.HasSystemCommand(ctx, ex, "ss")
	if err != nil {
		return r, err
	}
	if !hasSS {
		r.add("port", Warn, fmt.Sprintf("Не удалось проверить, свободен ли порт UDP %d", opt.UDPPort), "На сервере нет утилиты ss (пакет iproute2).")
		return r, nil
	}
	ls, err := remote.Listeners(ctx, ex, sudo)
	if err != nil {
		return r, err
	}
	r.checkPorts(ls, opt)
	return r, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "неизвестна"
	}
	return s
}

// rateOS follows the official installer's recommendations: Debian 11+ and
// Ubuntu 22.04+ are supported; other systemd distributions work as best
// effort; Alpine, OpenWrt and NixOS are not supported.
func rateOS(o remote.OSRelease) (Level, string) {
	major := func() int {
		n, _ := strconv.Atoi(strings.SplitN(o.VersionID, ".", 2)[0])
		return n
	}
	switch o.ID {
	case "debian":
		if major() >= 11 {
			return OK, ""
		}
		return Warn, "Рекомендуется Debian 11 или новее."
	case "ubuntu":
		if major() >= 22 {
			return OK, ""
		}
		return Warn, "Рекомендуется Ubuntu 22.04 или новее."
	case "alpine", "openwrt", "nixos":
		return Fail, "Эта система не поддерживается: нужен дистрибутив с systemd и GNU coreutils."
	case "":
		return Warn, "Не удалось определить дистрибутив (/etc/os-release)."
	}
	return Warn, "Поддержка по возможности: проверено на Debian и Ubuntu."
}

// Standard places of an installation made by the official script (and by
// HyRoute Server).
const (
	StdBinary = "/usr/local/bin/hysteria"
	StdUnit   = "hysteria-server.service"
	StdConfig = "/etc/hysteria/config.yaml"
)

func (r *Report) inspectHysteria(ctx context.Context, ex remote.Executor) error {
	// Without systemd there is no unit to ask about (systemctl fails).
	if r.Systemd {
		u, err := remote.Unit(ctx, ex, StdUnit)
		if err != nil {
			return err
		}
		if u.Exists() {
			r.Hysteria.Installed, r.Hysteria.Unit, r.Hysteria.Active = true, u.Name, u.ActiveState == "active"
		}
	}
	if ok, err := remote.PathExists(ctx, ex, StdBinary, false); err != nil {
		return err
	} else if ok {
		r.Hysteria.Installed, r.Hysteria.Binary = true, StdBinary
		if v, err := remote.HysteriaVersion(ctx, ex, StdBinary); err == nil {
			r.Hysteria.Version = v
		}
	}
	if r.Hysteria.Installed {
		d := "Чтобы управлять ей, импортируйте сервер: ничего на нём не изменится."
		if r.Hysteria.Version != "" {
			d = "Версия " + r.Hysteria.Version + ". " + d
		}
		r.add("hysteria", Warn, "Hysteria уже установлена", d)
	} else {
		r.add("hysteria", OK, "Hysteria ещё не установлена", "")
	}
	return nil
}

func (r *Report) checkPorts(ls []remote.Listener, opt Options) {
	used := false
	// ss lists a program once per socket: IPv4 and IPv6 listeners of one
	// port (nginx: listen 80; listen [::]:80;) are one check.
	seen := map[PortUse]bool{}
	for _, l := range ls {
		want := (l.Proto == "udp" && l.Port == opt.UDPPort)
		for _, p := range opt.TCPPorts {
			want = want || (l.Proto == "tcp" && l.Port == p)
		}
		if !want {
			continue
		}
		used = true
		u := PortUse{Proto: l.Proto, Port: l.Port, Process: l.Process}
		if seen[u] {
			continue
		}
		seen[u] = true
		r.Ports = append(r.Ports, u)
		title := fmt.Sprintf("Порт %s %d занят", strings.ToUpper(l.Proto), l.Port)
		if l.Process == "hysteria" {
			r.add("port", Warn, title+" Hysteria", "Это уже установленная Hysteria.")
			continue
		}
		who := l.Process
		if who == "" {
			who = "другой программой"
		}
		r.add("port", Fail, title+" ("+who+")", "Выберите другой порт или освободите этот.")
	}
	if !used {
		r.add("port", OK, fmt.Sprintf("Порт UDP %d свободен", opt.UDPPort), "")
	}
}

// JSON is the report as stored in the job's data.
func (r Report) JSON() string {
	b, _ := json.Marshal(r)
	return string(b)
}
