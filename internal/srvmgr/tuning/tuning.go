// Package tuning is the system settings of a server that matter for
// Hysteria: the UDP buffer limits QUIC needs, and BBR with the fq queue
// for the server's TCP (its own connections to sites, SSH, the
// masquerade site). They are kept in one file of HyRoute's in
// /etc/sysctl.d, set by a job with a copy and a rollback. Settings the
// kernel cannot do are not offered.
//
// Linux TCP congestion control is not Hysteria's: Hysteria's QUIC has its
// own (congestion.type in the config, BBR or Reno) and Brutal, the speed
// a client asks for (bandwidth); those are config settings.
package tuning

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// FilePath is HyRoute's sysctl file.
const FilePath = "/etc/sysctl.d/90-hyroute.conf"

// Buffer is the receive and send buffer limit QUIC needs: quic-go asks
// for 7 MiB and warns below.
const Buffer = 16 << 20

// The parameters.
const (
	Rmem  = "net.core.rmem_max"
	Wmem  = "net.core.wmem_max"
	Qdisc = "net.core.default_qdisc"
	TCPCC = "net.ipv4.tcp_congestion_control"
	avail = "net.ipv4.tcp_available_congestion_control"
)

// Groups of settings.
const (
	GroupUDP = "udp" // buffers for QUIC
	GroupTCP = "tcp" // Linux TCP: BBR and fq
)

// Keys are the settings HyRoute offers, in file order.
var Keys = []string{Rmem, Wmem, Qdisc, TCPCC}

// Setting is a kernel parameter: what it is and what HyRoute would set.
type Setting struct {
	Key     string `json:"key"`
	Group   string `json:"group"`
	Current string `json:"current"`
	Want    string `json:"want"`
	// Done: the current value is the wanted one (or better).
	Done bool `json:"done"`
	// Supported: the kernel can do it; Why says why not.
	Supported bool   `json:"supported"`
	Why       string `json:"why,omitempty"`
	// InFile: HyRoute's file sets it.
	InFile bool `json:"inFile"`
}

// State is the server's kernel as far as these settings go.
type State struct {
	Kernel string `json:"kernel"`
	// Available is the TCP congestion control algorithms loaded now.
	Available []string  `json:"available"`
	BBR       bool      `json:"bbr"`
	File      string    `json:"file"` // HyRoute's file ("": none)
	Settings  []Setting `json:"settings"`
}

// Setting is the setting of key.
func (s State) Setting(key string) (Setting, bool) {
	for _, x := range s.Settings {
		if x.Key == key {
			return x, true
		}
	}
	return Setting{}, false
}

// Read reads the kernel parameters, which modules it has, and HyRoute's
// file.
func Read(ctx context.Context, ex remote.Executor, kernel string) (State, error) {
	st := State{Kernel: kernel, Available: []string{}}
	v, err := remote.SysctlRead(ctx, ex, Rmem, Wmem, Qdisc, TCPCC, avail)
	if err != nil {
		return st, err
	}
	st.Available = strings.Fields(v[avail])
	st.BBR = slices.Contains(st.Available, "bbr")
	if !st.BBR {
		if st.BBR, err = remote.KernelModule(ctx, ex, "tcp_bbr"); err != nil {
			return st, err
		}
	}
	fq := v[Qdisc] == "fq"
	if !fq {
		if fq, err = remote.KernelModule(ctx, ex, "sch_fq"); err != nil {
			return st, err
		}
	}
	b, err := ex.ReadFile(ctx, FilePath, false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return st, err
	}
	st.File = string(b)
	inFile := fileKeys(st.File)

	for _, k := range []string{Rmem, Wmem} {
		cur, ok := v[k]
		n, _ := strconv.Atoi(cur)
		s := Setting{Key: k, Group: GroupUDP, Current: cur, Want: strconv.Itoa(max(n, Buffer)), Done: n >= Buffer, Supported: ok, InFile: inFile[k]}
		if !ok {
			s.Why = "Ядро не даёт этот параметр."
		}
		st.Settings = append(st.Settings, s)
	}
	q := Setting{Key: Qdisc, Group: GroupTCP, Current: v[Qdisc], Want: "fq", Done: v[Qdisc] == "fq", Supported: fq, InFile: inFile[Qdisc]}
	if !fq {
		q.Why = "В ядре нет очереди fq (модуль sch_fq)."
	}
	cc := Setting{Key: TCPCC, Group: GroupTCP, Current: v[TCPCC], Want: "bbr", Done: v[TCPCC] == "bbr", Supported: st.BBR, InFile: inFile[TCPCC]}
	if !st.BBR {
		cc.Why = "Ядро не поддерживает BBR (нет модуля tcp_bbr)."
	}
	st.Settings = append(st.Settings, q, cc)
	return st, nil
}

// fileKeys are the keys a sysctl file sets.
func fileKeys(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if k, _, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = true
		}
	}
	return out
}

// ErrUnsupported: a setting the kernel cannot do.
var ErrUnsupported = errors.New("tuning: not supported by the kernel")

// Plan is the settings HyRoute's file will hold: keys, each one HyRoute
// offers and the kernel can do. Errors are for the admin.
func Plan(st State, keys []string) ([]Setting, error) {
	if len(keys) == 0 {
		return nil, errors.New("выберите хотя бы одну настройку")
	}
	var out []Setting
	for _, k := range Keys {
		if !slices.Contains(keys, k) {
			continue
		}
		s, _ := st.Setting(k)
		if !s.Supported {
			return nil, fmt.Errorf("%w: %s. %s", ErrUnsupported, k, s.Why)
		}
		out = append(out, s)
	}
	for _, k := range keys {
		if !slices.Contains(Keys, k) {
			return nil, fmt.Errorf("HyRoute не меняет %q", k)
		}
	}
	return out, nil
}

// FileText is HyRoute's file for the settings.
func FileText(plan []Setting) string {
	var b strings.Builder
	b.WriteString("# Managed by HyRoute Server: system settings for Hysteria.\n")
	b.WriteString("# Changes here are replaced the next time HyRoute applies them.\n")
	for _, s := range plan {
		fmt.Fprintf(&b, "%s = %s\n", s.Key, s.Want)
	}
	return b.String()
}
