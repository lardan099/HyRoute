// Package service watches and controls the Hysteria service of a server:
// its status (read-only), start, stop and restart as jobs, and the secrets
// its journal is redacted with.
package service

import (
	"context"
	"errors"
	"math"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Status is the state of the Hysteria service and of the machine.
type Status struct {
	Unit     string `json:"unit"`
	State    string `json:"state"`    // active, inactive, failed, activating…
	SubState string `json:"subState"` // running, dead, auto-restart…
	Active   bool   `json:"active"`
	Enabled  bool   `json:"enabled"`
	PID      int    `json:"pid,omitempty"`
	Restarts int    `json:"restarts"`
	// UptimeSec is how long the service has been active (0: not active).
	UptimeSec int64  `json:"uptimeSec"`
	MemoryMiB int    `json:"memoryMiB"`
	Version   string `json:"version"`
	// Managed: HyRoute installed it (it can be reinstalled).
	Managed bool `json:"managed"`
	// Ports are the UDP ports Hysteria listens on.
	Ports  []int  `json:"ports"`
	System System `json:"system"`
}

// System is the machine's basic metrics.
type System struct {
	UptimeSec    int64      `json:"uptimeSec"`
	Load         [3]float64 `json:"load"`
	CPUs         int        `json:"cpus"`
	MemTotalMiB  int        `json:"memTotalMiB"`
	MemAvailMiB  int        `json:"memAvailMiB"`
	DiskFreeMiB  int        `json:"diskFreeMiB"`
	CheckedAtUTC time.Time  `json:"checkedAt"`
}

// Read reads the status; ex should be read-only.
func Read(ctx context.Context, ex remote.Executor, in model.Installation, sudo bool, now time.Time) (Status, error) {
	s := Status{Unit: in.Unit, Managed: in.Managed, Ports: []int{}}
	u, err := remote.Unit(ctx, ex, in.Unit)
	if err != nil {
		return s, err
	}
	if !u.Exists() {
		return s, &NotInstalledError{Unit: in.Unit}
	}
	s.State, s.SubState, s.Active = u.ActiveState, u.SubState, u.ActiveState == "active"
	s.Enabled, s.PID, s.Restarts = u.UnitFileState == "enabled", u.MainPID, u.NRestarts
	s.MemoryMiB = int(u.MemoryCurrent >> 20)

	up, err := remote.Uptime(ctx, ex)
	if err != nil {
		return s, err
	}
	s.System.UptimeSec = int64(up)
	if s.Active && u.ActiveEnter > 0 {
		s.UptimeSec = max(0, int64(math.Round(up-float64(u.ActiveEnter)/1e6)))
	}
	if s.System.Load, err = remote.LoadAverage(ctx, ex); err != nil {
		return s, err
	}
	if s.System.CPUs, err = remote.CPUCount(ctx, ex); err != nil {
		return s, err
	}
	if s.System.MemTotalMiB, s.System.MemAvailMiB, err = remote.Memory(ctx, ex); err != nil {
		return s, err
	}
	if s.System.DiskFreeMiB, err = remote.DiskFree(ctx, ex, "/"); err != nil {
		return s, err
	}
	s.System.CheckedAtUTC = now.UTC()

	if strings.HasPrefix(path.Base(in.Binary), "hysteria") {
		// A binary another user can change is not run: no version.
		var ub *remote.UntrustedBinaryError
		if s.Version, err = remote.HysteriaVersion(ctx, ex, in.Binary); err != nil && !errors.As(err, &ub) {
			return s, err
		}
	}
	ls, err := remote.Listeners(ctx, ex, sudo)
	if err != nil {
		return s, err
	}
	for _, l := range ls {
		if l.Proto == "udp" && (s.PID == 0 || l.PID == 0 || l.PID == s.PID) && strings.HasPrefix(l.Process, "hysteria") {
			s.Ports = append(s.Ports, l.Port)
		}
	}
	return s, nil
}

// NotInstalledError: systemd does not know the recorded unit any more.
type NotInstalledError struct{ Unit string }

func (e *NotInstalledError) Error() string {
	return "Службы " + e.Unit + " на сервере нет: Hysteria удалили или переименовали службу. Импортируйте сервер заново."
}

// Store is what the service package reads from the controller.
type Store interface {
	store.Configs
	store.Installations
}

// Redactor is redact.New with the passwords of the server's current config
// registered: journal lines pass through it.
func Redactor(ctx context.Context, st store.Configs, keys *secrets.Keyring, serverID int64) (*redact.Redactor, error) {
	r := redact.New()
	cur, err := st.CurrentConfig(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return r, nil
	} else if err != nil {
		return nil, err
	}
	b, err := keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	if err != nil {
		return nil, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return r, nil // an unparsable config has no fields to take secrets from
	}
	r.Add(ConfigSecrets(c)...)
	return r, nil
}

// ConfigSecrets are the secret values of a server config.
func ConfigSecrets(c *hyconfig.Server) []string {
	out := []string{c.Auth.Password, c.Obfs.Salamander.Password, c.Obfs.Gecko.Password, c.TrafficStats.Secret}
	// Realms: listen: realm://<token>@host/id.
	if strings.Contains(c.Listen, "://") {
		if u, err := url.Parse(c.Listen); err == nil && u.User != nil {
			out = append(out, u.User.Username())
		}
	}
	for _, p := range c.Auth.UserPass {
		out = append(out, p)
	}
	if c.ACME != nil {
		for _, v := range c.ACME.DNS.Config {
			out = append(out, v)
		}
	}
	for _, o := range c.Outbounds {
		out = append(out, o.SOCKS5.Password)
		if u, err := url.Parse(o.HTTP.URL); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok {
				out = append(out, pw)
			}
		}
	}
	return out
}
