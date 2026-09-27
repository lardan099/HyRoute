//go:build windows

package divert

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// InspectDriver reports the state of the shared "WinDivert" kernel service.
// All WinDivert 2.x programs (zapret, GoodbyeDPI, ...) use the same service
// and device name: if the service already exists, WinDivert.dll does not
// install ours but starts/opens whatever driver the service points to.
func InspectDriver(ourSys string) (*DriverInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	info := &DriverInfo{}
	if s, err := m.OpenService("WinDivert"); err == nil {
		info.Exists = true
		if cfg, err := s.Config(); err == nil {
			info.ImagePath = normalizeImagePath(cfg.BinaryPathName)
			info.Ours = strings.EqualFold(filepath.Clean(info.ImagePath), filepath.Clean(ourSys))
		}
		if st, err := s.Query(); err == nil {
			info.Running = st.State == svc.Running
		}
		s.Close()
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil, err
	}
	for _, name := range []string{"WinDivert1.0", "WinDivert1.1", "WinDivert1.2", "WinDivert1.3", "WinDivert1.4"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			info.Legacy = append(info.Legacy, name)
		}
		s.Close()
	}
	return info, nil
}

// DeleteStaleService removes a stopped "WinDivert" service entry left behind
// by an uninstalled program. A running service is never touched.
func DeleteStaleService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService("WinDivert")
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State != svc.Stopped {
		return errors.New("служба WinDivert запущена другой программой, удалять её нельзя")
	}
	return s.Delete()
}

func normalizeImagePath(p string) string {
	p = strings.Trim(p, `"`)
	for _, pre := range []string{`\??\`, `\\?\`} {
		p = strings.TrimPrefix(p, pre)
	}
	if strings.HasPrefix(strings.ToLower(p), `\systemroot\`) {
		if root, err := windows.GetWindowsDirectory(); err == nil {
			p = root + p[len(`\systemroot`):]
		}
	}
	return p
}
