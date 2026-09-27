//go:build windows

package procinfo

import (
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procGetWindow                = user32.NewProc("GetWindow")

	descMu    sync.Mutex
	descCache = map[string]string{} // path -> FileDescription
)

const gwOwner = 4

// The EnumWindows callback is made once: the runtime never frees a
// callback, and a process that made about 2000 of them dies ("too many
// callback functions"). enumOut receives its results under enumMu.
var (
	enumMu  sync.Mutex
	enumOut map[uint32]bool
	enumCB  = syscall.NewCallback(enumWindow)
)

func enumWindow(hwnd uintptr, _ uintptr) uintptr {
	if v, _, _ := procIsWindowVisible.Call(hwnd); v == 0 {
		return 1
	}
	if owner, _, _ := procGetWindow.Call(hwnd, gwOwner); owner != 0 {
		return 1
	}
	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	enumOut[pid] = true
	return 1
}

// windowedPIDs: processes with a visible, unowned top-level window.
func windowedPIDs() map[uint32]bool {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumOut = map[uint32]bool{}
	procEnumWindows.Call(enumCB, 0)
	out := enumOut
	enumOut = nil
	return out
}

// description reads FileDescription ("Discord", "Telegram Desktop").
func description(path string) string {
	descMu.Lock()
	d, ok := descCache[path]
	descMu.Unlock()
	if ok {
		return d
	}
	d = readDescription(path)
	descMu.Lock()
	descCache[path] = d
	descMu.Unlock()
	return d
}

func readDescription(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return ""
	}
	var tr *[2]uint16
	var n uint32
	langs := []string{}
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&tr), &n) == nil && n >= 4 {
		langs = append(langs, strings.ToUpper(hex4(tr[0])+hex4(tr[1])))
	}
	langs = append(langs, "040904B0", "040904E4", "000004B0")
	for _, l := range langs {
		var p *uint16
		if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\StringFileInfo\`+l+`\FileDescription`, unsafe.Pointer(&p), &n) == nil && n > 0 {
			return strings.TrimSpace(windows.UTF16PtrToString(p))
		}
	}
	return ""
}

func hex4(v uint16) string {
	const d = "0123456789abcdef"
	return string([]byte{d[v>>12], d[v>>8&15], d[v>>4&15], d[v&15]})
}

// ListRunning lists running programs, one entry per executable path.
func ListRunning() []Running {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	win := windowedPIDs()
	sysDir, _ := windows.GetWindowsDirectory()
	sysDir = strings.ToLower(sysDir) + `\`
	self := uint32(windows.GetCurrentProcessId())
	byPath := map[string]*Running{}
	var order []string
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pid := pe.ProcessID
		if pid == 0 || pid == 4 || pid == self {
			continue
		}
		path, _, ok := query(pid)
		if !ok || path == "" {
			continue
		}
		key := strings.ToLower(path)
		r := byPath[key]
		if r == nil {
			r = &Running{Name: filepath.Base(path), Path: path, System: strings.HasPrefix(key, sysDir)}
			byPath[key] = r
			order = append(order, key)
		}
		r.Count++
		if win[pid] {
			r.Windowed = true
		}
	}
	out := make([]Running, 0, len(order))
	for _, k := range order {
		r := byPath[k]
		r.Description = description(r.Path)
		out = append(out, *r)
	}
	return out
}
