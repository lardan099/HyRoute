//go:build windows

package procinfo

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewCache returns a cache backed by OpenProcess/QueryFullProcessImageName
// and Toolhelp snapshots.
func NewCache() *Cache { return NewCacheWith(System{Query: query, Snapshot: snapshot}) }

func query(pid uint32) (string, int64, bool) {
	if pid == 0 || pid == 4 {
		return "", 0, true
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", 0, false
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return "", 0, false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	path := ""
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
		path = windows.UTF16ToString(buf[:n])
	}
	return path, creation.Nanoseconds(), true
}

// snapshot lists processes with their parents and creation times (the
// Toolhelp snapshot has no creation times, and without them a PID reused
// by a sibling would look like the same process).
func snapshot() []ProcEntry {
	if out := processInfo(); out != nil {
		return out
	}
	return toolhelp()
}

var (
	infoMu  sync.Mutex
	infoBuf []uint64 // reused between snapshots (8-byte aligned)
)

// processInfo reads NtQuerySystemInformation(SystemProcessInformation),
// the source Toolhelp copies from; nil on failure.
func processInfo() []ProcEntry {
	infoMu.Lock()
	defer infoMu.Unlock()
	if infoBuf == nil {
		infoBuf = make([]uint64, 64<<10) // 512 KiB
	}
	for range 5 {
		size := uint32(len(infoBuf) * 8)
		var need uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation, unsafe.Pointer(&infoBuf[0]), size, &need)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH {
			// Processes come and go: leave room for more.
			infoBuf = make([]uint64, (max(need, size)+size/2)/8+1)
			continue
		}
		if err != nil {
			return nil
		}
		var out []ProcEntry
		base := unsafe.Pointer(&infoBuf[0])
		for off := uintptr(0); off < uintptr(size); {
			p := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Add(base, off))
			e := ProcEntry{PID: uint32(p.UniqueProcessID), PPID: uint32(p.InheritedFromUniqueProcessID)}
			if e.PID != 0 && e.PID != 4 { // query reports 0 for these
				ft := windows.Filetime{LowDateTime: uint32(p.CreateTime), HighDateTime: uint32(p.CreateTime >> 32)}
				e.Created = ft.Nanoseconds()
			}
			out = append(out, e)
			if p.NextEntryOffset == 0 {
				return out
			}
			off += uintptr(p.NextEntryOffset)
		}
		return nil
	}
	return nil
}

func toolhelp() []ProcEntry {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []ProcEntry
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out = append(out, ProcEntry{PID: pe.ProcessID, PPID: pe.ParentProcessID})
	}
	return out
}

// ServicePID returns the PID of a running service (e.g. "Dnscache").
func ServicePID(name string) (uint32, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(m)
	n, _ := windows.UTF16PtrFromString(name)
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, err
	}
	return st.ProcessId, nil
}
