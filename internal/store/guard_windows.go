//go:build windows

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	guardMu sync.Mutex
	held    = map[string]handles{} // held until HyRoute exits

	procAccessCheck = windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")
)

// handles are the two Windows handles Guard keeps open on a folder: the
// folder itself (so it cannot be renamed or deleted) and a file inside it
// (so it can never be emptied). Both are needed: an empty folder can be
// turned into a link even while its own handle is open.
type handles struct {
	dir  windows.Handle
	lock windows.Handle
}

// Guard prepares dir, a folder of HyRoute's data in the user's profile,
// for HyRoute to work in by file name. HyRoute runs elevated, and any
// program of the user can write to the profile: a folder that leads
// elsewhere would make saving settings, log rotation or "Очистить логи"
// create, replace or delete files the user cannot touch. Guard creates
// dir and accepts it only if it is an ordinary folder (not a link) that
// the user could write to without elevation; then it keeps the folder,
// and a lock file inside it, open until HyRoute exits, so that it can be
// neither renamed nor replaced (folder handle) nor turned into a link by
// being emptied first (lock file, see lockName). Not elevated, or elevated
// without a split UAC token, there is nothing to guard and Guard only
// creates dir.
func Guard(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	user, err := LimitedToken()
	if err != nil || user == 0 {
		return err
	}
	defer user.Close()
	key := strings.ToLower(filepath.Clean(dir))
	guardMu.Lock()
	defer guardMu.Unlock()
	if _, ok := held[key]; ok {
		return nil
	}
	h, err := hold(dir, user)
	if err != nil {
		return err
	}
	held[key] = h
	return nil
}

// release drops the handles Guard holds for dir. HyRoute holds its folders
// until it exits; only tests call this, so a test's temp folder can be
// removed (running the tests from an elevated console with a split UAC
// token is otherwise the one case where Guard would keep them locked).
func release(dir string) {
	key := strings.ToLower(filepath.Clean(dir))
	guardMu.Lock()
	defer guardMu.Unlock()
	if h, ok := held[key]; ok {
		if h.lock != 0 {
			windows.CloseHandle(h.lock)
		}
		if h.dir != 0 {
			windows.CloseHandle(h.dir)
		}
		delete(held, key)
	}
}

// LimitedToken is the user's own (non-elevated) token when HyRoute runs
// elevated over a split UAC token, 0 otherwise: what the user's other
// programs run with. The caller closes it.
func LimitedToken() (windows.Token, error) {
	t := windows.GetCurrentProcessToken()
	var typ, n uint32
	if err := windows.GetTokenInformation(t, windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), 4, &n); err != nil {
		return 0, err
	}
	const tokenElevationTypeFull = 2
	if typ != tokenElevationTypeFull {
		return 0, nil
	}
	return t.GetLinkedToken()
}

// hold opens dir for Guard, checks it against user's token and, once it is
// accepted, opens the lock file that keeps it non-empty.
func hold(dir string, user windows.Token) (handles, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return handles{}, err
	}
	// FILE_LIST_DIRECTORY makes the sharing mode count: without delete
	// sharing the folder cannot be renamed or deleted while it is open.
	dh, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return handles{}, fmt.Errorf("папка %s: %w", dir, err)
	}
	var fi windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(dh, &fi)
	if err == nil && (fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0) {
		err = fmt.Errorf("%s — ссылка на другое место, а не обычная папка: HyRoute работает с правами администратора и не пишет туда, куда она ведёт. Замените её обычной папкой", dir)
	}
	if err == nil {
		err = sameFinalPath(dh, dir)
	}
	if err == nil {
		err = userCanWrite(dh, dir, user)
	}
	var lh windows.Handle
	if err == nil {
		lh, err = lockFile(dir)
	}
	if err != nil {
		windows.CloseHandle(dh)
		return handles{}, err
	}
	return handles{dir: dh, lock: lh}, nil
}

// sameFinalPath refuses a folder whose path leads through a link higher
// up (a junction the user made and can retarget later): the open handles
// keep only the folder itself in place, while HyRoute works by name. The
// ordinary folders above it cannot be renamed while a handle inside is
// open, nor turned into links while not empty. appDataDir resolves the
// links of a legitimately moved profile beforehand.
func sameFinalPath(h windows.Handle, dir string) error {
	got, err := finalPath(h)
	if err != nil {
		return fmt.Errorf("папка %s: %w", dir, err)
	}
	want := filepath.Clean(dir)
	if p, err := windows.UTF16PtrFromString(want); err == nil {
		// 8.3 names (C:\Users\LONGNA~1 in %TEMP%) are not links.
		buf := make([]uint16, windows.MAX_LONG_PATH)
		if n, err := windows.GetLongPathName(p, &buf[0], uint32(len(buf))); err == nil && int(n) < len(buf) {
			want = windows.UTF16ToString(buf[:n])
		}
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("путь %s ведёт через ссылку в %s: HyRoute работает с правами администратора и не пишет туда, куда она ведёт. Замените ссылку обычной папкой", dir, got)
	}
	return nil
}

// finalPath is the path Windows resolves h to, without the \\?\ prefix.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED, VOLUME_NAME_DOS
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", windows.ERROR_FILENAME_EXCED_RANGE
	}
	p := windows.UTF16ToString(buf[:n])
	if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(p, `\\?\`), nil
}

// appDataDir is the user's roaming application data folder with the links
// on its path resolved (a profile moved to another disk through a
// junction), so that Guard finds none (see sameFinalPath). It comes from
// Windows rather than the APPDATA variable, which any program of the user
// can set for this elevated process.
func appDataDir() (string, error) {
	d, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil || d == "" {
		if d = os.Getenv("APPDATA"); d == "" {
			return os.UserConfigDir()
		}
	}
	p, err := windows.UTF16PtrFromString(d)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return d, nil // Guard reports what is wrong with it
	}
	defer windows.CloseHandle(h)
	if f, err := finalPath(h); err == nil {
		d = f
	}
	return d, nil
}

// lockName is a file Guard keeps open inside every guarded folder. An
// empty folder can be turned into a reparse point (a mount point) even
// while its own handle is open: anyone who can write to the profile could
// then redirect HyRoute's writes elsewhere. A folder that holds an open,
// undeletable file cannot — FSCTL_SET_REPARSE_POINT returns
// ERROR_DIR_NOT_EMPTY — so the lock file, not the folder's contents, is
// what keeps the folder ordinary. The name stays out of ClearLogs's
// *.log* glob.
const lockName = ".hyroute-lock"

// lockFile creates (or opens) lockName inside dir and keeps it open with
// no delete sharing, so it cannot be removed and the folder stays
// non-empty. The name must not lead elsewhere either.
func lockFile(dir string) (windows.Handle, error) {
	name := filepath.Join(dir, lockName)
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	// FILE_READ_DATA makes the sharing mode count (as FILE_LIST_DIRECTORY
	// does for the folder): a handle with attribute access only takes no
	// part in the sharing check, and the file could be deleted under it.
	// OPEN_ALWAYS creates it on first run. Hidden and system so it does
	// not show among the user's files.
	h, err := windows.CreateFile(p, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, fmt.Errorf("файл %s: %w", name, err)
	}
	var fi windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &fi)
	if err == nil && (fi.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || fi.NumberOfLinks != 1) {
		err = fmt.Errorf("%s — ссылка, а не обычный файл: замените папку %s обычной", name, dir)
	}
	if err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// userCanWrite checks the folder's permissions for user: HyRoute creates
// files there (settings, logs), which the user must be able to do without
// HyRoute.
func userCanWrite(h windows.Handle, dir string, user windows.Token) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("папка %s: %w", dir, err)
	}
	// FILE_ADD_FILE alone: the point is only that the user could create
	// files here without elevation. FILE_DELETE_CHILD belongs to Full
	// Control, not Modify, so requiring it would refuse a profile or a
	// redirected %APPDATA% that grants the user Modify (HyRoute would then
	// not start at all).
	const fileAddFile = 0x2
	granted, err := Access(sd, user, fileAddFile)
	if err != nil {
		return fmt.Errorf("папка %s: проверка прав: %w", dir, err)
	}
	if granted == 0 {
		return fmt.Errorf("в папку %s нельзя писать без прав администратора: HyRoute не будет работать там с файлами от имени администратора. Укажите папку в своём профиле", dir)
	}
	return nil
}

// Access is the access that user gets to a file or folder with the
// security descriptor sd (owner, group, DACL and integrity label), out of
// desired (MAXIMUM_ALLOWED: all it may have); 0 when desired is not
// granted in full. user is an identification token, as LimitedToken is.
func Access(sd *windows.SECURITY_DESCRIPTOR, user windows.Token, desired uint32) (uint32, error) {
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	mapping := struct{ read, write, execute, all uint32 }{
		windows.FILE_GENERIC_READ, windows.FILE_GENERIC_WRITE, windows.FILE_GENERIC_EXECUTE, fileAllAccess}
	var privs [64]uint32 // PRIVILEGE_SET
	privLen := uint32(unsafe.Sizeof(privs))
	var granted uint32
	var ok int32
	r, _, e := procAccessCheck.Call(uintptr(unsafe.Pointer(sd)), uintptr(user),
		uintptr(desired), uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&privs[0])), uintptr(unsafe.Pointer(&privLen)),
		uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&ok)))
	if r == 0 {
		return 0, e
	}
	if ok == 0 {
		return 0, nil
	}
	return granted, nil
}
