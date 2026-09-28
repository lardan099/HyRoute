//go:build windows

package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileListDirectory = 0x1 // FILE_LIST_DIRECTORY / FILE_READ_DATA
	fileAddFile       = 0x2
	fileDeleteChild   = 0x40
	fileReadData      = 0x1
)

// fileRenameInformation is FILE_RENAME_INFORMATION (and FILE_RENAME_INFO
// of FileRenameInfoEx, whose Flags share the first field).
type fileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// isRemote (tests replace it) reports whether h is on a network
// redirector: FileRemoteProtocolInfo succeeds only there.
var isRemote = func(h windows.Handle) bool {
	var buf [256]byte
	return windows.GetFileInformationByHandleEx(h, windows.FileRemoteProtocolInfo, &buf[0], uint32(len(buf))) == nil
}

// WriteUserFile writes b to path, a file the user picked in a save dialog.
// HyRoute runs elevated, so it writes only where the user could write
// without elevation, and never through a link at the target: the folder is
// opened once and kept open, its permissions are checked against the
// user's token (LimitedToken, Access), a temp file is created relative to
// that handle (NtCreateFile, FILE_CREATE, FILE_OPEN_REPARSE_POINT) and
// renamed over the target relative to the same handle
// (NtSetInformationFile FileRenameInformation, ReplaceIfExists): a symbolic
// or hard link at the target is replaced, not followed. On a network share
// the server authorizes the user's account instead (remote shares of this
// computer and hidden «$» shares are refused).
func WriteUserFile(path string, b []byte) error {
	user, err := LimitedToken()
	if err != nil {
		return err
	}
	if user != 0 {
		defer user.Close()
	}
	return writeUserFile(path, b, user)
}

func writeUserFile(path string, b []byte, user windows.Token) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return sentencef("Недопустимое имя файла: «%s»", path)
	}
	dir, name := filepath.Split(path)
	if checkUserName(name) != nil {
		return sentencef("Недопустимое имя файла: «%s»", path) // the whole path: masked in Privacy mode
	}
	dirDisplay := strings.TrimSuffix(dir, `\`)
	if strings.HasSuffix(dir, `:\`) {
		dirDisplay = dir
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	// Links on the folder path are followed on purpose (a redirected
	// «Документы»): the checks apply to the folder actually opened. No
	// delete sharing: it cannot be renamed away while held.
	dh, err := windows.CreateFile(p, fileListDirectory|fileAddFile|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return openErr(err, dirDisplay)
	}
	defer windows.CloseHandle(dh)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(dh, &fi); err != nil {
		return err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return sentencef("«%s» — не папка", dirDisplay)
	}
	if isRemote(dh) {
		if err := remoteCheck(dh, &fi); err != nil {
			return err
		}
		return writeRemote(dh, name, b)
	}
	var folderSD *windows.SECURITY_DESCRIPTOR
	if user != 0 {
		folderSD, err = securityOf(dh)
		if err != nil {
			return err
		}
		if g, err := Access(folderSD, user, fileAddFile); err != nil {
			return err
		} else if g == 0 {
			return sentencef("В папку «%s» нельзя записать без прав администратора: выберите папку в своём профиле, например «Документы»", dirDisplay)
		}
	}
	// The target, if there: a folder is refused; replacing an entry needs
	// what the user would need for it.
	if th, err := ntOpen(dh, name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE, windows.FILE_OPEN, 0, nil); err == nil {
		var tfi windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(th, &tfi)
		if err == nil && tfi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			err = sentencef("«%s» — это папка", path) // a link to a folder too: nothing renames over it
		}
		if err == nil && tfi.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
			err = sentencef("Файл «%s» только для чтения: выберите другое имя", path)
		}
		if err == nil && user != 0 {
			var tsd *windows.SECURITY_DESCRIPTOR
			if tsd, err = securityOf(th); err == nil {
				var g1, g2 uint32
				if g1, err = Access(tsd, user, windows.DELETE); err == nil && g1 == 0 {
					if g2, err = Access(folderSD, user, fileDeleteChild); err == nil && g2 == 0 {
						err = sentencef("Файл «%s» нельзя перезаписать без прав администратора: выберите другое имя", path)
					}
				}
			}
		}
		windows.CloseHandle(th)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return accessErr(err, dirDisplay)
	}

	var ownerSD *windows.SECURITY_DESCRIPTOR
	if user != 0 {
		// Owned by the user, not by Administrators: in folders where the
		// user's rights come through CREATOR OWNER they can still change or
		// delete their backup. No DACL: it is inherited from the folder.
		tu, err := user.GetTokenUser()
		if err != nil {
			return err
		}
		if ownerSD, err = windows.NewSecurityDescriptor(); err == nil {
			err = ownerSD.SetOwner(tu.User.Sid, false)
		}
		if err != nil {
			return err
		}
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	tmp := ".hyroute-" + hex.EncodeToString(rnd[:]) + ".tmp" // short: any valid name fits
	access := uint32(windows.GENERIC_WRITE | windows.DELETE | windows.SYNCHRONIZE)
	opts := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	th, err := ntOpen(dh, tmp, access, windows.FILE_CREATE, opts, ownerSD)
	if errors.Is(err, windows.STATUS_INVALID_OWNER) && ownerSD != nil {
		th, err = ntOpen(dh, tmp, access, windows.FILE_CREATE, opts, nil)
	}
	if err != nil {
		return accessErr(err, dirDisplay)
	}
	err = writeAll(th, b)
	if err == nil {
		err = renameAt(th, dh, name, windows.FileRenameInformation, false)
	}
	if err != nil {
		deleteOnClose(th)
		windows.CloseHandle(th)
		return accessErr(err, dirDisplay)
	}
	return windows.CloseHandle(th)
}

// writeRemote writes on a genuine remote share: the server checks the
// user's account; links there are the server's business.
func writeRemote(dh windows.Handle, name string, b []byte) error {
	dir, err := finalPath(dh)
	if err != nil {
		return err
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	tmpPath := filepath.Join(dir, ".hyroute-"+hex.EncodeToString(rnd[:])+".tmp")
	p, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	th, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.DELETE, 0, nil, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return remoteErr(err, dir)
	}
	err = writeAll(th, b)
	if err == nil {
		err = renameAt(th, 0, filepath.Join(dir, name), windows.FileRenameInfoEx, true)
	}
	if err != nil {
		deleteOnClose(th)
		windows.CloseHandle(th)
		return remoteErr(err, dir)
	}
	return windows.CloseHandle(th)
}

// ReadUserFile reads at most max bytes of path, a file the user picked,
// only if the user could read it without elevation (checked on the open
// handle, so links anywhere on the path change nothing).
func ReadUserFile(path string, max int64) ([]byte, error) {
	user, err := LimitedToken()
	if err != nil {
		return nil, err
	}
	if user != 0 {
		defer user.Close()
	}
	return readUserFile(path, max, user)
}

func readUserFile(path string, max int64, user windows.Token) ([]byte, error) {
	path = filepath.Clean(path)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// SQOS identification: a pipe server behind the path cannot
	// impersonate the elevated process.
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_SEQUENTIAL_SCAN|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, sentencef("Нет доступа к файлу «%s» под вашей учётной записью: HyRoute работает с правами администратора и открывает только файлы, которые можете открыть вы", path)
		case errors.Is(err, windows.ERROR_SHARING_VIOLATION):
			return nil, sentencef("Файл «%s» занят другой программой — закройте её и повторите", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_DISK {
		return nil, sentencef("«%s» — не обычный файл", path)
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil, sentencef("«%s» — не обычный файл", path)
	}
	if int64(fi.FileSizeHigh)<<32|int64(fi.FileSizeLow) > max {
		return nil, ErrUserFileTooLarge
	}
	if isRemote(h) {
		if err := remoteCheck(h, &fi); err != nil {
			return nil, err
		}
	} else if user != 0 {
		sd, err := securityOf(h)
		if err != nil {
			return nil, err
		}
		if g, err := Access(sd, user, fileReadData); err != nil {
			return nil, err
		} else if g == 0 {
			return nil, sentencef("Нет доступа к файлу «%s» под вашей учётной записью: HyRoute работает с правами администратора и открывает только файлы, которые можете открыть вы", path)
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			if isRemote(h) {
				return nil, sentencef("Сетевая папка не разрешила открыть «%s» под вашей учётной записью", path)
			}
			return nil, sentencef("Windows не дала открыть «%s». Возможно, папку защищает «Контролируемый доступ к папкам» Защитника Windows: выберите другую папку или разрешите HyRoute в настройках защиты", path)
		}
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrUserFileTooLarge
	}
	return b, nil
}

// remoteCheck applies the network-path policy to a handle on a network
// redirector: the final path's host and share (remoteRefusal), then the
// volume serial against the local disks (a DNS alias of this computer).
func remoteCheck(h windows.Handle, fi *windows.ByHandleFileInformation) error {
	final, err := finalPathRaw(h)
	if err != nil {
		return err
	}
	if err := remoteRefusal(final, gatherLocalNames()); err != nil {
		return err
	}
	for _, s := range localVolumeSerials() {
		if s == fi.VolumeSerialNumber {
			return sentencef("«%s» — общая папка этого компьютера: HyRoute работает с правами администратора и не пишет и не читает свои диски через сеть. Укажите обычный путь (C:\\…)", displayUNC(final))
		}
	}
	return nil
}

// finalPathRaw is GetFinalPathNameByHandle (normalized, DOS volume names)
// as Windows returns it.
func finalPathRaw(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if int(n) >= len(buf) {
		return "", windows.ERROR_FILENAME_EXCED_RANGE
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// gatherLocalNames: this computer's names (NetBIOS and DNS, physical
// too) and interface addresses.
func gatherLocalNames() localNames {
	var ln localNames
	for _, t := range []uint32{0, 1, 3, 4, 5, 7} { // ComputerName{NetBIOS,DnsHostname,DnsFullyQualified} and their Physical forms
		buf := make([]uint16, 256)
		n := uint32(len(buf))
		if windows.GetComputerNameEx(t, &buf[0], &n) == nil && n > 0 {
			ln.names = append(ln.names, windows.UTF16ToString(buf[:n]))
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ln.ips = append(ln.ips, ip.Unmap())
				}
			}
		}
	}
	return ln
}

// localVolumeSerials are the serial numbers of the local fixed and
// removable volumes.
func localVolumeSerials() []uint32 {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || int(n) > len(buf) {
		return nil
	}
	var out []uint32
	for i := 0; i < int(n); {
		j := i
		for j < int(n) && buf[j] != 0 {
			j++
		}
		if j > i {
			root := &buf[i]
			if t := windows.GetDriveType(root); t == windows.DRIVE_FIXED || t == windows.DRIVE_REMOVABLE {
				var serial uint32
				if windows.GetVolumeInformation(root, nil, 0, &serial, nil, nil, nil, 0) == nil {
					out = append(out, serial)
				}
			}
		}
		i = j + 1
	}
	return out
}

func securityOf(h windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|
		windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
}

// ntOpen opens name relative to the folder handle dir, never following a
// reparse point at the name.
func ntOpen(dir windows.Handle, name string, access, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	us, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: dir, ObjectName: us, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func writeAll(h windows.Handle, b []byte) error {
	for len(b) > 0 {
		var n uint32
		if err := windows.WriteFile(h, b, &n, nil); err != nil {
			return err
		}
		b = b[n:]
	}
	return windows.FlushFileBuffers(h)
}

// renameAt renames the open file h to name, relative to root (0 = name is
// a full path), replacing what is there.
func renameAt(h, root windows.Handle, name string, class uint32, byHandle bool) error {
	u, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameLen := (len(u) - 1) * 2
	var dummy fileRenameInformation
	buf := make([]byte, int(unsafe.Offsetof(dummy.FileName))+nameLen+2)
	info := (*fileRenameInformation)(unsafe.Pointer(&buf[0]))
	info.ReplaceIfExists = 1 // FILE_RENAME_FLAG_REPLACE_IF_EXISTS for FileRenameInfoEx
	info.RootDirectory = root
	info.FileNameLength = uint32(nameLen)
	copy(unsafe.Slice(&info.FileName[0], len(u)), u)
	if byHandle {
		return windows.SetFileInformationByHandle(h, class, &buf[0], uint32(len(buf)))
	}
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, &buf[0], uint32(len(buf)), class)
}

func deleteOnClose(h windows.Handle) {
	del := uint32(1) // FILE_DISPOSITION_INFO.DeleteFile
	windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&del)), 1)
}

func isDenied(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.STATUS_ACCESS_DENIED)
}

// accessErr: a refusal after the user-token checks passed comes from
// Controlled Folder Access or an antivirus.
func accessErr(err error, dir string) error {
	if isDenied(err) {
		return sentencef("Windows не дала записать файл в «%s». Возможно, папку защищает «Контролируемый доступ к папкам» Защитника Windows: выберите другую папку или разрешите HyRoute в настройках защиты", dir)
	}
	return err
}

func openErr(err error, dir string) error {
	if isDenied(err) {
		return sentencef("В папку «%s» нельзя записать без прав администратора: выберите папку в своём профиле, например «Документы»", dir)
	}
	return err
}

func remoteErr(err error, dir string) error {
	if isDenied(err) {
		return sentencef("Сетевая папка «%s» не разрешила запись под вашей учётной записью", displayUNC(dir))
	}
	return err
}
