package store

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// A backup is written to and read from a path the user picked in a file
// dialog, while HyRoute runs elevated: WriteUserFile and ReadUserFile
// (userfile_windows.go) touch it only as the user could without
// elevation. Every user-facing text puts a path in «…» (the window masks
// it in Privacy mode).

// ErrUserFileTooLarge: the file is larger than the caller accepts.
var ErrUserFileTooLarge = errors.New("файл слишком большой")

// checkUserName refuses names the Windows file API mistreats: empty, ".", "..",
// with ':' (alternate data streams), '\\' or '/', trailing '.' or ' ',
// or a reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9, any extension).
func checkUserName(name string) error {
	bad := sentencef("Недопустимое имя файла: «%s»", name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `:\/`) ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") ||
		strings.ContainsFunc(name, func(r rune) bool { return r < 32 || strings.ContainsRune(`<>"|?*`, r) }) {
		return bad
	}
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return bad
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return bad
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		// COM¹, LPT² …: superscript digits are device names too.
		if rest := []rune(base[3:]); len(rest) == 1 && strings.ContainsRune("¹²³", rest[0]) {
			return bad
		}
	}
	return nil
}

// localNames are this computer's own names and addresses: a share on one
// of them is a loopback share (see remoteRefusal).
type localNames struct {
	names []string
	ips   []netip.Addr
}

// uncHostShare splits a final path of a network handle («\\?\UNC\host\share\…»
// or «\\host\share\…») into host and share; ok is false for any other path.
func uncHostShare(final string) (host, share string, ok bool) {
	p := final
	switch {
	case strings.HasPrefix(strings.ToUpper(p), `\\?\UNC\`):
		p = p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\`) && !strings.HasPrefix(p, `\\?\`) && !strings.HasPrefix(p, `\\.\`):
		p = p[2:]
	default:
		return "", "", false
	}
	host, rest, _ := strings.Cut(p, `\`)
	share, _, _ = strings.Cut(rest, `\`)
	return host, share, host != ""
}

// displayUNC is a final path as the user writes it: «\\host\share\…».
func displayUNC(final string) string {
	if rest, ok := strings.CutPrefix(final, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return final
}

// remoteRefusal decides whether a network path may be used: hidden and
// administrative shares («$» at the end) and shares of this computer
// (loopback, its own names and addresses) are refused, anything else is
// the remote server's business. It never resolves a name.
func remoteRefusal(final string, local localNames) error {
	host, share, ok := uncHostShare(final)
	if !ok {
		return nil
	}
	if strings.HasSuffix(share, "$") {
		return sentence("Скрытые общие папки (имя кончается на «$») не поддерживаются: выберите обычную общую папку")
	}
	own := sentencef("«%s» — общая папка этого компьютера: HyRoute работает с правами администратора и не пишет и не читает свои диски через сеть. Укажите обычный путь (C:\\…)", displayUNC(final))
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" {
		return own
	}
	for _, n := range local.names {
		if n != "" && strings.EqualFold(strings.TrimSuffix(n, "."), h) {
			return own
		}
	}
	// IPv6 literals in UNC paths are written as «fe80--1.ipv6-literal.net».
	lit := strings.Trim(h, "[]")
	if v6, ok := strings.CutSuffix(lit, ".ipv6-literal.net"); ok {
		lit = strings.ReplaceAll(strings.ReplaceAll(v6, "-", ":"), "s", "%")
	}
	if a, err := netip.ParseAddr(lit); err == nil {
		a = a.Unmap().WithZone("")
		if a.IsLoopback() || a.IsUnspecified() {
			return own
		}
		for _, x := range local.ips {
			if x.Unmap().WithZone("") == a {
				return own
			}
		}
	}
	return nil
}

// sentencef is a message for the user that starts with a capital letter.
func sentencef(format string, a ...any) error { return sentence(fmt.Sprintf(format, a...)) }
