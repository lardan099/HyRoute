package divert

import "fmt"

// Windows error codes documented for WinDivertOpen, plus the ones the DLL's
// driver installation can surface.
const (
	errFileNotFound            = 2
	errPathNotFound            = 3
	errAccessDenied            = 5
	errInvalidParameter        = 87
	errInvalidImageHash        = 577
	errDriverFailedPriorUnload = 654
	errServiceDoesNotExist     = 1060
	errServiceMarkedForDelete  = 1072
	errServiceDisabled         = 1058
	errDriverBlocked           = 1275
	errEptSNotRegistered       = 1753
)

// Explain turns a WinDivertOpen error code into a user-facing message.
// driver describes the already installed WinDivert service, if any (see
// InspectDriver); it makes conflicts with zapret/GoodbyeDPI actionable.
func Explain(code uint32, driver *DriverInfo) string {
	other := ""
	if driver != nil && driver.Exists && !driver.Ours {
		other = fmt.Sprintf(" Служба WinDivert зарегистрирована другой программой: %s.", driver.ImagePath)
	}
	switch code {
	case errFileNotFound, errPathNotFound:
		if other != "" {
			return "Не удалось загрузить драйвер WinDivert: файл службы отсутствует." + other +
				" Это остаток удалённой программы (zapret, GoodbyeDPI и т. п.). Удалите запись службы кнопкой «Удалить устаревшую службу WinDivert» или командой «sc delete WinDivert» от администратора."
		}
		return "Не найден WinDivert64.sys рядом с HyRoute.exe. Переустановите приложение."
	case errAccessDenied:
		return "Нет прав администратора. Запустите HyRoute от имени администратора."
	case errInvalidParameter:
		// Usually our filter string or parameters. The driver version is
		// checked only once a handle is open, so an older driver of another
		// program that rejects them fails here: name it.
		return "WinDivert отклонил фильтр или параметры хэндла (внутренняя ошибка HyRoute)." + other
	case errInvalidImageHash:
		return "Windows отклонила подпись драйвера WinDivert. Проверьте, что файлы не повреждены, и что не включён режим, запрещающий сторонние драйверы (HVCI/Memory Integrity обычно не мешает)."
	case errDriverFailedPriorUnload:
		return "Загружена несовместимая версия драйвера WinDivert." + other +
			" Закройте программы, использующие WinDivert (zapret, GoodbyeDPI и др.), или перезагрузите компьютер."
	case errServiceMarkedForDelete:
		return "Драйвер WinDivert выгружается. Повторите подключение через несколько секунд."
	case errServiceDisabled:
		return "Служба WinDivert отключена (Start=Disabled)." + other
	case errDriverBlocked:
		return "Загрузка драйвера WinDivert заблокирована: антивирус, античит (Vanguard, FACEIT и др.) или виртуальная машина без поддержки драйверов. Добавьте HyRoute в исключения или закройте античит."
	case errEptSNotRegistered:
		return "Отключена служба Base Filtering Engine (BFE). Включите её: без неё WinDivert не работает."
	}
	return fmt.Sprintf("Ошибка WinDivert %d.%s", code, other)
}

// DriverInfo describes the "WinDivert" kernel service, which all WinDivert
// 2.x programs share.
type DriverInfo struct {
	Exists    bool
	Running   bool
	ImagePath string
	// Ours reports whether ImagePath is our own WinDivert64.sys.
	Ours bool
	// Legacy lists running WinDivert 1.x services ("WinDivert1.4" ...); they
	// use a different device and are not ordered by our priorities.
	Legacy []string
}

// Supported driver version: the DLL accepts any 2.x driver, but filters and
// semantics were tested with 2.2 only.
const (
	WantMajor = 2
	WantMinor = 2
)

// CheckVersion validates the version reported by an open handle.
func CheckVersion(major, minor uint64, driver *DriverInfo) error {
	if major == WantMajor && minor >= WantMinor {
		return nil
	}
	where := ""
	if driver != nil && driver.ImagePath != "" {
		where = " (" + driver.ImagePath + ")"
	}
	return fmt.Errorf("уже загружен драйвер WinDivert %d.%d%s, HyRoute требует %d.%d+. "+
		"Закройте программу, которая его использует (zapret, GoodbyeDPI и др.), или перезагрузите компьютер",
		major, minor, where, WantMajor, WantMinor)
}
