package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/lardan099/hyroute/browser"
	"github.com/lardan099/hyroute/internal/ctl"
)

// The browser extension (browser/): «Настройки» → «Расширение для
// браузера». Installing writes the extension next to HyRoute.exe (the user
// loads it as unpacked: no store), the native messaging host manifest for
// hyroutectl.exe beside it, and the browsers' registry keys of the
// interactive user that point at that manifest.

// BrowserApp is a Chromium browser on this computer.
type BrowserApp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Exe    string `json:"exe"`    // "" = not found
	Linked bool   `json:"linked"` // its registry key points at HyRoute's host
}

// BrowserExtView is the card.
type BrowserExtView struct {
	On        bool         `json:"on"`        // the extension may talk to HyRoute
	Installed bool         `json:"installed"` // the folder and the host manifest are in place
	Dir       string       `json:"dir"`
	Version   string       `json:"version"` // of the folder ("" = none)
	Host      bool         `json:"host"`    // hyroutectl.exe is next to HyRoute.exe
	Browsers  []BrowserApp `json:"browsers"`
	Seen      int64        `json:"seen"` // the extension's last request, Unix seconds (0 = none since start)
}

// browserKind: a browser, its registry keys (HKCU\Software\…, where it
// looks for native messaging hosts) and where its exe lives (relative to
// Program Files, Program Files (x86) or the user's AppData\Local).
type browserKind struct {
	id, name, page string
	keys           []string
	exes           []string
}

var browserKinds = []browserKind{
	{"chrome", "Google Chrome", "chrome://extensions/", []string{`Google\Chrome`}, []string{`Google\Chrome\Application\chrome.exe`}},
	{"edge", "Microsoft Edge", "edge://extensions/", []string{`Microsoft\Edge`}, []string{`Microsoft\Edge\Application\msedge.exe`}},
	{"yandex", "Яндекс Браузер", "browser://extensions/", []string{`Yandex\YandexBrowser`}, []string{`Yandex\YandexBrowser\Application\browser.exe`}},
	{"brave", "Brave", "brave://extensions/", []string{`BraveSoftware\Brave-Browser`}, []string{`BraveSoftware\Brave-Browser\Application\brave.exe`}},
	// Opera reads Chrome's key.
	{"opera", "Opera", "opera://extensions/", []string{`Google\Chrome`}, []string{`Programs\Opera\opera.exe`, `Opera\opera.exe`}},
	{"vivaldi", "Vivaldi", "vivaldi://extensions/", []string{`Vivaldi`, `Google\Chrome`}, []string{`Vivaldi\Application\vivaldi.exe`}},
	{"chromium", "Chromium", "chrome://extensions/", []string{`Chromium`}, []string{`Chromium\Application\chrome.exe`}},
}

func (g *GUI) browserDir() string      { return filepath.Join(g.dllDir, browser.DirName) }
func (g *GUI) browserManifest() string { return filepath.Join(g.dllDir, browser.HostFile) }

// browserHive is the interactive user's registry (HKEY_USERS\<SID>): under
// over-the-shoulder UAC HyRoute's own HKCU is another account's.
func (g *GUI) browserHive() (string, error) {
	if g.cli == nil || g.cli.owner == nil {
		return "", errors.New("не удалось узнать учётную запись Windows")
	}
	return g.cli.owner.String(), nil
}

func hostKey(sid, vendor string) string {
	return sid + `\Software\` + vendor + `\NativeMessagingHosts\` + ctl.BrowserHost
}

// BrowserExtInfo is the card's state.
func (g *GUI) BrowserExtInfo() BrowserExtView {
	v := BrowserExtView{On: g.ctl.BrowserOn(), Dir: g.browserDir(), Browsers: []BrowserApp{}}
	v.Version = browser.DiskVersion(v.Dir)
	v.Host = fileExists(filepath.Join(g.dllDir, "hyroutectl.exe"))
	v.Installed = v.Version != "" && fileExists(g.browserManifest())
	if t := g.ctl.BrowserSeen(); !t.IsZero() {
		v.Seen = t.Unix()
	}
	sid, _ := g.browserHive()
	local := g.userLocalAppData(sid)
	for _, k := range browserKinds {
		b := BrowserApp{ID: k.id, Name: k.name, Exe: findBrowser(k, local)}
		b.Linked = sid != "" && v.Installed
		for _, key := range k.keys {
			b.Linked = b.Linked && registryPoints(hostKey(sid, key), g.browserManifest())
		}
		if b.Exe != "" || b.Linked {
			v.Browsers = append(v.Browsers, b)
		}
	}
	return v
}

// InstallBrowserExt puts the extension and its host in place, links every
// known browser to the host and lets the extension in.
func (g *GUI) InstallBrowserExt() (BrowserExtView, error) {
	if err := g.writeBrowserExt(true); err != nil {
		return g.BrowserExtInfo(), err
	}
	if err := g.ctl.SetBrowserOn(true); err != nil {
		return g.BrowserExtInfo(), err
	}
	g.applyCLI(g.cliMode())
	g.ctl.Log.Info("browser extension installed", "version", browser.Version())
	return g.BrowserExtInfo(), nil
}

// writeBrowserExt writes the folder, the host manifest and the registry
// keys (link: create the keys of browsers not linked yet).
func (g *GUI) writeBrowserExt(link bool) error {
	exe := filepath.Join(g.dllDir, "hyroutectl.exe")
	if !fileExists(exe) {
		return errors.New("hyroutectl.exe нет рядом с HyRoute.exe: он есть в архиве с программой")
	}
	if err := browser.Write(g.browserDir()); err != nil {
		return errors.New("не удалось записать расширение: " + err.Error())
	}
	if err := browser.WriteHostManifest(g.browserManifest(), exe); err != nil {
		return errors.New("не удалось записать " + browser.HostFile + ": " + err.Error())
	}
	sid, err := g.browserHive()
	if err != nil {
		return err
	}
	done := map[string]bool{}
	var errs []error
	for _, k := range browserKinds {
		for _, vendor := range k.keys {
			if done[vendor] {
				continue
			}
			done[vendor] = true
			path := hostKey(sid, vendor)
			if !link && !registryExists(path) {
				continue
			}
			if err := registrySet(path, g.browserManifest()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return errors.New("не удалось записать ключи браузеров в реестр: " + err.Error())
	}
	return nil
}

// syncBrowserExt runs at start: an installed extension follows this
// HyRoute (a newer extension after an update, the host where hyroutectl
// is now). Nothing happens when it was never installed.
func (g *GUI) syncBrowserExt() {
	if !g.ctl.BrowserOn() || browser.DiskVersion(g.browserDir()) == "" {
		return
	}
	if err := g.writeBrowserExt(false); err != nil {
		g.ctl.Log.Warn("browser extension: not refreshed", "err", err)
	}
}

// SetBrowserExtOn lets the extension in or keeps it out (the files stay).
func (g *GUI) SetBrowserExtOn(on bool) (BrowserExtView, error) {
	if err := g.ctl.SetBrowserOn(on); err != nil {
		return g.BrowserExtInfo(), err
	}
	g.applyCLI(g.cliMode())
	g.ctl.Log.Info("browser extension switched", "on", on)
	return g.BrowserExtInfo(), nil
}

// RemoveBrowserExt unlinks the browsers and deletes the files; the
// extension itself is removed in the browser.
func (g *GUI) RemoveBrowserExt() (BrowserExtView, error) {
	var errs []error
	if err := g.ctl.SetBrowserOn(false); err != nil {
		errs = append(errs, err)
	}
	g.applyCLI(g.cliMode())
	if sid, err := g.browserHive(); err == nil {
		for _, k := range browserKinds {
			for _, vendor := range k.keys {
				path := hostKey(sid, vendor)
				// Only a key that points at this HyRoute's host.
				if registryPoints(path, g.browserManifest()) {
					if err := registry.DeleteKey(registry.USERS, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
						errs = append(errs, err)
					}
				}
			}
		}
	}
	if err := browser.Remove(g.browserDir(), g.browserManifest()); err != nil {
		errs = append(errs, err)
	}
	g.ctl.Log.Info("browser extension removed")
	return g.BrowserExtInfo(), errors.Join(errs...)
}

// OpenBrowserExtensions opens the browser's extensions page and shows the
// extension's folder in Explorer, its path on the clipboard: the user
// turns on developer mode and drags the folder onto the page.
func (g *GUI) OpenBrowserExtensions(id string) error {
	sid, _ := g.browserHive()
	local := g.userLocalAppData(sid)
	for _, k := range browserKinds {
		if k.id != id {
			continue
		}
		exe := findBrowser(k, local)
		if exe == "" {
			return errors.New(k.name + " не найден")
		}
		dir := g.browserDir()
		g.CopyText(dir)
		explorer := filepath.Join(windowsDir(), "explorer.exe")
		shellExecuteArgs(explorer, `/select,"`+dir+`"`)
		return shellExecuteArgs(exe, k.page)
	}
	return errors.New("неизвестный браузер")
}

func windowsDir() string {
	if d, err := windows.GetWindowsDirectory(); err == nil {
		return d
	}
	return `C:\Windows`
}

// findBrowser is the browser's exe: under Program Files, Program Files
// (x86) or the user's AppData\Local.
func findBrowser(k browserKind, local string) string {
	var roots []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if d := os.Getenv(env); d != "" {
			roots = append(roots, d)
		}
	}
	if local != "" {
		roots = append(roots, local)
	}
	for _, rel := range k.exes {
		for _, r := range roots {
			if p := filepath.Join(r, rel); fileExists(p) {
				return p
			}
		}
	}
	return ""
}

// userLocalAppData is the interactive user's AppData\Local (HyRoute's own
// %LOCALAPPDATA% may be an administrator's).
func (g *GUI) userLocalAppData(sid string) string {
	if sid != "" {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid, registry.QUERY_VALUE)
		if err == nil {
			defer k.Close()
			if p, _, err := k.GetStringValue("ProfileImagePath"); err == nil && p != "" {
				if x, err := registry.ExpandString(p); err == nil {
					p = x
				}
				return filepath.Join(p, "AppData", "Local")
			}
		}
	}
	return os.Getenv("LOCALAPPDATA")
}

func registryExists(path string) bool {
	k, err := registry.OpenKey(registry.USERS, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// registryPoints: the key's default value is path.
func registryPoints(key, path string) bool {
	k, err := registry.OpenKey(registry.USERS, key, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	return err == nil && strings.EqualFold(filepath.Clean(v), filepath.Clean(path))
}

func registrySet(key, path string) error {
	k, _, err := registry.CreateKey(registry.USERS, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("", path)
}

// browserLine is the diagnostics line.
func (g *GUI) browserLine() string {
	v := g.BrowserExtInfo()
	var linked []string
	for _, b := range v.Browsers {
		if b.Linked {
			linked = append(linked, b.Name)
		}
	}
	switch {
	case !v.Installed && !v.On:
		return "Расширение для браузера: не установлено"
	case !v.On:
		return "Расширение для браузера: выключено"
	case len(linked) == 0:
		return "Расширение для браузера: включено, браузеры не связаны"
	}
	line := "Расширение для браузера: включено (" + strings.Join(linked, ", ") + ")"
	if v.Seen == 0 {
		line += ", с запуска не обращалось"
	}
	return line
}
