package app

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

func TestRunningApps(t *testing.T) {
	c, _ := newCtl(t)
	c.ListRunning = func() []procinfo.Running {
		return []procinfo.Running{
			{Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, System: true, Count: 80},
			{Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, System: true, Windowed: true},
			{Name: "Telegram.exe", Path: `C:\Users\u\AppData\Roaming\Telegram Desktop\Telegram.exe`, Description: "Telegram Desktop", Windowed: true},
			{Name: "Discord.exe", Path: `C:\Users\u\AppData\Local\Discord\app-1.0.9\Discord.exe`, Description: "Discord", Windowed: true, Count: 6},
			{Name: "steamwebhelper.exe", Path: `C:\Program Files (x86)\Steam\bin\cef\steamwebhelper.exe`, Description: "Steam Client WebHelper"},
			{Name: "hysteria.exe", Path: `C:\ProgramData\HyRoute\runtime\hysteria.exe`},
		}
	}
	names := func(l []procinfo.Running) string {
		var s []string
		for _, r := range l {
			s = append(s, r.Name)
		}
		return strings.Join(s, ",")
	}
	cases := []struct {
		q    string
		all  bool
		want string
	}{
		{"", false, "Discord.exe,Telegram.exe,steamwebhelper.exe,explorer.exe"},
		{"", true, "Discord.exe,Telegram.exe,steamwebhelper.exe,explorer.exe,svchost.exe"},
		{"disc", false, "Discord.exe"},
		{"DISCORD.EXE", false, "Discord.exe"},
		{"desktop", false, "Telegram.exe"}, // description
		{"steam", false, "steamwebhelper.exe"},
		{"host", false, "svchost.exe"}, // a query finds Windows' own too
		{"hyster", false, ""},
	}
	for _, tc := range cases {
		if got := names(c.RunningApps(tc.q, tc.all, 0)); got != tc.want {
			t.Errorf("%q all=%v: %s, want %s", tc.q, tc.all, got, tc.want)
		}
	}
	if got := c.RunningApps("", false, 2); len(got) != 2 {
		t.Fatal(len(got))
	}
}
