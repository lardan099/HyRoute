package logx

import "testing"

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"dst=85.203.0.249:443 src=192.168.1.5:5000":         "dst=85.xxx.xxx.249:443 src=192.168.1.5:5000",
		"127.0.0.1 10.0.0.1 100.64.1.1 8.8.8.8":             "127.0.0.1 10.0.0.1 100.64.1.1 8.xxx.xxx.8",
		"[2a01:4f8:c0c:1234::1]:443 ::1 fe80::1":            "[2a01:xxxx::xxxx]:443 ::1 fe80::1",
		"21:37:10 info at 12:00:01.123":                     "21:37:10 info at 12:00:01.123",
		"server vpn.example.com ok":                         "server *** ok",
		"sub https://panel.example/sub/TOKEN?x=1 end":       "sub https://***/… end",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334 full form": "2001:xxxx::xxxx full form",
		"version 2.12.3.4 not an ip? 999.1.1.1":             "version 2.xxx.xxx.4 not an ip? 999.1.1.1",
		"geosite.dat from cdn.example.org":                  "geosite.dat from ***.org",
	} {
		if got := Sanitize(in, []string{"vpn.example.com"}); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}
