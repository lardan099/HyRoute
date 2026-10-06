package logx

import (
	"strings"
	"testing"
	"time"
)

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
		"visited 999.md, point.md and example.zip":          "visited ***.md, ***.md and ***.zip",
		"rename geosite.dat.new rules.json.new: denied":     "rename geosite.dat.new rules.json.new: denied",
		"go.md log.md html.zip tcp/999.md:443":              "***.md ***.md ***.zip tcp/***.md:443",
		`C:\docs\README.md package.zip`:                     `C:\docs\***.md ***.zip`,
		`from C:\Users\Иван\Downloads\HyRoute ok`:           `from C:\Users\***\Downloads\HyRoute ok`,
		"мой-магазин.рф и example.com, госуслуги.рф":        "***.рф и ***.com, ***.рф",
		"xn--e1afmkfd.xn--p1ai files.отчёт.txt":             "***.xn--p1ai files.отчёт.txt",
		"example.com2 a_b.example.com x_example.com жx.com": "example.com2 a_b.***.com x_example.com ***.com",
		"a.zip.new x.md.zip sub.example.com2 e.xn--p1aiф":   "a.zip.new x.md.zip ***.example.com2 ***.xn--p1aiф",
	} {
		if got := Sanitize(in, []string{"vpn.example.com"}); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// Long dotted runs that are not names (a.a.….com9) must not make MaskDomains
// retry every label and every prefix: exported logs have no line limit.
func TestMaskDomainsLong(t *testing.T) {
	x := strings.Repeat("x", 62)
	cases := map[string]string{
		strings.Repeat("a.", 5000) + "com9":           strings.Repeat("a.", 5000) + "com9",
		"sni=" + strings.Repeat("x1.", 3000) + "io0":  "sni=" + strings.Repeat("x1.", 3000) + "io0",
		strings.Repeat("a1-b.", 3000) + "c9":          strings.Repeat("a1-b.", 3000) + "c9",
		strings.Repeat("ab-c.", 3000) + "d9":          "***.ab-c.d9",
		strings.Repeat("ab.", 3000) + "com9 end":      "***.ab.com9 end",
		"_" + x + strings.Repeat(".a", 5000) + ".com": "_" + x + ".***.com",
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for in, want := range cases {
			if got := MaskDomains(in); got != want {
				t.Errorf("%.40q…: got %.60q…", in, got)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("MaskDomains takes too long on long dotted runs")
	}
}
