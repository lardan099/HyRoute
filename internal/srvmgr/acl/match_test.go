package acl

import (
	"slices"
	"strings"
	"testing"
)

const vectors = `reject(geoip:private)
direct(suffix:ru)
direct(пример.рф)
proxy(*.google.com, tcp/443)
reject(all, udp/443)
proxy(geoip:ru)
default(geosite:google)
direct(1.1.1.1, *, 9.9.9.9)
proxy(11.0.0.0/8, udp/53)
#~off reject(all)`

func TestMatch(t *testing.T) {
	d := Parse(vectors)
	env := Env{Outbounds: []string{"cascade", "Proxy"}, Geo: testGeo{}}
	for _, c := range []struct {
		q        Request
		rule     int
		outbound string
		hijack   string
		reason   string
	}{
		{Request{Host: "yandex.ru", Port: 443}, 1, "direct", "", "Правило 2: домен yandex.ru — это ru или его поддомен."},
		{Request{Host: " Mail.Yandex.RU. ", Port: 80}, 1, "direct", "", "mail.yandex.ru"},
		{Request{Host: "пример.рф", Port: 443}, 2, "direct", "", "(пример.рф клиент передаёт как xn--e1afmkfd.xn--p1ai)"},
		{Request{Host: "www.google.com", Proto: "TCP", Port: 443}, 3, "Proxy", "", "подходит под шаблон *.google.com, протокол и порт подходят под tcp/443"},
		{Request{Host: "www.google.com", Proto: "udp", Port: 443}, 4, "reject", "", "Соединение отклоняется."},
		{Request{Host: "mail.google.com", Port: 80}, 6, "cascade", "", "есть в списке geosite:google. default — outbound по умолчанию «cascade»."},
		{Request{Host: "5.6.7.8", Port: 22}, 5, "Proxy", "", "адрес 5.6.7.8 из geoip:ru"},
		{Request{Host: "example.org", IPs: []string{"2001:db8::1", "5.1.1.1", "6.1.1.1"}, Port: 22}, 5, "Proxy", "", "адрес 5.1.1.1 или 2001:db8::1 из geoip:ru"},
		{Request{Host: "example.org", Port: 22}, -1, "cascade", "", "Ни одно правило не подошло: соединение уходит в outbound по умолчанию «cascade»."},
		{Request{Host: "1.1.1.1", Port: 53}, 7, "direct", "9.9.9.9", "Соединение уходит на 9.9.9.9 вместо запрошенного адреса."},
		{Request{Host: "11.2.3.4", Proto: "udp", Port: 53}, 8, "Proxy", "", "в подсети 11.0.0.0/8"},
		{Request{Host: "11.2.3.4", Port: 53}, -1, "cascade", "", ""},
		{Request{Host: "127.0.0.1", Port: 8080}, 0, "reject", "", ""},
		{Request{Host: "::1", Port: 1}, 0, "reject", "", ""},
	} {
		v, err := Match(d, env, c.q)
		if err != nil {
			t.Errorf("%+v: %v", c.q, err)
			continue
		}
		if v.Rule != c.rule || v.Outbound != c.outbound || v.Hijack != c.hijack || !strings.Contains(v.Reason, c.reason) || len(v.Unknown) != 0 {
			t.Errorf("%+v: %+v", c.q, v)
		}
	}

	for _, q := range []Request{
		{Port: 443}, {Host: "a b", Port: 443}, {Host: "x.com"}, {Host: "x.com", Port: 70000},
		{Host: "x.com", Proto: "icmp", Port: 1}, {Host: "x.com", IPs: []string{"nope"}, Port: 1},
	} {
		if _, err := Match(d, env, q); err == nil {
			t.Errorf("%+v: no error", q)
		}
	}
}

// Rules the controller cannot try are named: on the server they may
// match first.
func TestMatchUnknown(t *testing.T) {
	v, err := Match(Parse("proxy(geosite:google)\nbad(all)\n#~off reject(all)\ndirect(all)"), Env{Outbounds: []string{"proxy"}}, Request{Host: "google.com", Port: 443})
	if err != nil || v.Rule != 3 || v.Outbound != "direct" || !slices.Equal(v.Unknown, []int{0, 1}) {
		t.Fatalf("%+v %v", v, err)
	}
	// No rules, no outbounds: Hysteria goes direct.
	v, _ = Match(Document{}, Env{}, Request{Host: "a.com", Port: 1})
	if v.Rule != -1 || v.Outbound != "direct" || !strings.Contains(v.Reason, "outbounds нет") {
		t.Fatalf("%+v", v)
	}
}

func TestDryRun(t *testing.T) {
	before := Parse("direct(suffix:example.com)\ndirect(1.1.1.1, udp/53, 9.9.9.9)\nproxy(all)")
	after := Parse("direct(www.example.com)\ndirect(1.1.1.1, udp/53, 8.8.8.8)\nproxy(all)\ndirect(11.0.0.0/8)")
	env := Env{Outbounds: []string{"proxy"}}
	changes, err := DryRun(before, after, env, Env{Outbounds: []string{"PROXY"}}, nil, []Request{{Host: "other.org", Port: 443}, {Host: "example.com", Port: 80}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range changes {
		got = append(got, c.Request.Host+":"+c.Before.Outbound+c.Before.Hijack+">"+c.After.Outbound+c.After.Hijack)
	}
	// example.com (given, port 80, and the sample on 443) leaves the
	// suffix rule; the hijack changes; 11.0.0.1 stays with proxy (all is
	// above); other.org and www.example.com stay.
	want := []string{"example.com:direct>PROXY", "example.com:direct>PROXY", "1.1.1.1:direct9.9.9.9>direct8.8.8.8"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if _, err := DryRun(before, after, env, env, nil, []Request{{Host: "x"}}); err == nil {
		t.Fatal("a bad request passed")
	}
}

// A renamed outbound is the same one: nothing of it changes, the default
// neither. One that took the old name of another is not.
func TestDryRunRenames(t *testing.T) {
	before := Parse("proxy(suffix:example.com)\ndirect(suffix:ru)")
	env := Env{Outbounds: []string{"proxy", "other"}}
	extra := []Request{{Host: "a.org", Port: 443}}
	renamed := Parse("nl(suffix:example.com)\ndirect(suffix:ru)")
	ch, err := DryRun(before, renamed, env, Env{Outbounds: []string{"nl", "other"}}, map[string]string{"nl": "proxy", "other": "other"}, extra)
	if err != nil || len(ch) != 0 {
		t.Fatalf("rename: %v %+v", err, ch)
	}
	// Without the map the names differ.
	if ch, _ := DryRun(before, renamed, env, Env{Outbounds: []string{"nl", "other"}}, nil, extra); len(ch) != 3 {
		t.Fatalf("by name: %+v", ch)
	}
	ch, err = DryRun(before, before, env, Env{Outbounds: []string{"proxy_old", "other", "proxy"}}, map[string]string{"proxy_old": "proxy", "other": "other"}, extra)
	var got []string
	for _, c := range ch {
		got = append(got, c.Request.Host+":"+c.Before.Outbound+">"+c.After.Outbound)
	}
	if err != nil || !slices.Equal(got, []string{"example.com:proxy>proxy", "www.example.com:proxy>proxy"}) {
		t.Fatalf("old name taken: %v %q", err, got)
	}
}

func TestSamples(t *testing.T) {
	for addr, want := range map[string][]string{
		"Example.com.":   {"example.com"},
		"suffix:ru":      {"ru", "www.ru"},
		"*.google.*":     {"a.google.a"},
		"10.0.0.0/8":     {"10.0.0.1"},
		"192.0.2.7/32":   {"192.0.2.7"},
		"2001:db8::/32":  {"2001:db8::1"},
		"1.2.3.4":        {"1.2.3.4"},
		"geoip:ru":       nil,
		"geosite:google": nil,
		"all":            nil,
	} {
		var got []string
		for _, q := range samples(Rule{Outbound: "x", Address: addr}) {
			got = append(got, q.Host)
			if q.Proto != "tcp" || q.Port != 443 {
				t.Errorf("%s: %+v", addr, q)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %q", addr, got)
		}
	}
	if q := samples(Rule{Outbound: "x", Address: "a.com", Proto: "udp", Port: "50-60"}); q[0].Proto != "udp" || q[0].Port != 50 {
		t.Fatalf("%+v", q)
	}
}
