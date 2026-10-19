package routing

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// catalogGeo has every category of the catalog, each with its service's
// sample domain, but those named in without; and geoip private.
type catalogGeo struct{ without []string }

func (g catalogGeo) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	m := map[string]*v2geo.GeoSite{}
	for _, c := range catalogServices() {
		for _, n := range c.Sites {
			if !slices.Contains(g.without, n) {
				m[n] = &v2geo.GeoSite{CountryCode: strings.ToUpper(n), Domain: []*v2geo.Domain{{Type: v2geo.Domain_RootDomain, Value: c.Sample}}}
			}
		}
	}
	return m, nil
}

func (g catalogGeo) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	m := map[string]*v2geo.GeoIP{"private": {CountryCode: "PRIVATE", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(10, 0, 0, 0).To4(), Prefix: 8}}}}
	for _, c := range catalogServices() {
		for _, n := range c.IPs {
			if !slices.Contains(g.without, n) {
				m[n] = &v2geo.GeoIP{CountryCode: strings.ToUpper(n), Cidr: []*v2geo.CIDR{{Ip: net.IPv4(198, 51, 100, 0).To4(), Prefix: 24}}}
			}
		}
	}
	return m, nil
}

func allVisible(t *testing.T) map[string]bool {
	t.Helper()
	v, err := visibleServices(catalogGeo{})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The catalog: unique IDs, every service with a category and a sample,
// no category of two services; every rule it builds passes Hysteria's
// compiler, and each sample goes by its own service's rule.
func TestServicesCatalog(t *testing.T) {
	ids, cats := map[string]bool{}, map[string]string{}
	all := map[string]string{}
	for _, sec := range Catalog() {
		if sec.ID == "" || sec.Name == "" || len(sec.Services) == 0 || ids["section:"+sec.ID] {
			t.Fatalf("section %+v", sec)
		}
		ids["section:"+sec.ID] = true
		for _, c := range sec.Services {
			if c.ID == "" || ids[c.ID] || c.Name == "" || strings.ContainsAny(c.Name, "#\r\n") || len(c.Sites) == 0 || c.Sample == "" || strings.ContainsAny(c.Sample, "/:* ") {
				t.Fatalf("service %+v", c)
			}
			ids[c.ID] = true
			for _, a := range slices.Concat(prefixed("geosite:", c.Sites), prefixed("suffix:", c.Domains), prefixed("geoip:", c.IPs)) {
				if was, ok := cats[a]; ok {
					t.Fatalf("%s is of %s and %s", a, was, c.ID)
				}
				cats[a] = c.ID
			}
			all[c.ID] = "direct"
		}
	}
	vis := allVisible(t)
	doc, err := buildServices(acl.Document{}, all, servicesEnv{visible: vis}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != len(cats) {
		t.Fatalf("%d rules for %d categories", len(doc.Rules), len(cats))
	}
	env := acl.Env{Geo: catalogGeo{}, GeoIPPath: "/etc/hysteria/geo/geoip.dat", GeoSitePath: "/etc/hysteria/geo/geosite.dat"}
	for _, p := range acl.Check(doc, env) {
		if p.Level == acl.Error {
			t.Errorf("%+v", p)
		}
	}
	for _, c := range catalogServices() {
		v, err := acl.Match(doc, env, acl.Request{Host: c.Sample, Port: 443})
		if err != nil || v.Rule < 0 || doc.Rules[v.Rule].Comment != c.Name {
			t.Errorf("%s: %+v %v", c.ID, v, err)
		}
	}
}

func prefixed(p string, ss []string) []string {
	var out []string
	for _, s := range ss {
		out = append(out, p+s)
	}
	return out
}

// manual is a routing with a block of local networks and rules of the
// admin's own.
const manual = "# правила сервера\n#~group Локальные сети\nreject(127.0.0.0/8)\nreject(10.0.0.0/8)\n#~group\n# свои\ndirect(suffix:example.com)\nnl(all) # остальное"

func entryEnv(t *testing.T) servicesEnv {
	return servicesEnv{entry: true, outbounds: []string{"cascade", "warp"}, visible: allVisible(t)}
}

// The group is built and read back without changes, through text and
// JSON; rules by name come before those by address.
func TestServicesRoundTrip(t *testing.T) {
	choices := map[string]string{"youtube": "cascade", "telegram": "direct", "banks-ru": "direct", "x": "reject", "chatgpt": "warp"}
	built, err := buildServices(acl.Parse(manual), choices, entryEnv(t), false)
	if err != nil {
		t.Fatal(err)
	}
	text := built.Text()
	group := "#~group По сервисам\n" + servicesMarkLine() + "\n" +
		"cascade(geosite:youtube) # YouTube\ndirect(geosite:telegram) # Telegram\nreject(geosite:twitter) # X (Twitter)\n" +
		"warp(geosite:openai) # ChatGPT\ndirect(geosite:category-bank-ru) # Банки России\n" +
		"direct(geoip:telegram) # Telegram\nreject(geoip:twitter) # X (Twitter)\n"
	want := strings.Replace(manual, "reject(10.0.0.0/8)\n", "reject(10.0.0.0/8)\n"+group, 1)
	if text != want {
		t.Fatalf("got:\n%s\nwant:\n%s", text, want)
	}
	var viaJSON acl.Document
	b, _ := json.Marshal(acl.Parse(text))
	json.Unmarshal(b, &viaJSON)
	for name, d := range map[string]acl.Document{"built": built, "text": acl.Parse(text), "json": viaJSON} {
		st := ReadServices(d)
		if !st.Found || st.Edited || st.Version != ServicesVersion || !maps.Equal(st.Choices, choices) {
			t.Fatalf("%s: %+v", name, st)
		}
		again, err := buildServices(d, st.Choices, entryEnv(t), false)
		if err != nil || again.Text() != text {
			t.Fatalf("%s: rebuilt (%v):\n%s", name, err, again.Text())
		}
	}
	if st := ReadServices(acl.Parse(manual)); st.Found || st.Edited || len(st.Choices) != 0 {
		t.Fatalf("no group: %+v", st)
	}
}

// The admin's rules keep their text and order; the group stays where the
// admin moved it; with no service chosen it goes, and the rules are as
// before it came.
func TestServicesKeepManual(t *testing.T) {
	env := entryEnv(t)
	built, _ := buildServices(acl.Parse(manual), map[string]string{"youtube": "cascade"}, env, false)
	// The admin moves the group to the end.
	d := acl.Parse(built.Text())
	var moved acl.Document
	for _, r := range d.Rules {
		if r.Group != ServicesGroup {
			moved.Rules = append(moved.Rules, r)
		}
	}
	for _, r := range d.Rules {
		if r.Group == ServicesGroup {
			moved.Rules = append(moved.Rules, r)
		}
	}
	moved = acl.Parse(moved.Text())
	if st := ReadServices(moved); st.Edited {
		t.Fatalf("a moved group is the builder's: %+v", st)
	}
	again, err := buildServices(moved, map[string]string{"youtube": "direct", "vk": "direct"}, env, false)
	if err != nil {
		t.Fatal(err)
	}
	got := again.Text()
	if !strings.HasPrefix(got, manual+"\n#~group По сервисам\n") || !strings.HasSuffix(got, "direct(geosite:youtube) # YouTube\ndirect(geosite:vk) # ВКонтакте") {
		t.Fatalf("moved group:\n%s", got)
	}
	// No service chosen: no group, the admin's rules as they were.
	none, err := buildServices(acl.Parse(built.Text()), map[string]string{"youtube": ""}, env, false)
	if err != nil || none.Text() != manual {
		t.Fatalf("%v\n%s", err, none.Text())
	}
	// Without a block of local networks the group goes first; a comment
	// above its header stays above it.
	plain := "direct(suffix:example.com)\nnl(all)"
	first, _ := buildServices(acl.Parse(plain), map[string]string{"youtube": "direct"}, env, false)
	if !strings.HasPrefix(first.Text(), "#~group По сервисам\n") || !strings.HasSuffix(first.Text(), "#~group\ndirect(suffix:example.com)\nnl(all)") {
		t.Fatalf("first:\n%s", first.Text())
	}
	noted := acl.Parse("reject(geoip:private)\n# заметка админа\n" + strings.TrimPrefix(first.Text(), ""))
	rebuilt, err := buildServices(noted, map[string]string{"youtube": "reject"}, env, false)
	if err != nil || !strings.HasPrefix(rebuilt.Text(), "reject(geoip:private)\n# заметка админа\n#~group По сервисам\n") {
		t.Fatalf("%v\n%s", err, rebuilt.Text())
	}
	cleared, _ := buildServices(noted, nil, env, false)
	if cleared.Text() != "reject(geoip:private)\n# заметка админа\n#~group\ndirect(suffix:example.com)\nnl(all)" {
		t.Fatalf("cleared:\n%s", cleared.Text())
	}
}

// Services whose categories the controller's databases lack are hidden
// and not built; without databases none is shown.
func TestServicesHidden(t *testing.T) {
	g := catalogGeo{without: []string{"youtube", "telegram"}} // geosite youtube, geoip telegram
	vis, err := visibleServices(g)
	if err != nil {
		t.Fatal(err)
	}
	if vis["youtube"] || vis["telegram"] || !vis["netflix"] || !vis["whatsapp"] {
		t.Fatalf("%v", vis)
	}
	e := newEnv(t, config, false)
	e.svc.Geo = g
	v, err := e.svc.Services(context.Background(), e.server, acl.Document{})
	if err != nil {
		t.Fatal(err)
	}
	shown := func(id string) bool {
		for _, s := range v.Sections {
			if slices.ContainsFunc(s.Services, func(c CatalogService) bool { return c.ID == id }) {
				return true
			}
		}
		return false
	}
	hidden := func(id string) bool {
		return slices.ContainsFunc(v.Hidden, func(c CatalogService) bool { return c.ID == id })
	}
	if v.NoGeo || shown("youtube") || shown("telegram") || !hidden("youtube") || !hidden("telegram") || !shown("netflix") || len(v.Hidden) != 2 {
		t.Fatalf("%+v", v)
	}
	var fe *model.FieldError
	if _, err := e.svc.BuildServices(context.Background(), e.server, ServicesInput{Choices: map[string]string{"youtube": "direct"}}); !errors.As(err, &fe) {
		t.Fatalf("a hidden service built: %v", err)
	}
	if _, err := e.svc.BuildServices(context.Background(), e.server, ServicesInput{Choices: map[string]string{"nonesuch": "direct"}}); !errors.As(err, &fe) {
		t.Fatalf("an unknown service built: %v", err)
	}
	e.svc.Geo = nil
	if v, err := e.svc.Services(context.Background(), e.server, acl.Document{}); err != nil || !v.NoGeo || len(v.Sections) != 0 || len(v.Hidden) != len(catalogServices()) {
		t.Fatalf("%v %+v", err, v)
	}
}

// "Through the exit" is the cascade outbound on the entry of a cascade;
// on another server it is refused, as is an outbound the draft lacks.
func TestServicesCascade(t *testing.T) {
	ctx := context.Background()
	entry := newEnv(t, config, true)
	entry.svc.Geo = catalogGeo{}
	v, err := entry.svc.Services(ctx, entry.server, acl.Document{})
	if err != nil || v.Cascade == nil || v.OwnGeo {
		t.Fatalf("%v %+v", err, v)
	}
	res, err := entry.svc.BuildServices(ctx, entry.server, ServicesInput{Outbounds: []string{"cascade", "proxy"}, Choices: map[string]string{"youtube": "Cascade", "spotify": "PROXY"}})
	if err != nil || !strings.Contains(res.ACL.Text(), "cascade(geosite:youtube) # YouTube\nproxy(geosite:spotify) # Spotify") || res.State.Choices["youtube"] != "cascade" {
		t.Fatalf("%v\n%s", err, res.ACL.Text())
	}

	plain := newEnv(t, config, false) // the config still has an outbound named cascade
	plain.svc.Geo = catalogGeo{}
	if v, err := plain.svc.Services(ctx, plain.server, acl.Document{}); err != nil || v.Cascade != nil {
		t.Fatalf("%v %+v", err, v)
	}
	var fe *model.FieldError
	for _, o := range []string{"cascade", "nl", "default"} {
		_, err := plain.svc.BuildServices(ctx, plain.server, ServicesInput{Outbounds: []string{"cascade", "proxy"}, Choices: map[string]string{"youtube": o}})
		if !errors.As(err, &fe) || fe.Field != "choices" {
			t.Errorf("%s: %v", o, err)
		}
	}
	for _, o := range []string{"direct", "reject", "proxy"} {
		if _, err := plain.svc.BuildServices(ctx, plain.server, ServicesInput{Outbounds: []string{"cascade", "proxy"}, Choices: map[string]string{"youtube": o}}); err != nil {
			t.Errorf("%s: %v", o, err)
		}
	}
}

// A group changed by hand reads as edited, says how, and is replaced only
// when the builder is told to; a service's outbound changed in the table
// is a choice.
func TestServicesEdited(t *testing.T) {
	env := entryEnv(t)
	built, _ := buildServices(acl.Parse(manual), map[string]string{"youtube": "cascade", "telegram": "cascade", "vk": "direct"}, env, false)
	text := built.Text()
	mark := servicesMarkLine() + "\n"
	for name, c := range map[string]struct{ from, to, says string }{
		"split outbounds":  {"cascade(geoip:telegram)", "direct(geoip:telegram)", "разными выходами"},
		"manual rule":      {"direct(geosite:vk) # ВКонтакте\n", "direct(geosite:vk) # ВКонтакте\ndirect(suffix:example.org)\n", "не из каталога"},
		"off":              {"cascade(geosite:youtube) # YouTube", "#~off cascade(geosite:youtube) # YouTube", "выключено"},
		"comment":          {"# ВКонтакте", "# VK", "изменено"},
		"port":             {"cascade(geosite:youtube)", "cascade(geosite:youtube, tcp/443)", "изменено"},
		"order":            {"cascade(geosite:youtube) # YouTube\ncascade(geosite:telegram) # Telegram", "cascade(geosite:telegram) # Telegram\ncascade(geosite:youtube) # YouTube", "переставлены"},
		"no mark":          {mark, "", "нет отметки"},
		"other version":    {mark, strings.Replace(mark, "v1 ", "v99 ", 1), "другая версия"},
		"comment inside":   {"cascade(geosite:telegram)", "# своё\ncascade(geosite:telegram)", "свои комментарии"},
		"rule taken out":   {"cascade(geoip:telegram) # Telegram\n", "", "нет правила geoip:telegram"},
		"not contiguous":   {"nl(all) # остальное", "nl(all) # остальное\n#~group По сервисам\nreject(geosite:ok) # Одноклассники", "не подряд"},
		"geoip by hand":    {"cascade(geoip:telegram)", "cascade(geoip:telegram)\ndirect(geoip:ru)", "не из каталога"},
		"not a rule":       {"cascade(geosite:youtube) # YouTube", "cascade(geosite:youtube) # YouTube\nкакая-то строка", "не правило"},
		"address spelling": {"geosite:youtube", "geosite:YouTube", "изменено"},
	} {
		if !strings.Contains(text, c.from) {
			t.Fatalf("%s: %q not in\n%s", name, c.from, text)
		}
		d := acl.Parse(strings.Replace(text, c.from, c.to, 1))
		st := ReadServices(d)
		if !st.Edited || !slices.ContainsFunc(st.Changes, func(s string) bool { return strings.Contains(s, c.says) }) {
			t.Errorf("%s: %+v", name, st)
			continue
		}
		var ee *ServicesEditedError
		if _, err := buildServices(d, st.Choices, env, false); !errors.As(err, &ee) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: built without overwrite: %v", name, err)
		}
		over, err := buildServices(d, map[string]string{"youtube": "direct"}, env, true)
		if st := ReadServices(over); err != nil || st.Edited || !maps.Equal(st.Choices, map[string]string{"youtube": "direct"}) {
			t.Errorf("%s: overwrite: %v %+v", name, err, st)
		}
		if !strings.Contains(over.Text(), "nl(all) # остальное") || !strings.HasPrefix(over.Text(), "# правила сервера\n#~group Локальные сети\n") {
			t.Errorf("%s: the admin's rules went:\n%s", name, over.Text())
		}
	}
	// The outbound of a whole service changed in the table is read as the
	// service's choice.
	d := acl.Parse(strings.Replace(text, "cascade(geosite:youtube)", "reject(geosite:youtube)", 1))
	if st := ReadServices(d); st.Edited || st.Choices["youtube"] != "reject" {
		t.Fatalf("%+v", st)
	}
}

// The dry run tries the sample domain of a service whose geosite category
// a rule names.
func TestServicesDryRun(t *testing.T) {
	e := newEnv(t, config, true)
	e.svc.Geo = catalogGeo{}
	ctx := context.Background()
	in := e.input()
	res, err := e.svc.BuildServices(ctx, e.server, ServicesInput{ACL: in.ACL, Outbounds: []string{"cascade", "proxy"}, Choices: map[string]string{"youtube": "proxy", "vk": "direct"}})
	if err != nil {
		t.Fatal(err)
	}
	in.ACL = res.ACL
	p, err := e.svc.Preview(ctx, e.server, in)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, c := range p.Changes {
		hosts = append(hosts, c.Request.Host+" "+c.After.Outbound)
	}
	slices.Sort(hosts)
	if !slices.Equal(hosts, []string{"vk.com direct", "youtube.com proxy"}) || !p.OK {
		t.Fatalf("%v ok=%v %+v", hosts, p.OK, p.Rules)
	}
}
