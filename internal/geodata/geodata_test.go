package geodata

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Tiny protobuf writer for test files.
func pv(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}
func pbytes(b []byte, field int, v []byte) []byte {
	b = pv(b, uint64(field)<<3|2)
	b = pv(b, uint64(len(v)))
	return append(b, v...)
}
func pint(b []byte, field int, v uint64) []byte {
	b = pv(b, uint64(field)<<3)
	return pv(b, v)
}

type dom struct {
	typ   int
	val   string
	attrs []string
}

func siteEntry(code string, doms ...dom) []byte {
	e := pbytes(nil, 1, []byte(code))
	for _, d := range doms {
		m := pint(nil, 1, uint64(d.typ))
		m = pbytes(m, 2, []byte(d.val))
		for _, a := range d.attrs {
			m = pbytes(m, 3, pbytes(nil, 1, []byte(a)))
		}
		e = pbytes(e, 2, m)
	}
	return e
}

func ipEntry(code string, reverse bool, cidrs ...string) []byte {
	e := pbytes(nil, 1, []byte(code))
	for _, c := range cidrs {
		p := netip.MustParsePrefix(c)
		m := pbytes(nil, 1, p.Addr().AsSlice())
		m = pint(m, 2, uint64(p.Bits()))
		e = pbytes(e, 2, m)
	}
	if reverse {
		e = pint(e, 3, 1)
	}
	return e
}

func writeList(t *testing.T, path string, entries ...[]byte) {
	t.Helper()
	var b []byte
	for _, e := range entries {
		b = pbytes(b, 1, e)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testDB(t *testing.T) *DB {
	dir := t.TempDir()
	writeList(t, filepath.Join(dir, "geosite.dat"),
		siteEntry("YOUTUBE",
			dom{typeDomain, "youtube.com", nil},
			dom{typeDomain, "googlevideo.com", nil},
			dom{typeFull, "youtu.be", nil},
		),
		siteEntry("GOOGLE",
			dom{typeDomain, "google.com", nil},
			dom{typeDomain, "google.cn", []string{"cn"}},
			dom{typePlain, "gstatic", nil},
			dom{typeRegex, `^ggpht[0-9]\.com$`, nil},
		),
	)
	writeList(t, filepath.Join(dir, "geoip.dat"),
		ipEntry("RU", false, "77.88.0.0/18", "5.255.255.0/24", "2a02:6b8::/32"),
		ipEntry("NOTRU", true, "77.88.0.0/18"),
	)
	return &DB{Dir: dir}
}

func TestSite(t *testing.T) {
	db := testDB(t)
	yt, err := db.Site("youtube")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"youtube.com": true, "www.youtube.com": true, "rr1---sn.googlevideo.com": true,
		"youtu.be": true, "www.youtu.be": false, "notyoutube.com": false, "example.com": false,
	} {
		if yt.Match(name) != want {
			t.Errorf("youtube %s: want %v", name, want)
		}
	}
	g, _ := db.Site("GOOGLE")
	for name, want := range map[string]bool{
		"mail.google.com": true, "google.cn": true, "fonts.gstatic.com": true, "ggpht3.com": true, "ggpht33.com": false,
	} {
		if g.Match(name) != want {
			t.Errorf("google %s: want %v", name, want)
		}
	}
	cn, _ := db.Site("google@cn")
	if !cn.Match("www.google.cn") || cn.Match("google.com") || cn.Len() != 1 {
		t.Errorf("attribute filter: %d", cn.Len())
	}
	_, err = db.Site("youtbe")
	var ue *UnknownError
	if !errors.As(err, &ue) || len(ue.Similar) == 0 || ue.Similar[0] != "youtube" {
		t.Fatalf("typo: %v", err)
	}
}

func TestIP(t *testing.T) {
	db := testDB(t)
	ru, err := db.IP("ru")
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{
		"77.88.8.8": true, "77.88.63.255": true, "77.88.64.0": false, "5.255.255.5": true,
		"8.8.8.8": false, "2a02:6b8::1": true, "2a02:6b9::1": false, "::ffff:77.88.8.8": true,
	} {
		if ru.Contains(netip.MustParseAddr(ip)) != want {
			t.Errorf("ru %s: want %v", ip, want)
		}
	}
	not, _ := db.IP("notru")
	if not.Contains(netip.MustParseAddr("77.88.8.8")) || !not.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("reverse_match")
	}
	// private is built in when the file lacks it.
	p, err := db.IP("private")
	if err != nil || !p.Contains(netip.MustParseAddr("192.168.1.1")) || p.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatalf("private: %v", err)
	}
}

func TestNoData(t *testing.T) {
	db := &DB{Dir: t.TempDir()}
	if _, err := db.Site("youtube"); !errors.Is(err, ErrNoData) {
		t.Fatal(err)
	}
	if p, err := db.IP("private"); err != nil || p != Private {
		t.Fatal("private must work without a database")
	}
}

func TestReloadAfterReplace(t *testing.T) {
	db := testDB(t)
	if _, err := db.Site("youtube"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(db.Dir, "geosite.dat")
	writeList(t, path, siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil}))
	db.Forget()
	if _, err := db.Site("youtube"); err == nil {
		t.Fatal("old category survived a new file")
	}
	tg, err := db.Site("telegram")
	if err != nil || !tg.Match("t.me") {
		t.Fatal(err)
	}
}

func TestMergeRanges(t *testing.T) {
	s := NewIPSet(mustPrefixes("10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "0.0.0.0/0", "::/0"))
	if len(s.v4) != 1 || len(s.v6) != 1 {
		t.Fatalf("%+v", s)
	}
	if !s.Contains(netip.MustParseAddr("255.255.255.255")) || !s.Contains(netip.MustParseAddr("ffff::1")) {
		t.Fatal("full range")
	}
}

func TestBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.dat")
	os.WriteFile(path, []byte("<html>not found</html>"), 0o600)
	if _, err := Check(path); err == nil {
		t.Fatal("html accepted as a database")
	}
}

// A prefix length that does not fit an int (a damaged or hostile file)
// is skipped: it used to become negative and panic in IPSet.add.
func TestHugePrefixLength(t *testing.T) {
	dir := t.TempDir()
	e := pbytes(nil, 1, []byte("EVIL"))
	e = pbytes(e, 2, pint(pbytes(nil, 1, []byte{10, 0, 0, 0}), 2, 1<<63))
	e = pbytes(e, 2, pint(pbytes(nil, 1, []byte{77, 88, 0, 0}), 2, 18))
	writeList(t, filepath.Join(dir, "geoip.dat"), e)
	if _, err := Check(filepath.Join(dir, "geoip.dat")); err != nil {
		t.Fatal(err)
	}
	db := &DB{Dir: dir}
	s, err := db.IP("evil")
	if err != nil || s.Len() != 1 || !s.Contains(netip.MustParseAddr("77.88.8.8")) || s.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("%v %+v", err, s)
	}
	l, err := db.List(IP, "evil", "", 0, 10)
	if err != nil || len(l.Entries) != 1 || l.Entries[0] != "77.88.0.0/18" {
		t.Fatalf("%v %+v", err, l)
	}
	for _, bits := range []uint64{33, 1 << 32, 1 << 63, ^uint64(0)} {
		if p, ok := decodeCIDR(pint(pbytes(nil, 1, []byte{10, 0, 0, 0}), 2, bits)); ok {
			t.Errorf("prefix length %d accepted: %v", bits, p)
		}
	}
	if s := NewIPSet([]netip.Prefix{{}}); s.Len() != 0 {
		t.Fatal("invalid prefix added")
	}
	err = func() (err error) {
		defer recoverDecode(&err)
		var b []byte
		_ = b[1]
		return nil
	}()
	if err == nil {
		t.Fatal("panic not turned into an error")
	}
}

// Regexps keep their case: \S is not \s. This entry is in geosite:openai
// of the real databases.
func TestSiteRegexpCase(t *testing.T) {
	dir := t.TempDir()
	const re = `^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$`
	writeList(t, filepath.Join(dir, "geosite.dat"),
		siteEntry("OPENAI", dom{typeDomain, "OpenAI.com", nil}, dom{typeRegex, re, nil}))
	db := &DB{Dir: dir}
	const host = "chatgpt-async-webps-prod-eastus-7.webpubsub.azure.com"
	d, err := db.Site("openai")
	if err != nil || !d.Match(host) || !d.Match("api.openai.com") || d.Match("chatgpt-async-webps-prod-x y-7.webpubsub.azure.com") {
		t.Fatal(err)
	}
	hits, err := db.FindSite(host)
	if err != nil || len(hits) != 1 || hits[0].Entry != "regexp:"+re {
		t.Fatalf("%v %+v", err, hits)
	}
	l, err := db.List(Site, "openai", "", 0, 10)
	if err != nil || len(l.Entries) != 2 || l.Entries[0] != "domain:openai.com" || l.Entries[1] != "regexp:"+re {
		t.Fatalf("%v %+v", err, l)
	}
	if l, _ := db.List(Site, "openai", `\S+`, 0, 10); l.Matched != 1 {
		t.Fatalf("filter: %+v", l)
	}

	// Names are lower case; a pattern with capitals still matches them.
	writeList(t, filepath.Join(dir, "geosite.dat"), siteEntry("CAPS", dom{typeRegex, `^Chat\.Example\.COM$`, nil}))
	db.Forget()
	if d, err := db.Site("caps"); err != nil || !d.Match("chat.example.com") {
		t.Fatal("pattern with capitals does not match", err)
	}
	if hits, err := db.FindSite("chat.example.com"); err != nil || len(hits) != 1 {
		t.Fatalf("%v %+v", err, hits)
	}
}

// The category viewer does not show a replaced file's list (update,
// rollback or another source), even for the category open before.
func TestListAfterReplace(t *testing.T) {
	db := testDB(t)
	if l, err := db.List(Site, "youtube", "", 0, 10); err != nil || l.Total != 3 {
		t.Fatalf("%v %+v", err, l)
	}
	writeList(t, filepath.Join(db.Dir, "geosite.dat"), siteEntry("TELEGRAM", dom{typeDomain, "t.me", nil}))
	db.Forget()
	var ue *UnknownError
	if l, err := db.List(Site, "youtube", "", 0, 10); !errors.As(err, &ue) {
		t.Fatalf("old list shown: %v %+v", err, l)
	}
	if l, err := db.List(Site, "telegram", "", 0, 10); err != nil || l.Total != 1 {
		t.Fatalf("%v %+v", err, l)
	}
}

// Readers share delete access: an update can replace a file being read,
// and the reader keeps the old content.
func TestOpenReadAllowsRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.WriteFile(path+".new", []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".prev"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 3)
	if _, err := f.ReadAt(b, 0); err != nil || string(b) != "old" {
		t.Fatalf("%v %q", err, b)
	}
}
