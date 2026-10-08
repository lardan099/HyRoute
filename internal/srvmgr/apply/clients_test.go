package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const usersConfig = `# comment
listen: :443
acme:
  domains: [vpn.example.com]
auth:
  type: userpass
  userpass:
    phone: fake-phone-pass
    link-1-0: fake-link-pass
obfs:
  type: salamander
  salamander:
    password: fake-obfs-pass
masquerade:
  type: proxy
  proxy:
    url: https://example.com/
acl:
  inline:
    - reject(geoip:cn)
someFutureKey: 1
`

// OnlyUsers lets through a change of auth.userpass and nothing else.
func TestOnlyUsers(t *testing.T) {
	cur := []byte(usersConfig)
	ok := map[string]string{
		"a user added":      strings.Replace(usersConfig, "    phone:", "    tablet: fake-new-pass\n    phone:", 1),
		"a password":        strings.Replace(usersConfig, "fake-phone-pass", "fake-other-pass", 1),
		"a user removed":    strings.Replace(usersConfig, "    phone: fake-phone-pass\n", "", 1),
		"formatting":        strings.Replace(usersConfig, "# comment\n", "", 1),
		"re-encoded config": "",
	}
	c, _ := hyconfig.ParseServer(cur)
	b, _ := c.Marshal()
	ok["re-encoded config"] = string(b)
	for name, cand := range ok {
		if err := OnlyUsers(cur, []byte(cand)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cand := range map[string]string{
		"listen":     strings.Replace(usersConfig, ":443", ":8443", 1),
		"obfs":       strings.Replace(usersConfig, "fake-obfs-pass", "fake-obfs-2", 1),
		"masquerade": strings.Replace(usersConfig, "https://example.com/", "https://example.org/", 1),
		"acl":        strings.Replace(usersConfig, "reject(geoip:cn)", "direct(all)", 1),
		"auth type":  strings.Replace(usersConfig, "type: userpass\n  userpass:\n    phone: fake-phone-pass\n    link-1-0: fake-link-pass", "type: password\n  password: fake-x", 1),
		"unknown":    strings.Replace(usersConfig, "someFutureKey: 1", "someFutureKey: 2", 1),
		"a new key":  usersConfig + "speedTest: true\n",
	} {
		if err := OnlyUsers(cur, []byte(cand)); !errors.Is(err, errNotOnlyUsers) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChangeClient(t *testing.T) {
	parse := func() *hyconfig.Server {
		c, err := hyconfig.ParseServer([]byte(usersConfig))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	links := []string{"link-1-0"}
	c := parse()
	p, err := changeClient(c, ClientOp{Op: ClientAdd, User: "мама", Links: links})
	if err != nil || len(p) < 20 || c.Auth.UserPass["мама"] != p || len(c.Auth.UserPass) != 3 {
		t.Fatalf("%v %+v", err, c.Auth.UserPass)
	}
	c = parse()
	if p, err = changeClient(c, ClientOp{Op: ClientPassword, User: "Phone", Links: links}); err != nil || c.Auth.UserPass["phone"] != p || c.Auth.UserPass["link-1-0"] != "fake-link-pass" {
		t.Fatalf("%v %+v", err, c.Auth.UserPass)
	}
	c = parse()
	if _, err = changeClient(c, ClientOp{Op: ClientRemove, User: "phone", Links: links}); err != nil || len(c.Auth.UserPass) != 1 {
		t.Fatalf("%v %+v", err, c.Auth.UserPass)
	}
	for _, op := range []ClientOp{{Op: ClientRemove, User: "LINK-1-0", Links: links}, {Op: ClientPassword, User: "link-1-0", Links: links}, {Op: ClientAdd, User: "link-1-0", Links: links}} {
		if _, err := changeClient(parse(), op); !errors.Is(err, ErrLinkUser) {
			t.Errorf("%+v: %v", op, err)
		}
	}
	var fe *model.FieldError
	for _, op := range []ClientOp{{Op: ClientAdd, User: "phone"}, {Op: ClientAdd, User: "link-2-0"}, {Op: ClientAdd, User: "a:b"}, {Op: ClientRemove, User: "x"}, {Op: "drop", User: "phone"}} {
		if _, err := changeClient(parse(), op); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", op, err)
		}
	}
	pw, _ := hyconfig.ParseServer([]byte("auth:\n  type: password\n  password: fake-x\n"))
	if _, err := changeClient(pw, ClientOp{Op: ClientAdd, User: "x"}); !errors.Is(err, ErrNotUserPass) {
		t.Fatalf("password auth: %v", err)
	}
}
