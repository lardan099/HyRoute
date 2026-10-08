package routing

import (
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Template is a set of rules (and outbounds, without passwords) to put
// into a server's routing at the top, at the end or instead of its rules.
type Template struct {
	// ID is "builtin:<name>" or "preset:<id>".
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	ACL         acl.Document `json:"acl"`
	Outbounds   []Outbound   `json:"outbounds,omitempty"`
	// Resolver, if set, replaces the server's.
	Resolver *Resolver `json:"resolver,omitempty"`
	Builtin  bool      `json:"builtin,omitempty"`
}

func copyOf(r Resolver) *Resolver { return &r }

func rules(group string, rs ...acl.Rule) acl.Document {
	for i := range rs {
		rs[i].Group = group
	}
	return acl.Document{Rules: rs}
}

// localGroup is the group of the "local networks" template, localNets
// the networks it rejects.
const localGroup = "Локальные сети"

var localNets = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"}

// Builtins are the templates HyRoute ships.
func Builtins() []Template {
	var local []acl.Rule
	for _, cidr := range localNets {
		local = append(local, acl.Rule{Outbound: "reject", Address: cidr})
	}
	return []Template{
		{
			ID: "builtin:local", Name: "Блок локальных сетей", Builtin: true,
			Description: "Клиенты не попадут на сам сервер (службы на 127.0.0.1) и в сети вокруг него, в том числе к адресу метаданных облака 169.254.169.254. Ставьте в начало.",
			ACL:         rules(localGroup, local...),
		},
		{
			ID: "builtin:ads", Name: "Блок рекламы", Builtin: true,
			Description: "Отклоняет домены рекламы и трекеров из списка category-ads-all базы geosite. Нужны базы geo на сервере.",
			ACL:         rules("Реклама", acl.Rule{Outbound: "reject", Address: "geosite:category-ads-all"}),
		},
		{
			ID: "builtin:ru", Name: "RU напрямую", Builtin: true,
			Description: "Для входа каскада в России: российские сайты (домены .ru, .рф, .su и адреса России по geoip) выходят прямо со входа, остальное — в outbound по умолчанию (каскад). Домены — до geoip; DNS over HTTPS, чтобы провайдер входа не видел, какие сайты открывают клиенты. Нужны базы geo на сервере.",
			Resolver:    copyOf(EncryptedResolver),
			ACL: rules("RU напрямую",
				acl.Rule{Outbound: "direct", Address: "suffix:ru"},
				acl.Rule{Outbound: "direct", Address: "suffix:рф"},
				acl.Rule{Outbound: "direct", Address: "suffix:su"},
				acl.Rule{Outbound: "direct", Address: "geoip:ru"},
			),
		},
	}
}

// FromPreset is the rules and outbounds of a preset with an acl section.
func FromPreset(p model.Preset) (Template, bool) {
	c, err := hyconfig.ParseServer([]byte(p.Config))
	if err != nil || len(c.ACL.Inline) == 0 {
		return Template{}, false
	}
	t := Template{ID: "preset:" + strconv.FormatInt(p.ID, 10), Name: p.Name, ACL: acl.ParseInline(c.ACL.Inline)}
	for _, o := range c.Outbounds {
		if strings.EqualFold(o.Name, cascade.OutboundName) {
			continue // the cascade's, made by its link
		}
		t.Outbounds = append(t.Outbounds, outboundOf(o).public())
	}
	return t, true
}
