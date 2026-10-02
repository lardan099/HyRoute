package routing

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Chain template format (P3-09).
const (
	ChainFormat  = "hyroute-chain"
	ChainVersion = 1
)

// ChainTemplate is a cascade without servers and secrets: the link's
// settings and, optionally, the entry's routing. A cascade made from it
// with servers on the roles is the cascade made by hand with the same
// settings.
type ChainTemplate struct {
	Format      string `json:"format"`
	Version     int    `json:"version"`
	ID          string `json:"id,omitempty"` // builtin:<name>
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Builtin     bool   `json:"builtin,omitempty"`
	// Link are the link's settings (no local port: it is the entry's).
	Link cascade.Params `json:"link"`
	// Entry is what the entry's routing gets: rules at the top and a
	// resolver.
	Entry *ChainEntry `json:"entry,omitempty"`
}

// ChainEntry is the entry's part of a chain template: its rules, the
// outbounds they may name (without passwords; not the cascade's, the link
// makes it) and its resolver.
type ChainEntry struct {
	ACL       acl.Document `json:"acl"`
	Outbounds []Outbound   `json:"outbounds,omitempty"`
	Resolver  *Resolver    `json:"resolver,omitempty"`
}

// EncryptedResolver is the resolver "RU direct" gives the entry: DoH by
// address, so the entry's ISP does not see the domains its clients open
// and nothing has to be resolved to reach it.
var EncryptedResolver = Resolver{Type: "https", Addr: "https://1.1.1.1/dns-query"}

// ChainBuiltins are the chain templates HyRoute ships.
func ChainBuiltins() []ChainTemplate {
	var ru acl.Document
	resolver := EncryptedResolver
	for _, t := range Builtins() {
		if t.ID == "builtin:local" || t.ID == "builtin:ru" {
			ru.Rules = append(ru.Rules, t.ACL.Rules...)
		}
		if t.ID == "builtin:ru" && t.Resolver != nil {
			resolver = *t.Resolver
		}
	}
	return []ChainTemplate{
		{
			Format: ChainFormat, Version: ChainVersion, ID: "builtin:all", Name: "Всё через exit", Builtin: true,
			Description: "Весь трафик клиентов входа уходит через выход. Правил на входе нет, поэтому вход не узнаёт адреса сайтов сам.",
		},
		{
			Format: ChainFormat, Version: ChainVersion, ID: "builtin:ru", Name: "RU напрямую", Builtin: true,
			Description: "Российские сайты (.ru, .рф, .su, адреса России) выходят прямо со входа, остальное — через выход. На вход — блок локальных сетей, правила по доменам выше правил по geoip и DNS over HTTPS: провайдер входа не видит, какие сайты открывают клиенты. Нужны базы geo на входе.",
			Entry:       &ChainEntry{ACL: ru, Resolver: &resolver},
		},
	}
}

// ChainOf is the template of a cascade: its link's settings and the
// entry's current routing (a resolver other than the system one). Rules
// kept in an acl.file are not in the view: such an entry is refused.
func ChainOf(c model.Chain, entry View) (ChainTemplate, error) {
	t := ChainTemplate{Format: ChainFormat, Version: ChainVersion, Name: c.Name, Description: c.Notes}
	if entry.File != "" {
		return t, &model.FieldError{Field: "acl.file", Msg: "Правила входа в файле " + entry.File + ": шаблон их не возьмёт. Перенесите их в конфиг (маршрутизация входа), потом сохраните шаблон."}
	}
	if len(c.Links) > 0 {
		p, err := cascade.ParseParams(c.Links[0].Params)
		if err != nil {
			return t, err
		}
		p.LocalPort = 0
		t.Link = p
	}
	if len(entry.ACL.Rules) > 0 || entry.Resolver.Type != "system" {
		e := &ChainEntry{ACL: entry.ACL}
		for _, o := range entry.Outbounds {
			if !o.Locked {
				e.Outbounds = append(e.Outbounds, o.public())
			}
		}
		if entry.Resolver.Type != "system" {
			r := entry.Resolver
			e.Resolver = &r
		}
		t.Entry = e
	}
	return t, nil
}

// ImportChain reads a chain template file.
func ImportChain(data []byte) (ChainTemplate, error) {
	if len(data) > MaxImport {
		return ChainTemplate{}, &model.FieldError{Field: "file", Msg: "Файл больше 1 МБ."}
	}
	var t ChainTemplate
	if err := json.Unmarshal(bytes.TrimSpace(data), &t); err != nil {
		return ChainTemplate{}, &model.FieldError{Field: "file", Msg: "Файл не разобрать: " + err.Error()}
	}
	switch {
	case t.Format != ChainFormat:
		return ChainTemplate{}, &model.FieldError{Field: "file", Msg: "Это не шаблон каскада HyRoute."}
	case t.Version < 1 || t.Version > ChainVersion:
		return ChainTemplate{}, &model.FieldError{Field: "file", Msg: fmt.Sprintf("Файл версии %d: эта версия HyRoute читает версию %d.", t.Version, ChainVersion)}
	}
	t.ID, t.Builtin, t.Link.LocalPort = "", false, 0
	if t.Entry != nil {
		for i, o := range t.Entry.Outbounds {
			t.Entry.Outbounds[i] = o.public()
		}
	}
	if err := t.Link.Validate(); err != nil {
		return ChainTemplate{}, err
	}
	return t, nil
}
