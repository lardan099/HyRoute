package routing

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Export format.
const (
	Format  = "hyroute-routing"
	Version = 1
	// MaxImport bounds an imported file.
	MaxImport = 1 << 20
)

// Export is a server's routing to save or move to another server: rules
// with HyRoute's marks, outbounds and resolver, no passwords and no
// cascade outbound (it belongs to the cascade).
type Export struct {
	Format    string       `json:"format"`
	Version   int          `json:"version"`
	ACL       acl.Document `json:"acl"`
	Outbounds []Outbound   `json:"outbounds,omitempty"`
	Resolver  *Resolver    `json:"resolver,omitempty"`
}

// Export is the view to save, without secrets.
func (v View) Export() Export {
	e := Export{Format: Format, Version: Version, ACL: v.ACL, Resolver: &v.Resolver}
	for _, o := range v.Outbounds {
		if !o.Locked {
			e.Outbounds = append(e.Outbounds, o.public())
		}
	}
	return e
}

// public is the outbound without passwords and without its place in a
// config.
func (o Outbound) public() Outbound {
	o.From, o.Locked = "", false
	if o.SOCKS5 != nil {
		s := *o.SOCKS5
		s.Password = ""
		o.SOCKS5 = &s
	}
	if o.HTTP != nil {
		h := *o.HTTP
		h.URL, _ = splitURL(h.URL)
		h.Password = ""
		o.HTTP = &h
	}
	return o
}

// Import reads an export or the text of a Hysteria ACL. Passwords never
// come in: they are typed on the server they are for.
func Import(data []byte) (Export, error) {
	if len(data) > MaxImport {
		return Export{}, &model.FieldError{Field: "file", Msg: "Файл больше 1 МБ."}
	}
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		var e Export
		if err := json.Unmarshal(t, &e); err != nil {
			return Export{}, &model.FieldError{Field: "file", Msg: "Файл не разобрать: " + err.Error()}
		}
		switch {
		case e.Format != Format:
			return Export{}, &model.FieldError{Field: "file", Msg: "Это не файл маршрутизации HyRoute."}
		case e.Version < 1 || e.Version > Version:
			return Export{}, &model.FieldError{Field: "file", Msg: fmt.Sprintf("Файл версии %d: эта версия HyRoute читает версию %d.", e.Version, Version)}
		}
		for i, o := range e.Outbounds {
			e.Outbounds[i] = o.public()
		}
		return e, nil
	}
	return Export{Format: Format, Version: Version, ACL: acl.Parse(string(data))}, nil
}
