// Package routing is the routing editor of a server (P3-06): its ACL
// rules, outbounds and resolver as typed data, checked and diffed against
// the current config and installed with the apply job.
package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/topology"
	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
)

// Chains lists the cascades (store.Chains).
type Chains interface {
	ListChains(ctx context.Context) ([]model.Chain, error)
}

// Service is the routing editor.
type Service struct {
	Editor  *apply.Editor
	Applier *apply.Applier
	Chains  Chains
	// Connect opens a server, for reading its acl.file.
	Connect func(ctx context.Context, serverID int64) (remote.Executor, error)
	// Geo reads the controller's geo databases (P3-07); nil: none.
	Geo hacl.GeoLoader
}

// ChainRef names a cascade.
type ChainRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// View is a server's routing as the editor opens it.
type View struct {
	Revision int          `json:"revision"`
	ACL      acl.Document `json:"acl"`
	// File is acl.file: the rules are in that file on the server and ACL
	// is empty.
	File      string     `json:"file,omitempty"`
	Outbounds []Outbound `json:"outbounds"`
	Resolver  Resolver   `json:"resolver"`
	// Cascade is the deployed cascade the server is the entry of.
	Cascade *ChainRef `json:"cascade,omitempty"`
	// Problems are the checks and lint of the rules (none for a file).
	Problems []acl.Problem `json:"problems"`
}

// Open is the server's current routing, passwords hidden.
func (s *Service) Open(ctx context.Context, serverID int64) (View, error) {
	cur, b, err := s.Editor.Current(ctx, serverID)
	if err != nil {
		return View{}, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return View{}, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	ref, err := s.entryOf(ctx, serverID)
	if err != nil {
		return View{}, err
	}
	v := View{Revision: cur.Revision, ACL: hiddenDoc(acl.ParseInline(c.ACL.Inline)), File: c.ACL.File, Resolver: resolverOf(c.Resolver), Cascade: ref, Outbounds: []Outbound{}, Problems: []acl.Problem{}}
	for _, o := range c.Outbounds {
		ov := outboundOf(o)
		ov.Locked = ref != nil && strings.EqualFold(o.Name, cascade.OutboundName)
		v.Outbounds = append(v.Outbounds, ov)
	}
	if v.File == "" {
		v.Problems = append(v.Problems, acl.Check(acl.ParseInline(c.ACL.Inline), s.env(c, ref))...)
	}
	return v, nil
}

// entryOf is the deployed cascade whose entry the server is.
func (s *Service) entryOf(ctx context.Context, serverID int64) (*ChainRef, error) {
	if s.Chains == nil {
		return nil, nil
	}
	chains, err := s.Chains.ListChains(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range chains {
		if len(c.Nodes) > 1 && c.Entry() == serverID && topology.Deployed(c) {
			return &ChainRef{ID: c.ID, Name: c.Name}, nil
		}
	}
	return nil, nil
}

func (s *Service) env(c *hyconfig.Server, ref *ChainRef) acl.Env {
	e := acl.EnvOf(c)
	e.Geo, e.Entry = s.geoOf(c), ref != nil
	return e
}

// geoOf is the geo databases the rules of c are checked against: the
// controller's when the server reads the same release (no paths set:
// Hysteria downloads it itself; or the files the geo job put in
// geo.ServerDir). Databases of its own may have other categories: their
// names are not checked (nil).
func (s *Service) geoOf(c *hyconfig.Server) hacl.GeoLoader {
	for _, p := range []string{c.ACL.GeoIP, c.ACL.GeoSite} {
		if p != "" && path.Dir(p) != geo.ServerDir {
			return nil
		}
	}
	return s.Geo
}

// GeoOf is the geo databases the server's rules are checked against
// (nil: names are not checked), for a check of one request. A server
// without a config yet gets the controller's.
func (s *Service) GeoOf(ctx context.Context, serverID int64) (hacl.GeoLoader, error) {
	_, b, err := s.Editor.Current(ctx, serverID)
	if errors.Is(err, apply.ErrNoConfig) {
		return s.Geo, nil
	} else if err != nil {
		return nil, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil, nil
	}
	return s.geoOf(c), nil
}

// Input is the editor's routing.
type Input struct {
	// Base is the revision the editor opened.
	Base int          `json:"base"`
	ACL  acl.Document `json:"acl"`
	// KeepFile leaves acl.file as it is; without it the rules go to
	// acl.inline and acl.file is dropped.
	KeepFile  bool       `json:"keepFile,omitempty"`
	Outbounds []Outbound `json:"outbounds"`
	Resolver  Resolver   `json:"resolver"`
	// Requests are tried before and after the edit besides the rules'
	// samples (dry run).
	Requests []acl.Request `json:"requests,omitempty"`
}

// Preview is what the editor's routing changes.
type Preview struct {
	apply.Check
	// ACL is the rules as they will be: renamed outbounds are renamed in
	// them too.
	ACL acl.Document `json:"acl"`
	// Rules are the checks and lint of the rules.
	Rules []acl.Problem `json:"rules"`
	// Changes are the requests the edit sends elsewhere.
	Changes []acl.Change `json:"changes"`
	// OK: the config passes and no rule has an error.
	OK bool `json:"ok"`
	// Same: the rules, outbounds and resolver are as on the server (the
	// diff may still show a reformatted config).
	Same bool `json:"same"`
}

// Preview checks the editor's routing; nothing is stored or sent.
func (s *Service) Preview(ctx context.Context, serverID int64, in Input) (Preview, error) {
	p, _, _, err := s.candidate(ctx, serverID, in)
	return p, err
}

// Apply queues the apply job that installs the editor's routing. Errors
// in the config or the rules, and no change, are a *model.FieldError.
func (s *Service) Apply(ctx context.Context, serverID int64, in Input, actor int64) (model.Job, error) {
	p, cand, cur, err := s.candidate(ctx, serverID, in)
	if err != nil {
		return model.Job{}, err
	}
	for _, pr := range p.Rules {
		if pr.Level == acl.Error {
			return model.Job{}, &model.FieldError{Field: "acl", Msg: fmt.Sprintf("Правило %d: %s", pr.Rule+1, pr.Message)}
		}
	}
	if p.Same {
		return model.Job{}, &model.FieldError{Field: "acl", Msg: "Изменений нет: маршрутизация на сервере уже такая."}
	}
	return s.Applier.Queue(ctx, serverID, cur, p.Check, cand, apply.ChangeRouting, actor)
}

func (s *Service) candidate(ctx context.Context, serverID int64, in Input) (Preview, []byte, model.ServerConfig, error) {
	ref, err := s.entryOf(ctx, serverID)
	if err != nil {
		return Preview{}, nil, model.ServerConfig{}, err
	}
	var before, after acl.Document
	var envBefore, envAfter acl.Env
	// kept: the outbounds after the edit that were there before (lower-case
	// name → name before), as the dry run tells them.
	kept := map[string]string{}
	file, same := false, false
	ch, cand, cur, err := s.Editor.Candidate(ctx, serverID, in.Base, func(c *hyconfig.Server) error {
		before, envBefore = acl.ParseInline(c.ACL.Inline), s.env(c, ref)
		file = c.ACL.File != ""
		was := routingOf(c)
		obs, renames, err := outbounds(c.Outbounds, in.Outbounds, ref)
		if err != nil {
			return err
		}
		if file && in.KeepFile && (len(renames) > 0 || removed(c.Outbounds, in.Outbounds)) {
			return &model.FieldError{Field: "outbounds", Msg: "Правила сервера в файле " + c.ACL.File + ": outbound, на который они могут ссылаться, нельзя переименовать или удалить — Hysteria не запустится. Сначала перенесите правила в конфиг."}
		}
		c.Outbounds = obs
		for i, o := range in.Outbounds { // obs[i] is the editor's outbound i
			if o.From != "" && i < len(obs) {
				kept[strings.ToLower(obs[i].Name)] = o.From
			}
		}
		in.Resolver.set(&c.Resolver)
		after = renamed(restoreDoc(in.ACL, before), renames)
		if !in.KeepFile || !file {
			lines := after.Inline()
			// A file's last line break is no rule.
			for file && len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
				lines = lines[:len(lines)-1]
			}
			c.ACL.File, c.ACL.Inline = "", lines
		}
		envAfter = s.env(c, ref)
		same = bytes.Equal(was, routingOf(c))
		return nil
	})
	if err != nil {
		return Preview{}, nil, cur, err
	}
	p := Preview{Check: ch, ACL: hiddenDoc(after), Rules: []acl.Problem{}, Changes: []acl.Change{}, Same: same}
	if !in.KeepFile || !file {
		p.Rules = append(p.Rules, acl.Check(after, envAfter)...)
	}
	if !file {
		changes, err := acl.DryRun(before, after, envBefore, envAfter, kept, in.Requests)
		if err != nil {
			return Preview{}, nil, cur, &model.FieldError{Field: "requests", Msg: err.Error()}
		}
		p.Changes = append(p.Changes, changes...)
	}
	p.OK = ch.OK && !slices.ContainsFunc(p.Rules, func(pr acl.Problem) bool { return pr.Level == acl.Error })
	return p, cand, cur, nil
}

// routingOf is what the routing editor changes in a config, encoded.
func routingOf(c *hyconfig.Server) []byte {
	b, _ := yaml.Marshal(struct {
		ACL       hyconfig.ACL
		Outbounds []hyconfig.Outbound
		Resolver  hyconfig.Resolver
	}{c.ACL, c.Outbounds, c.Resolver})
	return b
}

// removed: an outbound of the config is not in the editor's list.
func removed(cur []hyconfig.Outbound, in []Outbound) bool {
	for _, c := range cur {
		if !slices.ContainsFunc(in, func(o Outbound) bool { return strings.EqualFold(o.From, c.Name) }) {
			return true
		}
	}
	return false
}

// renamed is doc with the rules of renamed outbounds (lower-case old name
// → new name) pointing at the new names.
func renamed(doc acl.Document, renames map[string]string) acl.Document {
	doc.Rules = slices.Clone(doc.Rules)
	for i, r := range doc.Rules {
		if n, ok := renames[strings.ToLower(r.Outbound)]; ok && !r.Bad() {
			doc.Rules[i].Outbound = n
		}
	}
	return doc
}

// MaxFile bounds an acl.file the editor reads.
const MaxFile = 1 << 20

// FileView is the server's acl.file.
type FileView struct {
	Path     string        `json:"path"`
	ACL      acl.Document  `json:"acl"`
	Problems []acl.Problem `json:"problems"`
}

// File reads the server's acl.file: its rules with their checks, for
// viewing and moving into acl.inline.
func (s *Service) File(ctx context.Context, serverID int64) (FileView, error) {
	_, b, err := s.Editor.Current(ctx, serverID)
	if err != nil {
		return FileView{}, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return FileView{}, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	f := FileView{Path: c.ACL.File, Problems: []acl.Problem{}}
	switch {
	case f.Path == "":
		return f, &model.FieldError{Field: "acl.file", Msg: "Правила сервера — в конфиге (acl.inline), файла нет."}
	case !strings.HasPrefix(f.Path, "/"):
		return f, &model.FieldError{Field: "acl.file", Msg: "Путь acl.file относительный: непонятно, от какого каталога его читать. Укажите полный путь в конфиге."}
	case s.Connect == nil:
		return f, errors.New("routing: no connector")
	}
	ref, err := s.entryOf(ctx, serverID)
	if err != nil {
		return f, err
	}
	ex, err := s.Connect(ctx, serverID)
	if err != nil {
		return f, err
	}
	defer ex.Close()
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return f, err
	}
	data, err := ex.ReadFile(ctx, f.Path, !p.Root)
	if err != nil {
		return f, &model.FieldError{Field: "acl.file", Msg: fmt.Sprintf("Не удалось прочитать %s: %v", f.Path, err)}
	}
	if len(data) > MaxFile {
		return f, &model.FieldError{Field: "acl.file", Msg: fmt.Sprintf("%s больше 1 МБ: такой файл редактор не открывает.", f.Path)}
	}
	doc := acl.Parse(string(data))
	// A file that is mostly not rules is not shown: acl.file may name any
	// file of the server, and lines that are no rules come back as they
	// are.
	bad := 0
	for _, r := range doc.Rules {
		if r.Bad() {
			bad++
		}
	}
	if bad > 0 && bad*2 > len(doc.Rules) {
		return f, &model.FieldError{Field: "acl.file", Msg: fmt.Sprintf("%s не похож на файл правил Hysteria: редактор его не показывает.", f.Path)}
	}
	f.ACL = hiddenDoc(doc)
	f.Problems = append(f.Problems, acl.Check(doc, s.env(c, ref))...)
	return f, nil
}
