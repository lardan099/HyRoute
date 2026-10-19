package deploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preset"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Preset is a preset whose sections a deploy lays over the config its
// params make.
type Preset struct {
	ID       int64    `json:"id"`
	Sections []string `json:"sections"`
	// Name and Config are the preset as Submit read it: the job keeps it,
	// so a retry builds the same config whatever happens to the preset.
	Name   string `json:"name,omitempty"`
	Config string `json:"config,omitempty"`
}

// PresetSections are the sections a deploy takes from a preset: ports
// and obfuscation are the form's (the client links come from them).
var PresetSections = []string{preset.Masquerade, preset.Speed, preset.QUIC, preset.UDP, preset.Resolver, preset.Sniff, preset.ACL, preset.Outbounds}

// formSets reports whether the params set the section themselves.
func (p *Params) formSets(section string) bool {
	switch section {
	case preset.Masquerade:
		return p.Masq.Type != "" || p.Masquerade != ""
	case preset.Speed:
		return p.Bandwidth != (Bandwidth{})
	case preset.QUIC:
		return p.QUIC != (QUIC{})
	case preset.UDP:
		return p.UDP != (UDP{})
	case preset.Sniff:
		return p.Sniff != (Sniff{})
	case preset.Outbounds:
		return p.Outbound != (Outbound{})
	}
	return false
}

// normalizePreset checks the preset's sections: ones a deploy takes, not
// set in the form too, and in the preset (once Submit has read it).
func (p *Params) normalizePreset() error {
	if p.Preset == nil {
		return nil
	}
	if p.Preset.ID <= 0 {
		return errors.New("не выбран пресет")
	}
	if len(p.Preset.Sections) == 0 {
		return errors.New("выберите разделы пресета")
	}
	for _, s := range p.Preset.Sections {
		if !slices.Contains(PresetSections, s) {
			return fmt.Errorf("раздел пресета %q при развёртывании не применяется: порты и обфускацию задаёт форма", s)
		}
		if p.formSets(s) {
			return fmt.Errorf("раздел %q задан и в форме, и в пресете: оставьте что-то одно", s)
		}
	}
	if p.Preset.Config == "" {
		return nil
	}
	c, err := hyconfig.ParseServer([]byte(p.Preset.Config))
	if err != nil {
		return fmt.Errorf("пресет не разобрать: %w", err)
	}
	has := preset.Has(c)
	for _, s := range p.Preset.Sections {
		if !slices.Contains(has, s) {
			return fmt.Errorf("в пресете «%s» нет раздела %q", p.Preset.Name, s)
		}
	}
	if len(p.presetTCPPorts()) > 0 && p.TLS == TLSACME && p.Challenge != "dns" {
		return fmt.Errorf("сайт-маскировка пресета отвечает по TCP, а порты 80 и 443 нужны Let's Encrypt для проверки %s. Выберите проверку через DNS", p.Challenge)
	}
	return nil
}

// presetTCPPorts are the TCP ports of the preset's masquerade.
func (p *Params) presetTCPPorts() []int {
	if p.Preset == nil || p.Preset.Config == "" || !slices.Contains(p.Preset.Sections, preset.Masquerade) {
		return nil
	}
	c, err := hyconfig.ParseServer([]byte(p.Preset.Config))
	if err != nil {
		return nil
	}
	var out []int
	for _, a := range []string{c.Masquerade.ListenHTTP, c.Masquerade.ListenHTTPS} {
		if _, port, err := net.SplitHostPort(a); err == nil {
			if n, err := strconv.Atoi(port); err == nil && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// overlayPreset lays the preset's sections over the config.
func (p *Params) overlayPreset(c *hyconfig.Server) error {
	if p.Preset == nil || p.Preset.Config == "" {
		return nil
	}
	pc, err := hyconfig.ParseServer([]byte(p.Preset.Config))
	if err != nil {
		return err
	}
	_, err = preset.Overlay(c, pc, p.Preset.Sections, nil)
	return err
}

// loadPreset reads the preset of the params into them.
func (s *Submitter) loadPreset(ctx context.Context, p *Params) error {
	if p.Preset == nil {
		return nil
	}
	m, err := s.Store.PresetByID(ctx, p.Preset.ID)
	if errors.Is(err, store.ErrNotFound) {
		return &model.FieldError{Field: "preset", Msg: "Такого пресета нет."}
	} else if err != nil {
		return err
	}
	p.Preset.Name, p.Preset.Config = m.Name, m.Config
	if err := p.normalizePreset(); err != nil {
		return &model.FieldError{Field: "preset", Msg: sentence(err.Error())}
	}
	return nil
}

// presetNote is the log line about the preset.
func (p *Params) presetNote() string {
	if p.Preset == nil {
		return ""
	}
	return fmt.Sprintf("Разделы пресета «%s»: %s.", p.Preset.Name, strings.Join(p.Preset.Sections, ", "))
}
