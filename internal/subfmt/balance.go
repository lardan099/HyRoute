package subfmt

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/vless"
)

type XrayBalancer struct {
	Name string
	vless.Balance
}

// xrayBalancer recognizes one leastLoad TCP/UDP profile, optionally with
// a BitTorrent block. Keep its nodes together rather than exposing the
// constituent outbounds as separate servers.
func (r *Result) xrayBalancer(name string, raw json.RawMessage, outbounds []json.RawMessage) bool {
	var cfg struct {
		Routing struct {
			Rules     []map[string]json.RawMessage
			Balancers []struct {
				Tag         string
				Selector    []string
				FallbackTag string
				Strategy    struct {
					Type     string
					Settings struct {
						MaxRTT    string
						Expected  int
						Tolerance float64
					}
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Routing.Balancers) == 0 {
		return false
	}
	fail := func(err error) bool { r.fail(name, err); return true }
	if len(cfg.Routing.Balancers) != 1 {
		return fail(errors.New("поддерживается один балансировщик Xray"))
	}
	br := cfg.Routing.Balancers[0]
	if br.Tag == "" || br.Strategy.Type != "leastLoad" || br.FallbackTag != "" || len(br.Selector) == 0 || slices.Contains(br.Selector, "") {
		return fail(errors.New("поддерживается балансировщик leastLoad без fallbackTag"))
	}
	var blockTag string
	for i, rule := range cfg.Routing.Rules {
		var target, network, kind string
		var protocols []string
		json.Unmarshal(rule["type"], &kind)
		fields := len(rule)
		if kind == "field" || kind == "" && rule["type"] == nil {
			if kind != "" {
				fields--
			}
			if i == 0 && len(cfg.Routing.Rules) == 2 && fields == 2 &&
				json.Unmarshal(rule["protocol"], &protocols) == nil && slices.Equal(protocols, []string{"bittorrent"}) &&
				json.Unmarshal(rule["outboundTag"], &blockTag) == nil && blockTag != "" {
				continue
			}
			if i == len(cfg.Routing.Rules)-1 && fields == 2 &&
				json.Unmarshal(rule["balancerTag"], &target) == nil && target == br.Tag &&
				json.Unmarshal(rule["network"], &network) == nil && (network == "tcp,udp" || network == "udp,tcp") {
				continue
			}
		}
		return fail(errors.New("поддерживается правило leastLoad для всего TCP и UDP"))
	}
	if len(cfg.Routing.Rules) == 0 {
		return fail(errors.New("балансировщик не используется в правилах Xray"))
	}

	s := br.Strategy.Settings
	profile := XrayBalancer{Name: firstNonEmpty(name, br.Tag), Balance: vless.Balance{Expected: s.Expected, Tolerance: s.Tolerance}}
	if s.MaxRTT != "" {
		d, err := time.ParseDuration(s.MaxRTT)
		if err != nil {
			return fail(errors.New("некорректный maxRTT балансировщика Xray"))
		}
		profile.MaxRTT = d
	}
	for _, ob := range outbounds {
		var head struct{ Tag, Protocol string }
		if json.Unmarshal(ob, &head) != nil {
			continue
		}
		if blockTag != "" && head.Tag == blockTag && head.Protocol == "blackhole" {
			profile.BlockBitTorrent = true
		}
		if !slices.ContainsFunc(br.Selector, func(prefix string) bool { return strings.HasPrefix(head.Tag, prefix) }) {
			continue
		}
		if head.Protocol != "vless" {
			return fail(errors.New("поддерживаются только узлы VLESS в балансировщике Xray"))
		}
		node, err := xrayNode(ob, head.Tag)
		if err != nil {
			return fail(err)
		}
		profile.Nodes = append(profile.Nodes, node)
	}
	if blockTag != "" && !profile.BlockBitTorrent {
		return fail(errors.New("не найден выход blackhole для правила BitTorrent"))
	}
	if err := profile.Validate(); err != nil {
		return fail(err)
	}
	r.Balancers = append(r.Balancers, profile)
	return true
}

func xrayNode(ob json.RawMessage, tag string) (vless.Node, error) {
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(ob, &parts); err != nil {
		return vless.Node{}, errors.New("некорректный узел балансировщика Xray")
	}
	for k := range parts {
		switch k {
		case "tag", "protocol", "settings", "streamSettings", "mux":
		default:
			return vless.Node{}, errors.New("неподдерживаемый выход балансировщика Xray")
		}
	}
	var stream map[string]json.RawMessage
	json.Unmarshal(parts["streamSettings"], &stream)
	var fragment vless.TCPFragment
	if raw := stream["finalmask"]; raw != nil && string(raw) != "null" {
		var finalmask map[string]json.RawMessage
		var tcp []struct {
			Type     string
			Settings vless.TCPFragment
		}
		if json.Unmarshal(raw, &finalmask) != nil || len(finalmask) != 1 ||
			json.Unmarshal(finalmask["tcp"], &tcp) != nil || len(tcp) != 1 || tcp[0].Type != "fragment" ||
			tcp[0].Settings == (vless.TCPFragment{}) {
			return vless.Node{}, errors.New("у узла балансировщика неподдерживаемый finalmask")
		}
		fragment = tcp[0].Settings
		delete(stream, "finalmask")
		parts["streamSettings"], _ = json.Marshal(stream)
		ob, _ = json.Marshal(parts)
	}
	var converted Result
	converted.xray("vless", tag, ob)
	if len(converted.Links) != 1 || len(converted.Warnings) != 0 {
		return vless.Node{}, errors.New("узел балансировщика использует неподдерживаемые настройки VLESS")
	}
	link, _, err := vless.Parse(converted.Links[0])
	if err != nil {
		return vless.Node{}, errors.New("не удалось разобрать узел балансировщика VLESS")
	}
	return vless.Node{Host: link.Host, Port: link.Port, Settings: link.Settings, Fragment: fragment}, nil
}
