package vless

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// Balance is a selectable Xray leastLoad profile. Only the outbound
// parameters HyRoute supports are imported from a subscription.
type Balance struct {
	Nodes           []Node        `json:"nodes"`
	MaxRTT          time.Duration `json:"maxRTT,omitempty"`
	Expected        int           `json:"expected,omitempty"`
	Tolerance       float64       `json:"tolerance,omitempty"`
	BlockBitTorrent bool          `json:"blockBitTorrent,omitempty"`
}

type Node struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Settings Settings `json:"settings"`
	// Fragment is how HyRoute 1.3.38 stores the mask of a balanced node.
	Fragment TCPFragment `json:"fragment,omitzero"`
}

const MaxBalanceNodes = 64

func (n Node) connectionSettings() Settings {
	s := n.Settings
	if s.TCPFragment == (TCPFragment{}) {
		s.TCPFragment = n.Fragment
	}
	return s
}

func (b Balance) Validate() error {
	if len(b.Nodes) < 1 || len(b.Nodes) > MaxBalanceNodes {
		return errors.New("балансировщик поддерживает от 1 до 64 узлов")
	}
	if b.MaxRTT < 0 || b.MaxRTT > time.Minute || b.Expected < 0 || b.Expected > MaxBalanceNodes || b.Tolerance < 0 || b.Tolerance > 1 {
		return errors.New("недопустимые параметры leastLoad")
	}
	for _, n := range b.Nodes {
		if n.Host == "" || n.Port < 1 || n.Port > 65535 {
			return errors.New("у узла балансировщика нет корректного адреса или порта")
		}
		settings := n.connectionSettings()
		if err := settings.ValidateFor(n.Host); err != nil {
			return err
		}
	}
	return nil
}

func (b Balance) ValidateChain() error {
	for _, n := range b.Nodes {
		if err := n.connectionSettings().ValidateChain(); err != nil {
			return fmt.Errorf("узел %s: %w", n.Host, err)
		}
	}
	return nil
}

// BalanceConfig gives every resolved node its own Xray outbound. The
// addresses are pinned so the engine can exclude exactly what Xray dials.
// An invalid address marks a node whose DNS lookup failed this time.
func BalanceConfig(b Balance, ips []netip.Addr, r Run) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if r.Via == nil && len(ips) != len(b.Nodes) || r.Via != nil && len(ips) != 0 {
		return nil, errors.New("не совпадают адреса и узлы балансировщика")
	}
	cfg, err := clientConfig(r, b.BlockBitTorrent)
	if err != nil {
		return nil, err
	}
	const prefix = "balanced-"
	var outbounds []any
	for i, n := range b.Nodes {
		node := Run{Host: n.Host, Port: n.Port, Via: r.Via}
		if r.Via == nil {
			node.Dial = ips[i]
			if !node.Dial.IsValid() {
				continue
			}
		}
		out, err := outbound(n.connectionSettings(), node, prefix+strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, out)
	}
	if len(outbounds) == 0 {
		return nil, errors.New("ни один адрес балансировщика не разрешился")
	}
	if r.Via != nil {
		via, err := viaOutbound(*r.Via)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, via)
	}
	var rules []any
	if b.BlockBitTorrent {
		outbounds = append(outbounds, map[string]any{"tag": "block", "protocol": "blackhole"})
		rules = append(rules, map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"})
	}
	rules = append(rules, map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "balance"})
	strategy := map[string]any{"expected": b.Expected, "tolerance": b.Tolerance}
	if b.MaxRTT != 0 {
		strategy["maxRTT"] = b.MaxRTT.String()
	}
	cfg["outbounds"] = outbounds
	cfg["routing"] = map[string]any{
		"rules": rules,
		"balancers": []any{map[string]any{
			"tag": "balance", "selector": []string{prefix},
			"strategy": map[string]any{"type": "leastLoad", "settings": strategy},
		}},
	}
	cfg["burstObservatory"] = map[string]any{
		"subjectSelector": []string{prefix},
		"pingConfig": map[string]any{
			"destination": "http://www.gstatic.com/generate_204",
			"interval":    "30s", "timeout": "3s", "sampling": 1,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
