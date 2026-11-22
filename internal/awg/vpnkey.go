package awg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

// The Amnezia app shares a connection as "vpn://" and base64url (no
// padding) of Qt's qCompress: the length as 4 bytes big-endian, then
// zlib. Inside is a WireGuard configuration or the app's JSON, whose
// AmneziaWG or WireGuard container keeps the configuration in
// last_config.config (amnezia-client, ImportController).

// maxKey caps the decompressed key: a key is a few kilobytes.
const maxKey = 1 << 20

// IsVPNKey reports whether s is an Amnezia key.
func IsVPNKey(s string) bool {
	return len(s) > 6 && strings.EqualFold(s[:6], "vpn://")
}

type amneziaKey struct {
	Containers       []map[string]json.RawMessage `json:"containers"`
	DefaultContainer string                       `json:"defaultContainer"`
	Description      string                       `json:"description"`
	HostName         string                       `json:"hostName"`
	DNS1             string                       `json:"dns1"`
	DNS2             string                       `json:"dns2"`
	// Amnezia's own services: the connection comes from their API.
	APIConfig json.RawMessage `json:"api_config"`
	AuthData  json.RawMessage `json:"auth_data"`
	APIKey    json.RawMessage `json:"api_key"`
	UserName  string          `json:"userName"`
}

// ParseVPNKey reads an Amnezia key with an AmneziaWG or WireGuard
// connection. The name is the key's description (or its server).
func ParseVPNKey(key string) (Conf, []string, error) {
	data, err := decodeVPNKey(key)
	if err != nil {
		return Conf{}, nil, err
	}
	text := string(data)
	if IsConf(text) {
		return ParseConf(text)
	}
	var k amneziaKey
	if err := json.Unmarshal(data, &k); err != nil {
		return Conf{}, nil, errors.New("ключ vpn:// не прочитан: внутри нет ни конфига, ни данных приложения Amnezia")
	}
	if len(k.APIConfig) > 0 || len(k.AuthData) > 0 || len(k.APIKey) > 0 {
		return Conf{}, nil, errors.New("это ключ сервиса Amnezia: подключение к нему выдаёт сервер Amnezia по запросу приложения, HyRoute так не умеет. Возьмите в приложении Amnezia конфиг AmneziaWG (.conf) и добавьте его")
	}
	order := slices.Clone(k.Containers)
	slices.SortStableFunc(order, func(a, b map[string]json.RawMessage) int {
		return boolInt(containerName(b) == k.DefaultContainer) - boolInt(containerName(a) == k.DefaultContainer)
	})
	var others []string
	for _, cont := range order {
		for _, proto := range []string{"awg", "wireguard"} {
			raw, ok := cont[proto]
			if !ok {
				continue
			}
			conf, ok := lastConfig(raw)
			if !ok {
				continue
			}
			dns1, dns2 := k.DNS1, k.DNS2
			if dns1 == "" {
				dns1 = "1.1.1.1"
			}
			if dns2 == "" {
				dns2 = "1.0.0.1"
			}
			conf = strings.NewReplacer("$PRIMARY_DNS", dns1, "$SECONDARY_DNS", dns2).Replace(conf)
			c, warns, err := ParseConf(conf)
			if err != nil {
				return c, nil, err
			}
			if c.Name == "" {
				c.Name = strings.TrimSpace(k.Description)
			}
			if c.Name == "" {
				c.Name = k.HostName
			}
			return c, warns, nil
		}
		if n := containerName(cont); n != "" {
			others = append(others, strings.TrimPrefix(n, "amnezia-"))
		}
	}
	if k.UserName != "" {
		return Conf{}, nil, errors.New("в ключе vpn:// доступ к серверу для управления, а не подключение: в приложении Amnezia поделитесь подключением AmneziaWG")
	}
	if len(others) > 0 {
		return Conf{}, nil, errors.New("в ключе vpn:// нет подключения AmneziaWG или WireGuard (есть: " + strings.Join(others, ", ") + ")")
	}
	return Conf{}, nil, errors.New("в ключе vpn:// нет подключения AmneziaWG или WireGuard")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func containerName(c map[string]json.RawMessage) string {
	var s string
	json.Unmarshal(c["container"], &s)
	return s
}

// lastConfig is the configuration of a container's protocol: its
// last_config is JSON in a string.
func lastConfig(raw json.RawMessage) (string, bool) {
	var proto struct {
		LastConfig string `json:"last_config"`
	}
	if json.Unmarshal(raw, &proto) != nil || proto.LastConfig == "" {
		return "", false
	}
	var last struct {
		Config string `json:"config"`
	}
	if json.Unmarshal([]byte(proto.LastConfig), &last) != nil || !IsConf(last.Config) {
		return "", false
	}
	return last.Config, true
}

func decodeVPNKey(key string) ([]byte, error) {
	body := strings.TrimSpace(key)
	if IsVPNKey(body) {
		body = body[6:]
	}
	body = strings.TrimRight(strings.Join(strings.Fields(body), ""), "=")
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if raw, err = enc.DecodeString(body); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("ключ vpn:// повреждён: это не base64")
	}
	if out, ok := qUncompress(raw); ok {
		return out, nil
	}
	return raw, nil
}

// qUncompress undoes Qt's qCompress.
func qUncompress(b []byte) ([]byte, bool) {
	if len(b) < 6 {
		return nil, false
	}
	want := binary.BigEndian.Uint32(b[:4])
	if want == 0 || want > maxKey {
		return nil, false
	}
	r, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return nil, false
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxKey+1))
	if err != nil || len(out) > maxKey {
		return nil, false
	}
	return out, true
}

// VPNKey writes c as an Amnezia key (a compressed configuration, which
// the Amnezia app imports as well as a .conf).
func VPNKey(c Conf) string {
	text := []byte(c.String())
	var b bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(text)))
	b.Write(n[:])
	w := zlib.NewWriter(&b)
	w.Write(text)
	w.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(b.Bytes())
}
