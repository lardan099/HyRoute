package awg

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// qCompress is Qt's: the length, then zlib.
func qCompress(b []byte) []byte {
	var out bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	out.Write(n[:])
	w := zlib.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func amneziaKeyOf(t *testing.T, doc any) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress(b))
}

// appKey is laid out as the Amnezia app shares a self-hosted
// connection: the configuration in a JSON string in a JSON string.
func appKey(t *testing.T, containers ...map[string]any) string {
	t.Helper()
	return amneziaKeyOf(t, map[string]any{
		"containers":       containers,
		"defaultContainer": "amnezia-awg",
		"description":      "Мой сервер",
		"dns1":             "9.9.9.9",
		"dns2":             "149.112.112.112",
		"hostName":         "203.0.113.5",
	})
}

func awgContainer(t *testing.T, conf string) map[string]any {
	t.Helper()
	last, _ := json.Marshal(map[string]any{"config": conf, "hostName": "203.0.113.5", "port": 51820})
	return map[string]any{
		"container": "amnezia-awg",
		"awg":       map[string]any{"last_config": string(last), "port": "51820", "transport_proto": "udp"},
	}
}

func TestParseVPNKeyApp(t *testing.T) {
	conf := strings.Replace(amneziaConf(), "DNS = 1.1.1.1, 1.0.0.1", "DNS = $PRIMARY_DNS, $SECONDARY_DNS", 1)
	k := appKey(t, map[string]any{"container": "amnezia-xray", "xray": map[string]any{}}, awgContainer(t, conf))
	c, warns, err := ParseVPNKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings %v", warns)
	}
	if c.Name != "Мой сервер" || c.Host != "203.0.113.5" || c.Port != 51820 {
		t.Errorf("conf %+v", c)
	}
	if c.Settings.DNS != "9.9.9.9, 149.112.112.112" || c.Settings.Jc != 4 {
		t.Errorf("settings %+v", c.Settings)
	}
}

func TestParseVPNKeyConf(t *testing.T) {
	c, _, err := ParseConf(amneziaConf())
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "из HyRoute"
	back, _, err := ParseVPNKey(VPNKey(c))
	if err != nil {
		t.Fatal(err)
	}
	if back != c {
		t.Errorf("%+v\n%+v", back, c)
	}
	// Uncompressed configurations in base64 too.
	raw := "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(amneziaConf()))
	if _, _, err := ParseVPNKey(raw); err != nil {
		t.Errorf("uncompressed: %v", err)
	}
}

func TestParseVPNKeyRefused(t *testing.T) {
	for name, k := range map[string]string{
		"service":  amneziaKeyOf(t, map[string]any{"api_config": map[string]any{"service_type": "amnezia-premium"}, "containers": []any{}}),
		"ssh only": amneziaKeyOf(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{}}}, "hostName": "203.0.113.5", "userName": "root", "password": "x"}),
		"xray":     appKey(t, map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": "{}"}}),
		"garbage":  "vpn://!!!",
		"not json": "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress([]byte("hello"))),
	} {
		_, _, err := ParseVPNKey(k)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if name == "xray" && !strings.Contains(err.Error(), "xray") {
			t.Errorf("xray: %v", err)
		}
		if name == "service" && !strings.Contains(err.Error(), "сервиса Amnezia") {
			t.Errorf("service: %v", err)
		}
	}
}

func TestQUncompressLimit(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxKey+10)
	if _, ok := qUncompress(qCompress(big)); ok {
		t.Error("a key over the limit was decompressed")
	}
}
