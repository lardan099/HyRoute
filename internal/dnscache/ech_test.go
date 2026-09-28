package dnscache

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// echConfigList is an ECHConfigList with one 0xfe0d config for publicName.
func echConfigList(publicName string) []byte {
	// config_id, kem_id (X25519), public_key, cipher_suites,
	// maximum_name_length, public_name, extensions.
	c := []byte{7, 0, 0x20, 0, 32}
	c = append(c, make([]byte, 32)...)
	c = append(c, 0, 4, 0, 1, 0, 1)
	c = append(c, 0, byte(len(publicName)))
	c = append(c, publicName...)
	c = append(c, 0, 0)
	cfg := binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(c)))
	cfg = append(cfg, c...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...)
}

func httpsResponse(t *testing.T, q string, ttl uint32, echList []byte) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	r := dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(".")}}
	r.SetParam(dnsmessage.SVCParamALPN, []byte{2, 'h', '2'})
	r.SetParam(dnsmessage.SVCParamECH, echList)
	if err := b.HTTPSResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(q), Class: dnsmessage.ClassINET, TTL: ttl}, r); err != nil {
		t.Fatal(err)
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The outer SNI of real ECH is a public name: a known provider's, or one
// from the ECH config of an HTTPS answer, for as long as the answer lives.
// Any other outer name is taken for the site (GREASE ECH).
func TestPublicName(t *testing.T) {
	c, now := newCache()
	if !c.PublicName("Cloudflare-ECH.com.") || c.PublicName("www.youtube.com") || c.PublicName("") {
		t.Fatal("known public names")
	}
	if c.PublicName("ech.provider.test") {
		t.Fatal("public name before any HTTPS answer")
	}
	if _, err := c.AddResponse(httpsResponse(t, "site.test.", 300, echConfigList("ech.provider.test"))); err != nil {
		t.Fatal(err)
	}
	if !c.PublicName("ech.provider.test") || c.PublicName("site.test") {
		t.Fatal("public name from the HTTPS answer not learned")
	}
	// Truncated or malformed configs are ignored.
	bad := echConfigList("broken.test")
	c.AddResponse(httpsResponse(t, "b.test.", 300, bad[:len(bad)-5]))
	if c.PublicName("broken.test") {
		t.Fatal("public name from a malformed config")
	}
	*now = now.Add(301 * time.Second)
	c.Sweep()
	if c.PublicName("ech.provider.test") || len(c.public) != 0 {
		t.Fatal("public name outlived its answer")
	}
	// Any zone may claim any name as its public name: a learned one is kept
	// for an hour at most, however long the answer lives.
	c.AddResponse(httpsResponse(t, "long.test.", 86400, echConfigList("www.example.com")))
	*now = now.Add(59 * time.Minute)
	if !c.PublicName("www.example.com") {
		t.Fatal("long-lived public name not learned")
	}
	*now = now.Add(2 * time.Minute)
	if c.PublicName("www.example.com") {
		t.Fatal("learned public name kept for over an hour")
	}
}
