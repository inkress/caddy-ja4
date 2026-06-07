package ja4

import (
	"encoding/binary"
	"regexp"
	"testing"
)

// --- minimal ClientHello builder (test-only) ------------------------------

func u16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func vec16(body []byte) []byte { return append(u16(uint16(len(body))), body...) }
func vec8(body []byte) []byte  { return append([]byte{byte(len(body))}, body...) }

func ext(t uint16, data []byte) []byte { return append(u16(t), vec16(data)...) }

type helloOpts struct {
	ciphers    []uint16
	exts       []byte // pre-encoded extensions block (concatenated ext() calls)
	includeExt bool
}

func buildHello(o helloOpts) []byte {
	body := []byte{}
	body = append(body, u16(0x0303)...)      // legacy_version TLS1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, vec8(nil)...)        // empty session_id
	cs := []byte{}
	for _, c := range o.ciphers {
		cs = append(cs, u16(c)...)
	}
	body = append(body, vec16(cs)...)          // cipher_suites
	body = append(body, vec8([]byte{0x00})...) // compression_methods = [null]
	if o.includeExt {
		body = append(body, vec16(o.exts)...) // extensions
	}
	// handshake header: type 0x01 + 3-byte length
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	// record header: 0x16 + version + 2-byte length
	rec := append([]byte{0x16, 0x03, 0x03}, u16(uint16(len(hs)))...)
	return append(rec, hs...)
}

// a realistic-ish hello: GREASE in ciphers + exts, SNI, supported_versions, ALPN h2, sigalgs.
func sampleExts() []byte {
	b := []byte{}
	b = append(b, ext(extServerName, append(u16(0x0005), append([]byte{0x00}, append(u16(0x0002), 'h', 'i')...)...))...) // server_name list (contents irrelevant to JA4)
	b = append(b, ext(extSupportedV, vec8(append(u16(0x0304), u16(0x0303)...)))...)                                      // supported_versions: 1.3, 1.2
	b = append(b, ext(extALPN, vec16(vec8([]byte("h2"))))...)                                                            // ALPN: h2
	b = append(b, ext(extSigAlgs, vec16(append(u16(0x0403), u16(0x0804)...)))...)                                        // sig_algs
	b = append(b, ext(greaseExt, nil)...)                                                                                // a GREASE extension → must be dropped
	return b
}

// --------------------------------------------------------------------------

func TestGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("expected %#04x to be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x1302, 0xc02b, 0x0000, 0x0010} {
		if isGREASE(v) {
			t.Errorf("expected %#04x NOT to be GREASE", v)
		}
	}
}

func TestJA4PartAStructureAndGREASERemoval(t *testing.T) {
	raw := buildHello(helloOpts{
		ciphers:    []uint16{0x0a0a, 0x1301, 0x1302}, // GREASE + 2 real
		exts:       sampleExts(),
		includeExt: true,
	})
	ch, err := ParseRecord(raw)
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	// GREASE cipher dropped → 2 ciphers; GREASE ext dropped → 4 exts (SNI, supported_v, ALPN, sigalgs).
	if got := len(ch.Ciphers); got != 2 {
		t.Errorf("ciphers = %d, want 2 (GREASE removed)", got)
	}
	if got := len(ch.Extensions); got != 4 {
		t.Errorf("extensions = %d, want 4 (GREASE removed)", got)
	}
	if !ch.SNI {
		t.Error("SNI should be detected")
	}
	if ch.TLSVersion != 0x0304 {
		t.Errorf("TLSVersion = %#04x, want 0x0304 (from supported_versions)", ch.TLSVersion)
	}
	a := ch.partA()
	if want := "t13d0204h2"; a != want {
		t.Errorf("JA4_a = %q, want %q", a, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(ch.partB()) {
		t.Errorf("JA4_b = %q, not 12 lowercase hex", ch.partB())
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(ch.partC()) {
		t.Errorf("JA4_c = %q, not 12 lowercase hex", ch.partC())
	}
}

func TestJA4CipherOrderIndependent(t *testing.T) {
	// JA4_b sorts cipher suites, so wire order must not change the fingerprint.
	a, _ := ParseRecord(buildHello(helloOpts{ciphers: []uint16{0x1301, 0x1302, 0xc02b}, exts: sampleExts(), includeExt: true}))
	b, _ := ParseRecord(buildHello(helloOpts{ciphers: []uint16{0xc02b, 0x1302, 0x1301}, exts: sampleExts(), includeExt: true}))
	if a.JA4() != b.JA4() {
		t.Errorf("reordering ciphers changed JA4:\n %s\n %s", a.JA4(), b.JA4())
	}
}

func TestJA4Deterministic(t *testing.T) {
	raw := buildHello(helloOpts{ciphers: []uint16{0x1301}, exts: sampleExts(), includeExt: true})
	a, _ := ParseRecord(raw)
	b, _ := ParseRecord(raw)
	if a.JA4() != b.JA4() {
		t.Errorf("non-deterministic: %s != %s", a.JA4(), b.JA4())
	}
}

func TestNoExtensionsAndNoCiphers(t *testing.T) {
	ch, err := ParseRecord(buildHello(helloOpts{ciphers: nil, includeExt: false}))
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if ch.partB() != "000000000000" {
		t.Errorf("empty cipher JA4_b = %q, want all-zero", ch.partB())
	}
	// no SNI, no ALPN, legacy version 1.2
	if got := ch.partA(); got != "t12i0000"+"00" {
		t.Errorf("JA4_a = %q, want t12i000000", got)
	}
}

func TestRejectsNonHandshake(t *testing.T) {
	if _, err := ParseRecord([]byte{0x17, 0x03, 0x03, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("expected error on non-handshake record")
	}
}
