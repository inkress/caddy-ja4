// Package ja4 computes the FoxIO JA4 TLS client fingerprint from a raw ClientHello.
//
// JA4 = a_b_c (see https://github.com/FoxIO-LLC/ja4):
//
//	a (10 chars): <proto><tlsver><sni><cipherCount><extCount><alpn>
//	b (12 hex):   sha256(sorted cipher-suite hex, GREASE removed)[:12]
//	c (12 hex):   sha256(sorted ext hex w/o SNI+ALPN, GREASE removed) + "_" + sigalgs hex)[:12]
//
// This package is stdlib-only and has no Caddy dependency, so it can be unit-tested
// offline. The Caddy listener-wrapper + handler in the parent module feed it the
// ClientHello bytes peeked off the wire and inject the result as the X-JA4 header.
//
// NOTE: follows the JA4 spec as documented; before relying on cross-vendor equality
// (e.g. matching Cloudflare's cf-botmgmt-ja4) validate against the FoxIO pcap vectors.
package ja4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClientHello holds the JA4-relevant fields parsed from a TLS ClientHello.
type ClientHello struct {
	TLSVersion uint16   // highest offered (from supported_versions if present, else legacy_version)
	SNI        bool     // server_name (0x0000) extension present
	Ciphers    []uint16 // GREASE removed, original order
	Extensions []uint16 // GREASE removed, original order (incl. SNI + ALPN)
	ALPN       []string // application_layer_protocol_negotiation values, in order
	SigAlgs    []uint16 // signature_algorithms (0x000d) values, in order
	QUIC       bool     // transport is QUIC (proto char "q" vs "t")
}

const greaseExt = 0x0a0a // canonical GREASE value; all GREASE share the 0xNaNa shape

// isGREASE reports whether v is a GREASE placeholder (RFC 8701): both bytes equal and
// the low nibble is 0xa — i.e. one of 0x0a0a, 0x1a1a, … 0xfafa.
func isGREASE(v uint16) bool { return byte(v>>8) == byte(v) && v&0x0f == 0x0a }

// extType IDs we special-case.
const (
	extServerName uint16 = 0x0000
	extALPN       uint16 = 0x0010
	extSupportedV uint16 = 0x002b
	extSigAlgs    uint16 = 0x000d
)

var errShort = errors.New("ja4: truncated ClientHello")

// ParseRecord parses a ClientHello starting at the TLS record layer (leading 0x16
// handshake byte). Use this on raw bytes peeked off the wire.
func ParseRecord(b []byte) (*ClientHello, error) {
	if len(b) < 9 || b[0] != 0x16 {
		return nil, errors.New("ja4: not a TLS handshake record")
	}
	// Skip 5-byte record header. b[5] must be handshake type 0x01 (client_hello).
	hs := b[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, errors.New("ja4: not a ClientHello")
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+bodyLen {
		// A ClientHello can span multiple records; for the common single-record case
		// we parse what we have. Accept a short tail rather than failing outright.
		bodyLen = len(hs) - 4
	}
	return parseBody(hs[4 : 4+bodyLen])
}

// parseBody parses the ClientHello message body (after the 4-byte handshake header).
func parseBody(b []byte) (*ClientHello, error) {
	r := reader{b: b}
	ch := &ClientHello{}

	legacyVer, ok := r.u16()
	if !ok {
		return nil, errShort
	}
	ch.TLSVersion = legacyVer
	if !r.skip(32) { // random
		return nil, errShort
	}
	if !r.skipVec8() { // session_id
		return nil, errShort
	}
	// cipher_suites
	cs, ok := r.vec16()
	if !ok {
		return nil, errShort
	}
	for i := 0; i+1 < len(cs); i += 2 {
		v := binary.BigEndian.Uint16(cs[i:])
		if !isGREASE(v) {
			ch.Ciphers = append(ch.Ciphers, v)
		}
	}
	if !r.skipVec8() { // compression_methods
		return nil, errShort
	}
	// extensions (optional)
	ext, ok := r.vec16()
	if !ok {
		return ch, nil // no extensions block
	}
	er := reader{b: ext}
	for {
		etype, ok := er.u16()
		if !ok {
			break
		}
		edata, ok := er.vec16()
		if !ok {
			break
		}
		if isGREASE(etype) {
			continue
		}
		ch.Extensions = append(ch.Extensions, etype)
		switch etype {
		case extServerName:
			ch.SNI = true
		case extALPN:
			ch.ALPN = parseALPN(edata)
		case extSupportedV:
			if v := highestVersion(edata); v != 0 {
				ch.TLSVersion = v
			}
		case extSigAlgs:
			ch.SigAlgs = parseU16List(edata)
		}
	}
	return ch, nil
}

// JA4 renders the a_b_c fingerprint string.
func (ch *ClientHello) JA4() string {
	return fmt.Sprintf("%s_%s_%s", ch.partA(), ch.partB(), ch.partC())
}

func (ch *ClientHello) partA() string {
	proto := "t"
	if ch.QUIC {
		proto = "q"
	}
	sni := "i"
	if ch.SNI {
		sni = "d"
	}
	alpn := "00"
	if len(ch.ALPN) > 0 && ch.ALPN[0] != "" {
		p := ch.ALPN[0]
		alpn = string(p[0]) + string(p[len(p)-1])
	}
	return fmt.Sprintf("%s%s%s%s%s%s", proto, verCode(ch.TLSVersion), sni,
		count2(len(ch.Ciphers)), count2(len(ch.Extensions)), alpn)
}

func (ch *ClientHello) partB() string {
	if len(ch.Ciphers) == 0 {
		return "000000000000"
	}
	c := append([]uint16(nil), ch.Ciphers...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return hash12(joinHex16(c))
}

func (ch *ClientHello) partC() string {
	exts := make([]uint16, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		if e == extServerName || e == extALPN { // excluded from the JA4_c list by spec
			continue
		}
		exts = append(exts, e)
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	input := joinHex16(exts) + "_" + joinHex16(ch.SigAlgs) // sigalgs kept in original order
	return hash12(input)
}

/* --------------------------------------------------------------- helpers -- */

func parseALPN(b []byte) []string {
	r := reader{b: b}
	list, ok := r.vec16() // ALPNProtocolNameList
	if !ok {
		return nil
	}
	lr := reader{b: list}
	var out []string
	for {
		name, ok := lr.vec8()
		if !ok {
			break
		}
		out = append(out, string(name))
	}
	return out
}

func parseU16List(b []byte) []uint16 {
	r := reader{b: b}
	list, ok := r.vec16()
	if !ok {
		return nil
	}
	var out []uint16
	for i := 0; i+1 < len(list); i += 2 {
		v := binary.BigEndian.Uint16(list[i:])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func highestVersion(b []byte) uint16 {
	r := reader{b: b}
	list, ok := r.vec8() // supported_versions is an 8-bit-length vector of u16s
	if !ok {
		return 0
	}
	var best uint16
	for i := 0; i+1 < len(list); i += 2 {
		v := binary.BigEndian.Uint16(list[i:])
		if isGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	return best
}

// verCode maps a TLS version to its 2-char JA4 code.
func verCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func joinHex16(v []uint16) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

/* ------------------------------------------------------------- byte reader */

type reader struct {
	b   []byte
	pos int
}

func (r *reader) u16() (uint16, bool) {
	if r.pos+2 > len(r.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) skip(n int) bool {
	if r.pos+n > len(r.b) {
		return false
	}
	r.pos += n
	return true
}

// vec8 reads an 8-bit-length-prefixed byte vector.
func (r *reader) vec8() ([]byte, bool) {
	if r.pos+1 > len(r.b) {
		return nil, false
	}
	n := int(r.b[r.pos])
	r.pos++
	if r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

func (r *reader) skipVec8() bool { _, ok := r.vec8(); return ok }

// vec16 reads a 16-bit-length-prefixed byte vector.
func (r *reader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok || r.pos+int(n) > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return v, true
}
