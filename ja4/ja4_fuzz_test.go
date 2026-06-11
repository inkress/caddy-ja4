package ja4

import (
	"math/rand"
	"testing"
)

// FuzzParseRecord throws arbitrary bytes at the pre-TLS parser. It must never panic — a hostile
// ClientHello may only ever produce an error or a best-effort fingerprint, never crash the node.
func FuzzParseRecord(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseRecord(b) // must not panic
	})
}

// TestParseRecordNeverPanics is a deterministic smoke screen (runs without -fuzz): 200k random and
// adversarial buffers, including truncated TLS records with oversized declared lengths.
func TestParseRecordNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		n := rng.Intn(64)
		b := make([]byte, n)
		rng.Read(b)
		if n >= 5 { // bias toward looking like a handshake record with a lying length
			b[0] = 0x16
			b[3], b[4] = 0xff, 0xff
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseRecord panicked on %d-byte input %x: %v", n, b, r)
				}
			}()
			_, _ = ParseRecord(b)
		}()
	}
}
