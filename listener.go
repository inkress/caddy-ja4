package caddyja4

import (
	"bufio"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/inkress/caddy-ja4/ja4"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper is a Caddy listener wrapper (`caddy.listeners.ja4`) that peeks the
// TLS ClientHello off each new connection, computes its JA4 fingerprint, and stashes it
// for the companion HTTP handler. It MUST sit before the special "tls" wrapper in the
// server's `listener_wrappers` chain so it wraps the raw TCP conn (pre-termination).
type ListenerWrapper struct{}

// CaddyModule implements caddy.Module.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// WrapListener implements caddy.ListenerWrapper.
func (ListenerWrapper) WrapListener(l net.Listener) net.Listener { return &ja4Listener{l} }

// UnmarshalCaddyfile allows the bare directive `ja4` in a listener_wrappers block.
func (ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name; no args
	return nil
}

type ja4Listener struct{ net.Listener }

func (l *ja4Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Lazily peek on first Read (which is where the TLS server reads the ClientHello),
	// so a slow/idle client never blocks the accept loop.
	return &peekConn{Conn: c, br: bufio.NewReaderSize(c, 16384)}, nil
}

// peekConn reads through a bufio.Reader so we can Peek the ClientHello without consuming
// it (TLS still receives the full handshake). The peek runs exactly once.
type peekConn struct {
	net.Conn
	br     *bufio.Reader
	peeked bool
}

func (p *peekConn) Read(b []byte) (int, error) {
	if !p.peeked {
		p.peeked = true
		p.computeJA4()
	}
	return p.br.Read(b)
}

func (p *peekConn) computeJA4() {
	// TLS record header is 5 bytes: type(1) version(2) length(2). Peek the header, then
	// the full record. Peek never advances the reader, so the bytes remain for TLS.
	hdr, err := p.br.Peek(5)
	if err != nil || hdr[0] != 0x16 { // 0x16 = handshake; anything else isn't a ClientHello
		return
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	want := 5 + recLen
	if want > p.br.Size() {
		want = p.br.Size() // cap at the buffer; ParseRecord tolerates a short tail
	}
	raw, err := p.br.Peek(want)
	if err != nil && len(raw) < 9 {
		return
	}
	ch, err := ja4.ParseRecord(raw)
	if err != nil {
		return
	}
	shared.put(p.Conn.RemoteAddr().String(), ch.JA4())
}

// interface guards
var (
	_ caddy.Module          = ListenerWrapper{}
	_ caddy.ListenerWrapper = ListenerWrapper{}
	_ caddyfile.Unmarshaler = ListenerWrapper{}
)
