package caddyja4

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a Caddy HTTP middleware (`http.handlers.ja4`) that looks up the JA4 computed
// by the listener wrapper for this connection and sets it as a request header before the
// request is proxied upstream. Absent fingerprint → header simply not set, so upstreams
// can treat a missing X-JA4 as neutral.
type Handler struct {
	// HeaderName overrides the injected header (default "X-JA4").
	HeaderName string `json:"header_name,omitempty"`
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) header() string {
	if h.HeaderName != "" {
		return h.HeaderName
	}
	return "X-JA4"
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	name := h.header()
	// Never trust a client-supplied value — we are the authority for this header.
	r.Header.Del(name)
	if ja4, ok := shared.take(r.RemoteAddr); ok && ja4 != "" {
		r.Header.Set(name, ja4)
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile supports `ja4 [<header_name>]`.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		h.HeaderName = d.Val()
	}
	return nil
}

// interface guards
var (
	_ caddy.Module                = Handler{}
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
