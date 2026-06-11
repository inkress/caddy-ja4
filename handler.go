package caddyja4

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a Caddy HTTP middleware (`http.handlers.ja4`) that looks up the JA4 computed
// by the listener wrapper for this connection and (a) sets it as a request header before the
// request is proxied upstream and (b) attaches it to the access-log entry as the `ja4` field.
// Absent fingerprint → neither is set, so upstreams and log consumers treat a missing JA4 as
// neutral.
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
	// peek (not take): one TLS handshake serves many HTTP requests under keep-alive / HTTP/2,
	// and every one of them should carry the connection's fingerprint. The registry's TTL sweep
	// reclaims the entry once the connection goes idle.
	if ja4, ok := shared.peek(r.RemoteAddr); ok && ja4 != "" {
		r.Header.Set(name, ja4)
		// Request-header mutations made here are NOT reflected in Caddy's access log (it records
		// the request as received). A log/observability consumer — as opposed to an upstream —
		// only sees JA4 if we attach it as an explicit extra log field.
		if extra, ok := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields); ok {
			extra.Add(zap.String("ja4", ja4))
		}
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
