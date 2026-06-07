# caddy-ja4

A [Caddy](https://caddyserver.com) plugin that computes the **JA4 TLS client fingerprint**
at the edge (where TLS is terminated) and injects it as an **`X-JA4`** request header to your
upstreams. Useful for fraud/risk scoring, bot detection, and analytics where you want a stable,
client-side-unspoofable identity that survives cookie/localStorage clears.

## Why a plugin (and not a Caddyfile placeholder)

Caddy exposes the negotiated cipher suite, TLS version, SNI and ALPN as placeholders, but **not**
a real JA4 — Go's `crypto/tls.ClientHelloInfo` drops extension ordering and GREASE, which JA4
depends on. This plugin reads the raw ClientHello off the wire via a **listener wrapper** before
TLS termination, parses it, and computes JA4 itself.

## Install

Build a Caddy binary with the plugin using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/inkress/caddy-ja4
```

## Usage

The listener wrapper must come **before** the special `tls` wrapper so it sees the raw TCP
connection; the handler runs in the route chain before your proxy/handler.

### Caddyfile

```caddyfile
{
  servers :443 {
    listener_wrappers {
      ja4
      tls
    }
  }
}

example.com {
  route {
    ja4                       # inject X-JA4 (optional arg: a custom header name)
    reverse_proxy localhost:8080
  }
}
```

### JSON

```jsonc
{
  "apps": { "http": { "servers": { "srv0": {
    "listen": [":443"],
    "listener_wrappers": [
      { "wrapper": "ja4" },     // ← peek ClientHello (must precede "tls")
      { "wrapper": "tls" }
    ],
    "routes": [{
      "handle": [
        { "handler": "ja4" },                                  // sets X-JA4
        { "handler": "reverse_proxy", "upstreams": [{ "dial": "localhost:8080" }] }
      ]
    }]
  } } } }
}
```

Your upstream then reads the `X-JA4` request header. A missing header means the fingerprint
couldn't be computed for that connection — treat it as neutral rather than suspicious.

### Custom header name

```caddyfile
ja4 X-TLS-Fingerprint
```

## Modules

| Module ID | Type | Purpose |
|---|---|---|
| `caddy.listeners.ja4` | listener wrapper | Peeks the ClientHello, computes JA4, stashes it keyed by remote address. |
| `http.handlers.ja4` | HTTP middleware | Sets `X-JA4` (or a custom header) from the stash before proxying. |

## How it works

1. The **listener wrapper** wraps each accepted connection. On the first read (where the TLS
   server reads the ClientHello), it peeks the handshake bytes without consuming them, parses
   the ClientHello, computes JA4, and stores it in a small in-memory registry keyed by the
   connection's remote address (TTL-swept so abandoned handshakes can't leak memory).
2. The **HTTP handler** looks up that registry by `r.RemoteAddr` and sets the header.

The JA4 algorithm itself lives in the dependency-free [`ja4`](./ja4) subpackage and is unit-tested:

```sh
go test ./ja4/
```

## Caveats

- JA4 follows the [FoxIO specification](https://github.com/FoxIO-LLC/ja4). Before relying on
  cross-vendor equality (e.g. matching a CDN's JA4 value), validate against the FoxIO pcap vectors.
- The remote-address join key assumes an HTTP request shortly follows the handshake; keep-alive
  reuse falls back to "absent" rather than a stale value.
- ClientHellos are peeked up to 16 KiB; larger multi-record hellos are parsed best-effort.

## License

[MIT](./LICENSE)
