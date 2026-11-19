# Credential WebSocket origins

Honey, Pays, and VIP credential WebSocket connections accept only these exact
origins:

- `wss://auth.honey.id`
- `wss://api.honey.id`
- `wss://auth-dev.honey.id`
- `wss://api-dev.honey.id`
- `wss://merchant.pays.online`
- `wss://api.crates.vip`

A trailing `/` and an explicit `:443` are also accepted. The development names
are policy entries; their inclusion does not assert that deployed services
exist.

The validator rejects `ws://`, other hosts and subdomains, user information,
alternate ports, non-root paths, query strings, fragments, percent-encoded
characters, backslashes, whitespace, control characters, and trailing-dot
hosts. Validation happens before each credential WebSocket builder connects.
The failure is generic and does not include the input URL or handshake protocol.

This is an origin allowlist only. It does not bind a token to a service role:
a trusted host can still be the wrong trusted destination for a given token.
Do not treat this patch as audience-scoped token enforcement.
