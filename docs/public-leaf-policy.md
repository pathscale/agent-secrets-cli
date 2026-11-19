# Public scalar read policy

`get-path` reads are fail-closed. A requested leaf is emitted only when its
name and scalar type/value match this narrow policy. Paths are processed in
the requested order, and any refusal rejects the whole request without
returning partial output.

Sensitive names are refused regardless of suffix. This includes names
containing `pass`, `pwd`, `pin`, `dsn`, `webhook`, `cookie`, `jwt`, `session`,
`hmac`, `token`, `secret`, `seed`, `password`, `credential`, `private`, `auth`,
or `key`.

The only allowed scalar classes are:

- `port`: a nonnegative integer no greater than 65535.
- `timeout_ms` and `poll_interval_ms`: nonnegative integers.
- `decimals`: a nonnegative integer no greater than 9.
- `enabled`: a boolean.
- `cluster` and `network`: exactly `devnet`, `testnet`, or `mainnet-beta`.
- Names ending in `_url`: ASCII HTTPS or WSS URLs with a nonempty authority.
  Authorities cannot contain userinfo or percent escapes. URLs cannot contain
  a query, fragment, control character, or whitespace.

All other leaves are refused, including arbitrary strings, host aliases,
short hexadecimal values, and key-shaped values. `--allow-public-key` remains
parseable for compatibility but does not authorize an ambiguous key value.
