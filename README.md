# agent-secrets-cli

Zero-leak secret operations CLI designed so AI coding agents and automation can rotate, validate, stage, sign, and inject secrets across Doppler, Fly.io, Tigris/S3, and GitHub Actions **without ever exposing a secret value**.

## Security Model

1. **Zero Secret Output**:
   - Stdout is refused by default unless `--safe` is passed **and** stdout is connected to a pipe (direct redirection to regular files is refused).
   - Every secret read or minted in-process is registered with an output guard that rejects raw, Base64, Base64URL, hex, JSON-escaped, and URL-encoded substrings before a byte can reach stdout.
   - Errors emit generic categories; panics print only `agent-secrets-cli: internal error`.
2. **Zero Disk Writes**:
   - `clippy.toml` + `#![deny(clippy::disallowed_methods, clippy::disallowed_macros)]` forbid `std::fs::write`, `File::create`, `OpenOptions`, `println!`, `eprintln!`, and `dbg!` across the crate.
   - Split-custody Ed25519 signing seeds (`PAYSSEAL` v1: `HKDF-SHA256` + `XChaCha20-Poly1305`) are unsealed exclusively in locked memory (`mlock`, `RLIMIT_CORE=0`) and passed to `fexecve`-verified root-owned ELF signers over an anonymous stdin pipe with an empty environment.
3. **Cleared Child Environment (`exec`)**:
   - `agent-secrets-cli exec` calls `Command::env_clear()`, retains only `PATH`, `HOME`, and `LANG` (plus explicit `--pass-env NAME` allowlists), injects requested `project/SECRET[=ENV_VAR]` bindings in memory, and `execvp`-replaces the process.

## Installation

```sh
cargo install agent-secrets-cli
```

Requires `doppler` authenticated on the host (`--scope "$HOME"` is enforced automatically when `DOPPLER_TOKEN` is unset), plus `fly` (`to-fly`, `--restart`), `gh` (`to-github`), or `tigris` (`create-tigris-key`) for the subcommands that target those providers.

## Agent Operational Roadmap (`--roadmap`)

Teams can keep their non-secret fleet inventory (Doppler project map, Fly app names, public key pins, rotation playbooks, and secret name registers) in a local TOON file outside git at `.agent-secrets-cli/roadmap.toon` (or `$HOME/.agent-secrets-cli/roadmap.toon`, or `AGENT_SECRETS_ROADMAP=/path/to/roadmap.toon`).

See [`examples/roadmap.example.toon`](examples/roadmap.example.toon) for a ready-to-copy template.

```sh
# Print the full structured TOON roadmap (piped):
agent-secrets-cli --roadmap | cat

# Print a single table (e.g. agent_rules, recipes_and_playbooks, private_keys_and_custody):
agent-secrets-cli --roadmap=agent_rules | cat
```

## Common Agent Workflows

### 1. Run commands (`cargo vip`, `cargo publish`, integration tests) with secrets injected in memory (`exec`)

```sh
# Build or check against private crates.vip dependencies without exposing CARGO_VIP_TOKEN:
agent-secrets-cli exec \
  --config dev \
  --secret ci-tokens/CARGO_VIP_TOKEN \
  --pass-env TMPDIR \
  -- cargo vip check

# Publish to a private crates.vip registry (mapping publish-scoped token to CARGO_VIP_TOKEN):
agent-secrets-cli exec \
  --config prd \
  --secret ci-tokens/CARGO_VIP_PUBLISH_TOKEN=CARGO_VIP_TOKEN \
  --pass-env TMPDIR \
  -- cargo vip publish

# Publish to public crates.io:
agent-secrets-cli exec \
  --config prd \
  --secret agent-accounts/CRATES_IO_TOKEN=CARGO_REGISTRY_TOKEN \
  --pass-env TMPDIR \
  -- cargo publish
```

### 2. Read allow-listed public config scalars (`get-path`)

Follows the fail-closed [public scalar read policy](docs/public-leaf-policy.md) (`port`, `timeout_ms`, `poll_interval_ms`, `decimals`, `enabled`, `cluster`/`network`, and strict `*_url` leaves only; sensitive names and arbitrary strings exit non-zero with zero output):

```sh
agent-secrets-cli --safe get-path \
  --config dev \
  --secret api-billing/BILLING_CONFIG_TOML \
  --format toml \
  --path server.port \
  --path server.enabled | cat
```

### 3. Check, mint, or sync shared 32-character Base62 service keys

```sh
# Verify every target in a shared group matches without writing:
agent-secrets-cli --safe check \
  --config stg \
  --group auth-gateway/AUTH__CALLBACK_KEY,api-billing/BILLING__CALLBACK_KEY | cat

# Mint a fresh 32-char Base62 key, write & read-back verify all targets, and restart apps in order:
agent-secrets-cli --safe rotate \
  --config stg \
  --group auth-gateway/AUTH__CALLBACK_KEY,api-billing/BILLING__CALLBACK_KEY \
  --restart auth-gateway-stg-fly,api-billing-stg-fly | cat
```

### 4. Patch structured JSON/TOML secrets without exposing values (`patch-config`)

```sh
# Dry-run path validation (omit --apply):
agent-secrets-cli --safe patch-config \
  --config stg \
  --secret api-billing/BILLING_CONFIG_TOML \
  --format toml \
  --from-secret service.api_key=api-billing/BILLING_API_KEY | cat

# Apply to Doppler with read-back verification and stage onto Fly:
agent-secrets-cli --safe patch-config \
  --config stg \
  --secret api-billing/BILLING_CONFIG_TOML \
  --format toml \
  --from-secret service.api_key=api-billing/BILLING_API_KEY \
  --apply --to-fly api-billing-stg-fly | cat
```

### 5. Stage secrets to Fly.io or GitHub Actions over stdin

```sh
agent-secrets-cli --safe to-fly \
  --config prd \
  --secret api-billing/BILLING_WEBHOOK_SECRET \
  --app api-billing-prd-fly | cat

agent-secrets-cli --safe to-github \
  --config prd \
  --secret agent-accounts/CI_READER_TOKEN \
  --as DOPPLER_TOKEN \
  --repo example-org/api-billing | cat
```

### 6. Split-custody Ed25519 sealing, signing, and `fexecve` handoff

- `package-seal`, `package-sign`, `package-verify`: split-custody Ed25519 artifact signing (`HKDF-SHA256` + `XChaCha20-Poly1305` sealed S3 object + Doppler passphrase + GitHub OIDC role).
- `fsverity-seal`, `fsverity-sign`: split-custody Ed25519 signing over 44-byte SHA-256 `FSVerity` formatted digests.
- `assoc-seal` / `assoc-pubkey` / `assoc-exec`, `recovery-seal` / `recovery-pubkey` / `recovery-exec`, `mint-seal` / `mint-pubkey` / `mint-exec`: hardware-hardened Linux split custody delivering 32 raw seed bytes on stdin to a `SHA-256`-pinned, `O_NOFOLLOW`-verified root-owned ELF signer via `fexecve` (see [custody signer child policy](docs/custody-exec-policy.md)).

## License

Licensed under either of MIT or Apache-2.0 at your option.
