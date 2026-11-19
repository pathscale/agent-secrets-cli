//! Rotate, sync and check secrets that one or more services share through
//! Doppler, without ever printing a value.
//!
//! A *group* is one value held under several names, each `project/NAME` in the
//! same Doppler config:
//!
//! ```text
//! --group auth-honey-id/AUTH__SERVICE__PLATFORM_API_KEY,api-honey-id/API__SERVICE__HONEY_AUTH_PLATFORM_KEY
//! ```
//!
//! - `rotate` mints a fresh 32 character Base62 psc-nanoid per group, writes it
//!   under every name, reads each back to confirm, then restarts the `--restart`
//!   Fly apps in the order given. Services read Doppler only at boot, so a
//!   rotation without the restart leaves each app on its old value until it
//!   next starts, and the two sides of a pair drift apart.
//! - `sync` mints nothing: it copies the first name's value to the others. It
//!   heals a group split by an interrupted rotation. It restarts only what
//!   `--restart` names.
//! - `set` writes a value read from stdin under every name and reads each back.
//!   It is for settings the fleet does not mint, and restarts only what
//!   `--restart` names.
//! - `to-fly` copies Doppler values into a Fly app's secrets under the same
//!   names, staged. When `--restart` names that app, it deploys the staged
//!   secrets; other named apps get their normal restart.
//! - `patch-config` edits a JSON or TOML secret by dotted paths, prints only
//!   changed paths in a dry run, and writes only with `--apply`.
//! - `check` reads every name and reports, per group, whether they match and
//!   are a 32 character Base62 nanoid. It writes nothing.
//! - `create-tigris-key` makes a Tigris access key with the `tigris` CLI and
//!   writes its id and secret to Doppler.
//!
//! Doppler and Fly secret values go over stdin, never to stdout, so an agent
//! can run any of these. Sensitive config values can be copied with
//! `patch-config --from-secret` instead of being supplied to `--set`. Needs
//! `doppler` logged in, and `fly` too for `to-fly` or when `--restart` is given.

mod assoc_key;
mod config_patch;
mod honey;
mod output;
mod package_sign;
mod pays;
mod qa_fixtures;
mod qa_rotation;
mod reader;
mod safe_read;
mod sealed_seed;
mod split_custody;
mod vip;

#[global_allocator]
static GLOBAL: rusty_alloc::RustyAlloc = rusty_alloc::RustyAlloc;

use std::io::Write;
use std::process::{Command, Stdio};

pub(crate) use endpoint_libs::eyre;

use clap::{Parser, Subcommand};
use eyre::{Result, bail, ensure, eyre};
use psc_nanoid::Nanoid;
use psc_nanoid::alphabet::Base62Alphabet;

type Key = Nanoid<32, Base62Alphabet>;
type AppKeyId = Nanoid<16, Base62Alphabet>;

#[derive(Parser)]
#[command(
    version,
    about,
    after_help = "Operational roadmap: run `agent-secrets-cli --roadmap` (or `--roadmap=<table_name>`) to print `.agent-secrets-cli/roadmap.toon` (resolved via `AGENT_SECRETS_ROADMAP`, workspace ancestors, or `$HOME`)."
)]
struct Cli {
    /// Allow public output to a pipe.
    #[arg(long, global = true)]
    safe: bool,

    /// Print the local non-secret operational roadmap (`.agent-secrets-cli/roadmap.toon`) or a single table (`--roadmap=<table_name>`) and exit.
    #[arg(long, global = true, num_args = 0..=1, default_missing_value = "", require_equals = true, value_name = "TABLE")]
    roadmap: Option<String>,

    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Enroll the independent pool association authority with split custody.
    AssocSeal,
    /// Unseal the association authority and print only its Ed25519 public key.
    AssocPubkey,
    /// Give a trusted child the association seed through an inherited stdin pipe.
    AssocExec(assoc_key::AssocExecArgs),
    /// Enroll or resume the independent stuck-funds recovery authority.
    RecoverySeal,
    /// Unseal the recovery authority and print only its Ed25519 public key.
    RecoveryPubkey,
    /// Give a trusted recovery-only signer the seed through an inherited stdin pipe.
    RecoveryExec(split_custody::ExecArgs),
    /// Enroll or resume the stablecoin mint authority for poUSD and devnet USDT.
    MintSeal(split_custody::MintArgs),
    /// Print the stablecoin mint authority's lowercase hex key and Solana address.
    MintPubkey(split_custody::MintArgs),
    /// Give a trusted stablecoin minter exactly 32 seed bytes through an inherited stdin pipe.
    MintExec(split_custody::MintExecArgs),
    /// Create a config-scoped read-only token and store it through stdin.
    CreateReaderToken(reader::CreateReaderTokenArgs),
    /// Create an isolated root config and its environment, without cloning secrets.
    CreateConfig(reader::CreateConfigArgs),
    /// Copy a resolved binding to another config; optionally remove the source.
    CopySecret(reader::CopySecretArgs),
    /// Delete one Doppler secret binding.
    DeleteSecret(reader::DeleteSecretArgs),
    /// Print only explicitly selected public config leaf values.
    GetPath(safe_read::GetPathArgs),
    /// Run a command with Doppler secrets injected into its environment.
    Exec(safe_read::ExecArgs),
    /// Create-only split-custody package seed enrollment.
    #[command(
        name = "package-seal",
        about = "Enroll or resume the split-custody package Ed25519 seed",
        long_about = "Create-only package seed enrollment. A random passphrase is stored in Doppler and the sealed seed is stored as a private S3 object. Existing custody halves are never replaced; partial or mismatched state fails closed. The command reads both halves back, unseals locally, verifies the public key, and prints only its 64-character lowercase hex value."
    )]
    PackageSeal(package_sign::PackageSealArgs),
    /// Create-only split-custody fs-verity seed enrollment.
    #[command(
        name = "fsverity-seal",
        about = "Enroll or resume the split-custody fs-verity Ed25519 seed",
        long_about = "Create-only fs-verity seed enrollment. A random passphrase is stored only in pays-host/imagesigning, the sealed seed only in its private S3 object, and the public key only in pays-host/prd. The command reads custody back, unseals locally, verifies the public key, and prints only its lowercase hex value."
    )]
    FsVeritySeal(package_sign::FsVeritySealArgs),
    /// Unseal and sign package artifacts in a GitHub Actions job.
    #[command(name = "package-sign")]
    PackageSign(package_sign::PackageSignArgs),
    /// Unseal and sign fs-verity formatted digests in a GitHub Actions job.
    #[command(
        name = "fsverity-sign",
        about = "Sign exact fs-verity formatted digests with Ed25519",
        long_about = "Read the fs-verity passphrase from imagesigning, assume the supplied image-signing role with GitHub Actions OIDC, and download the one sealed seed object. Each input must be the exact 44-byte SHA-256 fs-verity payload; signatures are raw 64-byte Ed25519 outputs."
    )]
    FsVeritySign(package_sign::FsVeritySignArgs),
    /// Verify package artifact sidecars with a local public pin.
    #[command(name = "package-verify")]
    PackageVerify(package_sign::PackageVerifyArgs),
    /// Sign fixture files with a fresh in-memory key for rejection checks.
    #[command(name = "package-sign-fixture")]
    PackageSignFixture(package_sign::PackageSignFixtureArgs),
    /// Mint a new value per group, write it everywhere, restart the apps.
    Rotate(Args),
    /// Copy each group's first value to the rest of the group.
    Sync(Args),
    /// Report whether each group matches and holds a valid key. Writes nothing.
    Check(Args),
    /// Write the value read from stdin under every name, read each back, and
    /// restart only what `--restart` names. For a setting the fleet does not
    /// mint, such as an admin id; a value that is not a key is fine.
    Set(Args),
    /// Copy Doppler values to a Fly app's secrets under the same names, staged:
    /// `--restart` deploys the staged secrets on this app and restarts other
    /// named apps.
    ToFly(ToFlyArgs),
    /// Patch a JSON or TOML config secret in Doppler without printing values.
    PatchConfig(PatchConfigArgs),
    /// Register an app on honey.id and write its public id and API key to
    /// Doppler. The key is never printed.
    CreateApp(CreateAppArgs),
    /// Create an additional honey app key and write it to Doppler. The key is
    /// never printed.
    CreateAppKey(CreateAppKeyArgs),
    /// Stage a new honey app key, then revoke the old key after deployment.
    RotateAppKey(RotateAppKeyArgs),
    /// Set whether a honey app may authenticate service connections.
    SetAppService(SetAppServiceArgs),
    /// Create a private Tigris bucket with `fly storage create` and write its
    /// name and keys to Doppler. The keys are never printed, and the bucket is
    /// attached to no app, so no app's AWS_* secrets are overwritten.
    CreateBucket(CreateBucketArgs),
    /// Sign a honey.id account up with a minted password kept only in Doppler
    /// (PREFIX_USERNAME, PREFIX_PASSWORD), then sign in with it. The password
    /// is never printed; a rerun reuses the one already in Doppler.
    CreateAccount(CreateAccountArgs),
    /// List a honey app's users as public ids, usernames, and app roles.
    HoneyUsers(HoneyUsersArgs),
    /// Create a Tigris access key with the `tigris` CLI and write its id and
    /// secret to Doppler. The secret is never printed. `--admin` makes an
    /// org-wide admin key; otherwise pair each `--bucket` with a `--role`.
    CreateTigrisKey(CreateTigrisKeyArgs),
    /// List the crates.vip apps the account reaches: id, name, bucket. None of
    /// it is secret.
    VipApps(VipLogin),
    /// Create a crates.vip app on a private bucket of its own, with the
    /// account as its first member. Prints the app id.
    CreateVipApp(CreateVipAppArgs),
    /// Mint a crates.vip registry token and write it to Doppler. The token is
    /// never printed.
    CreateVipToken(CreateVipTokenArgs),
    /// List the pays.online merchant apps of the account (making it a merchant
    /// first if it is still Public): id and name. None of it is secret.
    PaysApps(PaysLogin),
    /// Create a pays.online merchant app and write its public id and its first
    /// API key to Doppler. The key is never printed.
    CreatePaysApp(CreatePaysAppArgs),
    /// Ensure one named app for HONEY_QA_MERCHANT and cold-read it through
    /// ListApps. Prints only its app id and name; the first key is discarded.
    #[command(name = "onboard-qa-pays-app")]
    OnboardQaPaysApp(OnboardQaPaysAppArgs),
    /// Ensure the fixed honey.id dev ps-qa fixture accounts and app.
    #[command(name = "ensure-honey-dev-qa-fixtures")]
    EnsureHoneyDevQaFixtures,
    /// Rotate Honey DEV QA passwords and revoke Honey DEV sessions.
    #[command(name = "rotate-honey-dev-qa-password")]
    RotateHoneyDevQaPassword {
        /// Rotate only the existing platform admin in agent-accounts/dev.
        /// Without this flag, all four honey-id/dev QA accounts are required.
        #[arg(long)]
        dev_admin_only: bool,
        /// Acknowledge that both Honey DEV apps restart and sign out all users.
        #[arg(long)]
        restart_dev: bool,
    },
    /// Copy Doppler values into GitHub Actions secrets of the same name with
    /// `gh secret set`, on stdin. Values are never printed.
    ToGithub(ToGithubArgs),
}

/// Who signs in to crates.vip, and where.
#[derive(clap::Args)]
struct VipLogin {
    /// `project/PREFIX` of the honey.id account: PREFIX_USERNAME and
    /// PREFIX_PASSWORD. It must be an AppAdmin or PlatformAdmin on crates.vip.
    #[arg(long, value_parser = parse_target, default_value = "agent-accounts/HONEY_ID_PROD")]
    login: Target,

    /// Doppler config the login is read from.
    #[arg(long, default_value = "prd")]
    login_config: String,

    #[arg(long, default_value = "wss://auth.honey.id/")]
    auth: String,

    #[arg(long, default_value = "wss://api.crates.vip/")]
    api: String,

    /// crates.vip's app on honey.id, the one its users sign in to.
    #[arg(long, default_value = "sj1lrtniQzOmIJWA")]
    honey_app: String,
}

#[derive(clap::Args)]
struct CreateVipAppArgs {
    #[command(flatten)]
    login: VipLogin,

    /// The app's name.
    #[arg(long)]
    name: String,

    /// honey.id public ids to add as members, so the app is theirs too.
    /// Repeatable or comma-separated.
    #[arg(long, value_delimiter = ',')]
    member: Vec<String>,
}

#[derive(clap::Args)]
struct CreateVipTokenArgs {
    #[command(flatten)]
    login: VipLogin,

    /// Doppler config the token is written to.
    #[arg(short, long)]
    config: String,

    /// The app the token reaches, from `vip-apps`.
    #[arg(long)]
    app_id: String,

    /// What the token is for, shown in the token list (e.g. "karen ci").
    #[arg(long)]
    name: String,

    /// `ReadOnly` to build against the registry, `Publish` to publish to it.
    #[arg(long, value_parser = ["ReadOnly", "Publish"])]
    scope: String,

    /// `project/NAME` targets that get the token.
    #[arg(long, required = true, value_parser = parse_group)]
    token: Vec<Vec<Target>>,
}

/// Who signs in to pays.online, and where.
#[derive(clap::Args)]
struct PaysLogin {
    /// `project/PREFIX` of the honey.id account: PREFIX_USERNAME and
    /// PREFIX_PASSWORD. It owns the merchant apps.
    #[arg(long, value_parser = parse_target, default_value = "agent-accounts/HONEY_ID_PROD")]
    login: Target,

    /// Doppler config the login is read from.
    #[arg(long, default_value = "prd")]
    login_config: String,

    #[arg(long, default_value = "wss://auth.honey.id/")]
    auth: String,

    #[arg(long, default_value = "wss://merchant.pays.online/")]
    api: String,

    /// pays.online's app on honey.id, the one its users sign in to.
    #[arg(long, default_value = "P72RG3UW9RhnChah")]
    honey_app: String,
}

#[derive(clap::Args)]
struct CreatePaysAppArgs {
    #[command(flatten)]
    login: PaysLogin,

    /// Doppler config the id and key are written to.
    #[arg(short, long)]
    config: String,

    /// The app's name, shown to the merchant (e.g. "Eden").
    #[arg(long)]
    name: String,

    /// The app's description.
    #[arg(long, default_value = "")]
    description: String,

    /// `project/NAME` targets that get the app's public id.
    #[arg(long, required = true, value_parser = parse_group)]
    app_id: Vec<Vec<Target>>,

    /// `project/NAME` targets that get the app's API key.
    #[arg(long, required = true, value_parser = parse_group)]
    key: Vec<Vec<Target>>,
}

#[derive(clap::Args)]
struct OnboardQaPaysAppArgs {
    /// Required, stable display name used to make this operation idempotent.
    #[arg(long)]
    name: String,

    /// App description. The new QA app is not provisioned with wallets or
    /// payment data by this command.
    #[arg(
        long,
        default_value = "Dedicated QA app for signed-in merchant acceptance"
    )]
    description: String,
}

#[derive(clap::Args)]
struct ToGithubArgs {
    /// Doppler config to read from.
    #[arg(short, long)]
    config: String,

    /// Comma-separated `project/NAME` to copy; the GitHub secret is named NAME
    /// unless `--as` renames it. Repeatable.
    #[arg(short, long = "secret", required = true, value_parser = parse_group)]
    secrets: Vec<Vec<Target>>,

    /// `owner/repo` to write to. Repeatable or comma-separated.
    #[arg(long, required = true, value_delimiter = ',')]
    repo: Vec<String>,

    /// The GitHub secret's name, when it differs from the Doppler one. Only
    /// with a single `--secret`.
    #[arg(long = "as")]
    rename: Option<String>,
}

#[derive(clap::Args)]
struct CreateTigrisKeyArgs {
    /// Doppler config to write to (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// The key's name in Tigris.
    #[arg(long)]
    name: String,

    /// Admin on every bucket in the organization: it can create buckets and
    /// mint and delete other keys.
    #[arg(long, conflicts_with_all = ["bucket", "role"])]
    admin: bool,

    /// Comma-separated buckets, each paired positionally with a `--role`.
    #[arg(long, requires = "role")]
    bucket: Option<String>,

    /// Comma-separated roles (Editor, ReadWrite, ReadOnly), one per bucket.
    #[arg(long, requires = "bucket")]
    role: Option<String>,

    /// `project/NAME` targets that get the access key id.
    #[arg(long, required = true, value_parser = parse_group)]
    access_key: Vec<Vec<Target>>,

    /// `project/NAME` targets that get the secret access key.
    #[arg(long, required = true, value_parser = parse_group)]
    secret_key: Vec<Vec<Target>>,
}

#[derive(clap::Args)]
struct CreateAccountArgs {
    /// Doppler config the credentials are written to (e.g. prd).
    #[arg(short, long)]
    config: String,

    /// `project/PREFIX`: the account lives at PREFIX_USERNAME and
    /// PREFIX_PASSWORD in that project.
    #[arg(long, value_parser = parse_target)]
    login: Target,

    /// The username to sign up with.
    #[arg(long)]
    username: String,

    #[arg(long, default_value = "wss://auth.honey.id/")]
    auth: String,

    /// The honey.id app the account signs up to: honey.id's own by default,
    /// or a site's app id to make an account on that site.
    #[arg(long, default_value = "4x3JVuCnNIfD4szt")]
    honey_app: String,

    /// A backend to open a session on afterwards, to learn the account's
    /// public id (e.g. wss://api.honey.id/). Empty skips it.
    #[arg(long, default_value = "wss://api.honey.id/")]
    api: String,
}

#[derive(clap::Args)]
struct HoneyUsersArgs {
    /// Honey app public id whose users are listed.
    #[arg(long)]
    app: String,

    /// `project/PREFIX` of the account that signs in. Defaults to
    /// `agent-accounts/HONEY_ID_PROD`.
    #[arg(
        long,
        value_parser = parse_target,
        default_value = "agent-accounts/HONEY_ID_PROD"
    )]
    login: Target,

    /// Doppler config the login is read from.
    #[arg(long, default_value = "prd")]
    login_config: String,

    /// Match this username exactly.
    #[arg(long)]
    username: Option<String>,

    /// One-based page to request.
    #[arg(long, default_value_t = 1)]
    page: u32,

    /// Number of users to request per page.
    #[arg(long = "page-size", default_value_t = 100)]
    page_size: u32,
}

#[derive(clap::Args)]
struct CreateBucketArgs {
    /// Doppler config to write to (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// The bucket's name.
    #[arg(long)]
    name: String,

    /// Fly organization that owns it.
    #[arg(long, default_value = "personal")]
    org: String,

    /// `project/NAME` targets that get the bucket name.
    #[arg(long, required = true, value_parser = parse_group)]
    bucket_name: Vec<Vec<Target>>,

    /// `project/NAME` targets that get the access key id.
    #[arg(long, required = true, value_parser = parse_group)]
    access_key: Vec<Vec<Target>>,

    /// `project/NAME` targets that get the secret access key.
    #[arg(long, required = true, value_parser = parse_group)]
    secret_key: Vec<Vec<Target>>,
}

#[derive(clap::Args)]
struct CreateAppArgs {
    /// Doppler config for every read and write (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// `project/PREFIX` of the account that signs in: PREFIX_USERNAME and
    /// PREFIX_PASSWORD in that project. It must be PlatformAdmin or AppAdmin.
    #[arg(long, value_parser = parse_target)]
    login: Target,

    /// Doppler config the login is read from, when it differs from `--config`
    /// (e.g. a prod honey.id account registering an app whose keys live in dev).
    #[arg(long)]
    login_config: Option<String>,

    #[arg(long, default_value = "wss://auth.honey.id/")]
    auth: String,

    #[arg(long, default_value = "wss://api.honey.id/")]
    api: String,

    /// honey.id's own app, the one its accounts sign in to.
    #[arg(long, default_value = "4x3JVuCnNIfD4szt")]
    honey_app: String,

    #[arg(long)]
    name: String,

    #[arg(long, default_value = "")]
    description: String,

    /// Where auth calls the site back, e.g. wss://api.example.com/.
    #[arg(long)]
    callback_url: String,

    /// Comma-separated `project/NAME` that get the new app's public id.
    /// Repeatable.
    #[arg(long, value_parser = parse_group)]
    app_id: Vec<Vec<Target>>,

    /// Comma-separated `project/NAME` that get the credential the site checks
    /// auth's callbacks against: its `honey_id.auth_api_key`. Repeatable.
    #[arg(long, required = true, value_parser = parse_group)]
    api_key: Vec<Vec<Target>>,

    /// Comma-separated `project/NAME` that get the app's own key (`hk_...`),
    /// which a service presents to prove it is this app. Repeatable; a site
    /// that only signs users in needs none.
    #[arg(long, value_parser = parse_group)]
    app_key: Vec<Vec<Target>>,
}

#[derive(clap::Args)]
struct HoneyAppLoginArgs {
    /// `project/PREFIX` of the account that signs in: PREFIX_USERNAME and
    /// PREFIX_PASSWORD in that project. It must be PlatformAdmin or AppAdmin
    /// for key management; `set-app-service` requires PlatformAdmin.
    #[arg(long, value_parser = parse_target)]
    login: Target,

    /// Doppler config the login is read from. Defaults to the key config for
    /// key operations and prd for `set-app-service`.
    #[arg(long)]
    login_config: Option<String>,

    #[arg(long, default_value = "wss://auth.honey.id/")]
    auth: String,

    #[arg(long, default_value = "wss://api.honey.id/")]
    api: String,

    /// honey.id's own app, the one its accounts sign in to.
    #[arg(long, default_value = "4x3JVuCnNIfD4szt")]
    honey_app: String,

    /// Honey app public id.
    #[arg(long)]
    app_id: String,
}

#[derive(clap::Args)]
struct CreateAppKeyArgs {
    #[command(flatten)]
    login: HoneyAppLoginArgs,

    /// Doppler config to write to (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// Label shown in the honey app key list.
    #[arg(long)]
    label: String,

    /// Expire the key this many seconds after creation.
    #[arg(long)]
    expires_in_secs: Option<u64>,

    /// `project/NAME` targets that get the key. Repeatable.
    #[arg(long = "key", required = true, value_parser = parse_group)]
    key_targets: Vec<Vec<Target>>,
}

#[derive(clap::Args)]
struct RotateAppKeyArgs {
    #[command(flatten)]
    login: HoneyAppLoginArgs,

    /// Doppler config for the key targets (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// Label to store for the replacement key.
    #[arg(long, required_unless_present = "finish", conflicts_with = "finish")]
    label: Option<String>,

    /// Expire the new key this many seconds after creation.
    #[arg(long, conflicts_with = "finish")]
    expires_in_secs: Option<u64>,

    /// `project/NAME` targets that get the key. Repeatable.
    #[arg(
        long = "key",
        required_unless_present = "finish",
        conflicts_with = "finish",
        value_parser = parse_group
    )]
    key_targets: Vec<Vec<Target>>,

    /// Fly apps that receive the staged key. Repeatable or comma-separated.
    #[arg(
        long = "fly-app",
        required_unless_present = "finish",
        conflicts_with = "finish",
        value_delimiter = ','
    )]
    fly_apps: Vec<String>,

    /// Existing key id to revoke. On the first phase, if omitted, it is read
    /// from the current key target or the app's `legacy` key row.
    #[arg(long)]
    old_key_id: Option<String>,

    /// Finish an earlier rotation by revoking `--old-key-id` after deployment.
    #[arg(long)]
    finish: bool,

    /// Seconds the old key remains valid after `--finish`; zero revokes now.
    #[arg(long, default_value_t = 0)]
    grace: u64,
}

#[derive(clap::Args)]
struct SetAppServiceArgs {
    #[command(flatten)]
    login: HoneyAppLoginArgs,

    /// Whether the app may authenticate service connections.
    #[arg(long, action = clap::ArgAction::Set, required = true)]
    service: bool,
}

#[derive(clap::Args)]
struct ToFlyArgs {
    /// Doppler config to read from (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// Comma-separated `project/NAME` to copy; the Fly secret is named NAME.
    /// Repeatable.
    #[arg(short, long = "secret", required = true, value_parser = parse_group)]
    secrets: Vec<Vec<Target>>,

    /// The Fly app whose secrets are written.
    #[arg(short, long)]
    app: String,

    /// Fly apps to restart afterwards, in order. Repeatable or comma-separated.
    #[arg(short, long, value_delimiter = ',')]
    restart: Vec<String>,
}

#[derive(clap::Args)]
struct PatchConfigArgs {
    /// Doppler config to read from and write to.
    #[arg(short, long)]
    config: String,

    /// The structured config secret to edit, as project/NAME.
    #[arg(long, value_parser = parse_target)]
    secret: Target,

    /// The config format to parse and edit.
    #[arg(long, value_parser = ["json", "toml"])]
    format: String,

    /// Set a dotted path to a JSON value. Repeatable.
    #[arg(long = "set", value_name = "PATH=JSONVALUE")]
    sets: Vec<String>,

    /// Remove a dotted path. Repeatable.
    #[arg(long = "unset", value_name = "PATH")]
    unsets: Vec<String>,

    /// Copy another Doppler secret into a dotted path. Repeatable.
    #[arg(long = "from-secret", value_name = "PATH=project/NAME")]
    from_secrets: Vec<String>,

    /// Create missing parent objects or tables for set operations.
    #[arg(long)]
    create_parents: bool,

    /// Write the patched config back to Doppler. Without this flag, show paths only.
    #[arg(long)]
    apply: bool,

    /// Stage the patched config secret on a Fly app. Requires --apply.
    #[arg(long, requires = "apply")]
    to_fly: Option<String>,

    /// Deploy the staged secret and start machines left stopped. Requires --to-fly.
    #[arg(long, requires = "to_fly")]
    restart: bool,
}

#[derive(clap::Args)]
struct Args {
    /// Doppler config, the same in every project (e.g. dev, prd).
    #[arg(short, long)]
    config: String,

    /// One shared value: comma-separated `project/NAME` targets. Repeatable.
    #[arg(short, long = "group", required = true, value_parser = parse_group)]
    groups: Vec<Vec<Target>>,

    /// Fly apps to restart afterwards, in order. Repeatable or comma-separated.
    #[arg(short, long, value_delimiter = ',')]
    restart: Vec<String>,
}

#[derive(Clone)]
struct Target {
    project: String,
    name: String,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.project, self.name)
    }
}

fn parse_target(raw: &str) -> Result<Target, String> {
    match parse_group(raw)?.as_slice() {
        [one] => Ok(one.clone()),
        _ => Err(format!("{raw:?} is not one project/NAME")),
    }
}

fn parse_group(raw: &str) -> Result<Vec<Target>, String> {
    let targets = raw
        .split(',')
        .map(|part| match part.trim().split_once('/') {
            Some((project, name)) if !project.is_empty() && !name.is_empty() => Ok(Target {
                project: project.to_string(),
                name: name.to_string(),
            }),
            _ => Err(format!("{part:?} is not project/NAME")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(targets)
}

fn honey_app_login(
    args: &HoneyAppLoginArgs,
    fallback_config: Option<&str>,
) -> Result<honey::Login> {
    let login_config = args
        .login_config
        .as_deref()
        .or(fallback_config)
        .unwrap_or("prd");
    let account = |suffix: &str| Target {
        project: args.login.project.clone(),
        name: format!("{}_{suffix}", args.login.name),
    };
    Ok(honey::Login {
        username: get(&account("USERNAME"), login_config)?,
        password: get(&account("PASSWORD"), login_config)?,
        auth: args.auth.clone(),
        api: args.api.clone(),
        honey_app: args.honey_app.clone(),
    })
}

fn parse_app_key_id(value: &str) -> Result<String> {
    ensure!(
        AppKeyId::try_from_str(value).is_ok(),
        "app key id must be 16 Base62 characters"
    );
    Ok(value.to_string())
}

fn prefixed_app_key_id(value: &str) -> Option<String> {
    let mut parts = value.split('_');
    let prefix = parts.next()?;
    let key_id = parts.next()?;
    let secret = parts.next()?;
    if prefix != "hk"
        || parts.next().is_some()
        || AppKeyId::try_from_str(key_id).is_err()
        || Key::try_from_str(secret).is_err()
    {
        return None;
    }
    Some(key_id.to_string())
}

fn created_app_key_id(created: &honey::CreatedKey) -> Result<String> {
    let key_id = parse_app_key_id(&created.key_id)?;
    ensure!(
        prefixed_app_key_id(&created.key).as_deref() == Some(key_id.as_str()),
        "CreateAppKey returned a malformed key"
    );
    Ok(key_id)
}

fn current_app_key_id(
    login: &honey::Login,
    app_public_id: &str,
    config: &str,
    targets: &[Target],
) -> Result<String> {
    let values = targets
        .iter()
        .map(|target| get(target, config))
        .collect::<Result<Vec<_>>>()?;
    let current = values
        .first()
        .ok_or_else(|| eyre!("give at least one --key target"))?;
    ensure!(
        values.iter().all(|value| value == current),
        "the --key targets do not hold the same current app key in {config}; sync them first"
    );
    let keys = honey::list_app_keys(login, app_public_id)?;
    let key_id = match prefixed_app_key_id(current) {
        Some(key_id) => key_id,
        None => {
            let mut legacy = keys.iter().filter(|key| key.label == "legacy");
            let key = legacy
                .next()
                .ok_or_else(|| eyre!("could not identify the legacy app key; pass --old-key-id"))?;
            ensure!(
                legacy.next().is_none(),
                "more than one app key is labelled legacy; pass --old-key-id"
            );
            key.key_id.clone()
        }
    };
    ensure!(
        keys.iter().any(|key| key.key_id == key_id),
        "the current app key id is not listed for this app; pass --old-key-id"
    );
    parse_app_key_id(&key_id)
}

fn listed_app_key_id(login: &honey::Login, app_public_id: &str, key_id: &str) -> Result<String> {
    let keys = honey::list_app_keys(login, app_public_id)?;
    ensure!(
        keys.iter().any(|key| key.key_id == key_id),
        "--old-key-id is not listed for this app"
    );
    parse_app_key_id(key_id)
}

fn resolve_roadmap_path() -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("AGENT_SECRETS_ROADMAP") {
        let path = std::path::PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
        return None;
    }
    if let Ok(mut dir) = std::env::current_dir() {
        loop {
            let candidate = dir.join(".agent-secrets-cli").join("roadmap.toon");
            if candidate.is_file() {
                return Some(candidate);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = std::path::PathBuf::from(home)
            .join(".agent-secrets-cli")
            .join("roadmap.toon");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn strip_toon_blank_and_comment_lines(raw: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw).map_err(|_| eyre!("roadmap is not valid UTF-8"))?;
    let mut compact = String::with_capacity(raw.len());
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        compact.push_str(line);
        compact.push('\n');
    }
    Ok(compact.into_bytes())
}

fn render_roadmap_selection(raw: &[u8], table_filter: &str) -> Result<Vec<u8>> {
    use endpoint_libs::libs::door::document::{Document, Format, decode_document, write_document};
    let compact = strip_toon_blank_and_comment_lines(raw)?;
    let doc = decode_document(&compact, Format::Toon).map_err(|_| eyre!("invalid roadmap TOON"))?;
    if table_filter.is_empty() {
        return Ok(raw.to_vec());
    }
    let selected: Vec<_> = doc
        .tables
        .into_iter()
        .filter(|table| &*table.name == table_filter)
        .collect();
    ensure!(!selected.is_empty(), "unknown roadmap table");
    let filtered = write_document(&Document { tables: selected }, Format::Toon)
        .map_err(|_| eyre!("failed to encode filtered roadmap"))?;
    Ok(filtered.into_bytes())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {
        output::status("agent-secrets-cli: internal error")
    }));
    let cli = Cli::parse();
    if let Some(filter) = &cli.roadmap {
        let Some(path) = resolve_roadmap_path() else {
            output::status(
                "error: roadmap not found (place `.agent-secrets-cli/roadmap.toon` in a workspace ancestor or `$HOME`, or set `AGENT_SECRETS_ROADMAP`)",
            );
            std::process::exit(1);
        };
        let Ok(content) = std::fs::read(&path) else {
            output::status("error: failed to read roadmap.toon");
            std::process::exit(1);
        };
        let Ok(rendered) = render_roadmap_selection(&content, filter) else {
            output::status("error: invalid roadmap or unknown table name");
            std::process::exit(1);
        };
        if output::roadmap(&rendered).is_err() {
            output::status("error: failed to write roadmap");
            std::process::exit(1);
        }
        return;
    }

    output::set_safe(cli.safe);
    let Some(action) = cli.action else {
        let _ = <Cli as clap::CommandFactory>::command().print_help();
        std::process::exit(2);
    };
    if run(action).is_err() {
        output::status("error: command failed");
        std::process::exit(1);
    }
}

fn run(action: Action) -> Result<()> {
    match action {
        Action::AssocSeal => assoc_key::seal(),
        Action::AssocPubkey => assoc_key::pubkey(),
        Action::AssocExec(args) => assoc_key::exec(args),
        Action::RecoverySeal => split_custody::seal(split_custody::CustodyPurpose::Recovery),
        Action::RecoveryPubkey => split_custody::pubkey(split_custody::CustodyPurpose::Recovery),
        Action::RecoveryExec(args) => {
            split_custody::exec(split_custody::CustodyPurpose::Recovery, args)
        }
        Action::MintSeal(args) => split_custody::mint_seal(args),
        Action::MintPubkey(args) => split_custody::mint_pubkey(args),
        Action::MintExec(args) => split_custody::mint_exec(args),
        Action::CreateReaderToken(args) => reader::create_reader_token(args),
        Action::CreateConfig(args) => reader::create_config(args),
        Action::CopySecret(args) => reader::copy_secret(args),
        Action::DeleteSecret(args) => reader::delete_secret(args),
        Action::EnsureHoneyDevQaFixtures => qa_fixtures::ensure(),
        Action::RotateHoneyDevQaPassword {
            dev_admin_only,
            restart_dev,
        } => {
            if !restart_dev {
                output::status("--restart-dev is required to revoke sessions on both Honey DEV apps");
                bail!("missing DEV restart acknowledgement");
            }
            std::panic::set_hook(Box::new(|info| output::panic_location(info.location())));
            qa_rotation::rotate(dev_admin_only)
        }
        Action::GetPath(args) => {
            // A refused read produces no output, including parser/backend errors.
            match safe_read::get_paths(args) {
                Ok(output) => output::line(output.trim_end()),
                Err(_) => std::process::exit(1),
            }
            .map_err(|_| eyre!("could not write selected values"))
        }
        Action::Exec(args) => safe_read::exec(args),
        Action::PackageSeal(args) => package_sign::package_seal(args),
        Action::FsVeritySeal(args) => package_sign::fsverity_seal(args),
        Action::PackageSign(args) => package_sign::package_sign(args),
        Action::FsVeritySign(args) => package_sign::fsverity_sign(args),
        Action::PackageVerify(args) => package_sign::package_verify(args),
        Action::PackageSignFixture(args) => package_sign::package_sign_fixture(args),
        Action::Rotate(args) => {
            for group in &args.groups {
                let key = Key::new().to_string();
                output::register_secret(key.as_bytes());
                write_group(&args.config, group, &key)?;
                output::line(&format!("rotated {} in {}", names(group), args.config))?;
            }
            restart(&args.restart)
        }
        Action::Sync(args) => {
            let mut reports = Vec::with_capacity(args.groups.len());
            for group in &args.groups {
                let (source, rest) = group.split_first().expect("clap requires a value");
                let key = get(source, &args.config)?;
                ensure!(
                    is_key(&key),
                    "{source} in {} is not a 32 character Base62 nanoid; rotate instead of syncing",
                    args.config
                );
                write_group(&args.config, rest, &key)?;
                reports.push(format!("synced {} in {}", names(group), args.config));
            }
            output::batch_lines(&reports)?;
            restart(&args.restart)
        }
        Action::Set(args) => {
            // All of stdin: a value may span lines (a whole config file).
            let mut value = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut value)?;
            let value = value.trim();
            ensure!(!value.is_empty(), "no value on stdin");
            let mut reports = Vec::with_capacity(args.groups.len());
            for group in &args.groups {
                write_group(&args.config, group, value)?;
                reports.push(format!("set {} in {}", names(group), args.config));
            }
            for report in reports {
                output::line(&report)?;
            }
            restart(&args.restart)
        }
        Action::ToFly(args) => {
            let targets: Vec<&Target> = args.secrets.iter().flatten().collect();
            let targets: Vec<Target> = targets.into_iter().cloned().collect();
            stage_to_fly(&args.config, &targets, std::slice::from_ref(&args.app))?;
            restart_after_to_fly(&args.app, &args.restart)
        }
        Action::PatchConfig(args) => patch_config(args),
        Action::CreateApp(args) => {
            let login_config = args.login_config.as_deref().unwrap_or(&args.config);
            let account = |suffix: &str| Target {
                project: args.login.project.clone(),
                name: format!("{}_{suffix}", args.login.name),
            };
            let login = honey::Login {
                username: get(&account("USERNAME"), login_config)?,
                password: get(&account("PASSWORD"), login_config)?,
                auth: args.auth,
                api: args.api,
                honey_app: args.honey_app,
            };
            let app = honey::NewApp {
                name: args.name.clone(),
                description: args.description,
                callback_url: args.callback_url,
            };
            let created = output::with_public_output(|| honey::create_app(&login, &app))?;
            let app_id: Vec<Target> = args.app_id.into_iter().flatten().collect();
            output::register_secret(created.callback_api_key.as_bytes());
            output::register_secret(created.app_api_key.as_bytes());
            if !app_id.is_empty() {
                write_public_group(&args.config, &app_id, &created.app_public_id)?;
            }
            let api_key: Vec<Target> = args.api_key.into_iter().flatten().collect();
            write_group(&args.config, &api_key, &created.callback_api_key)?;
            let app_key: Vec<Target> = args.app_key.into_iter().flatten().collect();
            if !app_key.is_empty() {
                write_group(&args.config, &app_key, &created.app_api_key)?;
            }
            output::line(&format!(
                "created {} as {}",
                args.name, created.app_public_id
            ))?;
            if !app_id.is_empty() {
                output::line(&format!("set {} in {}", names(&app_id), args.config))?;
            }
            output::line(&format!("set {} in {}", names(&api_key), args.config))?;
            if !app_key.is_empty() {
                output::line(&format!("set {} in {}", names(&app_key), args.config))?;
            }
            Ok(())
        }
        Action::CreateAppKey(args) => {
            let login = honey_app_login(&args.login, Some(&args.config))?;
            let created = output::with_public_output(|| {
                honey::create_app_key(
                    &login,
                    &args.login.app_id,
                    &args.label,
                    args.expires_in_secs,
                )
            })?;
            let key_id = created_app_key_id(&created)?;
            let targets: Vec<Target> = args.key_targets.into_iter().flatten().collect();
            output::register_secret(created.key.as_bytes());
            write_group(&args.config, &targets, &created.key)?;
            output::line(&format!(
                "created app key {} for {} and set {} in {}",
                key_id,
                args.login.app_id,
                names(&targets),
                args.config
            ))?;
            Ok(())
        }
        Action::RotateAppKey(args) => {
            let login = honey_app_login(&args.login, Some(&args.config))?;
            if args.finish {
                let key_id = args
                    .old_key_id
                    .as_deref()
                    .ok_or_else(|| eyre!("--finish requires --old-key-id"))?;
                let key_id = parse_app_key_id(key_id)?;
                honey::revoke_app_key(&login, &args.login.app_id, &key_id, args.grace)?;
                if args.grace == 0 {
                    output::line(&format!(
                        "revoked old app key {key_id} on {}",
                        args.login.app_id
                    ))?;
                } else {
                    output::line(&format!(
                        "scheduled old app key {key_id} on {} to expire in {}s",
                        args.login.app_id, args.grace
                    ))?;
                }
                return Ok(());
            }

            // The new key reaches Doppler and Fly before any report; refuse first.
            output::require_public_output()?;
            let targets: Vec<Target> = args.key_targets.into_iter().flatten().collect();
            let old_key_id = match args.old_key_id.as_deref() {
                Some(key_id) => listed_app_key_id(&login, &args.login.app_id, key_id)?,
                None => current_app_key_id(&login, &args.login.app_id, &args.config, &targets)?,
            };
            let label = args.label.as_deref().expect("clap requires a label");
            let created =
                honey::create_app_key(&login, &args.login.app_id, label, args.expires_in_secs)?;
            let new_key_id = created_app_key_id(&created)?;
            write_group(&args.config, &targets, &created.key)?;
            stage_to_fly(&args.config, &targets, &args.fly_apps)?;
            output::line(&format!(
                "staged new app key {} for {}",
                new_key_id, args.login.app_id
            ))?;
            output::line(&format!(
                "next step: after the owner restarts or deploys {}, rerun this command with --finish --old-key-id {} --grace {}",
                args.fly_apps.join(","),
                old_key_id,
                args.grace
            ))?;
            Ok(())
        }
        Action::SetAppService(args) => {
            let login = honey_app_login(&args.login, None)?;
            honey::set_app_service(&login, &args.login.app_id, args.service)?;
            output::line(&format!(
                "set service capability to {} on {}",
                args.service, args.login.app_id
            ))?;
            Ok(())
        }
        Action::CreateAccount(args) => {
            // The minted password reaches Doppler before signup; refuse first.
            output::require_public_output()?;
            let username = Target {
                project: args.login.project.clone(),
                name: format!("{}_USERNAME", args.login.name),
            };
            let password = Target {
                project: args.login.project.clone(),
                name: format!("{}_PASSWORD", args.login.name),
            };
            // Credentials go to Doppler before the account exists, so a failed
            // signup never strands an account whose password nobody holds.
            let (minted, password_notice) = match try_get(&password, &args.config)? {
                Some(existing) if !existing.is_empty() => {
                    (existing, format!("reusing {password} in {}", args.config))
                }
                _ => {
                    let value = Key::new().to_string();
                    write_group(&args.config, std::slice::from_ref(&password), &value)?;
                    (value, format!("minted {password} in {}", args.config))
                }
            };
            output::register_secret(minted.as_bytes());
            write_public_group(
                &args.config,
                std::slice::from_ref(&username),
                &args.username,
            )?;
            let public_id = honey::create_account(&honey::Login {
                auth: args.auth,
                api: args.api,
                honey_app: args.honey_app,
                username: args.username.clone(),
                password: minted,
            })?;
            output::line(&password_notice)?;
            output::line(&format!("set {username} in {}", args.config))?;
            match public_id {
                Some(id) => output::line(&format!("signed up {} as {id}", args.username))?,
                None => output::line(&format!("signed up {}", args.username))?,
            }
            Ok(())
        }
        Action::HoneyUsers(args) => {
            ensure!(args.page > 0, "--page must be at least 1");
            ensure!(args.page_size > 0, "--page-size must be at least 1");
            let login = honey_users_login(&args)?;
            let users = honey::list_users(
                &login,
                &args.app,
                args.page,
                args.page_size,
                args.username.as_deref(),
            )?;
            if args.username.is_some() && users.is_empty() {
                std::process::exit(1);
            }
            for user in users {
                let fields = honey_user_fields(&user);
                output::tsv_line(&[&fields[0], &fields[1], &fields[2]])?;
            }
            Ok(())
        }
        Action::CreateBucket(args) => {
            let created = output::with_public_output(|| fly_storage_create(&args.name, &args.org))?;
            let mut notices = vec![format!("created bucket {}", args.name)];
            for (targets, key) in [
                (args.bucket_name, "BUCKET_NAME"),
                (args.access_key, "AWS_ACCESS_KEY_ID"),
                (args.secret_key, "AWS_SECRET_ACCESS_KEY"),
            ] {
                let targets: Vec<Target> = targets.into_iter().flatten().collect();
                let value = created
                    .get(key)
                    .ok_or_else(|| eyre!("fly storage create printed no {key}"))?;
                if key == "BUCKET_NAME" {
                    write_public_group(&args.config, &targets, value)?;
                } else {
                    output::register_secret(value.as_bytes());
                    write_group(&args.config, &targets, value)?;
                }
                notices.push(format!("set {} in {}", names(&targets), args.config));
            }
            for notice in notices {
                output::line(&notice)?;
            }
            Ok(())
        }
        Action::VipApps(login) => {
            for app in vip::list_apps(&vip_login(&login)?)? {
                output::line(&format!("{}  {}  {}", app.app_id, app.bucket, app.name))?;
            }
            Ok(())
        }
        Action::CreateVipApp(args) => {
            let app = output::with_public_output(|| {
                vip::create_app(&vip_login(&args.login)?, &args.name, &args.member)
            })?;
            output::line(&format!(
                "created {} as {} on bucket {}",
                app.name, app.app_id, app.bucket
            ))?;
            for member in &args.member {
                output::line(&format!("added member {member}"))?;
            }
            Ok(())
        }
        Action::CreateVipToken(args) => {
            let minted = output::with_public_output(|| {
                vip::create_token(
                    &vip_login(&args.login)?,
                    &args.app_id,
                    &args.name,
                    &args.scope,
                )
            })?;
            output::register_secret(minted.token.as_bytes());
            let targets: Vec<Target> = args.token.into_iter().flatten().collect();
            write_group(&args.config, &targets, &minted.token)?;
            output::line(&format!(
                "minted {} token {} ({})",
                args.scope, args.name, minted.token_id
            ))?;
            output::line(&format!("set {} in {}", names(&targets), args.config))?;
            Ok(())
        }
        Action::PaysApps(args) => {
            for app in pays::list_apps(&pays_login(&args)?)? {
                output::line(&format!("{}  {}", app.app_public_id, app.name))?;
            }
            Ok(())
        }
        Action::OnboardQaPaysApp(args) => {
            let login = qa_pays_login().map_err(|_| eyre!("QA merchant login unavailable"))?;
            let ensured = pays::ensure_named_app(&login, &args.name, &args.description)
                .map_err(|_| eyre!("QA merchant app onboarding failed"))?;
            let status = if ensured.created {
                "created and cold-readback verified"
            } else {
                "already present and cold-readback verified"
            };
            output::line(&format!(
                "{status}: {} ({})",
                ensured.app.name, ensured.app.app_public_id
            ))?;
            Ok(())
        }
        Action::CreatePaysApp(args) => {
            let created = output::with_public_output(|| {
                pays::create_app(&pays_login(&args.login)?, &args.name, &args.description)
            })?;
            output::register_secret(created.key.as_bytes());
            let app_id: Vec<Target> = args.app_id.into_iter().flatten().collect();
            let key: Vec<Target> = args.key.into_iter().flatten().collect();
            write_public_group(&args.config, &app_id, &created.app.app_public_id)?;
            write_group(&args.config, &key, &created.key)?;
            output::line(&format!(
                "created pays app {} ({})",
                created.app.name, created.app.app_public_id
            ))?;
            output::line(&format!("set {} in {}", names(&app_id), args.config))?;
            output::line(&format!("set {} in {}", names(&key), args.config))?;
            Ok(())
        }
        Action::ToGithub(args) => {
            let targets: Vec<Target> = args.secrets.into_iter().flatten().collect();
            ensure!(
                args.rename.is_none() || targets.len() == 1,
                "--as renames a single --secret"
            );
            let mut reports = Vec::with_capacity(targets.len() * args.repo.len());
            for target in &targets {
                let value = get(target, &args.config)?;
                ensure!(!value.is_empty(), "{target} in {} is empty", args.config);
                let name = args.rename.as_deref().unwrap_or(&target.name);
                for repo in &args.repo {
                    gh_secret_set(repo, name, &value)?;
                    reports.push(format!(
                        "set {name} on {repo} from {target} ({})",
                        args.config
                    ));
                }
            }
            for report in reports {
                output::line(&report)?;
            }
            Ok(())
        }
        Action::CreateTigrisKey(args) => {
            ensure!(
                args.admin || args.bucket.is_some(),
                "give --admin, or --bucket with --role; a key with no role reaches nothing"
            );
            let created = output::with_public_output(|| tigris_key_create(&args))?;
            output::register_secret(created.secret.as_bytes());
            let access_key: Vec<Target> = args.access_key.into_iter().flatten().collect();
            let secret_key: Vec<Target> = args.secret_key.into_iter().flatten().collect();
            write_public_group(&args.config, &access_key, &created.id)?;
            write_group(&args.config, &secret_key, &created.secret)?;
            output::line(&format!(
                "created Tigris key {} ({})",
                args.name, created.id
            ))?;
            output::line(&format!("set {} in {}", names(&access_key), args.config))?;
            output::line(&format!("set {} in {}", names(&secret_key), args.config))?;
            Ok(())
        }
        Action::Check(args) => {
            let mut bad = 0;
            for group in &args.groups {
                let values = group
                    .iter()
                    .map(|target| get(target, &args.config))
                    .collect::<Result<Vec<_>>>()?;
                let verdict = if values.iter().any(|v| !is_key(v)) {
                    "NOT A KEY"
                } else if values.windows(2).any(|w| w[0] != w[1]) {
                    "DIFFER"
                } else {
                    "ok"
                };
                if verdict != "ok" {
                    bad += 1;
                }
                output::line(&format!("{verdict:9} {} in {}", names(group), args.config))?;
            }
            ensure!(bad == 0, "{bad} group(s) need attention");
            Ok(())
        }
    }
}

fn is_key(value: &str) -> bool {
    value.len() == 32 && Key::try_from_str(value).is_ok()
}

fn names(group: &[Target]) -> String {
    group
        .iter()
        .map(Target::to_string)
        .collect::<Vec<_>>()
        .join(" = ")
}

fn patch_config(args: PatchConfigArgs) -> Result<()> {
    let format = match args.format.as_str() {
        "json" => config_patch::Format::Json,
        "toml" => config_patch::Format::Toml,
        _ => bail!("format must be json or toml"),
    };

    let mut imported = Vec::new();
    for raw in &args.from_secrets {
        let (path, source) = raw
            .split_once('=')
            .ok_or_else(|| eyre!("--from-secret must be PATH=project/NAME"))?;
        let source = parse_target(source).map_err(|_| eyre!("--from-secret needs project/NAME"))?;
        imported.push((path.to_owned(), get(&source, &args.config)?));
    }

    let original = get_raw(&args.secret, &args.config)?;
    let patch = config_patch::build_patch(
        format,
        &original,
        &args.sets,
        &args.unsets,
        &imported,
        args.create_parents,
    )?;

    if !args.apply {
        for raw in &args.sets {
            let (path, _) = raw
                .split_once('=')
                .ok_or_else(|| eyre!("invalid set request"))?;
            output::line(&format!("set {path}"))?;
        }
        for path in &args.unsets {
            output::line(&format!("unset {path}"))?;
        }
        for (path, _) in &imported {
            output::line(&format!("set {path}"))?;
        }
        return Ok(());
    }

    let mut readback = original.clone();
    if !patch.changes.is_empty() {
        let value = patch.content.trim_end().to_owned();
        write_group(&args.config, std::slice::from_ref(&args.secret), &value)?;
        readback = get_raw(&args.secret, &args.config)?;
    }
    ensure!(
        config_patch::same_outside_paths(
            format,
            &original,
            &readback,
            config_patch::requested_paths(&patch),
        )?,
        "{} in {} changed outside requested paths",
        args.secret,
        args.config
    );

    if let Some(app) = &args.to_fly {
        stage_to_fly(
            &args.config,
            std::slice::from_ref(&args.secret),
            std::slice::from_ref(app),
        )?;
        if args.restart {
            restart_after_to_fly(app, std::slice::from_ref(app))?;
        }
    }
    print_config_changes(&patch.changes)?;
    Ok(())
}

fn print_config_changes(changes: &[config_patch::Change]) -> Result<()> {
    for change in changes {
        output::line(&format!("{} {}", change.kind, change.path))?;
    }
    Ok(())
}

/// Apply the staged secrets on the target app; keep the normal restart for
/// any other apps named by `to-fly --restart`.
fn restart_after_to_fly(staged_app: &str, apps: &[String]) -> Result<()> {
    for app in apps {
        if app == staged_app {
            deploy_staged_secrets(app)?;
            start_stopped_machines(app)?;
            output::line(&format!("deployed staged secrets on {app}"))?;
        } else {
            restart(std::slice::from_ref(app))?;
        }
    }
    Ok(())
}

fn deploy_staged_secrets(app: &str) -> Result<()> {
    let status = Command::new("fly")
        .args(["secrets", "deploy", "-a", app])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| eyre!("could not run fly: {e}"))?;
    ensure!(status.success(), "fly secrets deploy on {app} failed");
    Ok(())
}

fn start_stopped_machines(app: &str) -> Result<()> {
    let output = Command::new("fly")
        .args(["machines", "list", "--app", app, "--json"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| eyre!("could not run fly: {e}"))?;
    ensure!(
        output.status.success(),
        "could not list Fly machines on {app}"
    );
    let machines: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| eyre!("Fly returned an invalid machine list for {app}"))?;
    let machines = machines
        .as_array()
        .or_else(|| {
            machines
                .get("machines")
                .and_then(serde_json::Value::as_array)
        })
        .ok_or_else(|| eyre!("Fly returned no machine list for {app}"))?;

    for machine in machines {
        if machine
            .get("state")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|state| state.eq_ignore_ascii_case("stopped"))
        {
            let id = machine
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| eyre!("Fly returned a stopped machine without an id on {app}"))?;
            let status = Command::new("fly")
                .args(["machines", "start", id, "--app", app])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| eyre!("could not run fly: {e}"))?;
            ensure!(
                status.success(),
                "could not start stopped machine {id} on {app}"
            );
            output::line(&format!("started stopped machine {id} on {app}"))?;
        }
    }
    Ok(())
}

/// Read targets back from Doppler and stage them on each Fly app through stdin.
fn stage_to_fly(config: &str, targets: &[Target], apps: &[String]) -> Result<()> {
    ensure!(!targets.is_empty(), "give at least one secret target");
    ensure!(!apps.is_empty(), "give at least one Fly app");
    let mut pairs = String::new();
    for target in targets {
        let value = get(target, config)?;
        ensure!(!value.is_empty(), "{target} in {config} is empty");
        if value.contains('\n') {
            // fly secrets import takes a multi-line value between triple quotes.
            ensure!(
                !value.contains("\"\"\""),
                "{target} in {config} spans lines and holds \"\"\", which fly secrets import cannot take"
            );
            pairs.push_str(&format!("{}=\"\"\"{value}\"\"\"\n", target.name));
        } else {
            pairs.push_str(&format!("{}={value}\n", target.name));
        }
    }
    stage_to_fly_apps(apps, |app| fly_import(app, &pairs), |app| {
        for target in targets {
            output::line(&format!("staged {target} ({config}) on {app}"))?;
        }
        Ok(())
    })
}

fn stage_to_fly_apps(
    apps: &[String],
    mut import: impl FnMut(&str) -> Result<()>,
    mut report: impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    // Complete imports before reporting, so a closed output pipe cannot
    // prevent staging an otherwise valid remaining app.
    let mut staged = 0;
    let imports: Result<()> = apps.iter().try_for_each(|app| {
        import(app)?;
        staged += 1;
        Ok(())
    });
    let reports: Result<()> = apps[..staged].iter().try_for_each(|app| report(app));
    imports.and(reports)
}

#[cfg(test)]
mod stage_to_fly_tests {
    use super::*;

    #[test]
    fn report_failure_does_not_interrupt_imports() {
        let apps = ["first", "second", "third"].map(str::to_owned);
        let mut imported = Vec::new();
        let result = stage_to_fly_apps(&apps, |app| {
            imported.push(app.to_owned());
            Ok(())
        }, |_| Err(eyre!("synthetic output failure")));
        assert!(result.is_err());
        assert_eq!(imported, ["first", "second", "third"]);
    }

    #[test]
    fn import_failure_stops_later_apps_and_precedes_report_error() {
        let apps = ["first", "second", "third"].map(str::to_owned);
        let mut attempted = Vec::new();
        let mut reported = Vec::new();
        let result = stage_to_fly_apps(&apps, |app| {
            attempted.push(app.to_owned());
            ensure!(app != "second", "synthetic import failure");
            Ok(())
        }, |app| {
            reported.push(app.to_owned());
            Err(eyre!("synthetic output failure"))
        });
        assert_eq!(attempted, ["first", "second"]);
        assert_eq!(reported, ["first"]);
        assert_eq!(result.unwrap_err().to_string(), "synthetic import failure");
    }
}

/// Write `key` under every target and read each back.
fn write_group(config: &str, group: &[Target], key: &str) -> Result<()> {
    for target in group {
        set(target, config, key)?;
    }
    for target in group {
        ensure!(
            get_raw(target, config)? == key,
            "{target} in {config} did not take the new value; run sync"
        );
    }
    Ok(())
}

/// Persist public identifiers without adding them to the output secret filter.
fn write_public_group(config: &str, group: &[Target], value: &str) -> Result<()> {
    for target in group {
        set_unregistered(target, config, value)?;
    }
    for target in group {
        ensure!(
            get_raw_unregistered(target, config)? == value,
            "{target} in {config} did not take the new value; run sync"
        );
    }
    Ok(())
}

/// Run `fly storage create` for a bucket attached to no app, and return the
/// `NAME: value` pairs it prints. Its output carries the keys, so it is captured
/// and never echoed; on failure only the exit status is reported.
fn fly_storage_create(name: &str, org: &str) -> Result<std::collections::HashMap<String, String>> {
    let output = Command::new("fly")
        .args(["storage", "create", "--name", name, "--org", org, "--yes"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| eyre!("could not run fly: {e}"))?;
    ensure!(
        output.status.success(),
        "fly storage create {name} failed ({})",
        output.status
    );
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            let key = key.trim();
            (key.starts_with("AWS_") || key == "BUCKET_NAME")
                .then(|| (key.to_owned(), value.trim().to_owned()))
        })
        .collect())
}

/// Stage `NAME=VALUE` lines as secrets on a Fly app, through stdin.
/// The honey.id login for crates.vip, its credentials read from Doppler.
fn vip_login(login: &VipLogin) -> Result<honey::Login> {
    let account = |suffix: &str| Target {
        project: login.login.project.clone(),
        name: format!("{}_{suffix}", login.login.name),
    };
    Ok(honey::Login {
        username: get(&account("USERNAME"), &login.login_config)?,
        password: get(&account("PASSWORD"), &login.login_config)?,
        auth: login.auth.clone(),
        api: login.api.clone(),
        honey_app: login.honey_app.clone(),
    })
}

fn pays_login(login: &PaysLogin) -> Result<honey::Login> {
    let account = |suffix: &str| Target {
        project: login.login.project.clone(),
        name: format!("{}_{suffix}", login.login.name),
    };
    Ok(honey::Login {
        username: get(&account("USERNAME"), &login.login_config)?,
        password: get(&account("PASSWORD"), &login.login_config)?,
        auth: login.auth.clone(),
        api: login.api.clone(),
        honey_app: login.honey_app.clone(),
    })
}

fn qa_pays_login() -> Result<honey::Login> {
    let account = |suffix: &str| Target {
        project: "agent-accounts".to_owned(),
        name: format!("HONEY_QA_MERCHANT_{suffix}"),
    };
    Ok(honey::Login {
        username: get(&account("USERNAME"), "prd")?,
        password: get(&account("PASSWORD"), "prd")?,
        auth: "wss://auth.honey.id/".to_owned(),
        api: "wss://merchant.pays.online/".to_owned(),
        honey_app: "P72RG3UW9RhnChah".to_owned(),
    })
}

fn honey_users_login(args: &HoneyUsersArgs) -> Result<honey::Login> {
    let account = |suffix: &str| Target {
        project: args.login.project.clone(),
        name: format!("{}_{suffix}", args.login.name),
    };
    Ok(honey::Login {
        username: get(&account("USERNAME"), &args.login_config)?,
        password: get(&account("PASSWORD"), &args.login_config)?,
        auth: "wss://auth.honey.id/".to_string(),
        api: "wss://api.honey.id/".to_string(),
        honey_app: "4x3JVuCnNIfD4szt".to_string(),
    })
}

fn honey_user_fields(user: &honey::User) -> [String; 3] {
    let field = |value: &str| {
        value
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect::<String>()
    };
    [
        field(&user.user_public_id),
        field(&user.username),
        user.roles
            .iter()
            .map(|role| field(role))
            .collect::<Vec<_>>()
            .join(","),
    ]
}

/// `gh secret set NAME -R REPO`, the value on stdin. GitHub never gives a
/// secret back, so the check is that the name is then listed.
fn gh_secret_set(repo: &str, name: &str, value: &str) -> Result<()> {
    let mut child = Command::new("gh")
        .args(["secret", "set", name, "--repo", repo])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| eyre!("could not run gh: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    ensure!(
        status.success(),
        "gh secret set {name} on {repo} failed ({status})"
    );
    let listed = Command::new("gh")
        .args([
            "secret",
            "list",
            "--repo",
            repo,
            "--json",
            "name",
            "--template",
            r#"{{range .}}{{.name}}{{"\n"}}{{end}}"#,
        ])
        .output()
        .map_err(|e| eyre!("could not run gh: {e}"))?;
    ensure!(
        listed.status.success(),
        "gh secret list on {repo} failed ({})",
        listed.status
    );
    ensure!(
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|l| l == name),
        "{name} is not listed on {repo} after setting it"
    );
    Ok(())
}

struct TigrisKey {
    id: String,
    secret: String,
}

/// Run `tigris access-keys create --json` and return the key it made. Its
/// output carries the secret, so it is captured and never echoed; on failure
/// only the exit status is reported. The key id is not a secret.
fn tigris_key_create(args: &CreateTigrisKeyArgs) -> Result<TigrisKey> {
    let mut command = Command::new("tigris");
    command.args(["access-keys", "create", &args.name, "--json"]);
    if args.admin {
        command.arg("--admin");
    }
    if let (Some(bucket), Some(role)) = (&args.bucket, &args.role) {
        command.args(["--bucket", bucket, "--role", role]);
    }
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| eyre!("could not run tigris: {e}"))?;
    ensure!(
        output.status.success(),
        "tigris access-keys create {} failed ({}); is `tigris login` done?",
        args.name,
        output.status
    );
    let stdout = String::from_utf8(output.stdout)?;
    let json: serde_json::Value = stdout
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line.trim()).ok())
        .ok_or_else(|| eyre!("tigris access-keys create printed no JSON"))?;
    let field = |name: &str| {
        json.get(name)
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| eyre!("tigris access-keys create returned no {name}"))
    };
    Ok(TigrisKey {
        id: field("id")?,
        secret: field("secret")?,
    })
}

fn fly_import(app: &str, pairs: &str) -> Result<()> {
    let mut child = Command::new("fly")
        .args(["secrets", "import", "--stage", "-a", app])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| eyre!("could not run fly: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| eyre!("fly stdin unavailable"))?
        .write_all(pairs.as_bytes())?;
    let status = child.wait()?;
    ensure!(status.success(), "fly secrets import on {app} failed");
    Ok(())
}

fn restart(apps: &[String]) -> Result<()> {
    for app in apps {
        let status = Command::new("fly")
            .args(["apps", "restart", app])
            .status()
            .map_err(|e| eyre!("could not run fly: {e}"))?;
        ensure!(status.success(), "fly apps restart {app} failed");
        output::line(&format!("restarted {app}"))?;
    }
    Ok(())
}

/// Retry the same idempotent secret write when Doppler reports a transport error.
/// Attempts are bounded and immediate so the synchronous CLI does not block a thread.
fn set(target: &Target, config: &str, value: &str) -> Result<()> {
    output::register_secret(value.as_bytes());
    set_unregistered(target, config, value)
}

fn set_unregistered(target: &Target, config: &str, value: &str) -> Result<()> {
    let mut last = None;
    for _ in 0..3 {
        match set_once(target, config, value) {
            Ok(()) => return Ok(()),
            Err(err) => last = Some(err),
        }
    }
    Err(last.expect("at least one attempt"))
}

/// Pin authentication to the home scope instead of inheriting cwd's setup.
fn doppler_command() -> Result<Command> {
    let home =
        std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is required for Doppler scope"))?;
    ensure!(
        std::path::Path::new(&home).is_absolute(),
        "HOME must be absolute for Doppler scope"
    );
    let mut command = Command::new("doppler");
    command.arg("--scope").arg(home);
    Ok(command)
}

fn set_once(target: &Target, config: &str, value: &str) -> Result<()> {
    let mut child = doppler_command()?
        .args([
            "secrets",
            "set",
            &target.name,
            "--silent",
            "--no-interactive",
        ])
        .args(["-p", &target.project, "-c", config])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| eyre!("could not run doppler: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| eyre!("doppler stdin unavailable"))?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    ensure!(status.success(), "doppler set {target} in {config} failed");
    Ok(())
}

/// Like [`get`], but `None` when the secret does not exist yet. Only Doppler's
/// own "not found" counts as absent: any other failure is an error, so a
/// network blip can never pass for a missing password and get it overwritten.
fn try_get(target: &Target, config: &str) -> Result<Option<String>> {
    let output = doppler_command()?
        .args(["secrets", "get", &target.name, "--plain"])
        .args(["-p", &target.project, "-c", config])
        .output()
        .map_err(|e| eyre!("could not run doppler: {e}"))?;
    if output.status.success() {
        let value = String::from_utf8(output.stdout)?.trim().to_string();
        output::register_secret(value.as_bytes());
        return Ok(Some(value));
    }
    if String::from_utf8_lossy(&output.stderr).contains("Could not find requested secret") {
        return Ok(None);
    }
    bail!("doppler get {target} in {config} failed")
}

/// As stored, with `${REF}` references unexpanded: what `set` wrote.
fn get_raw(target: &Target, config: &str) -> Result<String> {
    get_raw_inner(target, config, true)
}

fn get_raw_unregistered(target: &Target, config: &str) -> Result<String> {
    get_raw_inner(target, config, false)
}

fn get_raw_inner(target: &Target, config: &str, register: bool) -> Result<String> {
    let output = doppler_command()?
        .args(["secrets", "get", &target.name, "--plain", "--raw"])
        .args(["-p", &target.project, "-c", config])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| eyre!("could not run doppler: {e}"))?;
    if !output.status.success() {
        bail!("doppler get {target} in {config} failed");
    }
    let value = String::from_utf8(output.stdout)?.trim().to_string();
    if register {
        output::register_secret(value.as_bytes());
    }
    Ok(value)
}

fn get(target: &Target, config: &str) -> Result<String> {
    let output = doppler_command()?
        .args(["secrets", "get", &target.name, "--plain"])
        .args(["-p", &target.project, "-c", config])
        .stderr(Stdio::null())
        .output()
        .map_err(|e| eyre!("could not run doppler: {e}"))?;
    if !output.status.success() {
        bail!("doppler get {target} in {config} failed");
    }
    let value = String::from_utf8(output.stdout)?.trim().to_string();
    output::register_secret(value.as_bytes());
    Ok(value)
}

#[cfg(test)]
mod honey_users_tests {
    use super::*;

    #[test]
    fn honey_users_arguments_parse_with_defaults_and_filters() {
        let cli = Cli::try_parse_from([
            "agent-secrets-cli",
            "honey-users",
            "--app",
            "app-public-id",
            "--login",
            "team-accounts/OPS",
            "--login-config",
            "dev",
            "--username",
            "alice",
            "--page",
            "2",
            "--page-size",
            "25",
        ])
        .unwrap();
        let Some(Action::HoneyUsers(args)) = cli.action else {
            panic!("expected honey-users action");
        };
        assert_eq!(args.app, "app-public-id");
        assert_eq!(args.login.project, "team-accounts");
        assert_eq!(args.login.name, "OPS");
        assert_eq!(args.login_config, "dev");
        assert_eq!(args.username.as_deref(), Some("alice"));
        assert_eq!(args.page, 2);
        assert_eq!(args.page_size, 25);

        let cli =
            Cli::try_parse_from(["agent-secrets-cli", "honey-users", "--app", "app-public-id"])
                .unwrap();
        let Some(Action::HoneyUsers(args)) = cli.action else {
            panic!("expected honey-users action");
        };
        assert_eq!(args.login.project, "agent-accounts");
        assert_eq!(args.login.name, "HONEY_ID_PROD");
        assert_eq!(args.login_config, "prd");
        assert_eq!(args.page, 1);
        assert_eq!(args.page_size, 100);
        assert!(args.username.is_none());
    }

    #[test]
    fn honey_user_output_has_only_public_fields_and_roles() {
        let user = honey::User {
            user_public_id: "public-123".to_string(),
            username: "alice".to_string(),
            roles: vec!["AppAdmin".to_string(), "User".to_string()],
        };
        assert_eq!(
            honey_user_fields(&user),
            ["public-123", "alice", "AppAdmin,User"]
        );
    }

    #[test]
    fn roadmap_flag_parses_without_subcommand_and_toon_files_decode() {
        let cli = Cli::try_parse_from(["agent-secrets-cli", "--roadmap"]).unwrap();
        assert_eq!(cli.roadmap.as_deref(), Some(""));
        assert!(cli.action.is_none());

        let filtered =
            Cli::try_parse_from(["agent-secrets-cli", "--roadmap=agent_rules"]).unwrap();
        assert_eq!(filtered.roadmap.as_deref(), Some("agent_rules"));

        use endpoint_libs::libs::door::document::{Format, decode_document};
        let example_raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/roadmap.example.toon"
        ))
        .expect("examples/roadmap.example.toon must exist");
        let example_compact = strip_toon_blank_and_comment_lines(&example_raw)
            .expect("examples/roadmap.example.toon must be UTF-8");
        let example_doc = decode_document(&example_compact, Format::Toon)
            .expect("examples/roadmap.example.toon must be valid TOON");
        assert!(
            example_doc.tables.len() >= 5,
            "example roadmap must contain structured tables"
        );
        let sliced = render_roadmap_selection(&example_raw, "agent_rules")
            .expect("filtering agent_rules must succeed");
        let sliced_doc = decode_document(&sliced, Format::Toon).unwrap();
        assert_eq!(sliced_doc.tables.len(), 1);
        assert_eq!(&*sliced_doc.tables[0].name, "agent_rules");

        if let Some(local_path) = resolve_roadmap_path()
            && let Ok(raw) = std::fs::read(local_path)
        {
            let local_compact = strip_toon_blank_and_comment_lines(&raw).unwrap();
            let doc = decode_document(&local_compact, Format::Toon)
                .expect("roadmap.toon must be valid TOON");
            assert!(
                doc.tables.iter().any(|t| &*t.name == "private_keys_and_custody"),
                "local roadmap must contain private_keys_and_custody table"
            );
            assert!(
                doc.tables.iter().any(|t| &*t.name == "fly_and_host_deployments"),
                "local roadmap must contain fly_and_host_deployments table"
            );
            assert!(
                doc.tables.iter().any(|t| &*t.name == "doppler_secrets_register"),
                "local roadmap must contain doppler_secrets_register table"
            );
        }
    }
}
