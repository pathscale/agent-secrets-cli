//! Owner-scoped provisioning. Provider output is always captured or discarded.
use std::process::Stdio;

use clap::Args;
use crate::eyre::{Result, ensure, eyre};

use crate::{Target, doppler_command, get, output, parse_target, try_get, write_group};

#[derive(Args)]
pub struct CreateReaderTokenArgs {
    #[arg(long)]
    project: String,
    /// The single config the reader can access.
    #[arg(long)]
    config: String,
    /// Public provider label, used to reconcile partial issuance failures.
    #[arg(long)]
    name: String,
    /// One project/NAME destination. Existing bindings are refused.
    #[arg(long, value_parser = parse_target)]
    token: Target,
    #[arg(long)]
    token_config: String,
}

#[derive(Args)]
pub struct CreateConfigArgs {
    #[arg(long)]
    project: String,
    /// A new environment slug and root config name, not a branch of prd.
    #[arg(long)]
    config: String,
}

#[derive(Args)]
pub struct CopySecretArgs {
    #[arg(long, value_parser = parse_target)]
    secret: Target,
    #[arg(long)]
    config: String,
    #[arg(long, value_parser = parse_target)]
    to: Target,
    #[arg(long)]
    to_config: String,
    /// Delete the source only after the destination has verified readback.
    #[arg(long)]
    remove_source: bool,
}

#[derive(Args)]
pub struct DeleteSecretArgs {
    #[arg(long)]
    config: String,
    #[arg(long, value_parser = parse_target)]
    secret: Target,
    #[arg(long = "i-know-this-is-custody")]
    i_know_this_is_custody: bool,
}

fn owner() -> Result<()> {
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "unset DOPPLER_TOKEN and use the owner HOME-scoped login"
    );
    Ok(())
}

pub fn create_reader_token(args: CreateReaderTokenArgs) -> Result<()> {
    owner()?;
    let existing_token = try_get(&args.token, &args.token_config)?;
    if let Some(value) = &existing_token {
        output::register_secret(value.as_bytes());
    }
    ensure!(
        existing_token.is_none(),
        "destination exists; reconcile prior issuance before retry"
    );
    // Never retry issuance: a lost response can leave a live provider token.
    let output = doppler_command()?
        .args([
            "--no-read-env",
            "--attempts",
            "1",
            "configs",
            "tokens",
            "create",
            &args.name,
            "--project",
            &args.project,
            "--config",
            &args.config,
            "--access",
            "read",
            "--plain",
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "reader issuance failed; reconcile named provider token before retry"
    );
    // Do not include invalid bytes in a UTF-8 conversion error.
    let token = std::str::from_utf8(&output.stdout)
        .map_err(|_| eyre!("invalid reader response; reconcile named provider token"))?
        .trim();
    ensure!(
        token.starts_with("dp.st.") && !token.chars().any(char::is_whitespace),
        "invalid reader response; reconcile named provider token"
    );
    output::register_secret(token.as_bytes());
    write_group(&args.token_config, &[args.token], token).map_err(|_| {
        eyre!("reader storage/readback failed; reconcile named provider token before retry")
    })
}

pub fn create_config(args: CreateConfigArgs) -> Result<()> {
    owner()?;
    ensure!(
        !args.config.is_empty()
            && args
                .config
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "use a lowercase alphanumeric environment slug"
    );
    // Environments create their own root config. A prd branch would inherit
    // all prd secrets and defeat the reader isolation boundary.
    let status = doppler_command()?
        .args([
            "--no-read-env",
            "--attempts",
            "1",
            "environments",
            "create",
            &args.config,
            &args.config,
            "--project",
            &args.project,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(
        status.success(),
        "config creation failed; reconcile environment before retry"
    );
    let status = doppler_command()?
        .args([
            "--no-read-env",
            "configs",
            "get",
            &args.config,
            "--project",
            &args.project,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(
        status.success(),
        "created environment root config is unavailable"
    );
    Ok(())
}

pub fn copy_secret(args: CopySecretArgs) -> Result<()> {
    owner()?;
    ensure!(
        args.config != args.to_config
            || args.secret.project != args.to.project
            || args.secret.name != args.to.name,
        "source and destination must differ"
    );
    let value = get(&args.secret, &args.config)?;
    output::register_secret(value.as_bytes());
    ensure!(
        !value.is_empty() && !value.contains("${"),
        "source is empty or unresolved"
    );
    if let Some(existing) = try_get(&args.to, &args.to_config)? {
        output::register_secret(existing.as_bytes());
        ensure!(existing == value, "destination differs; refusing overwrite");
    }
    write_group(&args.to_config, std::slice::from_ref(&args.to), &value)?;
    let destination = get(&args.to, &args.to_config)?;
    output::register_secret(destination.as_bytes());
    ensure!(destination == value, "destination resolution differs");
    if args.remove_source {
        let status = doppler_command()?
            .args([
                "--no-read-env",
                "secrets",
                "delete",
                &args.secret.name,
                "--project",
                &args.secret.project,
                "--config",
                &args.config,
                "--yes",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        ensure!(
            status.success(),
            "source deletion failed; destination is already stored"
        );
        ensure!(
            try_get(&args.secret, &args.config)?.is_none(),
            "source remains readable"
        );
        let destination = get(&args.to, &args.to_config)?;
        output::register_secret(destination.as_bytes());
        ensure!(destination == value, "destination changed after removal");
    }
    Ok(())
}

pub fn delete_secret(args: DeleteSecretArgs) -> Result<()> {
    owner()?;
    let is_custody_half = matches!(
        args.secret.name.as_str(),
        "PAYS_PACKAGE_SIGNING_PASSPHRASE"
            | "PAYS_FSVERITY_SIGNING_PASSPHRASE"
            | "PAYS_ASSOC_SIGNING_PASSPHRASE"
            | "PAYS_RECOVERY_SIGNING_PASSPHRASE"
            | "PAYS_SEED_CIPHERTEXT"
            | "PAYS_CUSTODIAN_SEED_SEALED"
    );
    ensure!(
        args.i_know_this_is_custody || !is_custody_half,
        "refusing to delete a live custody half without --i-know-this-is-custody"
    );

    let status = doppler_command()?
        .args([
            "--no-read-env",
            "--attempts",
            "1",
            "secrets",
            "delete",
            &args.secret.name,
            "--project",
            &args.secret.project,
            "--config",
            &args.config,
            "--yes",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    ensure!(status.success(), "secret deletion failed");
    output::status("secret deleted");
    Ok(())
}
