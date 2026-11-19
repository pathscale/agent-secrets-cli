//! Ed25519 package enrollment, signing and verification.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use clap::Args;
use data_encoding::{BASE64, HEXLOWER};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::eyre::{Result, bail, ensure, eyre};
use zeroize::{Zeroize, Zeroizing};

use crate::{Target, doppler_command, get, parse_target, sealed_seed, try_get};

const PRD_CONFIG: &str = "prd";
const SIGNING_CONFIG: &str = "signing";
const IMAGE_SIGNING_CONFIG: &str = "imagesigning";
const PASSPHRASE_NAME: &str = "PAYS_PACKAGE_SIGNING_PASSPHRASE";
const PUBLIC_NAME: &str = "PAYS_PACKAGE_SIGNING_PUBLIC_KEY";
const BUCKET_NAME: &str = "PAYS_SIGNING_SEALED_BUCKET";
const ROLE_NAME: &str = "AWS_PACKAGE_SIGNING_ROLE_ARN";
const FSVERITY_PASSPHRASE_NAME: &str = "PAYS_FSVERITY_SIGNING_PASSPHRASE";
const FSVERITY_PUBLIC_NAME: &str = "PAYS_FSVERITY_SIGNING_PUBLIC_KEY";
const IMAGE_ROLE_NAME: &str = "AWS_IMAGE_SIGNING_ROLE_ARN";
const PUBLIC_PIN: &str = "keys/package-signing.pub";
const SEALED_BUCKET: &str = "pays-signing-sealed";
const SEALED_OBJECT: &str = "package-seed.sealed";
const FSVERITY_SEALED_OBJECT: &str = "fsverity-seed.sealed";
const AWS_REGION: &str = "us-west-2";
const MAX_SEALED_BLOB_LEN: usize = 130;
const PACKAGE_PURPOSE: &str = "package-seed";
const FSVERITY_PURPOSE: &str = "fsverity-seed";
const FSVERITY_DIGEST_LENGTH: usize = 44;

#[derive(Args)]
pub struct PackageSealArgs {
    /// Purpose is fixed to package-seed for this command.
    #[arg(long, default_value = PACKAGE_PURPOSE)]
    purpose: String,
}

#[derive(Args)]
pub struct PackageSignArgs {
    /// Doppler config containing the signing reader values.
    #[arg(long, default_value = SIGNING_CONFIG)]
    config: String,

    /// Purpose is fixed to package-seed for this command.
    #[arg(long, default_value = PACKAGE_PURPOSE)]
    purpose: String,

    /// Fixed Doppler target for the package passphrase.
    #[arg(
        long,
        value_parser = parse_target,
        default_value = "pays-host/PAYS_PACKAGE_SIGNING_PASSPHRASE"
    )]
    passphrase: Target,

    /// Fixed Doppler target containing the OIDC role ARN.
    #[arg(
        long,
        value_parser = parse_target,
        default_value = "pays-host/AWS_PACKAGE_SIGNING_ROLE_ARN"
    )]
    role_arn: Target,

    /// Committed public key pin used to authorize signing.
    #[arg(long, default_value = PUBLIC_PIN)]
    public_key: PathBuf,

    /// Signature domain. Repeat with --file for each input.
    #[arg(long, required = true, value_parser = parse_domain)]
    domain: Vec<String>,

    /// Relative input path. Repeat with --domain for each input.
    #[arg(long, required = true)]
    file: Vec<PathBuf>,
}

#[derive(Args)]
pub struct FsVeritySealArgs {}

#[derive(Args)]
pub struct FsVeritySignArgs {
    /// Doppler config containing the fs-verity passphrase.
    #[arg(long, default_value = IMAGE_SIGNING_CONFIG)]
    passphrase_config: String,

    /// AWS image-signing role ARN supplied by the caller.
    #[arg(long, required = true)]
    role_arn: String,

    /// File containing the 64-character lowercase public key pin.
    #[arg(long, required = true)]
    public_key: PathBuf,

    /// Binary 44-byte fs-verity formatted digest. Repeat with --signature.
    #[arg(long, required = true)]
    digest: Vec<PathBuf>,

    /// Signature output path. Repeat with --digest.
    #[arg(long, required = true)]
    signature: Vec<PathBuf>,
}

#[derive(Args)]
pub struct PackageVerifyArgs {
    /// Committed public key pin.
    #[arg(long, default_value = PUBLIC_PIN)]
    public_key: PathBuf,

    /// Signature domain. Repeat with --file for each input.
    #[arg(long, required = true, value_parser = parse_domain)]
    domain: Vec<String>,

    /// Relative input path. Repeat with --domain for each input.
    #[arg(long, required = true)]
    file: Vec<PathBuf>,
}

#[derive(Args)]
pub struct PackageSignFixtureArgs {
    /// Fixture public key output. Keep it outside keys/.
    #[arg(long, default_value = "package-sign-fixture.pub")]
    public_key: PathBuf,

    /// Signature domain. Repeat with --file for each input.
    #[arg(long, required = true, value_parser = parse_domain)]
    domain: Vec<String>,

    /// Relative input path. Repeat with --domain for each input.
    #[arg(long, required = true)]
    file: Vec<PathBuf>,
}

struct FileSpec {
    domain: String,
    path: PathBuf,
    name: String,
}

struct SignedFile {
    sidecar: PathBuf,
    signature: [u8; 64],
}

struct FsVerityFile {
    signature_path: PathBuf,
    digest: Vec<u8>,
}

struct AwsCredentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
}

pub fn package_seal(args: PackageSealArgs) -> Result<()> {
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "unset DOPPLER_TOKEN and use the owner HOME-scoped login"
    );
    ensure!(
        args.purpose == PACKAGE_PURPOSE,
        "purpose is fixed to package-seed"
    );

    let passphrase_target = target(PASSPHRASE_NAME);
    let public_target = target(PUBLIC_NAME);

    let prd_passphrase = try_get_secret(&passphrase_target, PRD_CONFIG)?;
    let signing_passphrase = try_get_secret(&passphrase_target, SIGNING_CONFIG)?;
    if let (Some(prd), Some(signing)) = (&prd_passphrase, &signing_passphrase) {
        ensure!(
            prd.as_str() == signing.as_str(),
            "package passphrase copies differ; refusing to write"
        );
    }
    let stored_public = try_get_secret(&public_target, PRD_CONFIG)?;
    if let Some(public) = &stored_public {
        read_public_record(public.as_str())?;
    }
    let stored_bucket = try_get_secret(&target(BUCKET_NAME), PRD_CONFIG)?;
    if let Some(bucket) = &stored_bucket {
        ensure!(
            bucket.as_str() == SEALED_BUCKET,
            "sealed bucket setting differs"
        );
    }

    let object_size = sealed_object_size(None, SEALED_OBJECT)?;
    let object_versions = sealed_object_version_count(SEALED_OBJECT)?;
    ensure!(
        match object_size {
            Some(_) => object_versions == 1,
            None => object_versions == 0,
        },
        "sealed S3 object version history is unexpected; reconcile before enrollment"
    );
    let has_passphrase = prd_passphrase.is_some() || signing_passphrase.is_some();
    match (
        object_size.is_some(),
        has_passphrase,
        stored_public.is_some(),
    ) {
        (false, false, false) => {
            enroll_package_seed(&args.purpose, &passphrase_target, &public_target)
        }
        (true, true, _) => resume_package_seed(
            &args.purpose,
            &passphrase_target,
            &public_target,
            prd_passphrase,
            signing_passphrase,
            stored_public,
            object_size.unwrap_or_default(),
        ),
        (false, true, _) => bail!(
            "package passphrase exists without the sealed S3 object; refusing to generate a seed"
        ),
        (true, false, _) => bail!(
            "sealed S3 object exists without a Doppler passphrase; refusing to generate a seed"
        ),
        (false, false, true) => {
            bail!("package public key exists without the sealed seed; refusing to generate a seed")
        }
    }
}

pub fn fsverity_seal(_args: FsVeritySealArgs) -> Result<()> {
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "unset DOPPLER_TOKEN and use the owner HOME-scoped login"
    );

    let passphrase_target = target(FSVERITY_PASSPHRASE_NAME);
    let public_target = target(FSVERITY_PUBLIC_NAME);
    let stored_passphrase = try_get_secret(&passphrase_target, IMAGE_SIGNING_CONFIG)?;
    let stored_public = try_get_secret(&public_target, PRD_CONFIG)?;
    if let Some(public) = &stored_public {
        read_public_record(public.as_str())?;
    }

    let object_size = sealed_object_size(None, FSVERITY_SEALED_OBJECT)?;
    let object_versions = sealed_object_version_count(FSVERITY_SEALED_OBJECT)?;
    ensure!(
        match object_size {
            Some(_) => object_versions == 1,
            None => object_versions == 0,
        },
        "fs-verity sealed S3 object version history is unexpected; reconcile before enrollment"
    );

    match (
        object_size.is_some(),
        stored_passphrase.is_some(),
        stored_public.is_some(),
    ) {
        (false, false, false) => enroll_fsverity_seed(&passphrase_target, &public_target),
        (true, true, _) => resume_fsverity_seed(
            &passphrase_target,
            &public_target,
            stored_passphrase.ok_or_else(|| eyre!("fs-verity passphrase is missing"))?,
            stored_public,
            object_size.unwrap_or_default(),
        ),
        (false, true, _) => bail!(
            "fs-verity passphrase exists without its sealed S3 object; refusing to generate a seed"
        ),
        (true, false, _) => bail!(
            "sealed fs-verity seed exists without a Doppler passphrase; refusing to generate a seed"
        ),
        (false, false, true) => {
            bail!(
                "fs-verity public key exists without the sealed seed; refusing to generate a seed"
            )
        }
    }
}

pub fn package_sign(args: PackageSignArgs) -> Result<()> {
    ensure!(
        args.config == SIGNING_CONFIG,
        "--config is fixed to signing"
    );
    ensure!(
        args.purpose == PACKAGE_PURPOSE,
        "--purpose is fixed to package-seed"
    );
    ensure!(
        args.public_key.as_path() == Path::new(PUBLIC_PIN),
        "--public-key is fixed to keys/package-signing.pub"
    );
    ensure_fixed_target(&args.passphrase, PASSPHRASE_NAME, "--passphrase")?;
    ensure_fixed_target(&args.role_arn, ROLE_NAME, "--role-arn")?;
    let files = file_specs(args.domain, args.file)?;
    validate_stdout_paths(files.iter().map(|file| sidecar_path(&file.path)))?;
    let pin = read_public_pin(&args.public_key)?;

    let passphrase_base64 = Zeroizing::new(
        get(&args.passphrase, &args.config)
            .map_err(|_| eyre!("could not read package signing passphrase"))?,
    );
    crate::output::register_secret(passphrase_base64.as_bytes());
    let passphrase = decode_passphrase(&passphrase_base64)?;
    let role_arn = get(&args.role_arn, &args.config)
        .map_err(|_| eyre!("could not read package signing role"))?;
    crate::output::register_secret(role_arn.as_bytes());
    validate_role_arn(&role_arn, ROLE_NAME)?;

    let oidc_token = request_oidc_token()?;
    let credentials = assume_signing_role(
        &role_arn,
        &oidc_token,
        AWS_REGION,
        "agent-secrets-cli-package-sign",
    )?;
    let blob = read_sealed_object(Some(&credentials), SEALED_OBJECT)?;
    crate::output::register_secret(&blob);
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, &args.purpose)?;
    crate::output::register_secret(&seed[..]);
    let signing_key = signing_key_from_seed(&seed)?;
    ensure!(
        signing_key.verifying_key().to_bytes() == pin,
        "unsealed package key does not match keys/package-signing.pub"
    );

    let signed = sign_files(&signing_key, &files)?;
    for output in signed {
        emit_signature(&output.sidecar, &output.signature)?;
    }
    crate::output::status("signed package artifact(s)");
    Ok(())
}

pub fn fsverity_sign(args: FsVeritySignArgs) -> Result<()> {
    ensure!(
        args.passphrase_config == IMAGE_SIGNING_CONFIG,
        "--passphrase-config is fixed to imagesigning"
    );
    validate_stdout_paths(args.signature.iter().cloned())?;
    let pin = read_public_pin(&args.public_key)?;
    let files = fsverity_files(args.digest, args.signature, &args.public_key)?;

    let passphrase_base64 = Zeroizing::new(
        get(&target(FSVERITY_PASSPHRASE_NAME), &args.passphrase_config)
            .map_err(|_| eyre!("could not read fs-verity signing passphrase"))?,
    );
    crate::output::register_secret(passphrase_base64.as_bytes());
    let passphrase = decode_passphrase(&passphrase_base64)?;
    validate_role_arn(&args.role_arn, IMAGE_ROLE_NAME)?;

    let oidc_token = request_oidc_token()?;
    let credentials = assume_signing_role(
        &args.role_arn,
        &oidc_token,
        AWS_REGION,
        "agent-secrets-cli-fsverity-sign",
    )?;
    let blob = read_sealed_object(Some(&credentials), FSVERITY_SEALED_OBJECT)?;
    crate::output::register_secret(&blob);
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, FSVERITY_PURPOSE)?;
    crate::output::register_secret(&seed[..]);
    let signing_key = signing_key_from_seed(&seed)?;
    ensure!(
        signing_key.verifying_key().to_bytes() == pin,
        "unsealed fs-verity key does not match the public key pin"
    );

    let signatures = files
        .iter()
        .map(|file| signing_key.sign(&file.digest).to_bytes())
        .collect::<Vec<_>>();
    for (file, signature) in files.iter().zip(signatures) {
        emit_signature(&file.signature_path, &signature)?;
    }
    crate::output::status("signed fs-verity digest(s)");
    Ok(())
}

fn fsverity_files(
    digests: Vec<PathBuf>,
    signatures: Vec<PathBuf>,
    public_key: &Path,
) -> Result<Vec<FsVerityFile>> {
    ensure!(
        !digests.is_empty(),
        "at least one digest/signature pair is required"
    );
    ensure!(
        digests.len() == signatures.len(),
        "each --digest must have one matching --signature"
    );

    let digest_paths: std::collections::HashSet<_> = digests
        .iter()
        .map(|path| normalize_path(path.clone()))
        .collect();
    ensure!(digest_paths.len() == digests.len(), "duplicate digest path");
    let signature_paths: std::collections::HashSet<_> = signatures
        .iter()
        .map(|path| normalize_path(path.clone()))
        .collect();
    ensure!(
        signature_paths.len() == signatures.len(),
        "signature output paths collide"
    );
    ensure!(
        signature_paths
            .iter()
            .all(|path| !digest_paths.contains(path)),
        "signature output path overlaps a digest input"
    );
    let public_key_path = normalize_path(public_key.to_path_buf());
    ensure!(
        signature_paths.iter().all(|path| path != &public_key_path),
        "signature output path overlaps the public key pin"
    );

    digests
        .into_iter()
        .zip(signatures)
        .map(|(digest_path, signature_path)| {
            let digest =
                fs::read(digest_path).map_err(|_| eyre!("could not read fs-verity digest"))?;
            validate_fsverity_digest(&digest)?;
            Ok(FsVerityFile {
                signature_path,
                digest,
            })
        })
        .collect()
}

fn validate_fsverity_digest(digest: &[u8]) -> Result<()> {
    ensure!(
        digest.len() == FSVERITY_DIGEST_LENGTH,
        "fs-verity digest must be exactly 44 bytes"
    );
    ensure!(
        &digest[..8] == b"FSVerity",
        "fs-verity digest has invalid magic"
    );
    ensure!(
        digest[8] == 1 && digest[9] == 0,
        "fs-verity digest must use SHA-256"
    );
    ensure!(
        digest[10] == 32 && digest[11] == 0,
        "fs-verity digest must contain a 32-byte hash"
    );
    Ok(())
}

pub fn package_verify(args: PackageVerifyArgs) -> Result<()> {
    let files = file_specs(args.domain, args.file)?;
    let pin = read_public_pin(&args.public_key)?;
    let verifying_key = VerifyingKey::from_bytes(&pin)
        .map_err(|_| eyre!("public key pin is not a valid Ed25519 key"))?;
    verify_files(&verifying_key, &files)?;
    crate::output::status("verified package artifact(s)");
    Ok(())
}

pub fn package_sign_fixture(args: PackageSignFixtureArgs) -> Result<()> {
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "package-sign-fixture refuses a set DOPPLER_TOKEN"
    );
    ensure!(
        std::env::var_os("AWS_ACCESS_KEY_ID").is_none(),
        "package-sign-fixture refuses a set AWS_ACCESS_KEY_ID"
    );
    let files = file_specs(args.domain, args.file)?;
    validate_stdout_paths(files.iter().map(|file| sidecar_path(&file.path)))?;
    validate_stdout_path(
        &args.public_key,
        "public key output path contains a control character",
    )?;
    ensure!(
        !under_keys(&args.public_key)?,
        "package-sign-fixture refuses paths under keys/"
    );
    ensure!(
        files
            .iter()
            .map(|file| under_keys(&file.path))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .all(|under| !under),
        "package-sign-fixture refuses paths under keys/"
    );
    let public_path = normalized_absolute(&args.public_key)?;
    let input_paths = files
        .iter()
        .map(|file| normalized_absolute(&file.path))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        input_paths.iter().all(|path| path != &public_path),
        "fixture public key path must differ from each input path"
    );
    let sidecar_paths = files
        .iter()
        .map(|file| normalized_absolute(&sidecar_path(&file.path)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        sidecar_paths.iter().all(|path| path != &public_path),
        "fixture public key path must differ from each signature path"
    );

    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| eyre!("OS random fixture key generation failed"))?;
    crate::output::register_secret(&seed[..]);
    let signing_key = SigningKey::from_bytes(&seed);
    let signed = sign_files(&signing_key, &files)?;
    let public_hex = public_hex_for(&signing_key.verifying_key());
    crate::output::line(&format!(
        "public-key {public_hex} {}",
        args.public_key.display()
    ))?;
    for output in signed {
        emit_signature(&output.sidecar, &output.signature)?;
    }
    crate::output::status("created fixture signature(s)");
    Ok(())
}

fn target(name: &str) -> Target {
    Target {
        project: "pays-host".to_owned(),
        name: name.to_owned(),
    }
}

fn ensure_fixed_target(value: &Target, expected: &str, flag: &str) -> Result<()> {
    ensure!(
        value.project == "pays-host" && value.name == expected,
        "{flag} is fixed to pays-host/{expected}"
    );
    Ok(())
}

fn parse_domain(raw: &str) -> std::result::Result<String, String> {
    match raw {
        "package" | "executable" | "provenance" | "lock" | "measurement" => Ok(raw.to_owned()),
        "image" => Err("image signatures are not accepted by package signing".to_owned()),
        _ => Err("domain must be package, executable, provenance, lock, or measurement".to_owned()),
    }
}

fn file_specs(domains: Vec<String>, paths: Vec<PathBuf>) -> Result<Vec<FileSpec>> {
    ensure!(
        !domains.is_empty(),
        "at least one --domain and --file pair is required"
    );
    ensure!(
        domains.len() == paths.len(),
        "each --domain must have one matching --file"
    );
    let files = domains
        .into_iter()
        .zip(paths)
        .map(|(domain, path)| {
            let name = file_basename(&path)?;
            validate_name(&name)?;
            Ok(FileSpec { domain, path, name })
        })
        .collect::<Result<Vec<_>>>()?;
    let input_paths: std::collections::HashSet<_> = files
        .iter()
        .map(|file| normalize_path(file.path.clone()))
        .collect();
    ensure!(input_paths.len() == files.len(), "duplicate input path");
    let sidecar_paths: std::collections::HashSet<_> = files
        .iter()
        .map(|file| normalize_path(sidecar_path(&file.path)))
        .collect();
    ensure!(
        sidecar_paths
            .iter()
            .all(|path| !path.to_string_lossy().contains('\n')),
        "signature output path contains a newline"
    );
    ensure!(
        sidecar_paths.len() == files.len(),
        "signature output paths collide"
    );
    ensure!(
        sidecar_paths
            .iter()
            .all(|sidecar| !input_paths.contains(sidecar)),
        "signature output path overlaps an input path"
    );
    Ok(files)
}

fn file_basename(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| eyre!("input path must have a valid UTF-8 basename"))
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.starts_with('/')
            && name.is_ascii()
            && !name.bytes().any(|byte| byte.is_ascii_control())
            && !name.contains('\\')
            && !Path::new(name).is_absolute()
            && !(name.as_bytes().get(1) == Some(&b':')
                && name
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphabetic())),
        "signature name must be a relative path with forward slashes"
    );
    ensure!(
        name.split('/')
            .all(|segment| !segment.is_empty() && segment != ".."),
        "signature name cannot contain an empty or .. path segment"
    );
    Ok(())
}

fn signed_message(domain: &str, name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut message = format!(
        "pays-artifact-sign-v1\ndomain:{domain}\nname:{name}\nlength:{}\n",
        bytes.len()
    )
    .into_bytes();
    message.extend_from_slice(bytes);
    message
}

fn sidecar_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

fn emit_signature(path: &Path, signature: &[u8]) -> Result<()> {
    crate::output::line(&signature_output_line(path, signature)?)
}

fn signature_output_line(path: &Path, signature: &[u8]) -> Result<String> {
    let path = path.to_string_lossy();
    validate_stdout_path(
        Path::new(path.as_ref()),
        "signature output path contains a control character",
    )?;
    Ok(format!("{} {path}", BASE64.encode(signature)))
}

fn validate_stdout_path(path: &Path, error: &'static str) -> Result<()> {
    if path.to_string_lossy().chars().any(char::is_control) {
        crate::output::status(error);
        bail!(error);
    }
    Ok(())
}

fn validate_stdout_paths(paths: impl IntoIterator<Item = PathBuf>) -> Result<()> {
    for path in paths {
        validate_stdout_path(&path, "signature output path contains a control character")?;
    }
    Ok(())
}

fn sign_files(signing_key: &SigningKey, files: &[FileSpec]) -> Result<Vec<SignedFile>> {
    let mut signed = Vec::with_capacity(files.len());
    for file in files {
        let bytes = fs::read(&file.path).map_err(|_| eyre!("could not read package input"))?;
        let message = signed_message(&file.domain, &file.name, &bytes);
        signed.push(SignedFile {
            sidecar: sidecar_path(&file.path),
            signature: signing_key.sign(&message).to_bytes(),
        });
    }
    Ok(signed)
}

fn verify_files(verifying_key: &VerifyingKey, files: &[FileSpec]) -> Result<()> {
    for file in files {
        let bytes = fs::read(&file.path).map_err(|_| eyre!("could not read package input"))?;
        let sidecar = fs::read(sidecar_path(&file.path))
            .map_err(|_| eyre!("package signature is missing"))?;
        ensure!(
            sidecar.len() == 64,
            "package signature must be exactly 64 bytes"
        );
        let signature_bytes: [u8; 64] = sidecar
            .as_slice()
            .try_into()
            .map_err(|_| eyre!("package signature must be exactly 64 bytes"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let message = signed_message(&file.domain, &file.name, &bytes);
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| eyre!("package signature verification failed"))?;
    }
    Ok(())
}

fn public_hex_for(verifying_key: &VerifyingKey) -> String {
    HEXLOWER.encode(&verifying_key.to_bytes())
}

fn parse_public_hex(raw: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        raw.len() == 64,
        "public key must be 64 lowercase hex characters"
    );
    ensure!(
        raw.iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "public key must be 64 lowercase hex characters"
    );
    let mut key = [0u8; 32];
    for (index, pair) in raw.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => bail!("public key must be lowercase hexadecimal"),
    }
}

fn read_public_pin(path: &Path) -> Result<[u8; 32]> {
    let contents = fs::read(path).map_err(|_| eyre!("could not read public key pin"))?;
    ensure!(
        contents.len() == 65 && contents.last() == Some(&b'\n'),
        "public key pin must contain 64 lowercase hex characters and one newline"
    );
    parse_public_hex(&contents[..64])
}

fn read_public_record(raw: &str) -> Result<[u8; 32]> {
    parse_public_hex(raw.as_bytes())
}

fn signing_key_from_seed(seed: &[u8; 32]) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(seed))
}

fn try_get_secret(target: &Target, config: &str) -> Result<Option<Zeroizing<String>>> {
    Ok(try_get(target, config)?.map(|value| {
        crate::output::register_secret(value.as_bytes());
        Zeroizing::new(value)
    }))
}

fn decode_passphrase(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    crate::output::register_secret(encoded.as_bytes());
    ensure!(
        !encoded.is_empty() && !encoded.bytes().any(|byte| byte.is_ascii_whitespace()),
        "signing passphrase is not canonical base64"
    );
    let decoded = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| eyre!("signing passphrase is not canonical base64"))?,
    );
    ensure!(
        decoded.len() == 32 && BASE64.encode(decoded.as_slice()) == encoded,
        "signing passphrase is not canonical base64"
    );
    let mut passphrase = Zeroizing::new([0u8; 32]);
    passphrase.copy_from_slice(&decoded);
    Ok(passphrase)
}

fn enroll_package_seed(
    purpose: &str,
    passphrase_target: &Target,
    public_target: &Target,
) -> Result<()> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| eyre!("OS random seed generation failed"))?;
    crate::output::register_secret(&seed[..]);
    let passphrase = sealed_seed::generate_passphrase()?;
    crate::output::register_secret(&passphrase[..]);
    let passphrase_base64 = Zeroizing::new(BASE64.encode(&passphrase[..]));
    crate::output::register_secret(passphrase_base64.as_bytes());
    let signing_key = SigningKey::from_bytes(&seed);
    let expected_public = public_hex_for(&signing_key.verifying_key());
    let blob = Zeroizing::new(sealed_seed::seal_seed(&seed, &passphrase, purpose)?);
    crate::output::register_secret(&blob);

    ensure_passphrase_copy(passphrase_target, PRD_CONFIG, &passphrase_base64)?;
    ensure_passphrase_copy(passphrase_target, SIGNING_CONFIG, &passphrase_base64)?;
    upload_sealed_object(&blob, SEALED_OBJECT)?;

    let stored_blob = read_sealed_object(None, SEALED_OBJECT)?;
    ensure!(
        stored_blob.as_slice() == blob.as_slice(),
        "sealed seed readback differs"
    );
    let stored_prd_passphrase = try_get_secret(passphrase_target, PRD_CONFIG)?
        .ok_or_else(|| eyre!("package passphrase readback is missing"))?;
    let stored_signing_passphrase = try_get_secret(passphrase_target, SIGNING_CONFIG)?
        .ok_or_else(|| eyre!("signing passphrase readback is missing"))?;
    ensure!(
        stored_prd_passphrase.as_str() == passphrase_base64.as_str()
            && stored_signing_passphrase.as_str() == passphrase_base64.as_str(),
        "package passphrase readback differs"
    );
    let readback_passphrase = decode_passphrase(&stored_signing_passphrase)?;
    let readback_seed = sealed_seed::unseal_seed(&stored_blob, &readback_passphrase, purpose)?;
    crate::output::register_secret(&readback_seed[..]);
    let readback_key = signing_key_from_seed(&readback_seed)?;
    ensure!(
        public_hex_for(&readback_key.verifying_key()) == expected_public,
        "sealed seed readback does not match the generated key"
    );

    ensure_public_copy(public_target, &expected_public)?;
    ensure_bucket_copy()?;
    print_public_hex(&expected_public)
}

fn resume_package_seed(
    purpose: &str,
    passphrase_target: &Target,
    public_target: &Target,
    prd_passphrase: Option<Zeroizing<String>>,
    signing_passphrase: Option<Zeroizing<String>>,
    stored_public: Option<Zeroizing<String>>,
    expected_size: usize,
) -> Result<()> {
    let passphrase_base64 = prd_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str())
        .or_else(|| {
            signing_passphrase
                .as_ref()
                .map(|passphrase| passphrase.as_str())
        })
        .ok_or_else(|| eyre!("package passphrase is missing"))?;
    let passphrase = decode_passphrase(passphrase_base64)?;
    let blob = read_sealed_object(None, SEALED_OBJECT)?;
    ensure!(
        blob.len() == expected_size,
        "sealed seed object changed during readback"
    );
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, purpose)?;
    crate::output::register_secret(&seed[..]);
    let signing_key = signing_key_from_seed(&seed)?;
    let expected_public = public_hex_for(&signing_key.verifying_key());
    if let Some(public) = &stored_public {
        ensure!(
            read_public_record(public.as_str())? == signing_key.verifying_key().to_bytes(),
            "stored package public key does not match the sealed seed"
        );
    }

    ensure_passphrase_copy(passphrase_target, PRD_CONFIG, passphrase_base64)?;
    ensure_passphrase_copy(passphrase_target, SIGNING_CONFIG, passphrase_base64)?;
    ensure_public_copy(public_target, &expected_public)?;
    ensure_bucket_copy()?;

    let prd_readback = try_get_secret(passphrase_target, PRD_CONFIG)?
        .ok_or_else(|| eyre!("package passphrase readback is missing"))?;
    let signing_readback = try_get_secret(passphrase_target, SIGNING_CONFIG)?
        .ok_or_else(|| eyre!("signing passphrase readback is missing"))?;
    ensure!(
        prd_readback.as_str() == passphrase_base64
            && signing_readback.as_str() == passphrase_base64,
        "package passphrase readback differs"
    );
    let readback_passphrase = decode_passphrase(&signing_readback)?;
    let readback_blob = read_sealed_object(None, SEALED_OBJECT)?;
    ensure!(
        readback_blob.as_slice() == blob.as_slice(),
        "sealed seed object changed during enrollment"
    );
    let readback_seed = sealed_seed::unseal_seed(&readback_blob, &readback_passphrase, purpose)?;
    crate::output::register_secret(&readback_seed[..]);
    let readback_key = signing_key_from_seed(&readback_seed)?;
    ensure!(
        public_hex_for(&readback_key.verifying_key()) == expected_public,
        "sealed seed readback does not match the public key"
    );
    ensure!(
        try_get_secret(public_target, PRD_CONFIG)?
            .is_some_and(|public| public.as_str() == expected_public.as_str()),
        "package public key readback differs"
    );
    print_public_hex(&expected_public)
}

fn enroll_fsverity_seed(passphrase_target: &Target, public_target: &Target) -> Result<()> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| eyre!("OS random seed generation failed"))?;
    crate::output::register_secret(&seed[..]);
    let passphrase = sealed_seed::generate_passphrase()?;
    crate::output::register_secret(&passphrase[..]);
    let passphrase_base64 = Zeroizing::new(BASE64.encode(&passphrase[..]));
    crate::output::register_secret(passphrase_base64.as_bytes());
    let signing_key = SigningKey::from_bytes(&seed);
    let expected_public = public_hex_for(&signing_key.verifying_key());
    let blob = Zeroizing::new(sealed_seed::seal_seed(
        &seed,
        &passphrase,
        FSVERITY_PURPOSE,
    )?);
    crate::output::register_secret(&blob);

    ensure_passphrase_copy(passphrase_target, IMAGE_SIGNING_CONFIG, &passphrase_base64)?;
    upload_sealed_object(&blob, FSVERITY_SEALED_OBJECT)?;

    let stored_blob = read_sealed_object(None, FSVERITY_SEALED_OBJECT)?;
    ensure!(
        stored_blob.as_slice() == blob.as_slice(),
        "sealed fs-verity seed readback differs"
    );
    let stored_passphrase = try_get_secret(passphrase_target, IMAGE_SIGNING_CONFIG)?
        .ok_or_else(|| eyre!("fs-verity passphrase readback is missing"))?;
    ensure!(
        stored_passphrase.as_str() == passphrase_base64.as_str(),
        "fs-verity passphrase readback differs"
    );
    let readback_passphrase = decode_passphrase(&stored_passphrase)?;
    let readback_seed =
        sealed_seed::unseal_seed(&stored_blob, &readback_passphrase, FSVERITY_PURPOSE)?;
    crate::output::register_secret(&readback_seed[..]);
    let readback_key = signing_key_from_seed(&readback_seed)?;
    ensure!(
        public_hex_for(&readback_key.verifying_key()) == expected_public,
        "sealed fs-verity seed readback does not match the generated key"
    );

    ensure_public_copy(public_target, &expected_public)?;
    print_public_hex(&expected_public)
}

fn resume_fsverity_seed(
    passphrase_target: &Target,
    public_target: &Target,
    stored_passphrase: Zeroizing<String>,
    stored_public: Option<Zeroizing<String>>,
    expected_size: usize,
) -> Result<()> {
    let passphrase_base64 = stored_passphrase.as_str();
    let passphrase = decode_passphrase(passphrase_base64)?;
    let blob = read_sealed_object(None, FSVERITY_SEALED_OBJECT)?;
    ensure!(
        blob.len() == expected_size,
        "sealed fs-verity seed object changed during readback"
    );
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, FSVERITY_PURPOSE)?;
    crate::output::register_secret(&seed[..]);
    let signing_key = signing_key_from_seed(&seed)?;
    let expected_public = public_hex_for(&signing_key.verifying_key());
    if let Some(public) = &stored_public {
        ensure!(
            read_public_record(public.as_str())? == signing_key.verifying_key().to_bytes(),
            "stored fs-verity public key does not match the sealed seed"
        );
    }

    ensure_passphrase_copy(passphrase_target, IMAGE_SIGNING_CONFIG, passphrase_base64)?;
    ensure_public_copy(public_target, &expected_public)?;

    let passphrase_readback = try_get_secret(passphrase_target, IMAGE_SIGNING_CONFIG)?
        .ok_or_else(|| eyre!("fs-verity passphrase readback is missing"))?;
    ensure!(
        passphrase_readback.as_str() == passphrase_base64,
        "fs-verity passphrase readback differs"
    );
    let readback_passphrase = decode_passphrase(&passphrase_readback)?;
    let readback_blob = read_sealed_object(None, FSVERITY_SEALED_OBJECT)?;
    ensure!(
        readback_blob.as_slice() == blob.as_slice(),
        "sealed fs-verity seed object changed during enrollment"
    );
    let readback_seed =
        sealed_seed::unseal_seed(&readback_blob, &readback_passphrase, FSVERITY_PURPOSE)?;
    crate::output::register_secret(&readback_seed[..]);
    let readback_key = signing_key_from_seed(&readback_seed)?;
    ensure!(
        public_hex_for(&readback_key.verifying_key()) == expected_public,
        "sealed fs-verity seed readback does not match the public key"
    );
    ensure!(
        try_get_secret(public_target, PRD_CONFIG)?
            .is_some_and(|public| public.as_str() == expected_public.as_str()),
        "fs-verity public key readback differs"
    );
    print_public_hex(&expected_public)
}

fn ensure_passphrase_copy(target: &Target, config: &str, passphrase: &str) -> Result<()> {
    match try_get_secret(target, config)? {
        Some(existing) => ensure!(
            existing.as_str() == passphrase,
            "signing passphrase differs; refusing to overwrite it"
        ),
        None => write_absent(target, config, passphrase)?,
    }
    let readback = try_get_secret(target, config)?
        .ok_or_else(|| eyre!("signing passphrase readback is missing"))?;
    ensure!(
        readback.as_str() == passphrase,
        "signing passphrase readback differs"
    );
    Ok(())
}

fn ensure_public_copy(target: &Target, public_hex: &str) -> Result<()> {
    parse_public_hex(public_hex.as_bytes())?;
    match try_get_secret(target, PRD_CONFIG)? {
        Some(existing) => ensure!(
            existing.as_str() == public_hex,
            "signing public key differs; refusing to overwrite it"
        ),
        None => write_absent(target, PRD_CONFIG, public_hex)?,
    }
    let readback = try_get_secret(target, PRD_CONFIG)?
        .ok_or_else(|| eyre!("signing public key readback is missing"))?;
    ensure!(
        readback.as_str() == public_hex,
        "signing public key readback differs"
    );
    Ok(())
}

fn ensure_bucket_copy() -> Result<()> {
    let bucket_target = target(BUCKET_NAME);
    match try_get_secret(&bucket_target, PRD_CONFIG)? {
        Some(existing) => ensure!(
            existing.as_str() == SEALED_BUCKET,
            "sealed bucket setting differs; refusing to overwrite it"
        ),
        None => write_absent(&bucket_target, PRD_CONFIG, SEALED_BUCKET)?,
    }
    let readback = try_get_secret(&bucket_target, PRD_CONFIG)?
        .ok_or_else(|| eyre!("sealed bucket setting readback is missing"))?;
    ensure!(
        readback.as_str() == SEALED_BUCKET,
        "sealed bucket setting readback differs"
    );
    Ok(())
}

fn print_public_hex(public_hex: &str) -> Result<()> {
    parse_public_hex(public_hex.as_bytes())?;
    crate::output::line(public_hex)
}

fn validate_role_arn(role_arn: &str, name: &str) -> Result<()> {
    let rest = role_arn
        .strip_prefix("arn:aws:iam::")
        .ok_or_else(|| eyre!("{name} is invalid"))?;
    let (account, resource) = rest
        .split_once(":role/")
        .ok_or_else(|| eyre!("{name} is invalid"))?;
    ensure!(
        account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit()),
        "{name} is invalid"
    );
    ensure!(
        !resource.is_empty()
            && resource.len() <= 512
            && resource.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.len() <= 64
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@_-".contains(&byte))
            }),
        "{name} is invalid"
    );
    Ok(())
}

struct AwsCall {
    success: bool,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

fn aws_call(
    args: &[String],
    credentials: Option<&AwsCredentials>,
    unsigned: bool,
) -> Result<AwsCall> {
    aws_call_with_stdin(args, credentials, unsigned, None)
}

fn aws_call_with_stdin(
    args: &[String],
    credentials: Option<&AwsCredentials>,
    unsigned: bool,
    input: Option<&[u8]>,
) -> Result<AwsCall> {
    let mut command = Command::new("aws");
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("DOPPLER_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
    if unsigned {
        command
            .arg("--no-sign-request")
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_DEFAULT_PROFILE")
            .env_remove("AWS_WEB_IDENTITY_TOKEN_FILE")
            .env_remove("AWS_ROLE_ARN");
    }
    if let Some(credentials) = credentials {
        command
            .env("AWS_ACCESS_KEY_ID", credentials.access_key_id.as_str())
            .env(
                "AWS_SECRET_ACCESS_KEY",
                credentials.secret_access_key.as_str(),
            )
            .env("AWS_SESSION_TOKEN", credentials.session_token.as_str());
    }
    let mut child = command
        .spawn()
        .map_err(|_| eyre!("could not run aws CLI"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| eyre!("aws CLI stdin unavailable"))?
            .write_all(input)
            .map_err(|_| eyre!("could not pass AWS CLI input on stdin"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| eyre!("could not run aws CLI"))?;
    Ok(AwsCall {
        success: output.status.success(),
        stdout: Zeroizing::new(output.stdout),
        stderr: Zeroizing::new(output.stderr),
    })
}

fn aws_output(
    args: &[String],
    credentials: Option<&AwsCredentials>,
    unsigned: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let output = aws_call(args, credentials, unsigned)?;
    ensure!(output.success, "aws CLI request failed");
    Ok(output.stdout)
}

fn aws_output_with_stdin(
    args: &[String],
    credentials: Option<&AwsCredentials>,
    unsigned: bool,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let output = aws_call_with_stdin(args, credentials, unsigned, Some(input))?;
    ensure!(output.success, "aws CLI request failed");
    Ok(output.stdout)
}

fn aws_text_fields(output: &[u8]) -> Result<Vec<&str>> {
    let text = std::str::from_utf8(output).map_err(|_| eyre!("aws CLI returned invalid text"))?;
    let text = text.trim_end_matches(['\r', '\n']);
    Ok(text.split('\t').collect())
}

fn sealed_object_size(credentials: Option<&AwsCredentials>, object: &str) -> Result<Option<usize>> {
    let response = aws_call(
        &[
            "s3api".to_owned(),
            "head-object".to_owned(),
            "--bucket".to_owned(),
            SEALED_BUCKET.to_owned(),
            "--key".to_owned(),
            object.to_owned(),
            "--region".to_owned(),
            AWS_REGION.to_owned(),
            "--query".to_owned(),
            "ContentLength".to_owned(),
            "--output".to_owned(),
            "text".to_owned(),
        ],
        credentials,
        false,
    )?;
    if !response.success {
        let error = String::from_utf8_lossy(&response.stderr).to_ascii_lowercase();
        ensure!(
            error.contains("(404)") || error.contains("nosuchkey") || error.contains("not found"),
            "could not inspect the sealed seed object"
        );
        return Ok(None);
    }
    let text = std::str::from_utf8(&response.stdout)
        .map_err(|_| eyre!("aws returned an invalid sealed object size"))?;
    let size = text
        .trim()
        .parse::<usize>()
        .map_err(|_| eyre!("aws returned an invalid sealed object size"))?;
    ensure!(
        size <= MAX_SEALED_BLOB_LEN,
        "sealed seed object is too large"
    );
    Ok(Some(size))
}

fn sealed_object_version_count(object: &str) -> Result<usize> {
    let version_query = format!(
        "[length(Versions[?Key=='{object}'] || `[]`), length(DeleteMarkers[?Key=='{object}'] || `[]`)]"
    );
    let output = aws_output(
        &[
            "s3api".to_owned(),
            "list-object-versions".to_owned(),
            "--bucket".to_owned(),
            SEALED_BUCKET.to_owned(),
            "--prefix".to_owned(),
            object.to_owned(),
            "--region".to_owned(),
            AWS_REGION.to_owned(),
            "--query".to_owned(),
            version_query,
            "--output".to_owned(),
            "text".to_owned(),
        ],
        None,
        false,
    )?;
    // JMESPath has no addition, so the query returns both counts and they are summed here.
    let text = std::str::from_utf8(&output)
        .map_err(|_| eyre!("aws returned an invalid sealed object version count"))?;
    text.split_whitespace().try_fold(0usize, |total, count| {
        count
            .parse::<usize>()
            .ok()
            .and_then(|count| total.checked_add(count))
            .ok_or_else(|| eyre!("aws returned an invalid sealed object version count"))
    })
}

fn read_sealed_object(
    credentials: Option<&AwsCredentials>,
    object: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let size = sealed_object_size(credentials, object)?
        .ok_or_else(|| eyre!("sealed seed object is missing"))?;
    let mut command = Command::new("aws");
    command
        .args([
            "s3",
            "cp",
            &format!("s3://{SEALED_BUCKET}/{object}"),
            "-",
            "--only-show-errors",
            "--region",
            AWS_REGION,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("DOPPLER_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL");
    if let Some(credentials) = credentials {
        command
            .env("AWS_ACCESS_KEY_ID", credentials.access_key_id.as_str())
            .env(
                "AWS_SECRET_ACCESS_KEY",
                credentials.secret_access_key.as_str(),
            )
            .env("AWS_SESSION_TOKEN", credentials.session_token.as_str());
    }
    let mut child = command
        .spawn()
        .map_err(|_| eyre!("could not run aws CLI"))?;
    let mut blob = Zeroizing::new(Vec::with_capacity(size.min(MAX_SEALED_BLOB_LEN)));
    child
        .stdout
        .take()
        .ok_or_else(|| eyre!("aws CLI stdout unavailable"))?
        .take((MAX_SEALED_BLOB_LEN + 1) as u64)
        .read_to_end(&mut blob)
        .map_err(|_| eyre!("could not read sealed seed object"))?;
    let status = child.wait().map_err(|_| eyre!("could not run aws CLI"))?;
    ensure!(status.success(), "aws CLI request failed");
    ensure!(
        blob.len() <= MAX_SEALED_BLOB_LEN,
        "sealed seed object is too large"
    );
    ensure!(blob.len() == size, "sealed seed object changed during read");
    crate::output::register_secret(&blob);
    Ok(blob)
}

fn upload_sealed_object(blob: &[u8], object: &str) -> Result<()> {
    crate::output::register_secret(blob);
    aws_output_with_stdin(
        &[
            "s3api".to_owned(),
            "put-object".to_owned(),
            "--bucket".to_owned(),
            SEALED_BUCKET.to_owned(),
            "--key".to_owned(),
            object.to_owned(),
            "--body".to_owned(),
            "/dev/stdin".to_owned(),
            "--if-none-match".to_owned(),
            "*".to_owned(),
            "--region".to_owned(),
            AWS_REGION.to_owned(),
        ],
        None,
        false,
        blob,
    )?;
    Ok(())
}

fn request_oidc_token() -> Result<Zeroizing<String>> {
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| eyre!("GitHub Actions OIDC request URL is unavailable"))?;
    ensure!(
        request_url.starts_with("https://")
            && !request_url.bytes().any(|byte| byte.is_ascii_whitespace()),
        "GitHub Actions OIDC request URL is invalid"
    );
    let request_token = Zeroizing::new(
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .map_err(|_| eyre!("GitHub Actions OIDC request token is unavailable"))?,
    );
    crate::output::register_secret(request_token.as_bytes());
    ensure!(
        !request_token.is_empty()
            && request_token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "GitHub Actions OIDC request token is invalid"
    );
    let separator = if request_url.contains('?') { '&' } else { '?' };
    let url = format!("{request_url}{separator}audience=sts.amazonaws.com");
    let curl_config = Zeroizing::new(format!(
        "silent = true\nfail = true\nmax-time = 30\nheader = \"Authorization: Bearer {}\"\n",
        request_token.as_str()
    ));
    let mut child = Command::new("curl")
        .args(["--config", "-", &url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_remove("DOPPLER_TOKEN")
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .spawn()
        .map_err(|_| eyre!("could not request GitHub Actions OIDC token"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| eyre!("curl stdin unavailable"))?
        .write_all(curl_config.as_bytes())?;
    let output = child
        .wait_with_output()
        .map_err(|_| eyre!("could not request GitHub Actions OIDC token"))?;
    let body = Zeroizing::new(output.stdout);
    ensure!(
        output.status.success(),
        "GitHub Actions OIDC token request failed"
    );
    let mut response: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| eyre!("invalid OIDC token response"))?;
    let token = response
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| eyre!("OIDC token response has no token"))?;
    let token = Zeroizing::new(token.to_owned());
    crate::output::register_secret(token.as_bytes());
    if let Some(serde_json::Value::String(value)) = response.get_mut("value") {
        value.zeroize();
    }
    ensure!(
        !token.is_empty()
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
        "OIDC token response is invalid"
    );
    Ok(token)
}

fn assume_signing_role(
    role_arn: &str,
    oidc_token: &str,
    region: &str,
    session_name: &str,
) -> Result<AwsCredentials> {
    // The native token argument loads its paramfile once. AWS CLI loads
    // --cli-input-json twice, which consumes a stdin pipe before parsing.
    let output = aws_output_with_stdin(
        &[
            "sts".to_owned(),
            "assume-role-with-web-identity".to_owned(),
            "--role-arn".to_owned(),
            role_arn.to_owned(),
            "--role-session-name".to_owned(),
            session_name.to_owned(),
            "--web-identity-token".to_owned(),
            "file:///dev/stdin".to_owned(),
            "--duration-seconds".to_owned(),
            "900".to_owned(),
            "--query".to_owned(),
            "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]".to_owned(),
            "--output".to_owned(),
            "text".to_owned(),
            "--region".to_owned(),
            region.to_owned(),
        ],
        None,
        true,
        oidc_token.as_bytes(),
    );
    let output = output?;
    let fields = aws_text_fields(&output)?;
    ensure!(
        fields.len() == 3
            && fields
                .iter()
                .all(|field| !field.is_empty() && *field != "None"),
        "aws STS returned invalid temporary credentials"
    );
    for field in &fields {
        crate::output::register_secret(field.as_bytes());
    }
    Ok(AwsCredentials {
        access_key_id: Zeroizing::new(fields[0].to_owned()),
        secret_access_key: Zeroizing::new(fields[1].to_owned()),
        session_token: Zeroizing::new(fields[2].to_owned()),
    })
}

fn write_absent(target: &Target, config: &str, value: &str) -> Result<()> {
    ensure!(
        try_get_secret(target, config)?.is_none(),
        "refusing to overwrite existing secret {target} in {config}"
    );
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
        .map_err(|_| eyre!("could not run doppler"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| eyre!("doppler stdin unavailable"))?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    ensure!(status.success(), "doppler set {target} in {config} failed");
    let readback = try_get_secret(target, config)?
        .ok_or_else(|| eyre!("Doppler secret readback is missing for {target} in {config}"))?;
    ensure!(
        readback.as_str() == value,
        "Doppler secret readback differs for {target} in {config}"
    );
    Ok(())
}

fn under_keys(path: &Path) -> Result<bool> {
    let current = std::env::current_dir().map_err(|_| eyre!("could not read working directory"))?;
    let root = repository_root(&current);
    let candidate = if path.is_absolute() {
        normalize_path(path.to_path_buf())
    } else {
        normalize_path(current.join(path))
    };
    let keys = normalize_path(root.join("keys"));
    Ok(candidate.starts_with(keys))
}

fn repository_root(current: &Path) -> PathBuf {
    let mut candidate = current;
    loop {
        if candidate.join(".git").exists() {
            return candidate.to_path_buf();
        }
        let Some(parent) = candidate.parent() else {
            return current.to_path_buf();
        };
        candidate = parent;
    }
}

fn normalized_absolute(path: &Path) -> Result<PathBuf> {
    let current = std::env::current_dir().map_err(|_| eyre!("could not read working directory"))?;
    Ok(if path.is_absolute() {
        normalize_path(path.to_path_buf())
    } else {
        normalize_path(current.join(path))
    })
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_line_round_trips_and_matches_public_pin() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let message = b"package signing output test";
        let signature = key.sign(message).to_bytes();
        let output = signature_output_line(Path::new("artifact.sig"), &signature).unwrap();
        let (encoded, path) = output.split_once(' ').unwrap();
        assert_eq!(path, "artifact.sig");
        let decoded = BASE64.decode(encoded.as_bytes()).unwrap();
        let signature = Signature::from_slice(&decoded).unwrap();
        let pin = parse_public_hex(public_hex_for(&key.verifying_key()).as_bytes()).unwrap();
        VerifyingKey::from_bytes(&pin)
            .unwrap()
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn signature_line_refuses_newline_path() {
        assert!(signature_output_line(Path::new("artifact\nforged.sig"), &[0; 64]).is_err());
    }

    #[test]
    fn stdout_path_preflight_rejects_unicode_and_normalized_away_controls() {
        assert!(validate_stdout_path(Path::new("artifact\u{0085}.sig"), "invalid").is_err());
        let raw = Path::new("tab\tparent/../artifact.sig");
        let normalized = normalize_path(raw.to_path_buf());
        assert!(!normalized.to_string_lossy().chars().any(char::is_control));
        assert!(validate_stdout_path(raw, "invalid").is_err());
    }

    #[test]
    fn output_description_does_not_create_sidecar_or_pin_files() {
        let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let sidecar = sidecar_path(&input);
        let pin =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("agent-secrets-cli-test-fixture.pub");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        sign_files(
            &key,
            &[FileSpec {
                domain: "package".to_owned(),
                name: "Cargo.toml".to_owned(),
                path: input,
            }],
        )
        .unwrap();
        assert!(!sidecar.exists());
        assert!(!pin.exists());
    }
}
