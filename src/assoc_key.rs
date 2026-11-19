//! Independent pool association authority. Custody values never use local files.

use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    process::{Command, Stdio},
    sync::Arc,
};

use clap::Args;
use data_encoding::{BASE64, HEXLOWER};
use ed25519_dalek::SigningKey;
use crate::eyre::{Result, bail, ensure, eyre};
use zeroize::Zeroizing;

use crate::{doppler_command, sealed_seed, split_custody};

const CONFIG: &str = "assocsigning";
const PASSPHRASE: &str = "PAYS_ASSOC_SIGNING_PASSPHRASE";
const BUCKET: &str = "pays-signing-sealed";
const OBJECT: &str = "assoc-seed.sealed";
const PURPOSE: &str = "assoc-seed";
const REGION: &str = "us-west-2";
// PAYSSEAL, version, purpose length, purpose, salt, nonce, seed, AEAD tag.
const BLOB_LEN: usize = 10 + PURPOSE.len() + 16 + 24 + 32 + 16;

#[derive(Args)]
pub struct AssocExecArgs {
    /// Expected 64-character lowercase Ed25519 public key, never a private seed.
    #[arg(long)]
    public_key: String,
    /// Trusted signer child. Its stdin receives exactly 32 raw seed bytes and EOF.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

pub fn seal() -> Result<()> {
    harden()?;
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "unset DOPPLER_TOKEN and use the owner HOME-scoped login"
    );
    check_config()?;
    check_bucket()?;
    let stored = read_binding(PASSPHRASE)?;
    let versions = object_versions()?;
    match (versions, stored) {
        (0, None) => enroll(),
        (1, Some(encoded)) => {
            let passphrase = decode_passphrase(&encoded)?;
            let blob = download()?;
            let seed = sealed_seed::unseal_seed(&blob, &passphrase, PURPOSE)?;
            print_public(&SigningKey::from_bytes(&seed))
        }
        _ => bail!(
            "association custody is partial or has unexpected history; reconcile before retry"
        ),
    }
}

fn enroll() -> Result<()> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| eyre!("association seed generation failed"))?;
    let signer = Arc::new(SigningKey::from_bytes(&seed));
    let passphrase = sealed_seed::generate_passphrase()?;
    let encoded = Zeroizing::new(BASE64.encode(&passphrase[..]));
    let blob = Zeroizing::new(sealed_seed::seal_seed(&seed, &passphrase, PURPOSE)?);
    drop(seed);

    // Conditional S3 creation arbitrates concurrent enrollments before Doppler
    // writes. A lost response or a later failure leaves partial custody closed.
    let body = memory_file(&blob)?;
    aws(
        &[
            "s3api",
            "put-object",
            "--bucket",
            BUCKET,
            "--key",
            OBJECT,
            "--body",
            "/proc/self/fd/0",
            "--if-none-match",
            "*",
            "--server-side-encryption",
            "AES256",
        ],
        Some(body),
    )?;
    ensure!(
        object_versions()? == 1,
        "association object history changed"
    );
    ensure!(
        download()?.as_slice() == blob.as_slice(),
        "association upload readback differs"
    );
    write_passphrase(&encoded)?;

    let readback = load_signer()?;
    ensure!(
        readback.verifying_key() == signer.verifying_key(),
        "association custody readback public key differs"
    );
    print_public(&readback)
}

pub fn pubkey() -> Result<()> {
    harden()?;
    let signer = load_signer()?;
    print_public(&signer)
}

pub fn exec(args: AssocExecArgs) -> Result<()> {
    harden()?;
    ensure!(
        args.public_key.len() == 64
            && args
                .public_key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "association public pin must be lowercase hex"
    );
    let trusted_path = read_binding("ASSOC_SIGNER_PATH")?
        .ok_or_else(|| eyre!("association signer path pin is missing"))?;
    let trusted_hash = read_binding("ASSOC_SIGNER_SHA256")?
        .ok_or_else(|| eyre!("association signer hash pin is missing"))?;
    let (program, arguments) = args
        .command
        .split_first()
        .ok_or_else(|| eyre!("association signer child is required"))?;
    ensure!(
        arguments.is_empty(),
        "association signer child accepts no caller-supplied arguments"
    );
    let child = split_custody::verify_pinned_child(
        trusted_path.as_str(),
        trusted_hash.as_str(),
        program,
        "association",
    )?;

    let signer = load_signer()?;
    ensure!(
        HEXLOWER.encode(signer.verifying_key().as_bytes()) == args.public_key,
        "association authority does not match the public pin"
    );
    let (reader, mut writer) =
        std::io::pipe().map_err(|_| eyre!("could not create association signer pipe"))?;
    let seed = Zeroizing::new(signer.to_bytes());
    // The fixed 32-byte payload fits in an empty pipe before spawning. No
    // producer process or write descriptor survives exec, so the child sees EOF.
    writer
        .write_all(&seed[..])
        .map_err(|_| eyre!("could not fill association signer pipe"))?;
    drop(writer);
    drop(seed);
    drop(signer);
    split_custody::execute_pinned_child(child, reader, "association")
}

fn load_signer() -> Result<Arc<SigningKey>> {
    check_config()?;
    check_bucket()?;
    let encoded =
        read_binding(PASSPHRASE)?.ok_or_else(|| eyre!("association passphrase is missing"))?;
    let passphrase = decode_passphrase(&encoded)?;
    let blob = download()?;
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, PURPOSE)?;
    Ok(Arc::new(SigningKey::from_bytes(&seed)))
}

fn print_public(signer: &SigningKey) -> Result<()> {
    let public = HEXLOWER.encode(signer.verifying_key().as_bytes());
    crate::output::line(&public)
}

fn check_config() -> Result<()> {
    // A branch of prd would report environment prd. Require the independent
    // environment and its root config, both named assocsigning.
    for name in ["DOPPLER_ENVIRONMENT", "DOPPLER_CONFIG"] {
        let value =
            read_binding(name)?.ok_or_else(|| eyre!("association config metadata is missing"))?;
        ensure!(
            value.as_str() == CONFIG,
            "association config must be an isolated root environment"
        );
    }
    Ok(())
}

fn read_binding(name: &str) -> Result<Option<Zeroizing<String>>> {
    let output = doppler_command()?
        .args([
            "secrets",
            "get",
            name,
            "--plain",
            "--raw",
            "-p",
            "pays-host",
            "-c",
            CONFIG,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| eyre!("could not read association Doppler binding"))?;
    let stdout = Zeroizing::new(output.stdout);
    let stderr = Zeroizing::new(output.stderr);
    if !output.status.success() {
        ensure!(
            String::from_utf8_lossy(&stderr).contains("Could not find requested secret"),
            "association Doppler read failed"
        );
        return Ok(None);
    }
    let value = std::str::from_utf8(&stdout)
        .map_err(|_| eyre!("association Doppler response is invalid"))?;
    Ok(Some(Zeroizing::new(value.trim().to_owned())))
}

fn decode_passphrase(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| eyre!("association passphrase encoding is invalid"))?,
    );
    ensure!(
        bytes.len() == 32,
        "association passphrase length is invalid"
    );
    let mut passphrase = Zeroizing::new([0u8; 32]);
    passphrase.copy_from_slice(&bytes);
    Ok(passphrase)
}

fn write_passphrase(encoded: &str) -> Result<()> {
    ensure!(
        read_binding(PASSPHRASE)?.is_none(),
        "association passphrase already exists"
    );
    let mut child = doppler_command()?
        .args([
            "--no-read-env",
            "--attempts",
            "1",
            "secrets",
            "set",
            PASSPHRASE,
            "--silent",
            "--no-interactive",
            "-p",
            "pays-host",
            "-c",
            CONFIG,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| eyre!("could not set association passphrase"))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("association Doppler stdin unavailable"))?
        .write_all(encoded.as_bytes());
    let status = child
        .wait()
        .map_err(|_| eyre!("association Doppler wait failed"))?;
    ensure!(
        write_result.is_ok() && status.success(),
        "association passphrase storage failed; reconcile custody"
    );
    let readback = read_binding(PASSPHRASE)?
        .ok_or_else(|| eyre!("association passphrase readback is missing"))?;
    ensure!(
        readback.as_str() == encoded,
        "association passphrase readback differs"
    );
    Ok(())
}

fn aws(args: &[&str], body: Option<File>) -> Result<Zeroizing<Vec<u8>>> {
    let output = Command::new("aws")
        .args(args)
        .args(["--region", REGION, "--output", "json", "--no-cli-pager"])
        .env_remove("DOPPLER_TOKEN")
        .env("AWS_MAX_ATTEMPTS", "1")
        .stdin(body.map(Stdio::from).unwrap_or_else(Stdio::null))
        .output()
        .map_err(|_| eyre!("could not run association AWS request"))?;
    let stdout = Zeroizing::new(output.stdout);
    let _stderr = Zeroizing::new(output.stderr);
    ensure!(
        output.status.success(),
        "association AWS request failed; reconcile custody before retrying enrollment"
    );
    Ok(stdout)
}

fn check_bucket() -> Result<()> {
    let versioning = aws(
        &["s3api", "get-bucket-versioning", "--bucket", BUCKET],
        None,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&versioning)
        .map_err(|_| eyre!("invalid association bucket versioning response"))?;
    ensure!(
        value["Status"] == "Enabled",
        "association bucket must be versioned"
    );
    let access = aws(
        &["s3api", "get-public-access-block", "--bucket", BUCKET],
        None,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&access)
        .map_err(|_| eyre!("invalid association bucket public access response"))?;
    for setting in [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ] {
        ensure!(
            value["PublicAccessBlockConfiguration"][setting] == true,
            "association bucket must block all public access"
        );
    }
    Ok(())
}

fn object_versions() -> Result<u64> {
    let output = aws(
        &[
            "s3api",
            "list-object-versions",
            "--bucket",
            BUCKET,
            "--prefix",
            OBJECT,
            "--query",
            "[length(Versions[?Key=='assoc-seed.sealed'] || `[]`), length(DeleteMarkers[?Key=='assoc-seed.sealed'] || `[]`)]",
        ],
        None,
    )?;
    let counts: Vec<u64> = serde_json::from_slice(&output)
        .map_err(|_| eyre!("invalid association version history response"))?;
    ensure!(
        counts.len() == 2,
        "invalid association version history response"
    );
    counts[0]
        .checked_add(counts[1])
        .ok_or_else(|| eyre!("association version count overflow"))
}

fn download() -> Result<Zeroizing<Vec<u8>>> {
    let head = aws(
        &["s3api", "head-object", "--bucket", BUCKET, "--key", OBJECT],
        None,
    )?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&head).map_err(|_| eyre!("invalid association object metadata"))?;
    ensure!(
        metadata["ContentLength"].as_u64() == Some(BLOB_LEN as u64),
        "association blob length is invalid"
    );
    let version = metadata["VersionId"]
        .as_str()
        .filter(|version| !version.is_empty() && *version != "null")
        .ok_or_else(|| eyre!("association object must have a version"))?;
    let mut memory = memory_file(&[])?;
    aws(
        &[
            "s3api",
            "get-object",
            "--bucket",
            BUCKET,
            "--key",
            OBJECT,
            "--version-id",
            version,
            "/proc/self/fd/0",
        ],
        Some(
            memory
                .try_clone()
                .map_err(|_| eyre!("could not duplicate association memory descriptor"))?,
        ),
    )?;
    memory
        .seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind association blob"))?;
    let mut blob = Zeroizing::new(Vec::with_capacity(BLOB_LEN));
    memory
        .take((BLOB_LEN + 1) as u64)
        .read_to_end(&mut blob)
        .map_err(|_| eyre!("could not read association blob"))?;
    ensure!(
        blob.len() == BLOB_LEN,
        "association blob readback length is invalid"
    );
    Ok(blob)
}

#[cfg(target_os = "linux")]
fn memory_file(contents: &[u8]) -> Result<File> {
    use std::os::fd::FromRawFd;
    // This anonymous kernel object has no filesystem entry. AWS receives only
    // ciphertext via stdin fd 0, opened through procfs as a seekable body.
    let fd = unsafe { libc::memfd_create(c"assoc-sealed".as_ptr(), libc::MFD_CLOEXEC) };
    ensure!(fd >= 0, "could not allocate association memory descriptor");
    // SAFETY: memfd_create returned a new descriptor, owned exclusively here.
    let mut memory = unsafe { File::from_raw_fd(fd) };
    memory
        .write_all(contents)
        .map_err(|_| eyre!("could not fill association memory descriptor"))?;
    memory
        .seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind association memory descriptor"))?;
    Ok(memory)
}

#[cfg(not(target_os = "linux"))]
fn memory_file(_contents: &[u8]) -> Result<File> {
    bail!("association custody requires Linux memory descriptors")
}

#[cfg(target_os = "linux")]
fn harden() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointer and fixed prctl arguments. Both protections
    // must succeed before any association custody material is read/generated.
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "could not disable association core dumps"
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "could not disable association process dumps"
    );
    // Fail closed rather than let raw seeds/passphrases reach swap. Operators
    // must provide sufficient RLIMIT_MEMLOCK for this CLI's working set.
    ensure!(
        unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0,
        "could not lock association custody memory"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn harden() -> Result<()> {
    bail!("association custody requires Linux")
}
