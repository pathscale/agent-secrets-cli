//! Purpose-driven split custody for Ed25519 seeds. Custody values never use local files.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    process::{Command, Stdio},
    sync::Arc,
};

use clap::Args;
use data_encoding::{BASE64, HEXLOWER};
use ed25519_dalek::SigningKey;
use crate::eyre::{Result, bail, ensure, eyre};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{doppler_command, sealed_seed};

const BUCKET: &str = "pays-signing-sealed";
const REGION: &str = "us-west-2";
// PAYSSEAL, version, purpose length, purpose, salt, nonce, seed, AEAD tag.
const BLOB_FIXED_LEN: usize = 10 + 16 + 24 + 32 + 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPurpose {
    Recovery,
    Mint,
}

impl CustodyPurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::Mint => "mint",
        }
    }

    fn config(self) -> &'static str {
        match self {
            Self::Recovery => "recoverysigning",
            Self::Mint => "mintsigning",
        }
    }

    fn signer_path(self) -> &'static str {
        match self {
            Self::Recovery => "RECOVERY_SIGNER_PATH",
            Self::Mint => "MINT_SIGNER_PATH",
        }
    }

    fn signer_sha256(self) -> &'static str {
        match self {
            Self::Recovery => "RECOVERY_SIGNER_SHA256",
            Self::Mint => "MINT_SIGNER_SHA256",
        }
    }

    fn passphrase(self) -> &'static str {
        match self {
            Self::Recovery => "PAYS_RECOVERY_SIGNING_PASSPHRASE",
            Self::Mint => "PAYS_MINT_SIGNING_PASSPHRASE",
        }
    }

    fn object(self) -> &'static str {
        match self {
            Self::Recovery => "recovery-seed.sealed",
            Self::Mint => "mint-seed.sealed",
        }
    }

    fn seed_purpose(self) -> &'static str {
        match self {
            Self::Recovery => "recovery-seed",
            Self::Mint => "mint-seed",
        }
    }

    fn blob_len(self) -> usize {
        BLOB_FIXED_LEN + self.seed_purpose().len()
    }
}

#[derive(Args)]
pub struct ExecArgs {
    /// Expected 64-character lowercase Ed25519 public key, never a private seed.
    #[arg(long)]
    public_key: String,
    /// Trusted purpose-specific signer child. Its stdin receives exactly 32 raw seed bytes and EOF.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

#[derive(Args, Default)]
pub struct MintArgs {
    /// Read a config-scoped Doppler service token from the first stdin line.
    #[arg(long)]
    doppler_token_stdin: bool,
}

#[derive(Args)]
pub struct MintExecArgs {
    /// Read a config-scoped Doppler service token from the first stdin line.
    #[arg(long)]
    doppler_token_stdin: bool,
    /// Expected 64-character lowercase Ed25519 public key, never a private seed.
    #[arg(long)]
    public_key: String,
    /// Trusted mint-only signer child. Its stdin receives exactly 32 raw seed bytes and EOF.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

struct DopplerAuth {
    token: Option<Zeroizing<String>>,
}

impl DopplerAuth {
    fn owner() -> Self {
        Self { token: None }
    }

    fn from_stdin() -> Result<Self> {
        let mut input = std::io::stdin().lock();
        let mut token = Zeroizing::new(String::with_capacity(128));
        let mut byte = [0u8; 1];
        loop {
            let count = input
                .read(&mut byte)
                .map_err(|_| eyre!("could not read Doppler service token from stdin"))?;
            if count == 0 || byte[0] == b'\n' {
                break;
            }
            ensure!(token.len() < 512, "Doppler service token line is too long");
            token.push(char::from(byte[0]));
        }
        if token.ends_with('\r') {
            token.pop();
        }
        ensure!(
            token.starts_with("dp.st.") && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "stdin must contain one Doppler service token line"
        );
        Ok(Self { token: Some(token) })
    }

    fn is_scoped(&self) -> bool {
        self.token.is_some()
    }

    fn command(&self) -> Result<Command> {
        let command = if let Some(token) = &self.token {
            let mut command = Command::new("doppler");
            command
                .env_remove("DOPPLER_TOKEN")
                .env_remove("DOPPLER_PROJECT")
                .env_remove("DOPPLER_CONFIG")
                .env_remove("DOPPLER_ENVIRONMENT")
                .env("DOPPLER_TOKEN", token.as_str());
            command
        } else {
            let mut command = doppler_command()?;
            command.env_remove("DOPPLER_TOKEN");
            command
        };
        Ok(command)
    }

    fn verify_mint_scope(&self) -> Result<()> {
        let output = self
            .command()?
            .args(["me", "--json"])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| eyre!("could not verify Doppler service token"))?;
        let stdout = Zeroizing::new(output.stdout);
        let _stderr = Zeroizing::new(output.stderr);
        ensure!(
            output.status.success(),
            "could not verify Doppler service token"
        );
        let identity: serde_json::Value = serde_json::from_slice(&stdout)
            .map_err(|_| eyre!("Doppler service token scope response is invalid"))?;
        let identity = identity.get("data").unwrap_or(&identity);
        ensure!(
            identity["type"].as_str() == Some("service_token"),
            "mint scoped mode requires a single-config Doppler service token"
        );

        for (name, expected) in [
            ("DOPPLER_PROJECT", "pays-host"),
            ("DOPPLER_CONFIG", "mintsigning"),
        ] {
            let value = read_value(CustodyPurpose::Mint, name, self, false)?
                .ok_or_else(|| eyre!("Doppler service token scope is incomplete"))?;
            ensure!(
                value.as_str() == expected,
                "mint scoped mode requires a token scoped exactly to pays-host/mintsigning"
            );
        }
        Ok(())
    }
}

fn mint_auth(use_stdin: bool) -> Result<DopplerAuth> {
    if use_stdin {
        DopplerAuth::from_stdin()
    } else {
        Ok(DopplerAuth::owner())
    }
}

fn validate_mint_auth(auth: &DopplerAuth) -> Result<()> {
    if auth.is_scoped() {
        auth.verify_mint_scope()
    } else {
        require_owner_login()
    }
}

pub fn seal(purpose: CustodyPurpose) -> Result<()> {
    harden(purpose)?;
    require_owner_login()?;
    seal_hardened(purpose, &DopplerAuth::owner())
}

pub fn mint_seal(args: MintArgs) -> Result<()> {
    let auth = mint_auth(args.doppler_token_stdin)?;
    harden(CustodyPurpose::Mint)?;
    validate_mint_auth(&auth)?;
    seal_hardened(CustodyPurpose::Mint, &auth)
}

fn seal_hardened(purpose: CustodyPurpose, auth: &DopplerAuth) -> Result<()> {
    check_config(purpose, auth)?;
    check_bucket(purpose)?;
    let stored = read_binding(purpose, purpose.passphrase(), auth)?;
    let versions = object_versions(purpose)?;
    match (versions, stored) {
        (0, None) => enroll(purpose, auth),
        (1, Some(encoded)) => {
            let passphrase = decode_passphrase(purpose, &encoded)?;
            let blob = download(purpose)?;
            let seed = sealed_seed::unseal_seed(&blob, &passphrase, purpose.seed_purpose())?;
            print_public(&SigningKey::from_bytes(&seed), false)
        }
        _ => bail!(
            "{} custody is partial or has unexpected history; reconcile before retry",
            purpose.label()
        ),
    }
}

fn enroll(purpose: CustodyPurpose, auth: &DopplerAuth) -> Result<()> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| eyre!("{} seed generation failed", purpose.label()))?;
    let signer = Arc::new(SigningKey::from_bytes(&seed));
    let passphrase = sealed_seed::generate_passphrase()?;
    let encoded = Zeroizing::new(BASE64.encode(&passphrase[..]));
    let blob = Zeroizing::new(sealed_seed::seal_seed(
        &seed,
        &passphrase,
        purpose.seed_purpose(),
    )?);
    drop(seed);

    // Conditional S3 creation arbitrates concurrent enrollments before Doppler
    // writes. A lost response or a later failure leaves partial custody closed.
    let body = memory_file(&blob, purpose)?;
    aws(
        purpose,
        &[
            "s3api",
            "put-object",
            "--bucket",
            BUCKET,
            "--key",
            purpose.object(),
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
        object_versions(purpose)? == 1,
        "{} object history changed",
        purpose.label()
    );
    ensure!(
        download(purpose)?.as_slice() == blob.as_slice(),
        "{} upload readback differs",
        purpose.label()
    );
    write_passphrase(purpose, &encoded, auth)?;

    let readback = load_signer(purpose, auth)?;
    ensure!(
        readback.verifying_key() == signer.verifying_key(),
        "{} custody readback public key differs",
        purpose.label()
    );
    print_public(&readback, false)
}

pub fn pubkey(purpose: CustodyPurpose) -> Result<()> {
    harden(purpose)?;
    require_owner_login()?;
    let signer = load_signer(purpose, &DopplerAuth::owner())?;
    print_public(&signer, purpose == CustodyPurpose::Mint)
}

pub fn mint_pubkey(args: MintArgs) -> Result<()> {
    let auth = mint_auth(args.doppler_token_stdin)?;
    harden(CustodyPurpose::Mint)?;
    validate_mint_auth(&auth)?;
    let signer = load_signer(CustodyPurpose::Mint, &auth)?;
    print_public(&signer, true)
}

pub fn exec(purpose: CustodyPurpose, args: ExecArgs) -> Result<()> {
    harden(purpose)?;
    require_owner_login()?;
    exec_hardened(purpose, args.public_key, args.command, DopplerAuth::owner())
}

pub fn mint_exec(args: MintExecArgs) -> Result<()> {
    let auth = mint_auth(args.doppler_token_stdin)?;
    harden(CustodyPurpose::Mint)?;
    validate_mint_auth(&auth)?;
    exec_hardened(CustodyPurpose::Mint, args.public_key, args.command, auth)
}

fn exec_hardened(
    purpose: CustodyPurpose,
    public_key: String,
    command: Vec<OsString>,
    auth: DopplerAuth,
) -> Result<()> {
    ensure!(
        public_key.len() == 64
            && public_key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{} public pin must be lowercase hex",
        purpose.label()
    );
    let trusted_path = read_binding(purpose, purpose.signer_path(), &auth)?
        .ok_or_else(|| eyre!("{} signer path pin is missing", purpose.label()))?;
    let trusted_hash = read_binding(purpose, purpose.signer_sha256(), &auth)?
        .ok_or_else(|| eyre!("{} signer hash pin is missing", purpose.label()))?;
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| eyre!("{} signer child is required", purpose.label()))?;
    ensure!(
        arguments.is_empty(),
        "{} signer child accepts no caller-supplied arguments",
        purpose.label()
    );
    let child = verify_pinned_child(
        trusted_path.as_str(),
        trusted_hash.as_str(),
        program,
        purpose.label(),
    )?;

    let signer = load_signer(purpose, &auth)?;
    ensure!(
        HEXLOWER.encode(signer.verifying_key().as_bytes()) == public_key,
        "{} authority does not match the public pin",
        purpose.label()
    );
    drop(auth);
    let (reader, mut writer) =
        std::io::pipe().map_err(|_| eyre!("could not create {} signer pipe", purpose.label()))?;
    let seed = Zeroizing::new(signer.to_bytes());
    // The fixed 32-byte payload fits in an empty pipe before spawning. No
    // producer process or write descriptor survives exec, so the child sees EOF.
    writer
        .write_all(&seed[..])
        .map_err(|_| eyre!("could not fill {} signer pipe", purpose.label()))?;
    drop(writer);
    drop(seed);
    drop(signer);
    execute_pinned_child(child, reader, purpose.label())
}

pub(crate) struct PinnedChild {
    #[cfg(target_os = "linux")]
    file: File,
    #[cfg(target_os = "linux")]
    path: String,
}

fn validate_pinned_command(
    path: &str,
    expected_hash: &str,
    requested: &OsStr,
    label: &str,
) -> Result<()> {
    ensure!(
        path.starts_with('/')
            && path.as_bytes().iter().all(|byte| *byte != 0)
            && requested == OsStr::new(path),
        "{} signer command must exactly match its configured absolute path",
        label
    );
    ensure!(
        expected_hash.len() == 64
            && expected_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{} signer hash pin must be 64 lowercase hex characters",
        label
    );

    ensure!(
        !path
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == ".."),
        "{} signer path contains an invalid component",
        label
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_pinned_child(
    path: &str,
    expected_hash: &str,
    requested: &OsStr,
    label: &str,
) -> Result<PinnedChild> {
    use std::{
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, Path},
    };

    validate_pinned_command(path, expected_hash, requested, label)?;

    let mut components = Path::new(path).components();
    ensure!(
        matches!(components.next(), Some(Component::RootDir)),
        "{} signer path must be absolute",
        label
    );
    let mut parts = Vec::new();
    for component in components {
        match component {
            Component::Normal(part) => parts.push(part.to_os_string()),
            _ => bail!("{} signer path contains an invalid component", label),
        }
    }
    let filename = parts
        .pop()
        .ok_or_else(|| eyre!("{} signer path has no filename", label))?;

    let root = File::open("/").map_err(|_| eyre!("could not open {} signer path root", label))?;
    let mut parent = root;
    for part in parts {
        let metadata = parent
            .metadata()
            .map_err(|_| eyre!("could not inspect {} signer parent", label))?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "{} signer parent must be a root-owned directory without group or other write bits",
            label
        );
        let name = std::ffi::CString::new(part.as_bytes())
            .map_err(|_| eyre!("{} signer path contains a NUL byte", label))?;
        // SAFETY: name is NUL-terminated and parent is an open directory.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        ensure!(
            fd >= 0,
            "{} signer parent could not be opened safely",
            label
        );
        // SAFETY: openat returned a new descriptor owned exclusively here.
        parent = unsafe { File::from_raw_fd(fd) };
    }

    let parent_metadata = parent
        .metadata()
        .map_err(|_| eyre!("could not inspect {} signer parent", label))?;
    ensure!(
        parent_metadata.is_dir()
            && parent_metadata.uid() == 0
            && parent_metadata.mode() & 0o022 == 0,
        "{} signer parent must be a root-owned directory without group or other write bits",
        label
    );
    let filename = std::ffi::CString::new(filename.as_bytes())
        .map_err(|_| eyre!("{} signer path contains a NUL byte", label))?;
    // SAFETY: filename is NUL-terminated and parent is an open directory.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            filename.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    ensure!(fd >= 0, "{} signer file could not be opened safely", label);
    // SAFETY: openat returned a new descriptor owned exclusively here.
    let mut file = unsafe { File::from_raw_fd(fd) };
    drop(parent);

    let metadata = file
        .metadata()
        .map_err(|_| eyre!("could not inspect {} signer file", label))?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0,
        "{} signer must be a root-owned regular file without group or other write bits",
        label
    );

    let mut magic = [0u8; 4];
    let count = file
        .read(&mut magic)
        .map_err(|_| eyre!("could not inspect {} signer format", label))?;
    ensure!(
        count == magic.len() && magic == *b"\x7fELF",
        "{} signer must be a binary executable, not an interpreter script",
        label
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind {} signer", label))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| eyre!("could not hash {} signer", label))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    ensure!(
        HEXLOWER.encode(&hasher.finalize()) == expected_hash,
        "{} signer hash pin does not match",
        label
    );
    file.seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind {} signer", label))?;
    Ok(PinnedChild {
        file,
        path: path.to_owned(),
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn verify_pinned_child(
    path: &str,
    expected_hash: &str,
    requested: &OsStr,
    label: &str,
) -> Result<PinnedChild> {
    validate_pinned_command(path, expected_hash, requested, label)?;
    bail!("{} custody requires Linux", label)
}

#[cfg(target_os = "linux")]
pub(crate) fn execute_pinned_child(
    child: PinnedChild,
    reader: std::io::PipeReader,
    label: &str,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt},
    };

    // A closed standard stream can make one of the sources occupy fd 0, 1 or 2.
    fn above_stdio(fd: OwnedFd) -> std::io::Result<OwnedFd> {
        if fd.as_raw_fd() > libc::STDERR_FILENO {
            return Ok(fd);
        }
        // SAFETY: fd is open and fcntl returns a new descriptor on success.
        let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if copy < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: copy is a newly allocated descriptor owned exclusively here.
        Ok(unsafe { OwnedFd::from_raw_fd(copy) })
    }

    let path = std::ffi::CString::new(child.path.as_bytes())
        .map_err(|_| eyre!("{} signer path contains a NUL byte", label))?;
    let argv = [path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    let executable = above_stdio(child.file.into())
        .map_err(|_| eyre!("could not retain {} signer executable", label))?;
    let reader = above_stdio(reader.into())
        .map_err(|_| eyre!("could not retain {} signer pipe", label))?;

    // SAFETY: the path is NUL-terminated and these flags require no mode argument.
    let fd = unsafe {
        libc::open(
            c"/dev/null".as_ptr(),
            libc::O_WRONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY,
        )
    };
    ensure!(fd >= 0, "could not open {} signer output sink", label);
    // SAFETY: open returned a new descriptor owned exclusively here.
    let sink = unsafe { File::from_raw_fd(fd) };
    let metadata = sink
        .metadata()
        .map_err(|_| eyre!("could not inspect {} signer output sink", label))?;
    // Verify the opened device before routing either stream to it.
    ensure!(
        metadata.file_type().is_char_device()
            && libc::major(metadata.rdev()) == 1
            && libc::minor(metadata.rdev()) == 3,
        "invalid {} signer output sink",
        label
    );
    let sink = above_stdio(sink.into())
        .map_err(|_| eyre!("could not retain {} signer output sink", label))?;

    // Keep the CLI's diagnostic available on failure. The copy closes on exec.
    // SAFETY: fcntl checks whether stderr is open and duplicates it on success.
    let fd = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    let saved_stderr = if fd >= 0 {
        // SAFETY: fd is a newly allocated descriptor owned exclusively here.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    } else {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
            "could not save {} signer launch diagnostics",
            label
        );
        None
    };

    // SAFETY: the pipe is open and distinct from stdin. dup2 clears close-on-exec.
    ensure!(
        unsafe { libc::dup2(reader.as_raw_fd(), libc::STDIN_FILENO) } >= 0,
        "could not connect {} signer pipe",
        label
    );
    // SAFETY: dup2 installed the pipe on stdin. Close it if launch fails.
    let _stdin = unsafe { OwnedFd::from_raw_fd(libc::STDIN_FILENO) };
    drop(reader);

    // Redirect stderr last so any setup failure can still use the CLI's diagnostics.
    for stream in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: the sink is open and distinct from both output descriptors.
        ensure!(
            unsafe { libc::dup2(sink.as_raw_fd(), stream) } >= 0,
            "could not discard {} signer output",
            label
        );
    }

    drop(sink);

    // Run the same inode that was verified, with an empty environment.
    // SAFETY: the executable is open and argv/envp are NUL-terminated.
    unsafe { libc::fexecve(executable.as_raw_fd(), argv.as_ptr(), envp.as_ptr()) };
    if let Some(stderr) = saved_stderr {
        // SAFETY: stderr is an owned copy of the original output descriptor.
        while unsafe { libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
    }
    bail!("could not execute {} signer child", label)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn execute_pinned_child(
    _child: PinnedChild,
    _reader: std::io::PipeReader,
    label: &str,
) -> Result<()> {
    bail!("{} custody requires Linux", label)
}

fn load_signer(purpose: CustodyPurpose, auth: &DopplerAuth) -> Result<Arc<SigningKey>> {
    check_config(purpose, auth)?;
    check_bucket(purpose)?;
    let encoded = read_binding(purpose, purpose.passphrase(), auth)?
        .ok_or_else(|| eyre!("{} passphrase is missing", purpose.label()))?;
    let passphrase = decode_passphrase(purpose, &encoded)?;
    let blob = download(purpose)?;
    let seed = sealed_seed::unseal_seed(&blob, &passphrase, purpose.seed_purpose())?;
    Ok(Arc::new(SigningKey::from_bytes(&seed)))
}

fn print_public(signer: &SigningKey, include_address: bool) -> Result<()> {
    let public = HEXLOWER.encode(signer.verifying_key().as_bytes());
    crate::output::line(&public)?;
    if include_address {
        crate::output::line(&base58_address(signer.verifying_key().as_bytes()))?;
    }
    Ok(())
}

fn base58_address(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let leading_zeroes = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = [0u8; 45];
    let mut length = 0;
    for byte in &bytes[leading_zeroes..] {
        let mut carry = u32::from(*byte);
        for digit in &mut digits[..length] {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry != 0 {
            digits[length] = (carry % 58) as u8;
            carry /= 58;
            length += 1;
        }
    }
    let mut address = String::with_capacity(leading_zeroes + length);
    address.extend(std::iter::repeat_n('1', leading_zeroes));
    address.extend(
        digits[..length]
            .iter()
            .rev()
            .map(|digit| ALPHABET[*digit as usize] as char),
    );
    address
}

fn require_owner_login() -> Result<()> {
    ensure!(
        std::env::var_os("DOPPLER_TOKEN").is_none(),
        "unset DOPPLER_TOKEN and use the owner HOME-scoped login"
    );
    Ok(())
}

fn check_config(purpose: CustodyPurpose, auth: &DopplerAuth) -> Result<()> {
    // A branch of prd would report environment prd. Require the independent
    // environment and its root config, both named for this custody purpose.
    for (name, expected) in [
        ("DOPPLER_ENVIRONMENT", purpose.config()),
        ("DOPPLER_CONFIG", purpose.config()),
    ] {
        let value = read_value(purpose, name, auth, false)?
            .ok_or_else(|| eyre!("{} config metadata is missing", purpose.label()))?;
        ensure!(
            value.as_str() == expected,
            "{} config must be an isolated root environment",
            purpose.label()
        );
    }
    Ok(())
}

fn read_binding(
    purpose: CustodyPurpose,
    name: &str,
    auth: &DopplerAuth,
) -> Result<Option<Zeroizing<String>>> {
    read_value(purpose, name, auth, true)
}

/// Doppler computes DOPPLER_PROJECT and DOPPLER_CONFIG; their raw values are empty, so the
/// scope check reads them computed.
fn read_value(
    purpose: CustodyPurpose,
    name: &str,
    auth: &DopplerAuth,
    raw: bool,
) -> Result<Option<Zeroizing<String>>> {
    let mut args = vec!["secrets", "get", name, "--plain"];
    if raw {
        args.push("--raw");
    }
    let output = auth
        .command()?
        .args(args)
        .args(["-p", "pays-host", "-c", purpose.config()])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| eyre!("could not read {} Doppler binding", purpose.label()))?;
    let stdout = Zeroizing::new(output.stdout);
    let stderr = Zeroizing::new(output.stderr);
    if !output.status.success() {
        ensure!(
            String::from_utf8_lossy(&stderr).contains("Could not find requested secret"),
            "{} Doppler read failed",
            purpose.label()
        );
        return Ok(None);
    }
    let value = std::str::from_utf8(&stdout)
        .map_err(|_| eyre!("{} Doppler response is invalid", purpose.label()))?;
    Ok(Some(Zeroizing::new(value.trim().to_owned())))
}

fn decode_passphrase(purpose: CustodyPurpose, encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        BASE64
            .decode(encoded.as_bytes())
            .map_err(|_| eyre!("{} passphrase encoding is invalid", purpose.label()))?,
    );
    ensure!(
        bytes.len() == 32,
        "{} passphrase length is invalid",
        purpose.label()
    );
    let mut passphrase = Zeroizing::new([0u8; 32]);
    passphrase.copy_from_slice(&bytes);
    Ok(passphrase)
}

fn write_passphrase(purpose: CustodyPurpose, encoded: &str, auth: &DopplerAuth) -> Result<()> {
    ensure!(
        read_binding(purpose, purpose.passphrase(), auth)?.is_none(),
        "{} passphrase already exists",
        purpose.label()
    );
    let mut command = auth.command()?;
    if !auth.is_scoped() {
        command.arg("--no-read-env");
    }
    let mut child = command
        .args([
            "--attempts",
            "1",
            "secrets",
            "set",
            purpose.passphrase(),
            "--silent",
            "--no-interactive",
            "-p",
            "pays-host",
            "-c",
            purpose.config(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| eyre!("could not set {} passphrase", purpose.label()))?;
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("{} Doppler stdin unavailable", purpose.label()))?
        .write_all(encoded.as_bytes());
    let status = child
        .wait()
        .map_err(|_| eyre!("{} Doppler wait failed", purpose.label()))?;
    ensure!(
        write_result.is_ok() && status.success(),
        "{} passphrase storage failed; reconcile custody",
        purpose.label()
    );
    let readback = read_binding(purpose, purpose.passphrase(), auth)?
        .ok_or_else(|| eyre!("{} passphrase readback is missing", purpose.label()))?;
    ensure!(
        readback.as_str() == encoded,
        "{} passphrase readback differs",
        purpose.label()
    );
    Ok(())
}

fn aws(purpose: CustodyPurpose, args: &[&str], body: Option<File>) -> Result<Zeroizing<Vec<u8>>> {
    let output = Command::new("aws")
        .args(args)
        .args(["--region", REGION, "--output", "json", "--no-cli-pager"])
        .env_remove("DOPPLER_TOKEN")
        .env("AWS_MAX_ATTEMPTS", "1")
        .stdin(body.map(Stdio::from).unwrap_or_else(Stdio::null))
        .output()
        .map_err(|_| eyre!("could not run {} AWS request", purpose.label()))?;
    let stdout = Zeroizing::new(output.stdout);
    let _stderr = Zeroizing::new(output.stderr);
    ensure!(
        output.status.success(),
        "{} AWS request failed; reconcile custody before retrying enrollment",
        purpose.label()
    );
    Ok(stdout)
}

fn check_bucket(purpose: CustodyPurpose) -> Result<()> {
    let versioning = aws(
        purpose,
        &["s3api", "get-bucket-versioning", "--bucket", BUCKET],
        None,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&versioning)
        .map_err(|_| eyre!("invalid {} bucket versioning response", purpose.label()))?;
    ensure!(
        value["Status"] == "Enabled",
        "{} bucket must be versioned",
        purpose.label()
    );
    let access = aws(
        purpose,
        &["s3api", "get-public-access-block", "--bucket", BUCKET],
        None,
    )?;
    let value: serde_json::Value = serde_json::from_slice(&access)
        .map_err(|_| eyre!("invalid {} bucket public access response", purpose.label()))?;
    for setting in [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ] {
        ensure!(
            value["PublicAccessBlockConfiguration"][setting] == true,
            "{} bucket must block all public access",
            purpose.label()
        );
    }
    Ok(())
}

fn object_versions(purpose: CustodyPurpose) -> Result<u64> {
    let object = purpose.object();
    let query = format!(
        "[length(Versions[?Key=='{object}'] || `[]`), \
         length(DeleteMarkers[?Key=='{object}'] || `[]`)]"
    );
    let output = aws(
        purpose,
        &[
            "s3api",
            "list-object-versions",
            "--bucket",
            BUCKET,
            "--prefix",
            object,
            "--query",
            query.as_str(),
        ],
        None,
    )?;
    let counts: Vec<u64> = serde_json::from_slice(&output)
        .map_err(|_| eyre!("invalid {} version history response", purpose.label()))?;
    ensure!(
        counts.len() == 2,
        "invalid {} version history response",
        purpose.label()
    );
    counts[0]
        .checked_add(counts[1])
        .ok_or_else(|| eyre!("{} version count overflow", purpose.label()))
}

fn download(purpose: CustodyPurpose) -> Result<Zeroizing<Vec<u8>>> {
    let blob_len = purpose.blob_len();
    let object = purpose.object();
    let head = aws(
        purpose,
        &["s3api", "head-object", "--bucket", BUCKET, "--key", object],
        None,
    )?;
    let metadata: serde_json::Value = serde_json::from_slice(&head)
        .map_err(|_| eyre!("invalid {} object metadata", purpose.label()))?;
    ensure!(
        metadata["ContentLength"].as_u64() == Some(blob_len as u64),
        "{} blob length is invalid",
        purpose.label()
    );
    let version = metadata["VersionId"]
        .as_str()
        .filter(|version| !version.is_empty() && *version != "null")
        .ok_or_else(|| eyre!("{} object must have a version", purpose.label()))?;
    let mut memory = memory_file(&[], purpose)?;
    aws(
        purpose,
        &[
            "s3api",
            "get-object",
            "--bucket",
            BUCKET,
            "--key",
            object,
            "--version-id",
            version,
            "/proc/self/fd/0",
        ],
        Some(
            memory
                .try_clone()
                .map_err(|_| eyre!("could not duplicate {} memory descriptor", purpose.label()))?,
        ),
    )?;
    memory
        .seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind {} blob", purpose.label()))?;
    let mut blob = Zeroizing::new(Vec::with_capacity(blob_len));
    memory
        .take((blob_len + 1) as u64)
        .read_to_end(&mut blob)
        .map_err(|_| eyre!("could not read {} blob", purpose.label()))?;
    ensure!(
        blob.len() == blob_len,
        "{} blob readback length is invalid",
        purpose.label()
    );
    Ok(blob)
}

#[cfg(target_os = "linux")]
fn memory_file(contents: &[u8], purpose: CustodyPurpose) -> Result<File> {
    use std::os::fd::FromRawFd;
    // This anonymous kernel object has no filesystem entry. AWS receives only
    // ciphertext via stdin fd 0, opened through procfs as a seekable body.
    let fd = unsafe { libc::memfd_create(c"split-custody-sealed".as_ptr(), libc::MFD_CLOEXEC) };
    ensure!(
        fd >= 0,
        "could not allocate {} memory descriptor",
        purpose.label()
    );
    // SAFETY: memfd_create returned a new descriptor, owned exclusively here.
    let mut memory = unsafe { File::from_raw_fd(fd) };
    memory
        .write_all(contents)
        .map_err(|_| eyre!("could not fill {} memory descriptor", purpose.label()))?;
    memory
        .seek(SeekFrom::Start(0))
        .map_err(|_| eyre!("could not rewind {} memory descriptor", purpose.label()))?;
    Ok(memory)
}

#[cfg(not(target_os = "linux"))]
fn memory_file(_contents: &[u8], purpose: CustodyPurpose) -> Result<File> {
    bail!(
        "{} custody requires Linux memory descriptors",
        purpose.label()
    )
}

#[cfg(target_os = "linux")]
fn harden(purpose: CustodyPurpose) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointer and fixed prctl arguments. Both protections
    // must succeed before custody material is read or generated.
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "could not disable {} core dumps",
        purpose.label()
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "could not disable {} process dumps",
        purpose.label()
    );
    // Fail closed rather than let raw seeds/passphrases reach swap. Operators
    // must provide sufficient RLIMIT_MEMLOCK for this CLI's working set.
    ensure!(
        unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0,
        "could not lock {} custody memory",
        purpose.label()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn harden(purpose: CustodyPurpose) -> Result<()> {
    bail!("{} custody requires Linux", purpose.label())
}

#[cfg(test)]
mod signer_policy_tests {
    use super::*;

    #[test]
    fn command_and_digest_pins_are_exact_and_fail_closed() {
        let hash = "ab".repeat(32);
        assert!(
            validate_pinned_command(
                "/usr/bin/signer",
                &hash,
                OsStr::new("/usr/bin/signer"),
                "test"
            )
            .is_ok()
        );
        for path in [
            "signer",
            "/usr/../signer",
            "/usr/./signer",
            "/usr//signer",
            "/usr/bin/",
            "/",
            "/usr/bin/si\0gner",
        ] {
            assert!(validate_pinned_command(path, &hash, OsStr::new(path), "test").is_err());
        }
        for bad in ["", "abc", &"AB".repeat(32), &"gg".repeat(32)] {
            assert!(
                validate_pinned_command(
                    "/usr/bin/signer",
                    bad,
                    OsStr::new("/usr/bin/signer"),
                    "test"
                )
                .is_err()
            );
        }
        assert!(
            validate_pinned_command(
                "/usr/bin/signer",
                &hash,
                OsStr::new("/usr/bin/other"),
                "test"
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_signer_output_and_status() {
        use std::os::unix::process::ExitStatusExt;

        const FIXTURE: &str = "AGENT_SECRETS_CLI_SIGNER_OUTPUT_FIXTURE";
        const EXIT_SCRIPT: &[u8; 32] = b"set -e;echo ZX;echo ZY>&2;exit 7";
        const SIGNAL_SCRIPT: &[u8; 32] = b"kill -TERM $$ # fixture padding\n";
        const DIAGNOSTIC: &[u8] = b"error: command failed";

        // Run the production launcher in a subprocess because it replaces
        // the process and rewires its standard descriptors.
        if let Ok(mode) = std::env::var(FIXTURE) {
            let (program, input) = match mode.as_str() {
                "exit" | "closed-stdio" => ("/bin/sh", EXIT_SCRIPT),
                "signal" => ("/bin/sh", SIGNAL_SCRIPT),
                "invalid" => ("/dev/null", EXIT_SCRIPT),
                _ => panic!("unknown signer fixture mode"),
            };
            if mode == "closed-stdio" {
                // SAFETY: only this subprocess's standard descriptors are closed.
                unsafe {
                    libc::close(libc::STDIN_FILENO);
                    libc::close(libc::STDOUT_FILENO);
                    libc::close(libc::STDERR_FILENO);
                }
            }

            // Supply a local executable descriptor and synthetic seed bytes.
            let child = PinnedChild {
                file: File::open(program).unwrap(),
                path: program.into(),
            };
            let (reader, mut writer) = std::io::pipe().unwrap();
            writer.write_all(input).unwrap();
            drop(writer);

            assert!(execute_pinned_child(child, reader, "fixture").is_err());
            assert_eq!(mode, "invalid");
            crate::output::status("error: command failed");
            std::process::exit(1);
        }

        for (mode, code, signal) in [
            ("exit", Some(7), None),
            ("closed-stdio", Some(7), None),
            ("signal", None, Some(libc::SIGTERM)),
            ("invalid", Some(1), None),
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "split_custody::signer_policy_tests::pinned_signer_output_and_status",
                ])
                .env(FIXTURE, mode)
                .output()
                .unwrap();

            assert_eq!(output.status.code(), code, "{mode}");
            assert_eq!(output.status.signal(), signal, "{mode}");
            for stream in [&output.stdout, &output.stderr] {
                assert!(
                    !stream
                        .windows(3)
                        .any(|bytes| bytes == b"ZX\n" || bytes == b"ZY\n"),
                    "{mode} leaked signer output"
                );
            }
            assert_eq!(
                output
                    .stderr
                    .windows(DIAGNOSTIC.len())
                    .any(|bytes| bytes == DIAGNOSTIC),
                mode == "invalid",
                "{mode}"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_refuses_custody_execution() {
        assert!(
            verify_pinned_child(
                "/usr/bin/signer",
                &"ab".repeat(32),
                OsStr::new("/usr/bin/signer"),
                "test"
            )
            .is_err()
        );
    }
}
