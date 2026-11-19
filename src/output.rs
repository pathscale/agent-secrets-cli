use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use crate::eyre::{Result, eyre};

static SAFE: AtomicBool = AtomicBool::new(false);
static SECRETS: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();

pub fn set_safe(safe: bool) {
    SAFE.store(safe, Ordering::Relaxed);
}

pub fn register_secret(value: &[u8]) {
    if value.len() >= 8 {
        SECRETS
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .push(value.to_vec());
    }
}

/// Run an operation that requires public stdout after checking the destination.
pub fn with_public_output<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    with_checked_destination(SAFE.load(Ordering::Relaxed), stdout_is_regular_file()?, action)
}

/// Refuse before any side effect when the command's public report could not be written.
pub fn require_public_output() -> Result<()> {
    with_public_output(|| Ok(()))
}

fn with_checked_destination<T>(
    safe: bool,
    regular_file: bool,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    check_destination(safe, regular_file)?;
    action()
}

pub fn line(text: &str) -> Result<()> {
    let secrets = SECRETS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    check(
        text,
        SAFE.load(Ordering::Relaxed),
        stdout_is_regular_file()?,
        &secrets,
    )?;
    write_stdout(format!("{text}\n").as_bytes())
}

/// Validate every line before writing the batch with trusted newline separators.
pub fn batch_lines(lines: &[String]) -> Result<()> {
    let secrets = SECRETS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let safe = SAFE.load(Ordering::Relaxed);
    let regular_file = stdout_is_regular_file()?;
    let mut buffer = String::new();
    for line in lines {
        check(line, safe, regular_file, &secrets)?;
        buffer.push_str(line);
        buffer.push('\n');
    }
    check_secrets(&buffer, &secrets)?;
    write_stdout(buffer.as_bytes())
}

/// Write tab-separated fields with trusted tab delimiters. Each field still
/// passes the same control-character and secret checks as an ordinary line.
pub fn tsv_line(fields: &[&str]) -> Result<()> {
    let secrets = SECRETS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    check_tsv(
        fields,
        SAFE.load(Ordering::Relaxed),
        stdout_is_regular_file()?,
        &secrets,
    )?;
    write_stdout(format!("{}\n", fields.join("\t")).as_bytes())
}

/// Validate fields independently so only the separators added by `tsv_line`
/// may contain tabs.
fn check_tsv(fields: &[&str], safe: bool, regular_file: bool, secrets: &[Vec<u8>]) -> Result<()> {
    check("", safe, regular_file, secrets)?;
    for field in fields {
        check(field, safe, regular_file, secrets)?;
    }
    check_secrets(&fields.join("\t"), secrets)
}

/// The whole stdout policy, as a pure decision so it is testable without
/// touching the process-wide flag or the real stdout.
fn check(text: &str, safe: bool, regular_file: bool, secrets: &[Vec<u8>]) -> Result<()> {
    check_destination(safe, regular_file)?;
    if text.chars().any(char::is_control) {
        return Err(eyre!("refused output"));
    }
    check_secrets(text, secrets)
}

fn check_destination(safe: bool, regular_file: bool) -> Result<()> {
    if !safe || regular_file {
        return Err(eyre!("refused output"));
    }
    Ok(())
}

fn check_secrets(text: &str, secrets: &[Vec<u8>]) -> Result<()> {
    for secret in secrets {
        if encoded_forms(secret)
            .iter()
            .any(|form| text.as_bytes().windows(form.len()).any(|w| w == form))
        {
            return Err(eyre!("refused output"));
        }
    }
    Ok(())
}

pub fn status(text: &'static str) {
    let _ = write_stderr(format!("{text}\n").as_bytes());
}

/// Emit the non-secret documentation roadmap directly to stdout before any secrets
/// are loaded. Broken pipes (such as `agent-secrets-cli --roadmap | head`) succeed.
pub fn roadmap(bytes: &[u8]) -> Result<()> {
    match write_stdout_raw(bytes) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(_) => Err(eyre!("output failed")),
    }
}

pub(crate) fn panic_location(location: Option<&std::panic::Location<'_>>) {
    const MESSAGE: &str = "agent-secrets-cli: internal error";
    if let Some(location) = location {
        let basename = location.file().rsplit(['/', '\\']).next().unwrap_or("");
        if !basename.is_empty()
            && basename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            let _ = write_stderr(
                format!("{MESSAGE} ({basename}:{})\n", location.line()).as_bytes(),
            );
            return;
        }
    }
    status(MESSAGE);
}

#[allow(clippy::disallowed_methods)]
fn write_stdout_raw(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(bytes).and_then(|()| out.flush())
}

fn write_stdout(bytes: &[u8]) -> Result<()> {
    write_stdout_raw(bytes).map_err(|_| eyre!("output failed"))
}

#[allow(clippy::disallowed_methods)]
fn write_stderr(bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    std::io::stderr()
        .lock()
        .write_all(bytes)
        .map_err(|_| eyre!("output failed"))
}

/// A regular file behind stdout means shell redirection straight to disk.
#[allow(clippy::disallowed_methods)]
fn stdout_is_regular_file() -> Result<bool> {
    use std::os::fd::AsFd;
    let duplicate = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| eyre!("refused output"))?;
    let metadata = std::fs::File::from(duplicate)
        .metadata()
        .map_err(|_| eyre!("refused output"))?;
    Ok(metadata.file_type().is_file())
}

fn encoded_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
    let raw = String::from_utf8_lossy(secret).into_owned();
    let mut forms = vec![
        secret.to_vec(),
        BASE64.encode(secret).into_bytes(),
        BASE64_NOPAD.encode(secret).into_bytes(),
        BASE64URL.encode(secret).into_bytes(),
        BASE64URL_NOPAD.encode(secret).into_bytes(),
    ];
    let hex = secret
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    forms.push(hex.as_bytes().to_vec());
    forms.push(hex.to_uppercase().into_bytes());
    forms.push(serde_json::to_string(&raw).unwrap().into_bytes());
    let mut percent = Vec::new();
    for byte in secret {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(byte) {
            percent.push(*byte);
        } else {
            percent.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    forms.push(percent);
    forms
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"secret-value-123";

    #[test]
    fn public_output_preflight_gates_creator() {
        for (safe, regular_file, allowed) in [
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let mut called = false;
            let result = with_checked_destination(safe, regular_file, || {
                called = true;
                Ok(42)
            });

            assert_eq!(called, allowed, "safe={safe}, regular_file={regular_file}");
            if allowed {
                assert_eq!(result.unwrap(), 42);
            } else {
                assert_eq!(result.unwrap_err().to_string(), "refused output");
            }
        }
    }

    #[test]
    fn refuses_without_safe() {
        assert!(check("public", false, false, &[]).is_err());
    }
    #[test]
    fn refuses_a_regular_file() {
        assert!(check("public", true, true, &[]).is_err());
    }
    #[test]
    fn refuses_a_newline() {
        assert!(check("one\ntwo", true, false, &[]).is_err());
    }
    #[test]
    fn refuses_secret_encodings() {
        let secrets = [SECRET.to_vec()];
        for text in [
            "secret-value-123",
            "c2VjcmV0LXZhbHVlLTEyMw==",
            "7365637265742d76616c75652d313233",
            "\"secret-value-123\"",
        ] {
            assert!(check(text, true, false, &secrets).is_err(), "{text}");
        }
    }

    #[test]
    fn creation_report_allows_public_id_but_refuses_registered_credential() {
        let secrets = [b"callback-secret-value".to_vec()];
        assert!(
            check(
                "created sample as public-app-id-123456",
                true,
                false,
                &secrets
            )
            .is_ok()
        );
        assert!(
            check(
                "created sample with callback-secret-value",
                true,
                false,
                &secrets
            )
            .is_err()
        );
    }

    #[test]
    fn allows_public_text_to_a_pipe() {
        assert!(check("public output", true, false, &[SECRET.to_vec()]).is_ok());
    }

    #[test]
    fn allows_tsv_with_trusted_tab_separators() {
        assert!(check_tsv(&["public-123", "alice", "AppAdmin,User"], true, false, &[],).is_ok());
    }

    #[test]
    fn refuses_control_characters_inside_tsv_fields() {
        for field in ["public\t123", "alice\nother"] {
            assert!(check_tsv(&[field, "alice", "User"], true, false, &[]).is_err());
        }
    }

    #[test]
    fn empty_tsv_still_requires_output_permission() {
        assert!(check_tsv(&[], false, false, &[]).is_err());
        assert!(check_tsv(&[], true, true, &[]).is_err());
    }

    #[test]
    fn refuses_secret_spanning_tsv_fields() {
        assert!(
            check_tsv(
                &["secret", "value"],
                true,
                false,
                &[b"secret\tvalue".to_vec()]
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_secret_encodings_inside_tsv_fields() {
        assert!(
            check_tsv(
                &["public-123", "alice", "secret-value-123"],
                true,
                false,
                &[SECRET.to_vec()],
            )
            .is_err()
        );
    }
}
