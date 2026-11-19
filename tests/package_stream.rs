//! Signing stream fixtures contain no real credentials or custody material.
#![allow(clippy::disallowed_methods)]
pub(crate) use endpoint_libs::eyre;

#[allow(dead_code)]
#[path = "../src/sealed_seed.rs"]
mod sealed_seed;

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn package_sign_reads_only_s3_object_bytes_and_rejects_extra_output() {
    let root = std::env::temp_dir().join(format!("package-stream-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    fs::create_dir(root.join("keys")).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    fs::write(
        root.join("keys/package-signing.pub"),
        format!(
            "{}\n",
            data_encoding::HEXLOWER.encode(&key.verifying_key().to_bytes())
        ),
    )
    .unwrap();
    fs::write(
        root.join("blob"),
        sealed_seed::seal_seed(&[7; 32], &[11; 32], "package-seed").unwrap(),
    )
    .unwrap();
    fs::write(root.join("artifact.deb"), b"public package fixture").unwrap();
    let scripts = [
        (
            "doppler",
            format!(
                r#"#!/bin/sh
touch provider-called
[ "$1" = --scope ] && [ "$2" = "$HOME" ] || exit 90
shift 2
case "$*" in
'secrets get PAYS_PACKAGE_SIGNING_PASSPHRASE --plain -p pays-host -c signing') printf '%s' '{}' ;;
'secrets get AWS_PACKAGE_SIGNING_ROLE_ARN --plain -p pays-host -c signing') printf '%s' 'arn:aws:iam::123456789012:role/fixture-package-signing' ;;
*) exit 91 ;;
esac
"#,
                data_encoding::BASE64.encode(&[11; 32])
            ),
        ),
        (
            "curl",
            "#!/bin/sh\ntouch provider-called\ncat >/dev/null\nprintf '%s' '{\"value\":\"fixture.oidc.token\"}'\n"
                .to_owned(),
        ),
        (
            "aws",
            r#"#!/bin/sh
touch provider-called
case "$1 $2" in
'sts assume-role-with-web-identity')
    [ "$3" = --role-arn ] && [ "$5" = --role-session-name ] &&
    [ "$7" = --web-identity-token ] && [ "$8" = file:///dev/stdin ] &&
    [ "$9" = --duration-seconds ] || exit 93
    [ "$(cat)" = fixture.oidc.token ] || exit 94
    printf 'fixture-access\tfixture-secret\tfixture-session\n' ;;
's3api head-object') wc -c < blob ;;
's3api get-object') cat blob; printf '{"ContentLength":100}\n' ;;
's3 cp') cat blob; [ ! -f extra-output ] || printf '{"ContentLength":100}\n'; exit 0 ;;
*) exit 92 ;;
esac
"#
            .to_owned(),
        ),
    ];
    for (name, script) in scripts {
        fs::write(root.join(name), script).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let run = |files: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"));
        command.args(["--safe", "package-sign"]);
        for file in files {
            command.args(["--domain", "package", "--file", file]);
        }
        command
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
            .env("HOME", &root)
            .env(
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://fixture.invalid/oidc",
            )
            .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fixture-request-token")
            .current_dir(&root)
            .output()
    };
    let output = run(&["artifact.deb"]).unwrap();
    assert!(
        output.status.success(),
        "synthetic package signing must succeed"
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let (encoded, path) = text.trim().split_once(' ').unwrap();
    assert_eq!(path, "artifact.deb.sig");
    let signature = ed25519_dalek::Signature::from_slice(
        &data_encoding::BASE64.decode(encoded.as_bytes()).unwrap(),
    )
    .unwrap();
    use ed25519_dalek::Verifier;
    key.verifying_key().verify(b"pays-artifact-sign-v1\ndomain:package\nname:artifact.deb\nlength:22\npublic package fixture", &signature).unwrap();
    assert!(!root.join("artifact.deb.sig").exists());
    fs::write(root.join("extra-output"), b"").unwrap();
    let rejected = run(&["artifact.deb"]).unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());

    fs::create_dir(root.join("tab\tparent")).unwrap();
    fs::write(root.join("second.deb"), b"second artifact").unwrap();
    fs::remove_file(root.join("provider-called")).unwrap();
    let malformed = run(&["artifact.deb", "tab\tparent/../second.deb"]).unwrap();
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("signature output path"));
    assert!(malformed.stdout.is_empty());
    assert!(!root.join("provider-called").exists());
}

#[test]
fn fixture_signing_preflights_public_key_and_preserves_spaces() {
    let root = std::env::temp_dir().join(format!("package-fixture-stream-{}", std::process::id()));
    fs::create_dir_all(root.join("folder with spaces")).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    fs::write(
        root.join("folder with spaces/artifact.deb"),
        b"fixture with spaces",
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_agent-secrets-cli");
    let bad = Command::new(binary)
        .args([
            "--safe",
            "package-sign-fixture",
            "--domain",
            "package",
            "--file",
            "folder with spaces/artifact.deb",
            "--public-key",
            "bad\u{0085}key.pub",
        ])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("public key output path"));
    assert!(bad.stdout.is_empty());
    assert!(!root.join("bad\u{0085}key.pub").exists());

    let valid = Command::new(binary)
        .args([
            "--safe",
            "package-sign-fixture",
            "--domain",
            "package",
            "--file",
            "folder with spaces/artifact.deb",
            "--public-key",
            "fixture keys/pub.key",
        ])
        .env_clear()
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "valid fixture signing should succeed"
    );
    let records = String::from_utf8(valid.stdout).unwrap();
    let mut lines = records.lines();
    let public = lines.next().unwrap().strip_prefix("public-key ").unwrap();
    let (public_hex, public_path) = public.split_once(' ').unwrap();
    assert_eq!(public_path, "fixture keys/pub.key");
    let signature = lines.next().unwrap();
    let (encoded, signature_path) = signature.split_once(' ').unwrap();
    assert_eq!(signature_path, "folder with spaces/artifact.deb.sig");
    assert!(lines.next().is_none());
    let key_bytes = data_encoding::HEXLOWER
        .decode(public_hex.as_bytes())
        .unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes.try_into().unwrap()).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(
        &data_encoding::BASE64.decode(encoded.as_bytes()).unwrap(),
    )
    .unwrap();
    use ed25519_dalek::Verifier;
    key.verify(
        b"pays-artifact-sign-v1\ndomain:package\nname:artifact.deb\nlength:19\nfixture with spaces",
        &sig,
    )
    .unwrap();
}

#[test]
fn fsverity_sign_preflights_explicit_signature_before_provider() {
    let root = std::env::temp_dir().join(format!("fsverity-stream-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    fs::write(
        root.join("digest"),
        [b"FSVerity".as_slice(), &[1, 0, 32, 0], &[0; 32]].concat(),
    )
    .unwrap();
    fs::write(root.join("pin"), format!("{}\n", "00".repeat(32))).unwrap();
    fs::write(
        root.join("bin/doppler"),
        "#!/bin/sh\ntouch provider-called\nexit 90\n",
    )
    .unwrap();
    fs::set_permissions(root.join("bin/doppler"), fs::Permissions::from_mode(0o700)).unwrap();
    let run = |signature: &str| {
        Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
            .args([
                "--safe",
                "fsverity-sign",
                "--role-arn",
                "arn:aws:iam::123456789012:role/fixture",
                "--public-key",
                "pin",
                "--digest",
                "digest",
                "--signature",
                signature,
            ])
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            )
            .env("HOME", &root)
            .current_dir(&root)
            .output()
            .unwrap()
    };
    let output = run("bad\rpath.sig");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("signature output path"));
    assert!(output.stdout.is_empty());
    assert!(!root.join("provider-called").exists());

    let control = run("clean.sig");
    assert!(!control.status.success());
    assert!(root.join("provider-called").exists());
}
