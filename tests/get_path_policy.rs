// Synthetic test fixtures write temporary mock scripts under temp_dir.
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-secrets-url-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("doppler"),
            r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] || exit 90
shift 2
[ "$1 $2 $3 $4" = 'secrets get CONFIG --plain' ] || exit 91
[ "$5 $6 $7 $8" = '-p project -c dev' ] || exit 92
printf '%s' '{"api_url":"https://example.com/","path_url":"https://example.com/token-secret","numeric_url":"https://12345678901234567890123456789012.com/","hex_url":"https://0123456789abcdef0123456789abcdef.com/","base58_url":"https://11111111111111111111111111111111.com/","number":"12345678901234567890","hex":"0123456789abcdef0123456789abcdef","seed":"11111111111111111111111111111111"}'
"#,
        )
        .unwrap();
        fs::set_permissions(dir.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn run(&self, path: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
            .args([
                "--safe",
                "get-path",
                "--config",
                "dev",
                "--secret",
                "project/CONFIG",
                "--format",
                "json",
                "--path",
                path,
            ])
            .env_clear()
            .env("HOME", self.0.join("home"))
            .env("PATH", format!("{}:/usr/bin:/bin", self.0.display()))
            .current_dir(&self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn public_url_outputs_only_a_root_origin() {
    let fixture = Fixture::new();
    let output = fixture.run("api_url");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"\"https://example.com/\"\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn unsafe_urls_and_seed_lookalikes_are_refused_atomically() {
    let fixture = Fixture::new();
    for path in [
        "path_url",
        "numeric_url",
        "hex_url",
        "base58_url",
        "number",
        "hex",
        "seed",
    ] {
        let output = fixture.run(path);
        assert!(!output.status.success(), "{path}");
        assert!(output.stdout.is_empty(), "{path}");
        assert!(output.stderr.is_empty(), "{path}");
    }
}
