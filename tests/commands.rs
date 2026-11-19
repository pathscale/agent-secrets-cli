//! Process-level tests use only synthetic fixtures, never real credentials.
// The tests write synthetic fixture files; the binary under test never writes to disk.
#![allow(clippy::disallowed_methods)]
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn isolated_config_and_secret_move_verify_before_source_deletion() {
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("doppler"),
        r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] || exit 90
shift 2
case "$*" in
'--no-read-env --attempts 1 environments create signing signing --project source')
  : > created ;;
'--no-read-env configs get signing --project source')
  [ -f created ] ;;
'secrets get AUTHORITY --plain -p source -c prd')
  if [ -f deleted ]; then printf 'Could not find requested secret' >&2; exit 1
  else printf fixture-authority; fi ;;
'secrets get AUTHORITY --plain -p source -c signing')
  if [ -f stored ]; then cat stored
  else printf 'Could not find requested secret' >&2; exit 1; fi ;;
'secrets set AUTHORITY --silent --no-interactive -p source -c signing')
  cat > stored ;;
'secrets get AUTHORITY --plain --raw -p source -c signing')
  if [ -f fail-readback ]; then printf fixture-wrong
  else cat stored; fi ;;
'--no-read-env secrets delete AUTHORITY --project source --config prd --yes')
  [ -f stored ] || exit 91
  : > deleted ;;
*) exit 92 ;;
esac
"#,
    )
    .unwrap();
    let output = fixture.run(&[
        "create-config",
        "--project",
        "source",
        "--config",
        "signing",
    ]);
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let args = [
        "copy-secret",
        "--config",
        "prd",
        "--secret",
        "source/AUTHORITY",
        "--to-config",
        "signing",
        "--to",
        "source/AUTHORITY",
        "--remove-source",
    ];
    fs::write(fixture.0.join("fail-readback"), "").unwrap();
    let output = fixture.run(&args);
    assert!(!output.status.success());
    assert!(!fixture.0.join("deleted").exists());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-"));
    fs::remove_file(fixture.0.join("fail-readback")).unwrap();
    let output = fixture.run(&args);
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(fixture.0.join("deleted").exists());
    assert_eq!(
        fs::read(fixture.0.join("stored")).unwrap(),
        b"fixture-authority"
    );
}

#[test]
fn reader_token_is_read_only_stored_on_stdin_and_never_displayed() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("doppler"), r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] || exit 90
shift 2
case "$*" in
'--no-read-env --attempts 1 configs tokens create ci-fixture --project source --config signing --access read --plain')
  : > issued
  printf dp.st.synthetic-reader
  printf dp.st.synthetic-reader >&2
  [ ! -f fail-issue ] ;;
'secrets get READER --plain -p destination -c prd')
  if [ -f stored ]; then cat stored
  elif [ -f fail-preflight ]; then printf dp.st.synthetic-reader >&2; exit 1
  else printf 'Could not find requested secret' >&2; exit 1; fi ;;
'secrets set READER --silent --no-interactive -p destination -c prd')
  cat > stored
  [ ! -f fail-store ] ;;
'secrets get READER --plain --raw -p destination -c prd')
  if [ -f fail-readback ]; then printf dp.st.synthetic-wrong
  else cat stored; fi ;;
*) exit 91 ;;
esac
"#).unwrap();
    let args = [
        "create-reader-token",
        "--project",
        "source",
        "--config",
        "signing",
        "--name",
        "ci-fixture",
        "--token",
        "destination/READER",
        "--token-config",
        "prd",
    ];
    let output = fixture.run(&args);
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(
        fs::read(fixture.0.join("stored")).unwrap(),
        b"dp.st.synthetic-reader"
    );
    fs::remove_file(fixture.0.join("issued")).unwrap();
    let output = fixture.run(&args);
    assert!(!output.status.success());
    assert!(!fixture.0.join("issued").exists());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("dp.st."));
    fs::remove_file(fixture.0.join("stored")).unwrap();
    for failure in [
        "fail-preflight",
        "fail-issue",
        "fail-store",
        "fail-readback",
    ] {
        fs::write(fixture.0.join(failure), "").unwrap();
        let output = fixture.run(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("dp.st."));
        fs::remove_file(fixture.0.join(failure)).unwrap();
        let _ = fs::remove_file(fixture.0.join("stored"));
        let _ = fs::remove_file(fixture.0.join("issued"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
        .args(args)
        .env("DOPPLER_TOKEN", "synthetic-override")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-override"));
}

#[test]
fn to_github_finishes_verified_writes_before_reporting() {
    let fixture = Fixture::new();
    fs::write(
        fixture.0.join("doppler"),
        r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] && [ "${HOME#/}" != "$HOME" ] && [ -d "$HOME" ] || exit 90
shift 2
[ "$#" = 8 ] && [ "$1" = secrets ] && [ "$2" = get ] && [ "$4" = --plain ] && [ "$5" = -p ] && [ "$7" = -c ] || exit 91
if [ "$3" = ALPHA ] && [ "$6" = first ] && [ "$8" = dev ]; then
  printf 'get first ALPHA dev\n' >> "$CALL_LOG"
  printf synthetic-alpha
elif [ "$3" = BETA ] && [ "$6" = second ] && [ "$8" = dev ]; then
  printf 'get second BETA dev\n' >> "$CALL_LOG"
  printf synthetic-beta
else
  exit 91
fi
"#,
    )
    .unwrap();
    fs::set_permissions(fixture.0.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fixture.0.join("expected-alpha"), b"synthetic-alpha").unwrap();
    fs::write(fixture.0.join("expected-beta"), b"synthetic-beta").unwrap();
    fs::write(
        fixture.0.join("gh"),
        r#"#!/bin/sh
[ "$1 $2" = 'secret set' ] || [ "$1 $2" = 'secret list' ] || exit 90
if [ "$2" = set ]; then
  [ "$#" = 5 ] && [ "$4" = --repo ] || exit 91
  case "$3:$5" in
    ALPHA:org/one) expected_file="$PWD/expected-alpha" ;;
    ALPHA:org/two) expected_file="$PWD/expected-alpha" ;;
    BETA:org/one) expected_file="$PWD/expected-beta" ;;
    BETA:org/two) expected_file="$PWD/expected-beta" ;;
    *) exit 92 ;;
  esac
  /usr/bin/cmp -s - "$expected_file" || exit 93
  printf 'set %s %s\n' "$5" "$3" >> "$CALL_LOG"
  exit 0
fi
[ "$#" = 8 ] && [ "$3" = --repo ] && [ "$5" = --json ] && [ "$6" = name ] && [ "$7" = --template ] && [ "$8" = '{{range .}}{{.name}}{{"\n"}}{{end}}' ] || exit 95
repo=$4
last=$(tail -n 1 "$CALL_LOG")
case "$last" in
  "set $repo ALPHA") name=ALPHA ;;
  "set $repo BETA") name=BETA ;;
  *) exit 96 ;;
esac
printf 'list %s %s\n' "$repo" "$name" >> "$CALL_LOG"
if [ -f "$FAIL_LIST_STATUS" ] && [ "$repo" = org/two ] && [ "$name" = ALPHA ]; then
  printf '%s\n' "$name"
  exit 97
fi
if [ -f "$FAIL_LIST" ] && [ "$repo" = org/two ] && [ "$name" = ALPHA ]; then exit 0; fi
printf '%s\n' "$name"
"#,
    )
    .unwrap();
    fs::set_permissions(fixture.0.join("gh"), fs::Permissions::from_mode(0o700)).unwrap();
    let expected_calls = concat!(
        "get first ALPHA dev\n",
        "set org/one ALPHA\nlist org/one ALPHA\n",
        "set org/two ALPHA\nlist org/two ALPHA\n",
        "get second BETA dev\n",
        "set org/one BETA\nlist org/one BETA\n",
        "set org/two BETA\nlist org/two BETA\n",
    );
    let args = [
        "to-github", "--config", "dev", "--secret", "first/ALPHA", "--secret",
        "second/BETA", "--repo", "org/one", "--repo", "org/two",
    ];

    let output = fixture.run_with_call_log(&args);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(fixture.0.join("calls")).unwrap(), expected_calls);

    fs::write(fixture.0.join("calls"), "").unwrap();
    let mut safe_args = vec!["--safe"];
    safe_args.extend(args);
    let output = fixture.run_with_call_log(&safe_args);
    assert_eq!(output.status.code(), Some(0));
    let expected_stdout = concat!(
            "set ALPHA on org/one from first/ALPHA (dev)\n",
            "set ALPHA on org/two from first/ALPHA (dev)\n",
            "set BETA on org/one from second/BETA (dev)\n",
            "set BETA on org/two from second/BETA (dev)\n",
        )
        .as_bytes();
    assert!(output.stdout.as_slice() == expected_stdout, "unexpected to-github stdout");
    assert_eq!(fs::read_to_string(fixture.0.join("calls")).unwrap(), expected_calls);

    fs::write(fixture.0.join("calls"), "").unwrap();
    fs::write(fixture.0.join("fail-list"), "").unwrap();
    let output = fixture.run_with_call_log(&safe_args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(fixture.0.join("calls")).unwrap(),
        concat!(
            "get first ALPHA dev\n",
            "set org/one ALPHA\nlist org/one ALPHA\n",
            "set org/two ALPHA\nlist org/two ALPHA\n",
        )
    );

    fs::write(fixture.0.join("calls"), "").unwrap();
    fs::remove_file(fixture.0.join("fail-list")).unwrap();
    fs::write(fixture.0.join("fail-list-status"), "").unwrap();
    let output = fixture.run_with_call_log(&safe_args);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(fixture.0.join("calls")).unwrap(),
        concat!(
            "get first ALPHA dev\n",
            "set org/one ALPHA\nlist org/one ALPHA\n",
            "set org/two ALPHA\nlist org/two ALPHA\n",
        )
    );
}

#[test]
fn set_finishes_verified_groups_before_reporting() {
    let fixture = Fixture::new_in_temp_dir();
    fs::write(fixture.0.join("expected-value"), b"synthetic-set-value").unwrap();
    fs::write(
        fixture.0.join("doppler"),
        r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] && [ "$2" != "$PWD" ] || exit 90
shift 2
[ "$1" = secrets ] || exit 91
if [ "$2" = set ]; then
  [ "$#" = 9 ] && [ "$4" = --silent ] && [ "$5" = --no-interactive ] && [ "$6" = -p ] && [ "$8" = -c ] && [ "$9" = dev ] || exit 92
  case "$7:$3" in
    first:ALPHA|first:BETA|second:GAMMA) ;;
    *) exit 93 ;;
  esac
  /usr/bin/cmp -s - expected-value || exit 94
  printf 'set %s %s %s\n' "$7" "$3" "$9" >> "$CALL_LOG"
  exit 0
fi
if [ "$2" = get ]; then
  [ "$#" = 9 ] && [ "$4" = --plain ] && [ "$5" = --raw ] && [ "$6" = -p ] && [ "$8" = -c ] && [ "$9" = dev ] || exit 95
  case "$7:$3" in
    first:ALPHA|first:BETA|second:GAMMA) ;;
    *) exit 96 ;;
  esac
  printf 'get %s %s %s\n' "$7" "$3" "$9" >> "$CALL_LOG"
  if [ -f "$FAIL_SECOND_READ" ] && [ "$7:$3" = second:GAMMA ]; then exit 97; fi
  /bin/cat expected-value
  exit 0
fi
exit 98
"#,
    )
    .unwrap();
    fs::set_permissions(fixture.0.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();

    let args = [
        "set",
        "--config",
        "dev",
        "--group",
        "first/ALPHA,first/BETA",
        "--group",
        "second/GAMMA",
    ];
    let expected_calls = concat!(
        "set first ALPHA dev\n",
        "set first BETA dev\n",
        "get first ALPHA dev\n",
        "get first BETA dev\n",
        "set second GAMMA dev\n",
        "get second GAMMA dev\n",
    );
    let input = b"  synthetic-set-value\n";

    fs::write(fixture.0.join("calls"), "").unwrap();
    let _ = fs::remove_file(fixture.0.join("fail-second-read"));
    let refused = fixture.run_set_with_input(&args, input);
    assert_eq!(refused.status.code(), Some(1), "default set should be refused");
    assert!(refused.stdout.is_empty(), "default set emitted stdout");
    assert!(
        fs::read_to_string(fixture.0.join("calls")).unwrap() == expected_calls,
        "default set did not finish every verified group"
    );

    fs::write(fixture.0.join("calls"), "").unwrap();
    let _ = fs::remove_file(fixture.0.join("fail-second-read"));
    let mut safe_args = vec!["--safe"];
    safe_args.extend(args);
    let allowed = fixture.run_set_with_input(&safe_args, input);
    assert_eq!(allowed.status.code(), Some(0), "safe set should succeed");
    assert!(
        allowed.stdout.as_slice()
            == b"set first/ALPHA = first/BETA in dev\nset second/GAMMA in dev\n",
        "safe set emitted unexpected status text"
    );
    assert!(
        fs::read_to_string(fixture.0.join("calls")).unwrap() == expected_calls,
        "safe set did not preserve provider call order"
    );

    fs::write(fixture.0.join("calls"), "").unwrap();
    fs::write(fixture.0.join("fail-second-read"), "").unwrap();
    let failed = fixture.run_set_with_input(&safe_args, input);
    assert_eq!(failed.status.code(), Some(1), "failed readback should fail");
    assert!(failed.stdout.is_empty(), "failed set emitted stdout");
    assert!(
        fs::read_to_string(fixture.0.join("calls")).unwrap()
            == concat!(
                "set first ALPHA dev\n",
                "set first BETA dev\n",
                "get first ALPHA dev\n",
                "get first BETA dev\n",
                "set second GAMMA dev\n",
                "get second GAMMA dev\n",
            ),
        "failed set did not stop at the second-group readback"
    );
}

#[test]
fn sync_finishes_verified_groups_before_reporting() {
    let fixture = Fixture::new_in_temp_dir();
    let first_key = "aB3dE6gH9jK2mN5pQ7rS8tU4vW6xY2zA";
    let second_key = "bC4eF7hJ9kM2nP5qR8sT3uV6wX1yZ4aB";
    fs::write(fixture.0.join("first-key"), first_key).unwrap();
    fs::write(fixture.0.join("second-key"), second_key).unwrap();
    fs::write(
        fixture.0.join("doppler"),
        r#"#!/bin/sh
[ "$1" = --scope ] && [ "$2" = "$HOME" ] && [ "$2" != "$PWD" ] || exit 90
shift 2
[ "$1" = secrets ] || exit 91
if [ "$2" = get ] && [ "$4" = --plain ] && [ "$5" != --raw ]; then
  [ "$#" = 8 ] && [ "$5" = -p ] && [ "$7" = -c ] && [ "$8" = dev ] || exit 92
  case "$6:$3" in
    first:SOURCE) key_file=first-key ;;
    second:SOURCE) key_file=second-key ;;
    *) exit 93 ;;
  esac
  /bin/cat "$key_file" || exit 94
  printf 'get-source %s %s %s\n' "$6" "$3" "$8" >> "$CALL_LOG"
  exit
fi
if [ "$2" = set ]; then
  [ "$#" = 9 ] && [ "$4" = --silent ] && [ "$5" = --no-interactive ] && [ "$6" = -p ] && [ "$8" = -c ] && [ "$9" = dev ] || exit 95
  case "$7:$3" in
    first:ALPHA|first:BETA) expected_file=first-key ;;
    second:GAMMA|second:GAMMA_*) expected_file=second-key ;;
    *) exit 96 ;;
  esac
  /usr/bin/cmp -s - "$expected_file" || exit 97
  printf 'set %s %s %s\n' "$7" "$3" "$9" >> "$CALL_LOG"
  exit
fi
if [ "$2" = get ] && [ "$4" = --plain ] && [ "$5" = --raw ]; then
  [ "$#" = 9 ] && [ "$6" = -p ] && [ "$8" = -c ] && [ "$9" = dev ] || exit 98
  case "$7:$3" in
    first:ALPHA|first:BETA) key_file=first-key ;;
    second:GAMMA|second:GAMMA_*) key_file=second-key ;;
    *) exit 99 ;;
  esac
  readback_status=0
  if [ -f "$FAIL_SECOND_READ" ] && [ "$7:$3" = second:GAMMA ]; then
    readback_status=100
  else
    /bin/cat "$key_file" || exit 101
  fi
  printf 'get-raw %s %s %s\n' "$7" "$3" "$9" >> "$CALL_LOG" || exit 102
  exit "$readback_status"
fi
exit 103
"#,
    )
    .unwrap();
    fs::set_permissions(fixture.0.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();

    let args = [
        "sync",
        "--config",
        "dev",
        "--group",
        "first/SOURCE,first/ALPHA,first/BETA",
        "--group",
        "second/SOURCE,second/GAMMA",
    ];
    let expected_calls = |second_target: &str| {
        let prefix = concat!(
            "get-source first SOURCE dev\n",
            "set first ALPHA dev\n",
            "set first BETA dev\n",
            "get-raw first ALPHA dev\n",
            "get-raw first BETA dev\n",
            "get-source second SOURCE dev\n",
        );
        format!("{prefix}set second {second_target} dev\nget-raw second {second_target} dev\n")
    };
    let call_log = fixture.0.join("calls");

    let refused = fixture.run_set_with_input(&args, b"");
    assert_eq!(refused.status.code(), Some(1), "default sync should be refused");
    assert!(refused.stdout.is_empty(), "default sync emitted stdout");
    assert!(
        fs::read_to_string(&call_log).unwrap() == expected_calls("GAMMA"),
        "default sync did not finish every verified group"
    );

    fs::write(&call_log, "").unwrap();
    let mut safe_args = vec!["--safe"];
    safe_args.extend(args);
    let allowed = fixture.run_set_with_input(&safe_args, b"");
    assert_eq!(allowed.status.code(), Some(0), "safe sync should succeed");
    assert!(
        allowed.stdout.as_slice()
            == b"synced first/SOURCE = first/ALPHA = first/BETA in dev\nsynced second/SOURCE = second/GAMMA in dev\n",
        "safe sync emitted unexpected status text"
    );
    assert!(
        fs::read_to_string(&call_log).unwrap() == expected_calls("GAMMA"),
        "safe sync did not preserve provider call order"
    );

    fs::write(&call_log, "").unwrap();
    let refused_target = format!("GAMMA_{second_key}");
    let refused_group = format!("second/SOURCE,second/{refused_target}");
    let mut refused_args = safe_args.clone();
    *refused_args.last_mut().unwrap() = &refused_group;
    let refused = fixture.run_set_with_input(&refused_args, b"");
    assert_eq!(refused.status.code(), Some(1), "sync report should be refused");
    assert!(refused.stdout.is_empty(), "refused sync emitted stdout");
    assert_eq!(refused.stderr.as_slice(), b"error: command failed\n");
    assert!(
        fs::read_to_string(&call_log).unwrap() == expected_calls(&refused_target),
        "report refusal did not follow every verified group"
    );

    fs::write(&call_log, "").unwrap();
    fs::write(fixture.0.join("fail-second-read"), "").unwrap();
    let failed = fixture.run_set_with_input(&safe_args, b"");
    assert_eq!(failed.status.code(), Some(1), "failed sync should fail");
    assert!(failed.stdout.is_empty(), "failed sync emitted stdout");
    assert_eq!(failed.stderr.as_slice(), b"error: command failed\n");
    assert!(
        fs::read_to_string(&call_log).unwrap() == expected_calls("GAMMA"),
        "failed sync did not stop at the second-group readback"
    );
}

struct Fixture(std::path::PathBuf);

impl Fixture {
    #[allow(clippy::disallowed_methods)]
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-secrets-cli-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("doppler"), "#!/bin/sh\n[ \"$1\" = --scope ] && [ \"$2\" = \"$HOME\" ] && [ \"$2\" != \"$PWD\" ] || exit 92\nshift 2\n[ \"$1 $2\" = 'secrets get' ] || exit 90\n[ \"$4 $5 $6 $7 $8\" = '--plain -p project -c dev' ] || [ \"$4 $5 $6 $7 $8 $9\" = \"--plain --raw -p project -c dev\" ] || exit 91\ncase \"$3\" in\nCONFIG) printf '%s' '{\"honey_id\":{\"app_public_id\":\"aB3dE6gH9jK2mN5p\",\"auth_api_key\":\"fixture-private\"},\"a\":{\"port\":42,\"password\":\"fixture-private\",\"id\":\"aB3$dE6!gH9@jK2#mN5%\",\"value\":\"So11111111111111111111111111111111111111112\"}}';;\nTOML) printf '[a]\\nport=42\\npassword=\"fixture-private\"\\n';;\nFIRST) printf fixture-first;;\nSECOND) printf fixture-second;;\nFAIL) printf fixture-private; printf fixture-private >&2; exit 1;;\nesac\n").unwrap();
        fs::set_permissions(dir.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.join("home scope")).unwrap();
        Self(dir)
    }

    fn new_in_temp_dir() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-secrets-cli-set-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("doppler"), "#!/bin/sh\nexit 99\n").unwrap();
        fs::set_permissions(dir.join("doppler"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.join("home scope")).unwrap();
        Self(dir)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
            .args(args)
            .env_remove("DOPPLER_TOKEN")
            .env("HOME", self.0.join("home scope"))
            .current_dir(&self.0)
            .env("PATH", format!("{}:/usr/bin:/bin", self.0.display()))
            .output()
            .unwrap()
    }

    fn run_with_call_log(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
            .args(args)
            .env_clear()
            .env("HOME", self.0.join("home scope"))
            .env("PATH", format!("{}:/usr/bin:/bin", self.0.display()))
            .env("CALL_LOG", self.0.join("calls"))
            .env("FAIL_LIST", self.0.join("fail-list"))
            .env("FAIL_LIST_STATUS", self.0.join("fail-list-status"))
            .current_dir(&self.0)
            .output()
            .unwrap()
    }

    fn run_set_with_input(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
            .args(args)
            .env_clear()
            .env("HOME", self.0.join("home scope"))
            .env("PATH", ".")
            .env("CALL_LOG", self.0.join("calls"))
            .env("FAIL_SECOND_READ", self.0.join("fail-second-read"))
            .current_dir(&self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(input).unwrap();
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn get_path_outputs_only_leaves_and_refuses_atomically() {
    let fixture = Fixture::new();
    let args = [
        "get-path",
        "--safe",
        "--config",
        "dev",
        "--secret",
        "project/CONFIG",
        "--format",
        "json",
        "--path",
        "honey_id.app_public_id",
    ];
    let output = fixture.run(&args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let mut args = args.to_vec();
    args.extend(["--path", "honey_id.auth_api_key", "--allow-public-key"]);
    let output = fixture.run(&args);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    for (secret, format) in [("project/CONFIG", "json"), ("project/TOML", "toml")] {
        let args = [
            "get-path", "--safe", "--config", "dev", "--secret", secret, "--format", format,
            "--path", "a.port",
        ];
        let output = fixture.run(&args);
        assert!(output.status.success());
        assert_eq!(output.stdout, b"42\n");
        assert!(output.stderr.is_empty());
        for refused in ["a.password", "a", "missing", "a."] {
            let mut args = args.to_vec();
            args.extend(["--path", refused]);
            let output = fixture.run(&args);
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        }
    }
    for leaf in ["a.id", "a.value"] {
        let output = fixture.run(&[
            "get-path",
            "--safe",
            "--config",
            "dev",
            "--secret",
            "project/CONFIG",
            "--format",
            "json",
            "--path",
            "a.port",
            "--path",
            leaf,
        ]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
    let output = fixture.run(&[
        "get-path",
        "--safe",
        "--config",
        "dev",
        "--secret",
        "project/CONFIG",
        "--format",
        "json",
        "--path",
        "a.value",
        "--allow-public-key",
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    for format in ["json", "toml"] {
        let output = fixture.run(&[
            "get-path",
            "--safe",
            "--config",
            "dev",
            "--secret",
            "project/FAIL",
            "--format",
            format,
            "--path",
            "a.port",
        ]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
}

#[test]
fn get_path_requires_safe_and_succeeds_with_safe_through_pipe() {
    let fixture = Fixture::new();
    let args = [
        "get-path",
        "--config",
        "dev",
        "--secret",
        "project/CONFIG",
        "--format",
        "json",
        "--path",
        "a.port",
    ];
    let refused = fixture.run(&args);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let mut safe = vec!["--safe"];
    safe.extend(args);
    let allowed = fixture.run(&safe);
    assert!(allowed.status.success());
    assert_eq!(allowed.stdout, b"42\n");
}

#[test]
fn doppler_scope_never_falls_back_to_working_directory() {
    let fixture = Fixture::new();
    // The fake Doppler rejects omitted scopes and cwd's scope. Both reads must
    // use HOME even from a directory with its own Doppler setup.
    fs::write(
        fixture.0.join("doppler.yaml"),
        "setup:\n  project: other\n  config: prd\n",
    )
    .unwrap();
    let args = [
        "exec",
        "--config",
        "dev",
        "--secret",
        "project/FIRST",
        "--",
        "/bin/sh",
        "-c",
        "[ \"$FIRST\" = fixture-first ]",
    ];
    let output = fixture.run(&args);
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = fixture.run(&[
        "--safe",
        "patch-config",
        "--config",
        "dev",
        "--secret",
        "project/CONFIG",
        "--format",
        "json",
        "--set",
        "a.port=43",
    ]);
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-private"));
    for home in [None, Some(""), Some("relative")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"));
        command
            .args(args)
            .current_dir(&fixture.0)
            .env("PATH", format!("{}:/usr/bin:/bin", fixture.0.display()));
        if let Some(home) = home {
            command.env("HOME", home);
        } else {
            command.env_remove("HOME");
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-private"));
    }
}

#[test]
fn exec_injects_multiple_secrets_and_preserves_args_and_exit_code() {
    let fixture = Fixture::new();
    let output = fixture.run(&["exec", "--config", "dev", "--secret", "project/FIRST", "--secret", "project/SECOND=RENAMED", "--", "/bin/sh", "-c", "[ \"$FIRST\" = fixture-first ] && [ \"$RENAMED\" = fixture-second ] && [ \"$1\" = '--literal argument' ] || exit 99; exit 37", "test", "--literal argument"]);
    assert_eq!(output.status.code(), Some(37));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = fixture.run(&[
        "exec",
        "--config",
        "dev",
        "--secret",
        "project/FIRST",
        "--",
        "/bin/sh",
        "-c",
        "kill -TERM $$",
    ]);
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(output.status.signal(), Some(15));
}

#[test]
fn exec_bridges_only_explicit_environment_names() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_agent-secrets-cli"))
        .args([
            "exec",
            "--config",
            "dev",
            "--secret",
            "project/FIRST",
            "--pass-env",
            "BRIDGE_SENTINEL",
            "--pass-env",
            "OPTIONAL_MISSING",
            "--",
            "/bin/sh",
            "-c",
            "[ \"$BRIDGE_SENTINEL\" = bridge-value ] && [ -z \"$UNBRIDGED_SENTINEL\" ] && [ -z \"$OPTIONAL_MISSING\" ] && [ \"$FIRST\" = fixture-first ]",
        ])
        .current_dir(&fixture.0)
        .env("HOME", fixture.0.join("home scope"))
        .env("PATH", format!("{}:/usr/bin:/bin", fixture.0.display()))
        .env("BRIDGE_SENTINEL", "bridge-value")
        .env("UNBRIDGED_SENTINEL", "must-not-cross")
        .env_remove("OPTIONAL_MISSING")
        .env_remove("DOPPLER_TOKEN")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty() && output.stderr.is_empty());

    for args in [
        vec![
            "--pass-env",
            "BRIDGE_SENTINEL",
            "--pass-env",
            "BRIDGE_SENTINEL",
        ],
        vec!["--pass-env", "BAD-NAME"],
        vec!["--pass-env", "FIRST"],
    ] {
        let mut command_args = vec!["exec", "--config", "dev", "--secret", "project/FIRST"];
        command_args.extend(args);
        command_args.extend(["--", "/bin/sh", "-c", "echo child-started"]);
        let output = fixture.run(&command_args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-private"));
    }
}

#[test]
fn exec_refuses_failed_reads_duplicates_and_invalid_names_without_starting_child() {
    let fixture = Fixture::new();
    for bindings in [
        vec!["project/FAIL"],
        vec!["project/FIRST=BAD-NAME"],
        vec!["project/FIRST=SAME", "project/SECOND=SAME"],
    ] {
        let mut args = vec!["exec", "--config", "dev"];
        for binding in bindings {
            args.extend(["--secret", binding]);
        }
        args.extend(["--", "/bin/sh", "-c", "echo child-started"]);
        let output = fixture.run(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-private"));
    }
}
