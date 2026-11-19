//! Resumable password rotation and session revocation for the Honey DEV QA accounts.

use crate::qa_fixtures::{
    API_URL, AUTH_URL, CONFIG, DEV_ADMIN, FIXTURES, Fixture, HONEY_APP, SANDBOX_TOTP_PERIOD_SECS,
    sandbox_totp_target, totp_sha512,
};
use crate::{Key, Target, honey, output};
use crate::eyre::{Result, WrapErr, bail, ensure, eyre};
use nagoya::reactor::{Handle, Reactor, block_on_with};
use serde_json::Value;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEV_APPS: [&str; 2] = ["auth-honey-id-master-fly", "api-honey-id-master-fly"];
const READINESS_ATTEMPTS: usize = 5;
const READINESS_INTERVAL: Duration = Duration::from_secs(3);

struct Rotation {
    fixture: Fixture,
    current: String,
    replacement: String,
    pending_name: String,
    public_id: String,
    proof_token: String,
    staged: bool,
    needs_change: bool,
    totp_required: bool,
}

struct VerifiedLogin {
    token: String,
    public_id: String,
    totp_required: bool,
}

pub(crate) fn rotate(dev_admin_only: bool) -> Result<()> {
    let lock = rotation_lock()?;
    let _deadline = Deadline::start();
    let fixtures: &[Fixture] = if dev_admin_only {
        output::status("checking the DEV platform admin bindings in agent-accounts/dev");
        std::slice::from_ref(&DEV_ADMIN)
    } else {
        output::status("checking all four DEV QA account bindings in honey-id/dev");
        &FIXTURES
    };
    // Check every selected login before changing any password.
    let rotations = fixtures
        .iter()
        .copied()
        .map(|fixture| prepare(fixture).wrap_err(fixture.username))
        .collect::<Result<Vec<_>>>()?;
    output::status("applying staged DEV QA password rotations");
    for rotation in &rotations {
        change_password(rotation).wrap_err(rotation.fixture.username)?;
    }

    // Clear Auth's verified sockets before clearing the API tokens it issued.
    for app in DEV_APPS {
        restart_dev_app(app, &lock)?;
    }
    // A Fly Machine can be started before its Honey endpoint accepts requests.
    let (first, rest) = rotations
        .split_first()
        .ok_or_else(|| eyre!("no DEV QA fixtures"))?;
    wait_for_honey_ready(first)?;
    output::status("checking DEV API token rejection and fresh logins");
    for rotation in &rotations {
        honey::require_revoked_api_token(API_URL, &rotation.proof_token)
            .wrap_err(rotation.fixture.username)?;
    }
    for rotation in rest {
        verify_replacement(rotation).wrap_err(rotation.fixture.username)?;
    }
    for rotation in &rotations {
        crate::write_group(
            CONFIG,
            &[rotation.fixture.target(rotation.fixture.password_secret)],
            &rotation.replacement,
        )?;
    }
    // Keep the pending values and IDs so a retry resumes the same rotation.
    // Once promoted they equal the canonical bindings, and the next run
    // starts a new rotation instead of resuming this one.
    output::status("DEV QA password rotation verified and stored. Pre-restart tokens rejected.");
    Ok(())
}

fn prepare(fixture: Fixture) -> Result<Rotation> {
    let username = required_binding(&fixture.target(fixture.username_secret))?;
    if username != fixture.username {
        output::status("DEV QA username binding does not match the fixed account");
        bail!("DEV QA username mismatch");
    }
    let current = required_binding(&fixture.target(fixture.password_secret))?;
    let pending_name = format!("{}_PENDING", fixture.password_secret);
    let pending = crate::try_get(&fixture.target(&pending_name), CONFIG)
        .inspect_err(|_| output::status("DEV QA pending password lookup failed"))?
        // A pending value equal to the canonical password belongs to a
        // rotation that was already verified and promoted: start a new one.
        .filter(|pending| *pending != current);
    let staged = pending.is_some();
    let replacement = pending.unwrap_or_else(|| Key::new().to_string());
    output::register_secret(replacement.as_bytes());
    if !crate::is_key(&replacement) || (!staged && replacement == current) {
        output::status("DEV QA replacement password validation failed");
        bail!("invalid DEV QA replacement password");
    }

    let (verified, needs_change) = match authenticate(fixture, &current) {
        Ok(verified) => (verified, current != replacement),
        // SetPassword may have completed before the canonical binding was
        // promoted. Only try a replacement that was staged for this account.
        Err(_) if staged && current != replacement => {
            output::status("retrying DEV QA authentication with the staged password");
            (authenticate(fixture, &replacement)?, false)
        }
        Err(error) => return Err(error),
    };
    if staged {
        let expected = crate::get_raw_unregistered(
            &fixture.target(&format!("{pending_name}_USER_ID")),
            CONFIG,
        )
        .inspect_err(|_| output::status("DEV QA pending account identity lookup failed"))?;
        if verified.public_id != expected {
            output::status("DEV QA pending account identity changed");
            bail!("pending account identity changed");
        }
    }

    Ok(Rotation {
        fixture,
        current,
        replacement,
        pending_name,
        public_id: verified.public_id,
        proof_token: verified.token,
        staged,
        needs_change,
        totp_required: verified.totp_required,
    })
}

fn required_binding(target: &Target) -> Result<String> {
    let value = crate::get_raw(target, CONFIG).inspect_err(|_| {
        output::status("required DEV QA account binding is missing or unreadable");
    })?;
    if value.is_empty() {
        output::status("required DEV QA account binding is empty");
        bail!("empty DEV QA account binding");
    }
    Ok(value)
}

fn change_password(rotation: &Rotation) -> Result<()> {
    if !rotation.needs_change {
        return Ok(());
    }
    if !rotation.staged {
        // Persist the candidate and identity before changing the live password.
        let id = rotation.fixture.target(&format!("{}_USER_ID", rotation.pending_name));
        crate::write_public_group(CONFIG, &[id], &rotation.public_id)?;
        crate::write_group(
            CONFIG,
            &[rotation.fixture.target(&rotation.pending_name)],
            &rotation.replacement,
        )?;
    }
    let reactor = Reactor::local().map_err(|e| eyre!(e.to_string()))?;
    let handle = reactor.handle();
    let login = login(rotation.fixture, &rotation.current);
    let (mut session, totp_required) =
        block_on_with(&reactor, sign_in(rotation.fixture, &login, &handle))?;
    ensure!(totp_required == rotation.totp_required, "DEV QA MFA state changed");
    // api_identity owns a reactor; never nest it inside block_on_with.
    let id = verified_identity(rotation.fixture, session.access_token()?)?;
    ensure!(id == rotation.public_id, "current account identity changed");
    block_on_with(&reactor, session.set_password(&rotation.replacement))?;
    verify_replacement(rotation)
}

fn verify_replacement(rotation: &Rotation) -> Result<()> {
    let verified = authenticate(rotation.fixture, &rotation.replacement)?;
    ensure!(verified.public_id == rotation.public_id, "new account identity changed");
    ensure!(verified.totp_required == rotation.totp_required, "DEV QA MFA state changed");
    Ok(())
}

fn login(fixture: Fixture, password: &str) -> honey::Login {
    honey::Login {
        auth: AUTH_URL.to_owned(),
        api: API_URL.to_owned(),
        honey_app: HONEY_APP.to_owned(),
        username: fixture.username.to_owned(),
        password: password.to_owned(),
    }
}

async fn sign_in(
    fixture: Fixture,
    login: &honey::Login,
    handle: &Handle,
) -> Result<(honey::AuthSession, bool)> {
    let mut session = honey::AuthSession::submit_username(login, handle).await?;
    let step = session.submit_password(&login.password).await?;
    if step == honey::AuthStep::Totp {
        if !fixture.sandbox {
            output::status("Honey DEV Auth returned an unexpected MFA challenge");
            bail!("unexpected DEV QA authentication challenge");
        }
        let secret = crate::try_get(&sandbox_totp_target(), CONFIG)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| eyre!("sandbox TOTP binding is missing"))?;
        // Auth persists the last accepted step. A previous login, including
        // one from an interrupted run, may already have consumed this step.
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let elapsed = Duration::new(now.as_secs() % SANDBOX_TOTP_PERIOD_SECS, now.subsec_nanos());
        nagoya::sleep(Duration::from_secs(SANDBOX_TOTP_PERIOD_SECS + 1) - elapsed).await;
        let code = totp_sha512(&secret)?;
        output::register_secret(code.as_bytes());
        session.submit_totp_code(&code).await?;
    }
    Ok((session, step == honey::AuthStep::Totp))
}

fn authenticate(fixture: Fixture, password: &str) -> Result<VerifiedLogin> {
    let reactor = Reactor::local()
        .map_err(|e| eyre!(e.to_string()))
        .inspect_err(|_| output::status("DEV QA authentication reactor setup failed"))?;
    let handle = reactor.handle();
    let login = login(fixture, password);
    let (session, totp_required) = block_on_with(&reactor, sign_in(fixture, &login, &handle))?;
    let token = session.access_token()?.to_owned();
    let public_id = verified_identity(fixture, &token)?;
    Ok(VerifiedLogin {
        token,
        public_id,
        totp_required,
    })
}

fn verified_identity(fixture: Fixture, token: &str) -> Result<String> {
    output::register_secret(token.as_bytes());
    let identity = honey::api_identity(API_URL, token)
        .inspect_err(|_| output::status("Honey DEV API identity and role lookup failed"))?;
    if identity.username != fixture.username || identity.user_public_id.is_empty() {
        output::status("Honey DEV API identity does not match the fixed account");
        bail!("DEV QA account identity mismatch");
    }
    if identity.role != fixture.expected_role {
        output::status("Honey DEV API role does not match the required role");
        bail!("DEV QA account role mismatch");
    }
    Ok(identity.user_public_id)
}

#[derive(Default)]
struct RestartPlan {
    running: Vec<String>,
    suspended: Vec<String>,
}

impl RestartPlan {
    fn from_machine_list(list: &[u8]) -> Result<Option<Self>> {
        let value: Value =
            serde_json::from_slice(list).map_err(|_| eyre!("invalid Fly machine list"))?;
        let machines = value
            .as_array()
            .or_else(|| value.get("machines").and_then(Value::as_array))
            .ok_or_else(|| eyre!("missing Fly machine list"))?;
        ensure!(!machines.is_empty(), "empty Fly machine list");

        let mut plan = Self::default();
        for machine in machines {
            let id = machine
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| eyre!("missing Fly machine ID"))?;
            match machine.get("state").and_then(Value::as_str) {
                Some("started") => plan.running.push(id.to_owned()),
                Some("suspended") => plan.suspended.push(id.to_owned()),
                Some("created" | "stopped" | "destroyed") => {}
                // Wait for a possible start, stop, or suspend to settle before
                // deciding whether the Machine still has a live process.
                Some(_) => return Ok(None),
                None => bail!("missing Fly machine state"),
            }
        }
        Ok(Some(plan))
    }
}

fn restart_dev_app(app: &str, lock: &File) -> Result<()> {
    for attempt in 0..READINESS_ATTEMPTS {
        let list = fly_command(lock)
            .args(["machine", "list", "--app", app, "--json"])
            .output()
            .wrap_err("could not list Honey DEV Fly machines")?;
        ensure!(list.status.success(), "could not list Fly machines on {app}");
        if let Some(plan) = RestartPlan::from_machine_list(&list.stdout)? {
            // A suspended Machine can resume its old RAM. Convert it to
            // stopped so Fly discards the snapshot without starting it.
            if !plan.suspended.is_empty() {
                let stop = fly_command(lock)
                    .args(["machine", "stop", "--app", app, "--wait-timeout", "60s", "--"])
                    .args(&plan.suspended)
                    .output()
                    .wrap_err("could not stop suspended Honey DEV Fly machines")?;
                ensure!(stop.status.success(), "could not stop suspended machines on {app}");
            }
            // Explicit IDs include unmanaged Machines. Fly waits for every
            // restart to reach started and pass any configured health checks.
            if !plan.running.is_empty() {
                let restart = fly_command(lock)
                    .args(["machine", "restart", "--app", app, "--"])
                    .args(&plan.running)
                    .output()
                    .wrap_err("could not restart Honey DEV Fly machines")?;
                ensure!(restart.status.success(), "could not restart all running machines on {app}");
            }
            return Ok(());
        }
        if attempt + 1 < READINESS_ATTEMPTS {
            std::thread::sleep(READINESS_INTERVAL);
        }
    }
    bail!("Fly machines on {app} did not reach a known state")
}

fn wait_for_honey_ready(rotation: &Rotation) -> Result<()> {
    for _ in 1..READINESS_ATTEMPTS {
        if verify_replacement(rotation).is_ok() {
            return Ok(());
        }
        std::thread::sleep(READINESS_INTERVAL);
    }
    verify_replacement(rotation).wrap_err("Honey DEV did not verify a fresh login after restart")
}

/// `fly` without the rotation lock. Only Doppler children keep it; a
/// long-lived Fly helper must not block later rotations.
fn fly_command(lock: &File) -> Command {
    let fd = lock.as_raw_fd();
    let mut command = Command::new("fly");
    // SAFETY: close is async-signal-safe and only affects the forked child.
    unsafe {
        command.pre_exec(move || {
            if fd > libc::STDERR_FILENO {
                libc::close(fd);
            }
            Ok(())
        });
    }
    command
}

fn rotation_lock() -> Result<File> {
    // Lock the existing home directory inode: no lock files or secret bytes
    // are created, and replacing the executable cannot bypass serialization.
    let path = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is required"))?;
    let path = std::path::Path::new(&path);
    ensure!(path.is_absolute(), "HOME must be absolute");
    lock_directory(path)
}

fn lock_directory(path: &std::path::Path) -> Result<File> {
    let file = File::open(path).map_err(|_| eyre!("could not open DEV QA rotation lock"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "unsafe DEV QA rotation lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another DEV QA rotation is running"
    );
    // Doppler children must retain serialization if the parent times out
    // while a write is still in flight. Never unlink this lock inode.
    // `fly_command` closes the inherited descriptor in Fly children.
    ensure!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } == 0,
        "could not retain DEV QA lock across child execution"
    );
    Ok(file)
}

struct Deadline;
impl Deadline {
    fn start() -> Self {
        // SAFETY: the handler only calls the async-signal-safe write and _exit.
        unsafe {
            libc::signal(
                libc::SIGALRM,
                deadline_expired as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
            libc::alarm(600);
        }
        Self
    }
}

/// Report the expired deadline instead of the silent default SIGALRM exit.
extern "C" fn deadline_expired(_: libc::c_int) {
    const MESSAGE: &[u8] =
        b"DEV QA rotation exceeded its 10 minute deadline; rerun the same command to resume\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        let _ = libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len());
        libc::_exit(1);
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        unsafe {
            libc::alarm(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RestartPlan, lock_directory};
    use std::process::{Command, Stdio};

    #[test]
    fn restart_plan_covers_live_and_suspended_machines() {
        let plan = RestartPlan::from_machine_list(
            br#"[{"id":"active","state":"started"},{"id":"paused","state":"suspended"},{"id":"cold","state":"stopped"}]"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.running, ["active"]);
        assert_eq!(plan.suspended, ["paused"]);
        assert!(
            RestartPlan::from_machine_list(br#"[{"id":"waking","state":"starting"}]"#)
                .unwrap()
                .is_none(),
            "a transitioning machine must settle before revocation can be confirmed"
        );
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn child_keeps_rotation_serialized_after_parent_releases_lock() {
        let dir = std::env::temp_dir().join(format!(
            "agent-secrets-cli-rotation-lock-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let lock = lock_directory(&dir).unwrap();
        let mut child = Command::new("sleep")
            .arg("5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(lock);
        let still_locked = lock_directory(&dir).is_err();
        child.kill().unwrap();
        child.wait().unwrap();
        let released = lock_directory(&dir).is_ok();
        std::fs::remove_dir(&dir).unwrap();
        assert!(
            still_locked,
            "in-flight child must prevent a competing rotation"
        );
        assert!(released, "reaped child must release the lock");
    }
}
