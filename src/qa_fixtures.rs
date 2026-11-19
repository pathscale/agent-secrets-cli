//! Ensure the fixed honey.id dev accounts and the ps-qa owned app.

use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::eyre::{Result, bail, ensure, eyre};
use nagoya::reactor::{Reactor, block_on_with};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{Target, honey, output};

const PROJECT: &str = "honey-id";
pub(crate) const CONFIG: &str = "dev";
pub(crate) const AUTH_URL: &str = "wss://auth-dev.honey.id/";
pub(crate) const API_URL: &str = "wss://api-dev.honey.id/";
pub(crate) const HONEY_APP: &str = "4x3JVuCnNIfD4szt";
const OWNED_APP_NAME: &str = "qa-owned-app";
const OWNED_APP_ID: &str = "DDTxNnOZihI09XDz";
const SANDBOX_TOTP_SECRET: &str = "QA_2FA_SANDBOX_TOTP_SECRET";
pub(crate) const SANDBOX_TOTP_PERIOD_SECS: u64 = 30;

#[derive(Clone, Copy)]
pub(crate) struct Fixture {
    project: &'static str,
    pub(crate) username: &'static str,
    pub(crate) username_secret: &'static str,
    pub(crate) password_secret: &'static str,
    pub(crate) expected_role: &'static str,
    pub(crate) sandbox: bool,
}

impl Fixture {
    pub(crate) fn target(self, name: &str) -> Target {
        Target {
            project: self.project.to_owned(),
            name: name.to_owned(),
        }
    }
}

const PLATFORM_ADMIN: Fixture = Fixture {
    project: PROJECT,
    username: "qa-platform-admin",
    username_secret: "QA_PLATFORM_ADMIN_USERNAME",
    password_secret: "QA_PLATFORM_ADMIN_PASSWORD",
    expected_role: "PlatformAdmin",
    sandbox: false,
};

pub(crate) const DEV_ADMIN: Fixture = Fixture {
    project: "agent-accounts",
    username_secret: "HONEY_ID_DEV_USERNAME",
    password_secret: "HONEY_ID_DEV_PASSWORD",
    ..PLATFORM_ADMIN
};

pub(crate) const FIXTURES: [Fixture; 4] = [
    PLATFORM_ADMIN,
    Fixture {
        project: PROJECT,
        username: "qa-app-admin",
        username_secret: "QA_APP_ADMIN_USERNAME",
        password_secret: "QA_APP_ADMIN_PASSWORD",
        expected_role: "AppAdmin",
        sandbox: false,
    },
    Fixture {
        project: PROJECT,
        username: "qa-plain-guest",
        username_secret: "QA_PLAIN_GUEST_USERNAME",
        password_secret: "QA_PLAIN_GUEST_PASSWORD",
        expected_role: "Guest",
        sandbox: false,
    },
    Fixture {
        project: PROJECT,
        username: "qa-2fa-sandbox",
        username_secret: "QA_2FA_SANDBOX_USERNAME",
        password_secret: "QA_2FA_SANDBOX_PASSWORD",
        expected_role: "Guest",
        sandbox: true,
    },
];

struct SignedIn {
    fixture: Fixture,
    access_token: String,
    public_id: String,
    role: String,
}

pub fn ensure() -> Result<()> {
    ensure_store()?;

    let mut logins = Vec::with_capacity(FIXTURES.len());
    for fixture in FIXTURES {
        let password = required_secret(&fixture.target(fixture.password_secret))?;
        logins.push((
            fixture,
            honey::Login {
                auth: AUTH_URL.to_owned(),
                api: API_URL.to_owned(),
                honey_app: HONEY_APP.to_owned(),
                username: fixture.username.to_owned(),
                password,
            },
        ));
    }
    let totp_secret = optional_secret(&sandbox_totp_target())?;

    for fixture in FIXTURES {
        let username_target = fixture.target(fixture.username_secret);
        let current_username = crate::try_get(&username_target, CONFIG)?;
        if let Some(value) = &current_username {
            output::register_secret(value.as_bytes());
        }
        if current_username.as_deref() != Some(fixture.username) {
            output::status("fixture username configuration required");
            crate::write_group(
                CONFIG,
                std::slice::from_ref(&username_target),
                fixture.username,
            )?;
        }
    }

    let mut accounts = Vec::with_capacity(FIXTURES.len());
    for (fixture, login) in &logins {
        output::status("fixture sign-in started");
        let (access_token, totp_enabled) =
            sign_in_fixture(*fixture, login, totp_secret.as_deref())?;
        ensure!(!totp_enabled, "fixture authentication remains enabled");
        accounts.push(SignedIn {
            fixture: *fixture,
            access_token,
            public_id: String::new(),
            role: String::new(),
        });
    }

    output::status("fixture identity checked");
    let platform_identity = honey::api_identity(API_URL, &accounts[0].access_token)?;
    ensure_identity_name(accounts[0].fixture, &platform_identity)?;
    if platform_identity.role != "PlatformAdmin" {
        bail!("fixture administrator role is invalid");
    }
    accounts[0].public_id = platform_identity.user_public_id;
    accounts[0].role = platform_identity.role;

    for account in accounts.iter_mut().skip(1) {
        output::status("fixture identity checked");
        let identity = honey::api_identity(API_URL, &account.access_token)?;
        ensure_identity_name(account.fixture, &identity)?;
        account.public_id = identity.user_public_id;
        account.role = identity.role;
    }

    for (index, role) in [(1, "AppAdmin"), (2, "Guest"), (3, "Guest")] {
        output::status("fixture role configured");
        honey::set_user_role(
            API_URL,
            &accounts[0].access_token,
            &accounts[index].public_id,
            role,
        )?;
    }

    for account in accounts.iter_mut().skip(1) {
        output::status("fixture identity verified");
        let identity = honey::api_identity(API_URL, &account.access_token)?;
        ensure_identity_name(account.fixture, &identity)?;
        ensure!(
            identity.user_public_id == account.public_id,
            "fixture public id changed"
        );
        ensure!(
            identity.role == account.fixture.expected_role,
            "fixture role readback is invalid"
        );
        account.role = identity.role;
    }

    output::status("fixture app access checked");
    let platform_apps = honey::get_apps(API_URL, &accounts[0].access_token)?;
    let named_apps: Vec<_> = platform_apps
        .iter()
        .filter(|app| app.name == OWNED_APP_NAME)
        .collect();
    let _app_id = match named_apps.as_slice() {
        [app] if app.app_public_id == OWNED_APP_ID => {
            output::status("fixture app membership configured");
            honey::add_app_member(
                API_URL,
                &accounts[0].access_token,
                OWNED_APP_ID,
                &accounts[1].public_id,
            )?;
            output::status("fixture app membership checked");
            let app_admin_apps = honey::get_apps(API_URL, &accounts[1].access_token)?;
            ensure!(
                app_admin_apps
                    .iter()
                    .any(|app| app.app_public_id == OWNED_APP_ID),
                "fixture app membership is unavailable"
            );
            OWNED_APP_ID.to_owned()
        }
        [] => {
            output::status("fixture app creation required");
            let new_id = honey::create_app_with_token(
                API_URL,
                &accounts[1].access_token,
                OWNED_APP_NAME,
                "ps-qa fixture",
                "https://qa-owned-app.invalid/callback",
            )?;
            output::register_secret(new_id.as_bytes());
            bail!("fixture app identifier is invalid");
        }
        apps => {
            if apps.len() == 1 {
                bail!("fixture app identifier is invalid");
            }
            bail!("fixture app configuration is ambiguous");
        }
    };

    for _ in &accounts {
        output::status("fixture account verified");
    }
    Ok(())
}

fn ensure_store() -> Result<()> {
    output::status("fixture project checked");
    let project_status = crate::doppler_command()
        .map_err(|_| eyre!("fixture project is unavailable"))?
        .args(["--no-read-env", "projects", "get", PROJECT])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| eyre!("fixture project is unavailable"))?;
    ensure!(project_status.success(), "fixture project is unavailable");

    output::status("fixture config checked");
    let config_status = crate::doppler_command()
        .map_err(|_| eyre!("fixture config is unavailable"))?
        .args([
            "--no-read-env",
            "configs",
            "get",
            CONFIG,
            "--project",
            PROJECT,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| eyre!("fixture config is unavailable"))?;
    ensure!(config_status.success(), "fixture config is unavailable");
    Ok(())
}

pub(crate) fn sandbox_totp_target() -> Target {
    Target {
        project: PROJECT.to_owned(),
        name: SANDBOX_TOTP_SECRET.to_owned(),
    }
}

fn required_secret(target: &Target) -> Result<String> {
    match crate::try_get(target, CONFIG)? {
        Some(value) if !value.is_empty() => {
            output::register_secret(value.as_bytes());
            Ok(value)
        }
        _ => Err(eyre!("required fixture secret is missing or empty")),
    }
}

fn optional_secret(target: &Target) -> Result<Option<String>> {
    let value = crate::try_get(target, CONFIG)?.filter(|value| !value.is_empty());
    if let Some(value) = &value {
        output::register_secret(value.as_bytes());
    }
    Ok(value)
}

fn sign_in_fixture(
    fixture: Fixture,
    login: &honey::Login,
    existing_totp_secret: Option<&str>,
) -> Result<(String, bool)> {
    let reactor = Reactor::local().map_err(|e| eyre!(e.to_string()))?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        output::status("fixture signup started");
        honey::signup(login, &handle).await?;

        output::status("fixture authentication started");
        let mut auth = honey::AuthSession::submit_username(login, &handle).await?;
        output::status("fixture password submitted");
        let step = auth.submit_password(&login.password).await?;
        if step == honey::AuthStep::Totp {
            if !fixture.sandbox {
                bail!("unexpected fixture authentication challenge");
            }
            let secret = existing_totp_secret
                .ok_or_else(|| eyre!("fixture authentication secret is missing"))?;
            let code = totp_sha512(secret)?;
            output::register_secret(code.as_bytes());
            output::status("fixture verification code submitted");
            auth.submit_totp_code(&code).await?;
        }

        let access_token = auth.access_token()?.to_owned();
        output::register_secret(access_token.as_bytes());
        output::status("fixture authentication status checked");
        let mut enabled = auth.totp_enabled().await?;

        if fixture.sandbox && enabled {
            ensure!(
                step == honey::AuthStep::Totp,
                "GetTotpStatus: qa-2fa-sandbox is enabled without a TOTP challenge"
            );
            output::status("fixture authentication disabled");
            auth.disable_totp().await?;
            output::status("fixture authentication status checked");
            enabled = auth.totp_enabled().await?;
        } else if fixture.sandbox && existing_totp_secret.is_none() {
            output::status("fixture authentication enrollment started");
            let manual_secret = auth.start_totp_enrollment().await?;
            output::register_secret(manual_secret.as_bytes());
            output::status("fixture authentication secret stored");
            let secret_target = sandbox_totp_target();
            crate::write_group(CONFIG, std::slice::from_ref(&secret_target), &manual_secret)?;
            let code = totp_sha512(&manual_secret)?;
            output::register_secret(code.as_bytes());
            output::status("fixture authentication enrollment confirmed");
            auth.confirm_totp_enrollment(&code).await?;
            output::status("fixture authentication disabled");
            auth.disable_totp().await?;
            output::status("fixture authentication status checked");
            enabled = auth.totp_enabled().await?;
        }

        ensure!(!enabled, "fixture authentication remains enabled");
        Ok((access_token, enabled))
    })
}

pub(crate) fn totp_sha512(secret: &str) -> Result<String> {
    let secret_bytes = Secret::Encoded(secret.to_owned())
        .to_bytes()
        .map_err(|_| eyre!("fixture authentication secret is invalid"))?;
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        SANDBOX_TOTP_PERIOD_SECS,
        secret_bytes,
        None,
        "qa-2fa-sandbox".to_owned(),
    )
    .map_err(|_| eyre!("could not prepare SHA-512 TOTP code"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| eyre!("system time is before the Unix epoch"))?;
    Ok(totp.generate(now.as_secs()))
}

fn ensure_identity_name(fixture: Fixture, identity: &honey::ApiIdentity) -> Result<()> {
    ensure!(
        identity.username == fixture.username,
        "fixture identity is invalid"
    );
    Ok(())
}
