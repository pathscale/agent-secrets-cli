//! Register honey.id apps and manage their app keys without printing them.
//!
//! Signs in to auth with an account whose username and password live in
//! Doppler and opens an api.honey session with the access token before calling
//! app management endpoints. Created keys are returned to the caller so it
//! can write them to Doppler, never to standard output.

use std::sync::Arc;
use std::time::Duration;

use endpoint_libs::libs::ws::{WsClient, WsClientBuilder};
use crate::eyre::{Result, WrapErr, bail, ensure, eyre};
use futures::FutureExt;
use futures::future::{Either, select};
use nagoya::reactor::{Handle, Reactor, block_on_with};
use serde_json::{Value, json};

use crate::output;

/// auth: `SubmitUsername` (connect), then `SubmitPassword`.
const SUBMIT_PASSWORD: u32 = 13;
/// auth: `SubmitTotpCode`.
const SUBMIT_TOTP_CODE: u32 = 24;
/// auth: `GetTotpStatus`.
const GET_TOTP_STATUS: u32 = 25;
/// auth: `StartTotpEnrollment`.
const START_TOTP_ENROLLMENT: u32 = 26;
/// auth: `ConfirmTotpEnrollment`.
const CONFIRM_TOTP_ENROLLMENT: u32 = 27;
/// auth: `DisableTotp`.
const DISABLE_TOTP: u32 = 28;
/// auth: `SetPassword` replaces the password on a fully verified session.
const SET_PASSWORD: u32 = 29;
/// api.honey: `Init` (connect) opens a session from an access token.
const INIT: &str = "Init";
/// HoneyErrorCode::Unauthorized, returned by Init when the token is invalid.
const INIT_UNAUTHORIZED: u64 = 100401;
/// api.honey: `SetUserRole(userPublicId, newPlatformRole)`.
const SET_USER_ROLE: u32 = 10004;
/// api.honey: `GetApps(statusFilter, paymentFilter)`.
const GET_APPS: u32 = 20000;
/// api.honey: `CreateApp(name, description, callbackUrl)`.
const CREATE_APP: u32 = 20001;
/// api.honey: `AddAppMember(appPublicId, userPublicId)`.
const ADD_APP_MEMBER: u32 = 20007;
/// api.honey: `CreateAppKey(appPublicId, label, expiresInSecs)`.
const CREATE_APP_KEY: u32 = 20009;
/// api.honey: `ListAppKeys(appPublicId)`.
const LIST_APP_KEYS: u32 = 20010;
/// api.honey: `RevokeAppKey(appPublicId, keyId, graceSecs)`.
const REVOKE_APP_KEY: u32 = 20011;
/// api.honey: `SetAppService(appPublicId, service)`.
const SET_APP_SERVICE: u32 = 20014;
/// api.honey: `GetUsers(appPublicId, page, pageSize)`.
const GET_USERS: u32 = 10000;
/// api.honey: `GetUserRoles(appPublicId, userPublicId)`.
const GET_USER_ROLES: u32 = 11005;
/// How long one frame may take before the service counts as unresponsive.
const RECV_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Login {
    pub auth: String,
    pub api: String,
    pub honey_app: String,
    pub username: String,
    pub password: String,
}

pub struct NewApp {
    pub name: String,
    pub description: String,
    pub callback_url: String,
}

pub struct Created {
    pub app_public_id: String,
    pub app_api_key: String,
    /// What auth presents on callbacks, and what a site configures as its
    /// `honey_id.auth_api_key`. Before honey kept the two apart it was the
    /// app key itself, so an answer without it falls back to that.
    pub callback_api_key: String,
}

pub struct CreatedKey {
    pub key_id: String,
    pub key: String,
}

pub struct AppKeySummary {
    pub key_id: String,
    pub label: String,
}

pub struct User {
    pub user_public_id: String,
    pub username: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum AuthStep {
    Complete,
    Totp,
}

pub(crate) struct AuthSession {
    client: WsClient,
    access_token: Option<String>,
}

pub(crate) struct ApiIdentity {
    pub user_public_id: String,
    pub username: String,
    pub role: String,
}

pub(crate) struct App {
    pub app_public_id: String,
    pub name: String,
}

/// Run the normal Signup handshake with the already stored password.
pub(crate) async fn signup(login: &Login, handle: &Handle) -> Result<()> {
    let password = crockford_base32(login.password.as_bytes());
    connect(
        &login.auth,
        &header(
            "Signup",
            &[&login.honey_app, &login.username, password.as_str()],
        )?,
        handle,
    )
    .await
    .wrap_err("Signup")?;
    Ok(())
}

impl AuthSession {
    pub(crate) async fn submit_username(login: &Login, handle: &Handle) -> Result<Self> {
        let protocol = header("SubmitUsername", &[&login.honey_app, &login.username])
            .inspect_err(|_| {
                output::status("Honey Auth username submission could not be prepared");
            })?;
        let mut client = open_websocket(&login.auth, &protocol, handle)
            .await
            .inspect_err(|_| output::status("Honey Auth WebSocket connection or upgrade failed"))
            .wrap_err("SubmitUsername")?;
        require_handshake_response(&login.auth, &mut client)
            .await
            .inspect_err(|_| output::status("Honey Auth username submission response failed"))
            .wrap_err("SubmitUsername")?;
        Ok(Self {
            client,
            access_token: None,
        })
    }

    pub(crate) async fn submit_password(&mut self, password: &str) -> Result<AuthStep> {
        let encoded = crockford_base32(password.as_bytes());
        let response = request(&mut self.client, SUBMIT_PASSWORD, json!([encoded]))
            .await
            .inspect_err(|_| output::status("Honey Auth password authentication request failed"))
            .wrap_err("SubmitPassword")?;
        let next_step = response.get("nextStep").ok_or_else(|| {
            output::status("Honey Auth password response omitted the next step");
            eyre!("SubmitPassword answered without nextStep")
        })?;
        let step = auth_step(next_step)
            .inspect_err(|_| {
                output::status("Honey Auth password response had an unknown next step");
            })?;
        if step == AuthStep::Complete {
            self.access_token = Some(
                string_field(&response, "accessToken", "SubmitPassword")
                    .inspect_err(|_| {
                        output::status("Honey Auth password response omitted the access token");
                    })?,
            );
        }
        Ok(step)
    }

    pub(crate) async fn submit_totp_code(&mut self, code: &str) -> Result<()> {
        let response = request(&mut self.client, SUBMIT_TOTP_CODE, json!([code]))
            .await
            .wrap_err("SubmitTotpCode")?;
        self.access_token = Some(string_field(&response, "accessToken", "SubmitTotpCode")?);
        Ok(())
    }

    pub(crate) fn access_token(&self) -> Result<&str> {
        self.access_token
            .as_deref()
            .ok_or_else(|| eyre!("auth session is not fully verified"))
    }

    pub(crate) async fn totp_enabled(&mut self) -> Result<bool> {
        let response = request(&mut self.client, GET_TOTP_STATUS, json!([]))
            .await
            .wrap_err("GetTotpStatus")?;
        response
            .get("enabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| eyre!("GetTotpStatus answered without enabled"))
    }

    pub(crate) async fn start_totp_enrollment(&mut self) -> Result<String> {
        let response = request(&mut self.client, START_TOTP_ENROLLMENT, json!([]))
            .await
            .wrap_err("StartTotpEnrollment")?;
        string_field(&response, "manualSecret", "StartTotpEnrollment")
    }

    pub(crate) async fn confirm_totp_enrollment(&mut self, code: &str) -> Result<()> {
        request(&mut self.client, CONFIRM_TOTP_ENROLLMENT, json!([code]))
            .await
            .wrap_err("ConfirmTotpEnrollment")?;
        Ok(())
    }

    pub(crate) async fn disable_totp(&mut self) -> Result<()> {
        request(&mut self.client, DISABLE_TOTP, json!([]))
            .await
            .wrap_err("DisableTotp")?;
        Ok(())
    }

    pub(crate) async fn set_password(&mut self, password: &str) -> Result<()> {
        self.access_token()?;
        let encoded = crockford_base32(password.as_bytes());
        request(&mut self.client, SET_PASSWORD, json!([encoded]))
            .await
            .wrap_err("SetPassword")?;
        Ok(())
    }
}

pub(crate) fn api_identity(api_url: &str, access_token: &str) -> Result<ApiIdentity> {
    with_api(api_url, access_token, async |_, params| {
        Ok(ApiIdentity {
            user_public_id: string_field(params, "userPublicId", "Init")?,
            username: string_field(params, "username", "Init")?,
            role: api_role(
                params
                    .get("role")
                    .ok_or_else(|| eyre!("Init answered without role"))?,
            )?,
        })
    })
}

pub(crate) fn require_revoked_api_token(api_url: &str, access_token: &str) -> Result<()> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    let (_, frame) = block_on_with(&reactor, api_init_frame(api_url, access_token, &handle))?;
    ensure!(
        frame.get("type").and_then(Value::as_str) == Some("Error")
            && frame.get("code").and_then(Value::as_u64) == Some(INIT_UNAUTHORIZED),
        "Init did not reject the pre-restart DEV token as unauthorized"
    );
    Ok(())
}

pub(crate) fn set_user_role(
    api_url: &str,
    access_token: &str,
    user_public_id: &str,
    role: &str,
) -> Result<()> {
    with_api(api_url, access_token, async |api, _| {
        request(api, SET_USER_ROLE, json!([user_public_id, role]))
            .await
            .wrap_err("SetUserRole")?;
        Ok(())
    })
}

pub(crate) fn get_apps(api_url: &str, access_token: &str) -> Result<Vec<App>> {
    with_api(api_url, access_token, async |api, _| {
        let response = request(api, GET_APPS, json!([null, null]))
            .await
            .wrap_err("GetApps")?;
        response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("GetApps answered without data"))?
            .iter()
            .map(|app| {
                Ok(App {
                    app_public_id: string_field(app, "appPublicId", "GetApps")?,
                    name: string_field(app, "name", "GetApps")?,
                })
            })
            .collect()
    })
}

pub(crate) fn add_app_member(
    api_url: &str,
    access_token: &str,
    app_public_id: &str,
    user_public_id: &str,
) -> Result<()> {
    with_api(api_url, access_token, async |api, _| {
        request(api, ADD_APP_MEMBER, json!([app_public_id, user_public_id]))
            .await
            .wrap_err("AddAppMember")?;
        Ok(())
    })
}

/// Create an app using an existing API bearer and return only its public id.
pub(crate) fn create_app_with_token(
    api_url: &str,
    access_token: &str,
    name: &str,
    description: &str,
    callback_url: &str,
) -> Result<String> {
    with_api(api_url, access_token, async |api, _| {
        let response = request(api, CREATE_APP, json!([name, description, callback_url]))
            .await
            .wrap_err("CreateApp")?;
        string_field(&response, "appPublicId", "CreateApp")
    })
}

fn with_api<T>(
    api_url: &str,
    access_token: &str,
    f: impl AsyncFnOnce(&mut WsClient, &Value) -> Result<T>,
) -> Result<T> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let (mut api, init) = connect_api(api_url, access_token, &handle).await?;
        f(&mut api, &init).await
    })
}

async fn connect_api(
    api_url: &str,
    access_token: &str,
    handle: &Handle,
) -> Result<(WsClient, Value)> {
    let (client, frame) = api_init_frame(api_url, access_token, handle).await?;
    if frame.get("type").and_then(Value::as_str) == Some("Error") {
        bail!("Init refused: {}", describe(&frame));
    }
    Ok((client, frame.get("params").cloned().unwrap_or(Value::Null)))
}

async fn api_init_frame(
    api_url: &str,
    access_token: &str,
    handle: &Handle,
) -> Result<(WsClient, Value)> {
    validate_credential_origin(api_url)?;
    let (mut client, _) = websocket_client(&header(INIT, &[access_token])?)?
        .build(api_url, handle)
        .await
        .wrap_err("Init")?;
    let frame = recv(&mut client).await.wrap_err("Init")?;
    Ok((client, frame))
}

fn string_field(value: &Value, name: &str, method: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| eyre!("{method} answered without {name}"))
}

fn auth_step(value: &Value) -> Result<AuthStep> {
    if let Some(name) = value.as_str() {
        return match name.to_ascii_lowercase().as_str() {
            "complete" => Ok(AuthStep::Complete),
            "totp" => Ok(AuthStep::Totp),
            _ => Err(eyre!("SubmitPassword returned an unknown next step")),
        };
    }
    match value.as_u64() {
        Some(1) => Ok(AuthStep::Complete),
        Some(2) => Ok(AuthStep::Totp),
        _ => Err(eyre!("SubmitPassword returned an unknown next step")),
    }
}

fn api_role(value: &Value) -> Result<String> {
    if let Some(role) = value.as_str() {
        return Ok(role.to_owned());
    }
    let role = match value.as_u64() {
        Some(0) => "Public",
        Some(1) => "PlatformAdmin",
        Some(2) => "PlatformSupport",
        Some(3) => "AppAdmin",
        Some(4) => "AppSupport",
        Some(5) => "Guest",
        Some(6) => "AuthApiKey",
        Some(7) => "AppUser",
        Some(8) => "Service",
        _ => return Err(eyre!("Init returned an unknown role")),
    };
    Ok(role.to_owned())
}

pub fn create_app(login: &Login, app: &NewApp) -> Result<Created> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        let response = request(
            &mut api,
            CREATE_APP,
            json!([app.name, app.description, app.callback_url]),
        )
        .await
        .wrap_err("CreateApp")?;
        let field = |name: &str| {
            response
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("CreateApp answered without {name}"))
        };
        Ok(Created {
            app_public_id: field("appPublicId")?,
            app_api_key: field("appApiKey")?,
            callback_api_key: field("callbackApiKey").or_else(|_| field("appApiKey"))?,
        })
    })
}

pub fn create_app_key(
    login: &Login,
    app_public_id: &str,
    label: &str,
    expires_in_secs: Option<u64>,
) -> Result<CreatedKey> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        let response = request(
            &mut api,
            CREATE_APP_KEY,
            json!([app_public_id, label, expires_in_secs]),
        )
        .await
        .wrap_err("CreateAppKey")?;
        let field = |name: &str| {
            response
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("CreateAppKey answered without {name}"))
        };
        Ok(CreatedKey {
            key_id: field("keyId")?,
            key: field("key")?,
        })
    })
}

pub fn list_app_keys(login: &Login, app_public_id: &str) -> Result<Vec<AppKeySummary>> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        let response = request(&mut api, LIST_APP_KEYS, json!([app_public_id]))
            .await
            .wrap_err("ListAppKeys")?;
        let keys = response
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("ListAppKeys answered without keys"))?;
        keys.iter()
            .map(|key| {
                let field = |name: &str| {
                    key.get(name)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| eyre!("ListAppKeys key entry has no {name}"))
                };
                Ok(AppKeySummary {
                    key_id: field("keyId")?,
                    label: field("label")?,
                })
            })
            .collect()
    })
}

pub fn revoke_app_key(
    login: &Login,
    app_public_id: &str,
    key_id: &str,
    grace_secs: u64,
) -> Result<()> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        request(
            &mut api,
            REVOKE_APP_KEY,
            json!([app_public_id, key_id, grace_secs]),
        )
        .await
        .wrap_err("RevokeAppKey")?;
        Ok(())
    })
}

pub fn set_app_service(login: &Login, app_public_id: &str, service: bool) -> Result<()> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        request(&mut api, SET_APP_SERVICE, json!([app_public_id, service]))
            .await
            .wrap_err("SetAppService")?;
        Ok(())
    })
}

/// List users on one page of an app, optionally limiting role lookups to an
/// exact username match.
pub fn list_users(
    login: &Login,
    app_public_id: &str,
    page: u32,
    page_size: u32,
    username: Option<&str>,
) -> Result<Vec<User>> {
    ensure!(page > 0, "page must be at least 1");
    ensure!(page_size > 0, "page size must be at least 1");
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header(INIT, &[&token])?, &handle).await?;
        let response = request(&mut api, GET_USERS, json!([app_public_id, page, page_size]))
            .await
            .wrap_err("GetUsers")?;
        let data = response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("GetUsers answered without data"))?;
        let mut users = Vec::new();
        for value in data {
            let mut user = parse_user(value)?;
            if username.is_some_and(|expected| user.username.as_str() != expected) {
                continue;
            }
            let roles = request(
                &mut api,
                GET_USER_ROLES,
                json!([app_public_id, user.user_public_id]),
            )
            .await
            .wrap_err("GetUserRoles")?;
            user.roles = parse_roles(&roles, app_public_id)?;
            users.push(user);
        }
        Ok(users)
    })
}

fn parse_user(value: &Value) -> Result<User> {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| eyre!("GetUsers user entry has no {name}"))
    };
    Ok(User {
        user_public_id: field("userPublicId")?,
        username: field("username")?,
        roles: Vec::new(),
    })
}

/// GetUserRoles answers `roles: { platform, apps: [{ appPubId, appName, joinedAt, status }] }`.
/// Reported as the platform role and the membership status in the app being listed.
fn parse_roles(response: &Value, app_public_id: &str) -> Result<Vec<String>> {
    let roles = response
        .get("roles")
        .ok_or_else(|| eyre!("GetUserRoles answered without roles"))?;
    let mut out = Vec::new();
    if let Some(platform) = roles.get("platform").and_then(Value::as_str) {
        out.push(format!("platform:{platform}"));
    }
    let membership = roles
        .get("apps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|app| app.get("appPubId").and_then(Value::as_str) == Some(app_public_id));
    if let Some(status) = membership
        .and_then(|app| app.get("status"))
        .and_then(Value::as_str)
    {
        out.push(format!("member:{status}"));
    }
    Ok(out)
}

/// Sign an account up to `login.honey_app` on auth, then sign in with it to
/// prove the credentials work. With `login.api` non-empty, also open a session
/// there and return the account's public id, which is not a secret.
pub fn create_account(login: &Login) -> Result<Option<String>> {
    let reactor = Reactor::local()?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        validate_credential_origin(&login.auth)?;
        if !login.api.is_empty() {
            validate_credential_origin(&login.api)?;
        }

        // Signup is a handshake: the whole request rides in the header, and the
        // one frame the server answers with is its verdict.
        connect(
            &login.auth,
            &header(
                "Signup",
                &[
                    &login.honey_app,
                    &login.username,
                    &crockford_base32(login.password.as_bytes()),
                ],
            )?,
            &handle,
        )
        .await
        .wrap_err("Signup")?;
        let token = sign_in(login, &handle).await?;
        if login.api.is_empty() {
            return Ok(None);
        }
        // The session opens with Init, which answers with who signed in:
        // api.honey names the id userPublicId, the sites name it userId.
        validate_credential_origin(&login.api)?;
        let (mut client, _) = websocket_client(&header(INIT, &[&token])?)?
            .build(&login.api, &handle)
            .await
            .wrap_err_with(|| format!("could not connect to {}", login.api))?;
        let frame = recv(&mut client).await?;
        if frame.get("type").and_then(Value::as_str) == Some("Error") {
            bail!("{} refused Init: {}", login.api, describe(&frame));
        }
        let params = frame.get("params").unwrap_or(&Value::Null);
        Ok(params
            .get("userPublicId")
            .or_else(|| params.get("userId"))
            .and_then(Value::as_str)
            .map(str::to_owned))
    })
}

pub(crate) async fn sign_in(login: &Login, handle: &Handle) -> Result<String> {
    let mut auth = connect(
        &login.auth,
        &header("SubmitUsername", &[&login.honey_app, &login.username])?,
        handle,
    )
    .await?;
    let response = request(
        &mut auth,
        SUBMIT_PASSWORD,
        json!([crockford_base32(login.password.as_bytes())]),
    )
    .await
    .wrap_err("sign-in refused")?;
    response
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| eyre!("SubmitPassword answered without an access token"))
}

/// The `Sec-WebSocket-Protocol` value endpoint-libs servers read a connect
/// endpoint from: `0<endpoint>, 1<param>, ...`.
pub(crate) fn header(endpoint: &str, params: &[&str]) -> Result<String> {
    ensure!(
        params.iter().all(|p| !p.contains(',')),
        "a handshake parameter cannot contain a comma"
    );
    Ok(
        std::iter::once(format!("0{}", endpoint.to_ascii_lowercase()))
            .chain(
                params
                    .iter()
                    .enumerate()
                    .map(|(i, p)| format!("{}{p}", i + 1)),
            )
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Accept only the fixed set of credential service origins.
///
/// This deliberately checks a small URL grammar without parsing or normalizing
/// the input, so alternate spellings cannot expand the trusted host set.
fn validate_credential_origin(url: &str) -> Result<()> {
    let invalid = || eyre!("credential service origin is not allowed");
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\\' | '%' | '?' | '#'))
    {
        return Err(invalid());
    }

    let remainder = url.strip_prefix("wss://").ok_or_else(invalid)?;
    let (authority, path) = match remainder.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (remainder, None),
    };
    if path.is_some_and(|path| !path.is_empty()) {
        return Err(invalid());
    }

    let trusted = [
        "auth.honey.id",
        "api.honey.id",
        "auth-dev.honey.id",
        "api-dev.honey.id",
        "merchant.pays.online",
        "api.crates.vip",
    ];
    if !trusted
        .iter()
        .any(|host| authority == *host || authority == format!("{host}:443"))
    {
        return Err(invalid());
    }
    Ok(())
}

/// Connect and read the frame every handshake is answered with.
pub(crate) async fn connect(url: &str, protocol: &str, handle: &Handle) -> Result<WsClient> {
    let mut client = open_websocket(url, protocol, handle).await?;
    require_handshake_response(url, &mut client).await?;
    Ok(client)
}

async fn open_websocket(url: &str, protocol: &str, handle: &Handle) -> Result<WsClient> {
    validate_credential_origin(url)?;
    let (client, _) = websocket_client(protocol)?
        .build(url, handle)
        .await
        .wrap_err_with(|| format!("could not connect to {url}"))?;
    Ok(client)
}

fn websocket_client(protocol: &str) -> Result<WsClientBuilder> {
    let roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    Ok(WsClientBuilder::new()
        .tls_config(websocket_tls_config(roots)?)
        .protocol_header(protocol))
}

fn websocket_tls_config(roots: rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>> {
    // Public certificate chains can use RSA signatures. The ps-rustcrypto
    // `rsa-pss` feature adds RSA verification; the provider negotiates
    // ChaCha20-Poly1305.
    let provider = Arc::new(ps_rustcrypto::provider_with_rsa_pss());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .wrap_err("could not configure WebSocket TLS")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn require_handshake_response(url: &str, client: &mut WsClient) -> Result<()> {
    let frame = recv(client).await?;
    if frame.get("type").and_then(Value::as_str) == Some("Error") {
        bail!("{url} refused the handshake: {}", describe(&frame));
    }
    Ok(())
}

/// One request; the `params` of the answer carrying its `seq`.
pub(crate) async fn request(client: &mut WsClient, method: u32, params: Value) -> Result<Value> {
    client.send_req(method, params).await?;
    loop {
        let frame = recv(client).await?;
        match frame.get("type").and_then(Value::as_str) {
            Some("Immediate")
                if frame.get("method").and_then(Value::as_u64) == Some(method.into()) =>
            {
                return Ok(frame.get("params").cloned().unwrap_or(Value::Null));
            }
            Some("Error") => bail!("refused: {}", describe(&frame)),
            _ => {}
        }
    }
}

/// An error frame's code only. A server message could echo a credential.
fn describe(frame: &Value) -> String {
    let code = frame.get("code").map(Value::to_string).unwrap_or_default();
    format!("code {code}")
}

async fn recv(client: &mut WsClient) -> Result<Value> {
    let frame = client.recv_raw().fuse();
    let timeout = nagoya::sleep(RECV_TIMEOUT).fuse();
    futures::pin_mut!(frame, timeout);
    match select(frame, timeout).await {
        Either::Left((frame, _)) => frame,
        Either::Right(_) => bail!("no answer within {}s", RECV_TIMEOUT.as_secs()),
    }
}

/// Crockford base32, unpadded: how honey.id takes a password.
fn crockford_base32(bytes: &[u8]) -> String {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.encoding()
        .expect("a valid base32 alphabet")
        .encode(bytes)
}

#[cfg(test)]
mod tls_tests {
    use std::sync::Arc;

    use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePrivateKey};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use rustls::{
        CertificateError, CipherSuite, ClientConnection, Connection, RootCertStore, ServerConfig,
        ServerConnection,
    };

    use super::websocket_tls_config;

    struct TestSigner(SigningKey);

    impl rcgen::PublicKeyData for TestSigner {
        fn der_bytes(&self) -> &[u8] {
            self.0.as_ref().as_bytes()
        }

        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_ED25519
        }
    }

    impl rcgen::SigningKey for TestSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
    }

    fn transfer_tls(sender: &mut Connection, receiver: &mut Connection) -> Result<(), rustls::Error> {
        let mut flight = Vec::new();
        sender.write_tls(&mut flight).expect("write TLS records");
        let mut pending = flight.as_slice();
        while !pending.is_empty() {
            let read = receiver.read_tls(&mut pending).expect("read TLS records");
            assert_ne!(read, 0);
            receiver.process_new_packets()?;
        }
        Ok(())
    }

    #[test]
    fn wss_tls_handshake_verifies_server_identity() {
        let signer = TestSigner(SigningKey::from_bytes(&[7; 32]));
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.serial_number = Some(1u64.into());
        let cert = params.self_signed(&signer).unwrap();
        let key = signer.0.to_pkcs8_der().unwrap();
        let key = PrivatePkcs8KeyDer::from(key.as_bytes().to_vec());
        let server_config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(ps_rustcrypto::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key.into())
                .unwrap(),
        );

        let handshake = |roots, name: &'static str| {
            let config = websocket_tls_config(roots).unwrap();
            let name = ServerName::try_from(name).unwrap();
            let mut client = Connection::Client(ClientConnection::new(config, name).unwrap());
            let mut server =
                Connection::Server(ServerConnection::new(server_config.clone()).unwrap());
            for _ in 0..8 {
                transfer_tls(&mut client, &mut server)?;
                transfer_tls(&mut server, &mut client)?;
                if !client.is_handshaking() && !server.is_handshaking() {
                    return Ok(client.negotiated_cipher_suite().unwrap().suite());
                }
            }
            panic!("TLS handshake did not complete");
        };

        let mut trusted_roots = RootCertStore::empty();
        trusted_roots.add(cert.der().clone()).unwrap();
        assert_eq!(
            handshake(trusted_roots.clone(), "localhost").unwrap(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
        assert!(matches!(
            handshake(trusted_roots, "other.example"),
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
            ))
        ));
        assert!(matches!(
            handshake(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
                "localhost"
            ),
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer))
        ));
    }
}

#[cfg(test)]
mod credential_origin_tests {
    use super::validate_credential_origin;

    #[test]
    fn trusted_origins_accept_only_exact_authorities_and_root_paths() {
        for host in [
            "auth.honey.id",
            "api.honey.id",
            "auth-dev.honey.id",
            "api-dev.honey.id",
            "merchant.pays.online",
            "api.crates.vip",
        ] {
            for suffix in ["", "/", ":443", ":443/"] {
                assert!(validate_credential_origin(&format!("wss://{host}{suffix}")).is_ok());
            }
        }
    }

    #[test]
    fn untrusted_forms_fail_without_echoing_credentials() {
        for url in [
            "ws://auth.honey.id",
            "wss://evil.example",
            "wss://auth.honey.id.evil.example",
            "wss://user:secret@auth.honey.id",
            "wss://auth.honey.id:444",
            "wss://auth.honey.id/path",
            "wss://auth.honey.id?secret",
            "wss://auth.honey.id#secret",
            "wss://%61uth.honey.id",
            "wss://auth.honey.id\\evil",
            "wss://auth.honey.id\n",
            "wss://auth.honey.id.",
            "wss://AUTH.HONEY.ID",
            "wss://auth.honey.id//",
        ] {
            assert_eq!(
                validate_credential_origin(url).unwrap_err().to_string(),
                "credential service origin is not allowed"
            );
        }
    }
}
