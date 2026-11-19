//! crates.vip: apps and registry tokens, the token going straight to Doppler.
//!
//! Signs in to honey.id as an account kept in Doppler, opens a crates.vip
//! session with `Init`, and calls the registry's API. App ids and bucket names
//! are not secrets and are printed; a token is written to Doppler and never
//! printed.

use endpoint_libs::libs::ws::WsClient;
use crate::eyre::{Result, WrapErr, eyre};
use nagoya::reactor::{Reactor, block_on_with};
use serde_json::{Value, json};

use crate::honey::{Login, connect, header, request, sign_in};

/// crates.vip: `CreateToken(appId, name, scope)`.
const CREATE_TOKEN: u32 = 40002;
/// crates.vip: `CreateApp(name)`.
const CREATE_APP: u32 = 50000;
/// crates.vip: `ListApps()`.
const LIST_APPS: u32 = 50001;
/// crates.vip: `AddAppMember(appId, userPubId)`.
const ADD_APP_MEMBER: u32 = 50003;

pub struct App {
    pub app_id: String,
    pub name: String,
    pub bucket: String,
}

pub struct Minted {
    pub token_id: String,
    pub token: String,
}

/// Every app the account can reach: its own, or all of them for a platform
/// admin.
pub fn list_apps(login: &Login) -> Result<Vec<App>> {
    with_session(login, async |api| {
        let response = request(api, LIST_APPS, json!([]))
            .await
            .wrap_err("ListApps")?;
        response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre!("ListApps answered without data"))?
            .iter()
            .map(app)
            .collect()
    })
}

/// A new app on a private bucket of its own; the account becomes its first
/// member.
pub fn create_app(login: &Login, name: &str, members: &[String]) -> Result<App> {
    with_session(login, async |api| {
        let response = request(api, CREATE_APP, json!([name]))
            .await
            .wrap_err("CreateApp")?;
        let created = app(response
            .get("app")
            .ok_or_else(|| eyre!("CreateApp answered without app"))?)?;
        for member in members {
            request(api, ADD_APP_MEMBER, json!([created.app_id, member]))
                .await
                .wrap_err_with(|| format!("AddAppMember {member}"))?;
        }
        Ok(created)
    })
}

/// A registry token in `app_id`, `ReadOnly` or `Publish`.
pub fn create_token(login: &Login, app_id: &str, name: &str, scope: &str) -> Result<Minted> {
    with_session(login, async |api| {
        let response = request(api, CREATE_TOKEN, json!([app_id, name, scope]))
            .await
            .wrap_err("CreateToken")?;
        let field = |name: &str| {
            response
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("CreateToken answered without {name}"))
        };
        Ok(Minted {
            token_id: field("tokenId")?,
            token: field("token")?,
        })
    })
}

fn app(value: &Value) -> Result<App> {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| eyre!("an app without {name}"))
    };
    Ok(App {
        app_id: field("appId")?,
        name: field("name")?,
        bucket: field("bucket")?,
    })
}

/// Sign in, open a crates.vip session and run `f` on it.
fn with_session<T>(login: &Login, f: impl AsyncFnOnce(&mut WsClient) -> Result<T>) -> Result<T> {
    let reactor = Reactor::local().map_err(|e| eyre!(e.to_string()))?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header("Init", &[&token])?, &handle).await?;
        f(&mut api).await
    })
}
