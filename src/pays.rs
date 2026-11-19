//! pays.online: merchant apps and their API keys, the key going straight to
//! Doppler.
//!
//! Signs in to honey.id as an account kept in Doppler, opens a merchant session
//! with `Init`, makes the account a merchant when it is still `Public`, and
//! creates the app. App ids and names are not secrets and are printed; the app
//! API key is returned once by `CreateApp`, written to Doppler and never
//! printed.

use endpoint_libs::libs::ws::WsClient;
use crate::eyre::{Result, WrapErr, eyre};
use nagoya::reactor::{Reactor, block_on_with};
use serde_json::{Value, json};

use crate::honey::{Login, connect, header, request, sign_in};

/// pays merchant: `ListApps()`.
const LIST_APPS: u32 = 23100;
/// pays merchant: `CreateApp(name, description)`, returns the first key once.
const CREATE_APP: u32 = 23101;
/// pays merchant: `BecomeMerchant()`, Public -> MerchantAdmin.
const BECOME_MERCHANT: u32 = 41001;

pub struct App {
    pub app_public_id: String,
    pub name: String,
}

pub struct Created {
    pub app: App,
    pub key: String,
}

pub struct Ensured {
    pub app: App,
    pub created: bool,
}

/// The merchant's apps, making the account a merchant first if needed.
pub fn list_apps(login: &Login) -> Result<Vec<App>> {
    with_merchant(login, async |api| apps(api).await)
}

/// A new app and its first API key. Refuses when the merchant already has an
/// app of that name, so a rerun never mints a second key by accident.
pub fn create_app(login: &Login, name: &str, description: &str) -> Result<Created> {
    with_merchant(login, async |api| {
        if let Some(existing) = apps(api).await?.into_iter().find(|app| app.name == name) {
            return Err(eyre!(
                "the merchant already has an app named {name} ({}); rotate its key instead",
                existing.app_public_id
            ));
        }
        let response = request(api, CREATE_APP, json!([name, description]))
            .await
            .wrap_err("CreateApp")?;
        let app = response
            .get("app")
            .ok_or_else(|| eyre!("CreateApp answered without app"))?;
        let field = |field: &str| {
            app.get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| eyre!("CreateApp answered without {field}"))
        };
        Ok(Created {
            app: App {
                app_public_id: field("appPublicId")?,
                name: field("name")?,
            },
            key: field("appApiKey")?,
        })
    })
}

/// Ensure one explicitly named merchant app, then verify it through a fresh
/// authenticated connection. The CreateApp response includes its first API
/// key; this QA flow deliberately never accesses, persists, formats, or prints it.
pub fn ensure_named_app(login: &Login, name: &str, description: &str) -> Result<Ensured> {
    if name.trim().is_empty() || name.trim() != name {
        return Err(eyre!("QA app name must be non-empty and trimmed"));
    }

    let (app, created) = with_merchant_session(login, async |api| {
        if let Some(existing) = app_named(apps(api).await?, name)? {
            return Ok((existing, false));
        }

        let response = request(api, CREATE_APP, json!([name, description]))
            .await
            .wrap_err("CreateApp")?;
        let returned = created_app(&response, name)?;
        let listed = app_named(apps(api).await?, name)?
            .ok_or_else(|| eyre!("CreateApp result was not listed as owned"))?;
        if listed.app_public_id != returned.app_public_id {
            return Err(eyre!(
                "CreateApp ownership readback returned a different app"
            ));
        }
        Ok((listed, true))
    })?;

    // A new sign-in and WebSocket session prove the app survived beyond the
    // CreateApp connection and is still visible in this merchant's ListApps.
    let expected_public_id = app.app_public_id.clone();
    let persisted = with_merchant_session(login, async |api| {
        let app = app_named(apps(api).await?, name)?
            .ok_or_else(|| eyre!("QA app was absent from cold ListApps readback"))?;
        if app.app_public_id != expected_public_id {
            return Err(eyre!("QA app id changed during cold readback"));
        }
        Ok(app)
    })?;

    if persisted.app_public_id != app.app_public_id || persisted.name != name {
        return Err(eyre!("QA app cold readback did not match the created app"));
    }

    Ok(Ensured {
        app: persisted,
        created,
    })
}

async fn apps(api: &mut WsClient) -> Result<Vec<App>> {
    let response = request(api, LIST_APPS, json!([]))
        .await
        .wrap_err("ListApps")?;
    response
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| eyre!("ListApps answered without data"))?
        .iter()
        .map(|app| {
            let field = |field: &str| {
                app.get(field)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| eyre!("an app without {field}"))
            };
            Ok(App {
                app_public_id: field("appPublicId")?,
                name: field("name")?,
            })
        })
        .collect()
}

fn app_named(apps: Vec<App>, name: &str) -> Result<Option<App>> {
    let mut named = apps.into_iter().filter(|app| app.name == name);
    let app = named.next();
    if named.next().is_some() {
        return Err(eyre!("multiple owned apps have the requested QA name"));
    }
    Ok(app)
}

fn created_app(response: &Value, requested_name: &str) -> Result<App> {
    let details = response
        .get("app")
        .ok_or_else(|| eyre!("CreateApp answered without app"))?;
    let field = |field: &str| {
        details
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| eyre!("CreateApp answered without {field}"))
    };
    let app_public_id = field("appPublicId")?;
    let name = field("name")?;
    if app_public_id.is_empty() || name != requested_name {
        return Err(eyre!("CreateApp returned unexpected app metadata"));
    }
    // Do not inspect app.appApiKey from the actual CreateApp response.
    Ok(App {
        app_public_id,
        name,
    })
}

fn with_merchant_session<T>(
    login: &Login,
    f: impl AsyncFnOnce(&mut WsClient) -> Result<T>,
) -> Result<T> {
    let reactor = Reactor::local().map_err(|e| eyre!(e.to_string()))?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header("Init", &[&token])?, &handle).await?;
        f(&mut api).await
    })
}

/// Sign in, open a merchant session (becoming a merchant first when the
/// account is still Public) and run `f` on it.
fn with_merchant<T>(login: &Login, f: impl AsyncFnOnce(&mut WsClient) -> Result<T>) -> Result<T> {
    let reactor = Reactor::local().map_err(|e| eyre!(e.to_string()))?;
    let handle = reactor.handle();
    block_on_with(&reactor, async {
        let token = sign_in(login, &handle).await?;
        let mut api = connect(&login.api, &header("Init", &[&token])?, &handle).await?;
        if apps(&mut api).await.is_err() {
            // A Public account cannot list apps. Promote it, then reopen the
            // session so the new role applies.
            request(&mut api, BECOME_MERCHANT, json!([]))
                .await
                .wrap_err("BecomeMerchant")?;
            api = connect(&login.api, &header("Init", &[&token])?, &handle).await?;
        }
        f(&mut api).await
    })
}
