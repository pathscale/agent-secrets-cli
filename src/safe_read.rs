//! Allow-listed public leaf reads and in-process secret injection.

use clap::Args;
use crate::eyre::{Result, ensure, eyre};
use serde_json::Value;
use std::collections::HashSet;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::{Target, config_patch::parse_path_segments, get, parse_target};

#[derive(Args)]
pub struct GetPathArgs {
    #[arg(long)]
    config: String,
    #[arg(long, value_parser = parse_target)]
    secret: Target,
    #[arg(long, value_parser = ["json", "toml"])]
    format: String,
    #[arg(long, required = true)]
    path: Vec<String>,
    /// Kept for compatibility; ambiguous key values remain refused.
    /// See docs/public-leaf-policy.md.
    #[arg(long)]
    allow_public_key: bool,
}

#[derive(Clone)]
struct Binding {
    target: Target,
    env: String,
}

fn parse_binding(raw: &str) -> Result<Binding, String> {
    let (target, rename) = raw
        .split_once('=')
        .map_or((raw, None), |(t, e)| (t, Some(e)));
    let target = parse_target(target).map_err(|_| "expected project/NAME[=ENVNAME]".to_owned())?;
    let env = rename.unwrap_or(&target.name).to_owned();
    if !valid_env(&env) {
        return Err("environment name must match [A-Za-z_][A-Za-z0-9_]*".into());
    }
    Ok(Binding { target, env })
}

fn valid_env(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_env_name(raw: &str) -> Result<String, String> {
    if valid_env(raw) {
        Ok(raw.to_owned())
    } else {
        Err("environment name must match [A-Za-z_][A-Za-z0-9_]*".into())
    }
}

#[derive(Args)]
pub struct ExecArgs {
    #[arg(long)]
    config: String,
    #[arg(long, required = true, value_parser = parse_binding)]
    secret: Vec<Binding>,
    /// Pass this caller environment variable to the child; may be repeated.
    #[arg(long = "pass-env", value_name = "NAME", value_parser = parse_env_name)]
    pass_env: Vec<String>,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<std::ffi::OsString>,
}

pub fn exec(args: ExecArgs) -> Result<()> {
    let mut seen = HashSet::new();
    for binding in &args.secret {
        ensure!(
            seen.insert(binding.env.clone()),
            "duplicate environment name"
        );
    }
    for name in &args.pass_env {
        ensure!(seen.insert(name.clone()), "duplicate environment name");
    }
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    command.env_clear();
    for name in ["PATH", "HOME", "LANG"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for name in &args.pass_env {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    for binding in &args.secret {
        let value = get(&binding.target, &args.config)
            .map_err(|_| eyre!("could not read requested secret"))?;
        ensure!(
            !value.contains('\0'),
            "secret cannot be used as an environment value"
        );
        command.env(&binding.env, value);
    }
    // Replace this process: preserve the child's exit code, signals and stdio.
    let error = command.exec();
    Err(eyre!("could not execute command: {}", error.kind()))
}

pub fn get_paths(args: GetPathArgs) -> Result<String> {
    let raw = get(&args.secret, &args.config)?;
    select(&raw, &args.format, &args.path, args.allow_public_key)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReadSegment {
    Key(String),
    Index(usize),
}

fn parse_read_path(raw: &str) -> Result<Vec<ReadSegment>> {
    parse_path_segments(raw)?
        .into_iter()
        .map(|segment| {
            let decimal = !segment.quoted
                && !segment.value.is_empty()
                && segment.value.bytes().all(|byte| byte.is_ascii_digit());
            if decimal {
                ensure!(
                    segment.value == "0" || !segment.value.starts_with('0'),
                    "array index must be canonical decimal"
                );
                let index = segment
                    .value
                    .parse::<usize>()
                    .map_err(|_| eyre!("array index is out of range"))?;
                Ok(ReadSegment::Index(index))
            } else {
                Ok(ReadSegment::Key(segment.value))
            }
        })
        .collect()
}

fn select_json(root: &Value, segments: &[ReadSegment]) -> Result<Value> {
    let mut value = root;
    for segment in segments {
        value = match segment {
            ReadSegment::Key(key) => value.as_object().and_then(|object| object.get(key)),
            ReadSegment::Index(index) => value.as_array().and_then(|array| array.get(*index)),
        }
        .ok_or_else(|| eyre!("missing leaf"))?;
    }
    Ok(value.clone())
}

enum TomlNode<'a> {
    Table(&'a dyn toml_edit::TableLike),
    Item(&'a toml_edit::Item),
    Value(&'a toml_edit::Value),
}

impl<'a> TomlNode<'a> {
    fn child(self, segment: &ReadSegment) -> Option<Self> {
        match segment {
            ReadSegment::Key(key) => match self {
                Self::Table(table) => table.get(key).map(Self::Item),
                Self::Item(item) => item.as_table_like()?.get(key).map(Self::Item),
                Self::Value(value) => value.as_inline_table()?.get(key).map(Self::Value),
            },
            ReadSegment::Index(index) => match self {
                Self::Table(_) => None,
                Self::Item(item) => item
                    .as_array_of_tables()
                    .and_then(|tables| tables.get(*index))
                    .map(|table| Self::Table(table))
                    .or_else(|| {
                        item.as_array()
                            .and_then(|array| array.get(*index))
                            .map(Self::Value)
                    }),
                Self::Value(value) => value
                    .as_array()
                    .and_then(|array| array.get(*index))
                    .map(Self::Value),
            },
        }
    }

    fn scalar(self) -> Result<Value> {
        match self {
            Self::Table(_) => Err(eyre!("not a scalar leaf")),
            Self::Item(item) => item
                .as_value()
                .ok_or_else(|| eyre!("not a scalar leaf"))
                .and_then(toml_scalar),
            Self::Value(value) => toml_scalar(value),
        }
    }
}

fn toml_scalar(value: &toml_edit::Value) -> Result<Value> {
    match value {
        toml_edit::Value::String(s) => Ok(Value::String(s.value().clone())),
        toml_edit::Value::Integer(n) => Ok(Value::from(*n.value())),
        toml_edit::Value::Float(n) if n.value().is_finite() => Ok(Value::from(*n.value())),
        toml_edit::Value::Boolean(b) => Ok(Value::from(*b.value())),
        toml_edit::Value::Datetime(d) => Ok(Value::String(d.value().to_string())),
        _ => Err(eyre!("not a scalar leaf")),
    }
}

fn select(raw: &str, format: &str, paths: &[String], allow_public_key: bool) -> Result<String> {
    let (json, toml) = if format == "json" {
        (
            Some(serde_json::from_str::<Value>(raw).map_err(|_| eyre!("invalid config"))?),
            None,
        )
    } else {
        (
            None,
            Some(
                raw.parse::<toml_edit::DocumentMut>()
                    .map_err(|_| eyre!("invalid config"))?,
            ),
        )
    };
    let mut output = String::new();
    for path in paths {
        let segments = parse_read_path(path)?;
        let key = match segments.last().ok_or_else(|| eyre!("missing leaf"))? {
            ReadSegment::Key(key) => key.to_ascii_lowercase(),
            ReadSegment::Index(_) => return Err(eyre!("not a scalar leaf")),
        };
        let value = if let Some(root) = &json {
            select_json(root, &segments)?
        } else {
            let document = toml.as_ref().ok_or_else(|| eyre!("invalid config"))?;
            let mut node = TomlNode::Table(document.as_table());
            for segment in &segments {
                node = node.child(segment).ok_or_else(|| eyre!("missing leaf"))?;
            }
            node.scalar()?
        };
        ensure!(!value.is_object() && !value.is_array(), "not a scalar leaf");
        let encoded = serde_json::to_string(&value)?;
        let refused_public_key = allow_public_key && value.as_str().is_some_and(is_public_key);
        let allowed_leaf = public_scalar(&key, &value);
        if refused_public_key || !allowed_leaf {
            crate::output::register_secret(encoded.as_bytes());
        }
        ensure!(!refused_public_key && allowed_leaf, "refused leaf");
        // One JSON scalar per line, regardless of source format; no labels.
        output.push_str(&encoded);
        output.push('\n');
    }
    Ok(output)
}

fn sensitive_leaf_name(key: &str) -> bool {
    [
        "token",
        "secret",
        "seed",
        "password",
        "pass",
        "pwd",
        "pin",
        "dsn",
        "webhook",
        "cookie",
        "jwt",
        "session",
        "hmac",
        "credential",
        "private",
        "auth",
        "key",
    ]
    .iter()
    .any(|word| key.contains(word))
}

fn public_scalar(key: &str, value: &Value) -> bool {
    if sensitive_leaf_name(key) {
        return false;
    }

    match key {
        "port" => value.as_u64().is_some_and(|n| n <= 65_535),
        "decimals" => value.as_u64().is_some_and(|n| n <= 9),
        "timeout_ms" | "poll_interval_ms" => value.as_u64().is_some(),
        "enabled" => value.is_boolean(),
        "cluster" | "network" => value
            .as_str()
            .is_some_and(|s| matches!(s, "devnet" | "testnet" | "mainnet-beta")),
        _ if key.ends_with("_url") => value.as_str().is_some_and(strict_public_url),
        _ => false,
    }
}

fn strict_public_url(value: &str) -> bool {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }

    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "https" | "wss") {
        return false;
    }
    let authority = match remainder.split_once('/') {
        Some((authority, "")) | Some((authority, "api")) => authority,
        None => remainder,
        _ => return false,
    };
    if authority.is_empty() || authority.contains(['@', '%', '?', '#', '\\']) {
        return false;
    }

    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let Ok(number) = port.parse::<u16>() else {
                return false;
            };
            if number == 0 || port != number.to_string() {
                return false;
            }
            host
        }
        Some(_) => return false,
        None => authority,
    };
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || label.bytes().all(|byte| byte.is_ascii_digit())
            || is_seed_lookalike_label(label)
        {
            return false;
        }
    }
    labels[labels.len() - 1]
        .bytes()
        .any(|byte| byte.is_ascii_alphabetic())
}

fn is_seed_lookalike_label(label: &str) -> bool {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let base58 = (32..=44).contains(&label.len()) && label.chars().all(|ch| BASE58.contains(ch));
    let hex =
        (32..=64).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_hexdigit());
    base58 || hex
}

fn is_public_key(value: &str) -> bool {
    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if !(32..=44).contains(&value.len()) {
        return false;
    }
    let mut bytes = Vec::<u8>::new();
    for ch in value.chars() {
        let Some(mut carry) = ALPHABET.find(ch) else {
            return false;
        };
        for byte in &mut bytes {
            carry += usize::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
        if bytes.len() > 32 {
            return false;
        }
    }
    bytes.len() + value.bytes().take_while(|&b| b == b'1').count() == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_public_scalars_work_in_json_and_toml() {
        let json = r#"{"port":65535,"decimals":9,"timeout_ms":0,"poll_interval_ms":42,"enabled":false,"network":"devnet","cluster":"mainnet-beta","api_url":"https://example.com/api"}"#;
        let toml = "port=65535\ndecimals=9\ntimeout_ms=0\npoll_interval_ms=42\nenabled=false\nnetwork='devnet'\ncluster='mainnet-beta'\napi_url='https://example.com/api'\n";
        let paths: Vec<String> = [
            "port",
            "decimals",
            "timeout_ms",
            "poll_interval_ms",
            "enabled",
            "network",
            "cluster",
            "api_url",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let expected =
            "65535\n9\n0\n42\nfalse\n\"devnet\"\n\"mainnet-beta\"\n\"https://example.com/api\"\n";
        for (raw, format) in [(json, "json"), (toml, "toml")] {
            assert_eq!(select(raw, format, &paths, false).unwrap(), expected);
        }
    }

    #[test]
    fn ambiguous_and_sensitive_values_fail_with_or_without_compatibility_flag() {
        for leaf in [
            "public_id",
            "app_id",
            "mint",
            "owner",
            "host",
            "value",
            "password_url",
            "auth_url",
            "api_key_url",
            "webhook_url",
            "dsn_url",
            "pin",
            "session",
            "cookie",
            "jwt",
            "hmac",
            "pwd",
        ] {
            for value in [
                "short",
                "aB3dE6gH9jK2mN5p",
                "11111111111111111111111111111111",
                "https://example.com",
            ] {
                let json = format!(r#"{{"{leaf}":"{value}"}}"#);
                let toml = format!("{leaf}='{value}'\n");
                for (raw, format) in [(&json, "json"), (&toml, "toml")] {
                    for flag in [false, true] {
                        assert!(
                            select(raw, format, &[leaf.into()], flag).is_err(),
                            "{format} {leaf}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scalar_types_and_bounds_are_enforced() {
        for raw in [
            r#"{"port":65536}"#,
            r#"{"port":-1}"#,
            r#"{"port":"42"}"#,
            r#"{"decimals":10}"#,
            r#"{"enabled":1}"#,
            r#"{"timeout_ms":-1}"#,
            r#"{"poll_interval_ms":1.5}"#,
            r#"{"cluster":"production"}"#,
            r#"{"network":true}"#,
        ] {
            let key = raw.split('"').nth(1).unwrap();
            assert!(select(raw, "json", &[key.into()], false).is_err());
        }
    }

    #[test]
    fn urls_reject_credentials_and_ambiguous_authorities() {
        for value in [
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com?token=short",
            "https://example.com/#secret",
            "https://%65xample.com",
            "https://",
            "https://:443",
            "https://example.com:",
            "https://example.com:bad",
            "https://example.com/with space",
            "https://é.com",
        ] {
            assert!(!strict_public_url(value), "{value}");
        }
        for value in [
            "https://example.com",
            "wss://example.com:443/",
            "https://example.com/",
        ] {
            assert!(strict_public_url(value));
        }
    }

    #[test]
    fn array_paths_quoted_keys_and_output_order_remain_supported() {
        for (raw, format) in [
            (
                r#"{"tokens":[{"decimals":9}],"object":{"0":{"enabled":true}},"x.y":{"port":42}}"#,
                "json",
            ),
            (
                "[object.\"0\"]\nenabled=true\n[\"x.y\"]\nport=42\n[[tokens]]\ndecimals=9\n",
                "toml",
            ),
        ] {
            assert_eq!(
                select(
                    raw,
                    format,
                    &[
                        "tokens.0.decimals".into(),
                        r#"object."0".enabled"#.into(),
                        r#""x.y".port"#.into()
                    ],
                    false
                )
                .unwrap(),
                "9\ntrue\n42\n"
            );
            for path in [
                "tokens.1.decimals",
                "tokens.-1.decimals",
                "tokens.00.decimals",
                "tokens.\"0\".decimals",
                "object.0.enabled",
                "tokens",
                "tokens.0",
            ] {
                assert!(select(raw, format, &[path.into()], false).is_err());
            }
        }
    }

    #[test]
    fn refusal_rejects_the_entire_selection() {
        assert!(
            select(
                r#"{"port":42,"password":"sentinel"}"#,
                "json",
                &["port".into(), "password".into()],
                false
            )
            .is_err()
        );
        assert!(select("invalid", "json", &["port".into()], false).is_err());
        assert!(select("{}", "json", &["port".into()], false).is_err());
        assert!(
            select(
                r#"{"passwords":["short"]}"#,
                "json",
                &["passwords.0".into()],
                false
            )
            .is_err()
        );
    }

    #[test]
    fn validate_bindings() {
        assert_eq!(
            parse_binding("project/TOKEN=RENAMED").unwrap().env,
            "RENAMED"
        );
        assert_eq!(parse_binding("project/TOKEN").unwrap().env, "TOKEN");
        for bad in [
            "project/TOKEN=",
            "project/TOKEN=1BAD",
            "project/TOKEN=A=B",
            "missing",
            "project/A-B",
        ] {
            assert!(parse_binding(bad).is_err());
        }
    }
}
