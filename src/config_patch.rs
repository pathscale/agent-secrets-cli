//! Structured JSON and TOML secret editing without printing values.

use std::collections::{BTreeMap, BTreeSet};

use crate::eyre::{Result, bail, ensure, eyre};
use serde_json::Value as JsonValue;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value as TomlValue};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Json,
    Toml,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub kind: &'static str,
    pub path: String,
}

pub struct Patch {
    pub content: String,
    pub changes: Vec<Change>,
    requested_paths: Vec<Vec<String>>,
}

#[derive(Clone)]
enum Operation {
    Set(Vec<String>, JsonValue, String),
    Unset(Vec<String>, String),
    FromSecret(Vec<String>, String, String),
}

pub fn build_patch(
    format: Format,
    original: &str,
    sets: &[String],
    unsets: &[String],
    imported: &[(String, String)],
    create_parents: bool,
) -> Result<Patch> {
    ensure!(
        !sets.is_empty() || !unsets.is_empty() || !imported.is_empty(),
        "give at least one --set, --unset, or --from-secret"
    );

    let mut operations = Vec::new();
    for raw in sets {
        let (path, raw_value) = raw
            .split_once('=')
            .ok_or_else(|| eyre!("--set must be PATH=JSONVALUE"))?;
        let segments = parse_path(path)?;
        let value = serde_json::from_str(raw_value)
            .map_err(|_| eyre!("--set value for {path} must be valid JSON"))?;
        operations.push(Operation::Set(segments, value, path.to_owned()));
    }
    for path in unsets {
        operations.push(Operation::Unset(parse_path(path)?, path.clone()));
    }
    for (path, value) in imported {
        operations.push(Operation::FromSecret(
            parse_path(path)?,
            value.clone(),
            path.clone(),
        ));
    }

    let requested_paths = operations
        .iter()
        .map(|operation| match operation {
            Operation::Set(path, ..)
            | Operation::Unset(path, ..)
            | Operation::FromSecret(path, ..) => path.clone(),
        })
        .collect::<Vec<_>>();

    let (content, changes): (String, _) = match format {
        Format::Json => {
            let original_value = parse_json(original)?;
            let mut patched = original_value.clone();
            for operation in &operations {
                match operation {
                    Operation::Set(path, value, raw_path) => {
                        set_json_path(&mut patched, path, value.clone(), create_parents, raw_path)?;
                    }
                    Operation::Unset(path, _) => unset_json_path(&mut patched, path),
                    Operation::FromSecret(path, value, raw_path) => set_json_path(
                        &mut patched,
                        path,
                        JsonValue::String(value.clone()),
                        create_parents,
                        raw_path,
                    )?,
                }
            }
            let changes = json_changes(&original_value, &patched, &operations);
            let content = serde_json::to_string_pretty(&patched)
                .map_err(|_| eyre!("could not serialize patched JSON"))?;
            Ok::<_, crate::eyre::Report>((content, changes))
        }
        Format::Toml => {
            let original_doc = parse_toml(original)?;
            let mut patched = original_doc.clone();
            for operation in &operations {
                match operation {
                    Operation::Set(path, value, raw_path) => {
                        let item = toml_item_from_json(value)?;
                        set_toml_path(
                            patched.as_table_mut(),
                            path,
                            item,
                            create_parents,
                            raw_path,
                        )?;
                    }
                    Operation::Unset(path, _) => unset_toml_path(patched.as_table_mut(), path),
                    Operation::FromSecret(path, value, raw_path) => set_toml_path(
                        patched.as_table_mut(),
                        path,
                        Item::Value(TomlValue::from(value.clone())),
                        create_parents,
                        raw_path,
                    )?,
                }
            }
            let changes = toml_changes(&original_doc, &patched, &operations)?;
            Ok((patched.to_string(), changes))
        }
    }?;

    ensure!(
        same_outside_paths(format, original, &content, &requested_paths)?,
        "patch modifies parsed config outside requested paths"
    );

    Ok(Patch {
        content,
        changes,
        requested_paths,
    })
}

pub fn requested_paths(patch: &Patch) -> &[Vec<String>] {
    &patch.requested_paths
}

/// Compare parsed values while ignoring the paths explicitly requested.
pub fn same_outside_paths(
    format: Format,
    before: &str,
    after: &str,
    paths: &[Vec<String>],
) -> Result<bool> {
    match format {
        Format::Json => {
            let before = parse_json(before)?;
            let after = parse_json(after)?;
            Ok(json_same_outside(Some(&before), Some(&after), paths))
        }
        Format::Toml => {
            let before = parse_toml(before)?;
            let after = parse_toml(after)?;
            let before = toml_node_from_table(before.as_table())?;
            let after = toml_node_from_table(after.as_table())?;
            Ok(node_same_outside(Some(&before), Some(&after), paths))
        }
    }
}

fn parse_json(raw: &str) -> Result<JsonValue> {
    let value: JsonValue =
        serde_json::from_str(raw).map_err(|_| eyre!("config secret is not valid JSON"))?;
    ensure!(
        value.is_object(),
        "JSON config secret must have an object at its root"
    );
    Ok(value)
}

fn parse_toml(raw: &str) -> Result<DocumentMut> {
    raw.parse::<DocumentMut>()
        .map_err(|_| eyre!("config secret is not valid TOML"))
}

pub(crate) struct PathSegment {
    pub(crate) value: String,
    pub(crate) quoted: bool,
}

pub(crate) fn parse_path(raw: &str) -> Result<Vec<String>> {
    Ok(parse_path_segments(raw)?
        .into_iter()
        .map(|segment| segment.value)
        .collect())
}

pub(crate) fn parse_path_segments(raw: &str) -> Result<Vec<PathSegment>> {
    ensure!(!raw.is_empty(), "config path cannot be empty");
    let mut path = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        if raw[index..].starts_with('"') {
            let start = index;
            index += 1;
            let mut escaped = false;
            let mut closed = false;
            while index < raw.len() {
                let ch = raw[index..].chars().next().expect("index is in bounds");
                index += ch.len_utf8();
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    closed = true;
                    break;
                }
            }
            ensure!(closed, "config path has an unterminated quoted segment");
            let segment: String = serde_json::from_str(&raw[start..index])
                .map_err(|_| eyre!("config path has an invalid quoted segment"))?;
            ensure!(!segment.is_empty(), "config path segments cannot be empty");
            path.push(PathSegment {
                value: segment,
                quoted: true,
            });
        } else {
            let start = index;
            while index < raw.len() && !raw[index..].starts_with('.') {
                let ch = raw[index..].chars().next().expect("index is in bounds");
                ensure!(ch != '"', "quote a path segment from its first character");
                index += ch.len_utf8();
            }
            let segment = &raw[start..index];
            ensure!(!segment.is_empty(), "config path segments cannot be empty");
            ensure!(
                segment.trim() == segment,
                "unquoted config path segments cannot start or end with whitespace"
            );
            path.push(PathSegment {
                value: segment.to_owned(),
                quoted: false,
            });
        }
        if index < raw.len() {
            ensure!(
                raw[index..].starts_with('.'),
                "expected a dot in config path"
            );
            index += 1;
            ensure!(index < raw.len(), "config path cannot end with a dot");
        }
    }
    Ok(path)
}

fn set_json_path(
    root: &mut JsonValue,
    path: &[String],
    value: JsonValue,
    create_parents: bool,
    display_path: &str,
) -> Result<()> {
    let mut current = root
        .as_object_mut()
        .ok_or_else(|| eyre!("JSON config root must be an object"))?;
    for segment in &path[..path.len() - 1] {
        if !current.contains_key(segment) {
            ensure!(
                create_parents,
                "parent table for {display_path} does not exist; pass --create-parents"
            );
            current.insert(segment.clone(), JsonValue::Object(Default::default()));
        }
        current = current
            .get_mut(segment)
            .and_then(JsonValue::as_object_mut)
            .ok_or_else(|| eyre!("parent path for {display_path} is not an object"))?;
    }
    current.insert(path.last().expect("path has a segment").clone(), value);
    Ok(())
}

fn unset_json_path(root: &mut JsonValue, path: &[String]) {
    let mut current = match root.as_object_mut() {
        Some(current) => current,
        None => return,
    };
    for segment in &path[..path.len() - 1] {
        match current.get_mut(segment).and_then(JsonValue::as_object_mut) {
            Some(next) => current = next,
            None => return,
        }
    }
    current.remove(path.last().expect("path has a segment"));
}

fn toml_item_from_json(value: &JsonValue) -> Result<Item> {
    match value {
        JsonValue::Null => bail!("TOML has no null value"),
        JsonValue::Bool(value) => Ok(Item::Value(TomlValue::from(*value))),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(Item::Value(TomlValue::from(value)))
            } else if let Some(value) = value.as_u64() {
                let value =
                    i64::try_from(value).map_err(|_| eyre!("integer is outside the TOML range"))?;
                Ok(Item::Value(TomlValue::from(value)))
            } else if let Some(value) = value.as_f64() {
                Ok(Item::Value(TomlValue::from(value)))
            } else {
                bail!("JSON number cannot be represented in TOML")
            }
        }
        JsonValue::String(value) => Ok(Item::Value(TomlValue::from(value.clone()))),
        JsonValue::Array(values) => {
            let mut array = Array::new();
            for value in values {
                match toml_item_from_json(value)? {
                    Item::Value(value) => array.push(value),
                    _ => bail!("JSON value cannot be represented in a TOML array"),
                }
            }
            Ok(Item::Value(TomlValue::Array(array)))
        }
        JsonValue::Object(values) => {
            let mut table = InlineTable::new();
            for (key, value) in values {
                match toml_item_from_json(value)? {
                    Item::Value(value) => {
                        table.insert(key.clone(), value);
                    }
                    _ => bail!("JSON value cannot be represented in a TOML inline table"),
                }
            }
            Ok(Item::Value(TomlValue::InlineTable(table)))
        }
    }
}

fn set_toml_path(
    table: &mut dyn TableLike,
    path: &[String],
    value: Item,
    create_parents: bool,
    display_path: &str,
) -> Result<()> {
    let key = path.first().expect("path has a segment");
    if path.len() == 1 {
        table.insert(key, value);
        return Ok(());
    }
    if !table.contains_key(key) {
        ensure!(
            create_parents,
            "parent table for {display_path} does not exist; pass --create-parents"
        );
        table.insert(key, Item::Table(Table::new()));
    }
    let child = table
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| eyre!("parent path for {display_path} is not a table"))?;
    set_toml_path(child, &path[1..], value, create_parents, display_path)
}

fn unset_toml_path(table: &mut dyn TableLike, path: &[String]) {
    let key = path.first().expect("path has a segment");
    if path.len() == 1 {
        table.remove(key);
    } else if let Some(child) = table.get_mut(key).and_then(Item::as_table_like_mut) {
        unset_toml_path(child, &path[1..]);
    }
}

fn json_changes(before: &JsonValue, after: &JsonValue, operations: &[Operation]) -> Vec<Change> {
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    for operation in operations {
        let (path, display) = match operation {
            Operation::Set(path, _, display)
            | Operation::Unset(path, display)
            | Operation::FromSecret(path, _, display) => (path, display),
        };
        if !seen.insert(path.clone()) {
            continue;
        }
        let old = json_at_path(before, path);
        let new = json_at_path(after, path);
        if let Some(change) = change_kind(old, new) {
            changes.push(Change {
                kind: change,
                path: display.clone(),
            });
        }
    }
    changes
}

fn toml_changes(
    before: &DocumentMut,
    after: &DocumentMut,
    operations: &[Operation],
) -> Result<Vec<Change>> {
    let before = toml_node_from_table(before.as_table())?;
    let after = toml_node_from_table(after.as_table())?;
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    for operation in operations {
        let (path, display) = match operation {
            Operation::Set(path, _, display)
            | Operation::Unset(path, display)
            | Operation::FromSecret(path, _, display) => (path, display),
        };
        if !seen.insert(path.clone()) {
            continue;
        }
        let old = node_at_path(&before, path);
        let new = node_at_path(&after, path);
        if let Some(change) = change_kind(old, new) {
            changes.push(Change {
                kind: change,
                path: display.clone(),
            });
        }
    }
    Ok(changes)
}

fn change_kind<T: PartialEq>(old: Option<&T>, new: Option<&T>) -> Option<&'static str> {
    match (old, new) {
        (None, Some(_)) => Some("added"),
        (Some(_), None) => Some("removed"),
        (Some(old), Some(new)) if old != new => Some("changed"),
        _ => None,
    }
}

fn json_at_path<'a>(root: &'a JsonValue, path: &[String]) -> Option<&'a JsonValue> {
    let mut current = root;
    for segment in path {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn json_same_outside(
    before: Option<&JsonValue>,
    after: Option<&JsonValue>,
    paths: &[Vec<String>],
) -> bool {
    if paths.iter().any(Vec::is_empty) {
        return true;
    }
    if paths.is_empty() {
        return before == after;
    }
    let before_object = before.and_then(JsonValue::as_object);
    let after_object = after.and_then(JsonValue::as_object);
    if before_object.is_none() && after_object.is_none() {
        return before == after;
    }
    let mut keys = BTreeSet::new();
    if let Some(object) = before_object {
        keys.extend(object.keys().cloned());
    }
    if let Some(object) = after_object {
        keys.extend(object.keys().cloned());
    }
    keys.into_iter().all(|key| {
        let nested = paths
            .iter()
            .filter(|path| path.first() == Some(&key))
            .map(|path| path[1..].to_vec())
            .collect::<Vec<_>>();
        let old = before_object.and_then(|object| object.get(&key));
        let new = after_object.and_then(|object| object.get(&key));
        if nested.is_empty() {
            old == new
        } else {
            json_same_outside(old, new, &nested)
        }
    })
}

#[derive(Clone, Debug, PartialEq)]
enum TomlNode {
    Map(BTreeMap<String, TomlNode>),
    Array(Vec<TomlNode>),
    String(String),
    Integer(i64),
    Float(u64),
    Boolean(bool),
    Datetime(String),
    None,
}

fn toml_node_from_table(table: &Table) -> Result<TomlNode> {
    toml_node_from_table_like(table)
}

fn toml_node_from_table_like(table: &dyn TableLike) -> Result<TomlNode> {
    let mut values = BTreeMap::new();
    for (key, item) in table.iter() {
        values.insert(key.to_owned(), toml_node_from_item(item)?);
    }
    Ok(TomlNode::Map(values))
}

fn toml_node_from_item(item: &Item) -> Result<TomlNode> {
    if let Some(array) = item.as_array_of_tables() {
        return Ok(TomlNode::Array(
            array
                .iter()
                .map(|table| toml_node_from_table_like(table))
                .collect::<Result<Vec<_>>>()?,
        ));
    }
    if let Some(table) = item.as_table_like() {
        return toml_node_from_table_like(table);
    }
    if item.is_none() {
        return Ok(TomlNode::None);
    }
    if let Some(value) = item.as_value() {
        return toml_node_from_value(value);
    }
    bail!("unsupported TOML table value")
}

fn toml_node_from_value(value: &TomlValue) -> Result<TomlNode> {
    if let Some(value) = value.as_str() {
        return Ok(TomlNode::String(value.to_owned()));
    }
    if let Some(value) = value.as_integer() {
        return Ok(TomlNode::Integer(value));
    }
    if let Some(value) = value.as_float() {
        return Ok(TomlNode::Float(value.to_bits()));
    }
    if let Some(value) = value.as_bool() {
        return Ok(TomlNode::Boolean(value));
    }
    if let Some(value) = value.as_datetime() {
        return Ok(TomlNode::Datetime(value.to_string()));
    }
    if let Some(array) = value.as_array() {
        return Ok(TomlNode::Array(
            array
                .iter()
                .map(toml_node_from_value)
                .collect::<Result<Vec<_>>>()?,
        ));
    }
    if let Some(table) = value.as_inline_table() {
        return toml_node_from_table_like(table);
    }
    bail!("unsupported TOML value")
}

fn node_at_path<'a>(root: &'a TomlNode, path: &[String]) -> Option<&'a TomlNode> {
    let mut current = root;
    for segment in path {
        current = match current {
            TomlNode::Map(table) => table.get(segment)?,
            _ => return None,
        };
    }
    Some(current)
}

fn node_same_outside(
    before: Option<&TomlNode>,
    after: Option<&TomlNode>,
    paths: &[Vec<String>],
) -> bool {
    if paths.iter().any(Vec::is_empty) {
        return true;
    }
    if paths.is_empty() {
        return before == after;
    }
    let before_map = before.and_then(|node| match node {
        TomlNode::Map(values) => Some(values),
        _ => None,
    });
    let after_map = after.and_then(|node| match node {
        TomlNode::Map(values) => Some(values),
        _ => None,
    });
    if before_map.is_none() && after_map.is_none() {
        return before == after;
    }
    let mut keys = BTreeSet::new();
    if let Some(table) = before_map {
        keys.extend(table.keys().cloned());
    }
    if let Some(table) = after_map {
        keys.extend(table.keys().cloned());
    }
    keys.into_iter().all(|key| {
        let nested = paths
            .iter()
            .filter(|path| path.first() == Some(&key))
            .map(|path| path[1..].to_vec())
            .collect::<Vec<_>>();
        let old = before_map.and_then(|table| table.get(&key));
        let new = after_map.and_then(|table| table.get(&key));
        if nested.is_empty() {
            old == new
        } else {
            node_same_outside(old, new, &nested)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_lists_only_change_types_and_paths() {
        let patch = build_patch(
            Format::Json,
            r#"{"keep":1,"credential":"old"}"#,
            &[
                r#"credential="new-secret""#.to_owned(),
                r#"enabled=true"#.to_owned(),
            ],
            &["keep".to_owned()],
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            patch.changes,
            vec![
                Change {
                    kind: "changed",
                    path: "credential".to_owned(),
                },
                Change {
                    kind: "added",
                    path: "enabled".to_owned(),
                },
                Change {
                    kind: "removed",
                    path: "keep".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn toml_edit_preserves_untouched_bytes() {
        let original = "# config\nkeep = 1_000 # preserve spacing\n\n[service_identity]\nname = 'api'\n\n[service_identity.allowlist]\nexisting = 'value'\n";
        let patch = build_patch(
            Format::Toml,
            original,
            &[r#"service_identity.allowlist."RTUU5jqvSSIj7x99"=true"#.to_owned()],
            &[],
            &[],
            false,
        )
        .unwrap();
        assert!(patch.content.contains("keep = 1_000 # preserve spacing"));
        assert!(patch.content.contains("name = 'api'"));
        assert!(patch.content.contains("existing = 'value'"));
    }

    #[test]
    fn missing_parent_table_requires_create_parents() {
        let set = r#"service_identity.allowlist."token"=true"#.to_owned();
        assert!(
            build_patch(
                Format::Toml,
                "name = 'api'\n",
                std::slice::from_ref(&set),
                &[],
                &[],
                false
            )
            .is_err()
        );
        let patch = build_patch(Format::Toml, "name = 'api'\n", &[set], &[], &[], true).unwrap();
        assert!(patch.content.contains("[service_identity.allowlist]"));
    }

    #[test]
    fn from_secret_copies_the_value_without_including_it_in_changes() {
        let patch = build_patch(
            Format::Json,
            r#"{"service_identity":{"allowlist":{}}}"#,
            &[],
            &[],
            &[(
                "service_identity.allowlist.token".to_owned(),
                "private-token".to_owned(),
            )],
            false,
        )
        .unwrap();
        assert_eq!(patch.changes[0].path, "service_identity.allowlist.token");
        assert_eq!(patch.changes[0].kind, "added");
        assert!(!format!("{:?}", patch.changes).contains("private-token"));
        let actual: JsonValue = serde_json::from_str(&patch.content).unwrap();
        assert_eq!(
            actual["service_identity"]["allowlist"]["token"],
            JsonValue::String("private-token".to_owned())
        );
    }
}
