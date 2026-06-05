//! Minimal JSON writer used by deterministic snapshots and report exports.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
    Raw(String),
}

impl JsonValue {
    pub(crate) fn null() -> Self {
        Self::Null
    }

    pub(crate) fn bool(value: bool) -> Self {
        Self::Bool(value)
    }

    pub(crate) fn number(value: impl ToString) -> Self {
        Self::Number(value.to_string())
    }

    pub(crate) fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub(crate) fn optional_string(value: Option<&str>) -> Self {
        value.map(Self::string).unwrap_or_else(Self::null)
    }

    pub(crate) fn array(values: impl IntoIterator<Item = JsonValue>) -> Self {
        Self::Array(values.into_iter().collect())
    }

    pub(crate) fn string_array<'a>(values: impl IntoIterator<Item = impl AsRef<str> + 'a>) -> Self {
        Self::array(values.into_iter().map(|value| Self::string(value.as_ref())))
    }

    pub(crate) fn object(fields: impl IntoIterator<Item = (impl Into<String>, JsonValue)>) -> Self {
        Self::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }

    pub(crate) fn raw(value: impl Into<String>) -> Self {
        Self::Raw(value.into())
    }

    pub(crate) fn to_json(&self) -> String {
        let mut json = String::new();
        self.write_json(&mut json);
        json
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) | Self::Raw(value) => out.push_str(value),
            Self::String(value) => write_json_string(value, out),
            Self::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    value.write_json(out);
                }
                out.push(']');
            }
            Self::Object(fields) => {
                out.push('{');
                for (index, (key, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

pub(crate) fn object_members(
    fields: impl IntoIterator<Item = (impl Into<String>, JsonValue)>,
) -> String {
    match JsonValue::object(fields) {
        JsonValue::Object(fields) => fields
            .into_iter()
            .map(|(key, value)| format!("{}:{}", JsonValue::string(key).to_json(), value.to_json()))
            .collect::<Vec<_>>()
            .join(","),
        _ => unreachable!("object() always returns object"),
    }
}

pub(crate) fn json_string(value: &str) -> String {
    JsonValue::string(value).to_json()
}

fn write_json_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_writer_escapes_strings_and_builds_objects() {
        let json = JsonValue::object([
            ("name", JsonValue::string("a\"b")),
            ("items", JsonValue::string_array(["x", "y\nz"])),
        ])
        .to_json();

        assert_eq!(json, "{\"name\":\"a\\\"b\",\"items\":[\"x\",\"y\\nz\"]}");
    }
}
