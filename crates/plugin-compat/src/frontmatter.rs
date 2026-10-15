use crate::CompatError;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_FRONTMATTER_BYTES: usize = 256 * 1024;
const MAX_SCALAR_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 8192;

/// Parsed YAML metadata and Markdown body, with surrounding body whitespace trimmed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FrontmatterDocument {
    pub frontmatter: serde_json::Value,
    pub body: String,
}

/// Parse a leading, delimiter-line YAML block without executing source content.
///
/// Metadata must be a mapping with string keys. Anchors, aliases and custom
/// tags are rejected because their expansion or host meaning is not portable.
/// Errors contain stable codes and no source values or parser excerpts.
pub fn parse_frontmatter(text: &str) -> Result<FrontmatterDocument, CompatError> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(diagnostic("document_size_limit"));
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split_inclusive('\n');
    let opening = lines.next().unwrap_or_default();
    if !is_delimiter(opening) {
        return Err(diagnostic("frontmatter_missing"));
    }
    let start = opening.len();
    let mut offset = start;
    for line in lines {
        if is_delimiter(line) {
            let metadata = &text[start..offset];
            if metadata.len() > MAX_FRONTMATTER_BYTES {
                return Err(diagnostic("frontmatter_size_limit"));
            }
            return Ok(FrontmatterDocument {
                frontmatter: parse_yaml_metadata(metadata)?,
                body: text[offset + line.len()..].trim().to_owned(),
            });
        }
        offset += line.len();
        if offset - start > MAX_FRONTMATTER_BYTES {
            return Err(diagnostic("frontmatter_size_limit"));
        }
    }
    Err(diagnostic("frontmatter_unterminated"))
}

fn is_delimiter(line: &str) -> bool {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    line.trim_end_matches([' ', '\t']) == "---"
}

pub(crate) fn parse_yaml_metadata(text: &str) -> Result<Value, CompatError> {
    if text.len() > MAX_FRONTMATTER_BYTES {
        return Err(diagnostic("frontmatter_size_limit"));
    }
    preflight(text)?;
    let mut budget = Budget::default();
    let result = ValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(yaml_serde::Deserializer::from_str(text));
    let value = result.map_err(|_| diagnostic(budget.failure.unwrap_or("yaml_invalid")))?;
    if !value.is_object() {
        return Err(diagnostic("yaml_root_type"));
    }
    Ok(value)
}

fn diagnostic(code: &'static str) -> CompatError {
    let message = match code {
        "document_size_limit" => "Markdown document exceeds the byte limit",
        "frontmatter_missing" => "A leading YAML frontmatter delimiter is required",
        "frontmatter_unterminated" => "YAML frontmatter has no closing delimiter line",
        "frontmatter_size_limit" => "YAML frontmatter exceeds the byte limit",
        "yaml_alias_unsupported" => {
            "YAML anchors and aliases are not supported; expand them explicitly"
        }
        "yaml_depth_limit" => "YAML metadata exceeds the nesting limit",
        "yaml_node_limit" => "YAML metadata exceeds the node limit",
        "yaml_scalar_limit" => "A YAML scalar exceeds the byte limit",
        "yaml_multiple_documents" => "Frontmatter must contain exactly one YAML document",
        "yaml_root_type" => "YAML frontmatter must be a mapping",
        "yaml_key_type" => "YAML metadata keys must be strings",
        "yaml_duplicate_key" => "YAML metadata contains a duplicate mapping key",
        "yaml_tag_unsupported" => "A YAML tag is unsupported or does not match its value kind",
        "yaml_number_range" => "A YAML number cannot be represented as a finite JSON number",
        _ => "YAML frontmatter is malformed",
    };
    CompatError::new(code, message)
}

fn preflight(text: &str) -> Result<(), CompatError> {
    let mut parser = events::Parser::new(text)?;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut documents = 0usize;
    loop {
        let event = parser.next()?;
        match event {
            events::Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(diagnostic("yaml_multiple_documents"));
                }
            }
            events::Event::CollectionStart { anchored } => {
                if anchored {
                    return Err(diagnostic("yaml_alias_unsupported"));
                }
                depth += 1;
                nodes += 1;
                if depth > MAX_DEPTH {
                    return Err(diagnostic("yaml_depth_limit"));
                }
            }
            events::Event::CollectionEnd => depth = depth.saturating_sub(1),
            events::Event::Scalar { anchored, bytes } => {
                if anchored {
                    return Err(diagnostic("yaml_alias_unsupported"));
                }
                if bytes > MAX_SCALAR_BYTES as u64 {
                    return Err(diagnostic("yaml_scalar_limit"));
                }
                nodes += 1;
            }
            events::Event::Alias => return Err(diagnostic("yaml_alias_unsupported")),
            events::Event::UnsupportedTag => return Err(diagnostic("yaml_tag_unsupported")),
            events::Event::StreamEnd => return Ok(()),
            events::Event::Other => {}
        }
        if nodes > MAX_NODES {
            return Err(diagnostic("yaml_node_limit"));
        }
    }
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    failure: Option<&'static str>,
}

impl Budget {
    fn error<E: de::Error>(&mut self, code: &'static str) -> E {
        self.failure.get_or_insert(code);
        E::custom("invalid bounded metadata")
    }
}

struct ValueSeed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.budget.nodes += 1;
        if self.budget.nodes > MAX_NODES {
            return Err(self.budget.error("yaml_node_limit"));
        }
        deserializer.deserialize_any(ValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValueVisitor<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded YAML metadata")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<Value, E> {
        Number::from_i128(value)
            .map(Value::Number)
            .ok_or_else(|| self.budget.error("yaml_number_range"))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<Value, E> {
        Number::from_u128(value)
            .map(Value::Number)
            .ok_or_else(|| self.budget.error("yaml_number_range"))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| self.budget.error("yaml_number_range"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > MAX_SCALAR_BYTES {
            return Err(self.budget.error("yaml_scalar_limit"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > MAX_SCALAR_BYTES {
            return Err(self.budget.error("yaml_scalar_limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.budget.error("yaml_depth_limit"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.budget.error("yaml_depth_limit"));
        }
        let mut values = Map::new();
        while let Some(key) = mapping.next_key_seed(ValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            let Value::String(key) = key else {
                return Err(self.budget.error("yaml_key_type"));
            };
            if values.contains_key(&key) {
                return Err(self.budget.error("yaml_duplicate_key"));
            }
            let value = mapping.next_value_seed(ValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }

    fn visit_enum<A: de::EnumAccess<'de>>(self, _data: A) -> Result<Value, A::Error> {
        Err(self.budget.error("yaml_tag_unsupported"))
    }
}

// This module alone handles the parser's raw allocation API. It copies only
// event metadata; no raw pointers or source excerpts cross the boundary.
mod events {
    use super::{CompatError, diagnostic};
    use libyaml_rs as sys;
    use std::ffi::CStr;
    use std::marker::PhantomData;
    use std::mem::MaybeUninit;

    pub(super) enum Event {
        DocumentStart,
        CollectionStart { anchored: bool },
        CollectionEnd,
        Scalar { anchored: bool, bytes: u64 },
        Alias,
        UnsupportedTag,
        StreamEnd,
        Other,
    }

    pub(super) struct Parser<'a> {
        raw: Box<MaybeUninit<sys::yaml_parser_t>>,
        input: PhantomData<&'a str>,
    }

    impl<'a> Parser<'a> {
        pub(super) fn new(input: &'a str) -> Result<Self, CompatError> {
            let mut raw = Box::new(MaybeUninit::<sys::yaml_parser_t>::uninit());
            // SAFETY: The allocated parser has a stable address and enough space
            // for initialization. Its pointee is never moved after initialization.
            if unsafe { sys::yaml_parser_initialize(raw.as_mut_ptr()) }.fail {
                return Err(diagnostic("yaml_invalid"));
            }
            // SAFETY: Initialization succeeded. The input bytes stay borrowed
            // for the parser's lifetime and are never modified by the parser.
            unsafe {
                sys::yaml_parser_set_input_string(
                    raw.as_mut_ptr(),
                    input.as_ptr(),
                    input.len() as u64,
                );
            }
            Ok(Self {
                raw,
                input: PhantomData,
            })
        }

        pub(super) fn next(&mut self) -> Result<Event, CompatError> {
            let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
            // SAFETY: The initialized parser and event output are exclusive.
            // On failure libyaml owns cleanup of any unfinished event state.
            if unsafe { sys::yaml_parser_parse(self.raw.as_mut_ptr(), event.as_mut_ptr()) }.fail {
                return Err(diagnostic("yaml_invalid"));
            }
            // SAFETY: A successful parse initializes the complete event. Union
            // fields are read only for their matching discriminant. All event
            // allocations are deleted before returning the copied summary.
            let summary = unsafe {
                let mut event = event.assume_init();
                let summary = match event.type_ {
                    sys::YAML_DOCUMENT_START_EVENT => Event::DocumentStart,
                    sys::YAML_MAPPING_START_EVENT => {
                        if allowed_tag(event.data.mapping_start.tag, TagKind::Mapping) {
                            Event::CollectionStart {
                                anchored: !event.data.mapping_start.anchor.is_null(),
                            }
                        } else {
                            Event::UnsupportedTag
                        }
                    }
                    sys::YAML_SEQUENCE_START_EVENT => {
                        if allowed_tag(event.data.sequence_start.tag, TagKind::Sequence) {
                            Event::CollectionStart {
                                anchored: !event.data.sequence_start.anchor.is_null(),
                            }
                        } else {
                            Event::UnsupportedTag
                        }
                    }
                    sys::YAML_MAPPING_END_EVENT | sys::YAML_SEQUENCE_END_EVENT => {
                        Event::CollectionEnd
                    }
                    sys::YAML_SCALAR_EVENT => {
                        if allowed_tag(event.data.scalar.tag, TagKind::Scalar) {
                            Event::Scalar {
                                anchored: !event.data.scalar.anchor.is_null(),
                                bytes: event.data.scalar.length,
                            }
                        } else {
                            Event::UnsupportedTag
                        }
                    }
                    sys::YAML_ALIAS_EVENT => Event::Alias,
                    sys::YAML_STREAM_END_EVENT => Event::StreamEnd,
                    _ => Event::Other,
                };
                sys::yaml_event_delete(&raw mut event);
                summary
            };
            Ok(summary)
        }
    }

    enum TagKind {
        Scalar,
        Sequence,
        Mapping,
    }

    unsafe fn allowed_tag(tag: *const u8, kind: TagKind) -> bool {
        // Implicit tags are null. Explicit non-specific/custom tags are rejected
        // rather than guessing a source-specific coercion or extension meaning.
        if tag.is_null() {
            return true;
        }
        // SAFETY: The caller passes the matching initialized event's tag field.
        // libyaml owns its NUL-terminated bytes until yaml_event_delete runs.
        let tag = unsafe { CStr::from_ptr(tag.cast()) }.to_bytes();
        let allowed: &[&[u8]] = match kind {
            TagKind::Scalar => &[
                b"tag:yaml.org,2002:str",
                b"tag:yaml.org,2002:bool",
                b"tag:yaml.org,2002:int",
                b"tag:yaml.org,2002:float",
                b"tag:yaml.org,2002:null",
            ],
            TagKind::Sequence => &[b"tag:yaml.org,2002:seq"],
            TagKind::Mapping => &[b"tag:yaml.org,2002:map"],
        };
        allowed.contains(&tag)
    }

    impl Drop for Parser<'_> {
        fn drop(&mut self) {
            // SAFETY: Only successfully initialized parsers construct Self.
            // This is the sole deletion and all emitted events were freed.
            unsafe { sys::yaml_parser_delete(self.raw.as_mut_ptr()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn code(text: &str) -> String {
        parse_frontmatter(text).unwrap_err().code
    }

    #[test]
    fn preserves_yaml_types_and_multiline_metadata() {
        let parsed = parse_frontmatter(
            "---\nname: sample\ndescription: >-\n  First line\n  second line.\nnotes: |\n  One\n  Two\ntools:\n  - Read\n  - Grep\nquoted: 'false'\nboolean: false\nextra: {count: 2, values: [null, true]}\n---\n\nInstructions.\n",
        )
        .unwrap();
        assert_eq!(parsed.frontmatter["description"], "First line second line.");
        assert_eq!(parsed.frontmatter["notes"], "One\nTwo\n");
        assert_eq!(parsed.frontmatter["tools"], json!(["Read", "Grep"]));
        assert_eq!(parsed.frontmatter["quoted"], "false");
        assert_eq!(parsed.frontmatter["boolean"], false);
        assert_eq!(
            parsed.frontmatter["extra"],
            json!({"count": 2, "values": [null, true]})
        );
        assert_eq!(parsed.body, "Instructions.");
    }

    #[test]
    fn accepts_bom_crlf_and_preserves_internal_body_bytes() {
        let parsed = parse_frontmatter(
            "\u{feff}--- \t\r\nname: sample\r\n---\r\n\r\nFirst — line\r\n\r\n---\r\nlast---text\r\n",
        )
        .unwrap();
        assert_eq!(parsed.body, "First — line\r\n\r\n---\r\nlast---text");
    }

    #[test]
    fn delimiters_are_complete_lines() {
        assert_eq!(
            code("---prefix\nname: sample\n---\n"),
            "frontmatter_missing"
        );
        let parsed = parse_frontmatter("---\nname: sample---suffix\n---\nbody---tail").unwrap();
        assert_eq!(parsed.frontmatter["name"], "sample---suffix");
        assert_eq!(parsed.body, "body---tail");
        assert_eq!(
            code("---\nname: sample\n---suffix\n"),
            "frontmatter_unterminated"
        );
    }

    #[test]
    fn distinguishes_missing_unterminated_and_malformed() {
        assert_eq!(code("body only"), "frontmatter_missing");
        assert_eq!(code("---\nname: sample"), "frontmatter_unterminated");
        assert_eq!(code("---\nname: [unterminated\n---\n"), "yaml_invalid");
    }

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for yaml in [
            "tools: [Read]\ntools: [Write]",
            "extra: {key: 1, key: 2}",
            "name: one\n'name': two",
        ] {
            assert_eq!(code(&format!("---\n{yaml}\n---\n")), "yaml_duplicate_key");
        }
    }

    #[test]
    fn rejects_anchors_aliases_and_recursive_expansion() {
        for yaml in [
            "name: &entry sample",
            "name: *entry",
            "extra: &entry [*entry]",
            "a: &a [one]\nb: [*a, *a, *a]",
        ] {
            assert_eq!(
                code(&format!("---\n{yaml}\n---\n")),
                "yaml_alias_unsupported"
            );
        }
    }

    #[test]
    fn accepts_literal_anchor_characters_and_merge_named_metadata() {
        let parsed = parse_frontmatter("---\nname: '&entry *entry'\ndescription: |\n  &entry *entry\nextra: {'<<': literal}\n---\n").unwrap();
        assert_eq!(parsed.frontmatter["name"], "&entry *entry");
        assert_eq!(parsed.frontmatter["description"], "&entry *entry\n");
        assert_eq!(parsed.frontmatter["extra"]["<<"], "literal");
    }

    #[test]
    fn rejects_multiple_yaml_documents() {
        assert_eq!(
            code("---\nname: first\n--- # second document\nname: second\n---\n"),
            "yaml_multiple_documents"
        );
        assert_eq!(
            code("---\n--- # explicit first\nname: first\n...\n--- # second\nname: second\n---\n"),
            "yaml_multiple_documents"
        );
    }

    #[test]
    fn requires_a_mapping_with_string_keys() {
        for yaml in ["[one, two]", "scalar", "null", ""] {
            assert_eq!(
                code(&format!("---\n{yaml}\n---\n")),
                "yaml_root_type",
                "root case: {yaml:?}"
            );
        }
        for yaml in ["1: value", "false: value", "? [one, two]\n: value"] {
            assert_eq!(code(&format!("---\n{yaml}\n---\n")), "yaml_key_type");
        }
    }

    #[test]
    fn empty_and_comment_only_frontmatter_have_root_type_diagnostics() {
        for yaml in ["", "   \n", "# metadata is absent\n"] {
            assert_eq!(
                code(&format!("---\n{yaml}\n---\nbody")),
                "yaml_root_type",
                "empty case: {yaml:?}"
            );
        }
        let parsed = parse_frontmatter("---\n{}\n---\nbody").unwrap();
        assert_eq!(parsed.frontmatter, json!({}));
        assert_eq!(code("---\n \t\n---\nbody"), "yaml_invalid");
    }

    #[test]
    fn raw_yaml_metadata_uses_the_same_bounds_and_mapping_contract() {
        assert_eq!(
            parse_yaml_metadata("name: sample\nextra: false\n").unwrap(),
            json!({"name": "sample", "extra": false})
        );
        assert_eq!(
            parse_yaml_metadata("null").unwrap_err().code,
            "yaml_root_type"
        );
        assert_eq!(parse_yaml_metadata("").unwrap_err().code, "yaml_root_type");
        assert_eq!(
            parse_yaml_metadata(&" ".repeat(MAX_FRONTMATTER_BYTES + 1))
                .unwrap_err()
                .code,
            "frontmatter_size_limit"
        );
    }

    #[test]
    fn accepts_standard_string_tags_and_rejects_custom_tags() {
        let parsed = parse_frontmatter("---\nname: !!str false\n---\n").unwrap();
        assert_eq!(parsed.frontmatter["name"], "false");
        assert_eq!(
            code("---\nextra: !execute source-value\n---\n"),
            "yaml_tag_unsupported"
        );
    }

    #[test]
    fn rejects_custom_uri_tags_on_scalars_sequences_and_mappings() {
        for yaml in [
            "name: !<tag:example.com,2026:inherit> sample",
            "tools: !<tag:example.com,2026:inherit> [Read]",
            "extra: !<tag:example.com,2026:inherit> {key: value}",
            "name: ! sample",
        ] {
            assert_eq!(
                code(&format!("---\n{yaml}\n---\n")),
                "yaml_tag_unsupported",
                "custom tag case: {yaml:?}"
            );
        }
    }

    #[test]
    fn rejects_custom_tags_expanded_by_tag_directives() {
        for value in ["sample", "[Read]", "{key: value}"] {
            let yaml = format!(
                "---\n%TAG !extension! tag:example.com,2026:\n--- # YAML document\nextra: !extension!inherit {value}\n---\n"
            );
            assert_eq!(code(&yaml), "yaml_tag_unsupported");
        }
    }

    #[test]
    fn rejects_core_tags_on_the_wrong_node_kind() {
        for yaml in [
            "tools: !!str [Read]",
            "extra: !!str {key: value}",
            "extra: !!seq value",
            "extra: !!map value",
            "extra: !!map [value]",
            "extra: !!seq {key: value}",
            "extra: !!int [1]",
            "extra: !!bool {key: value}",
        ] {
            assert_eq!(
                code(&format!("---\n{yaml}\n---\n")),
                "yaml_tag_unsupported",
                "wrong node kind case: {yaml:?}"
            );
        }
    }

    #[test]
    fn accepts_core_tags_on_matching_node_kinds() {
        let parsed = parse_frontmatter(
            "---\n!!map {name: !!str false, enabled: !!bool false, count: !!int 2, ratio: !!float 1.5, missing: !!null null, tools: !!seq [Read]}\n---\n",
        )
        .unwrap();
        assert_eq!(
            parsed.frontmatter,
            json!({"name": "false", "enabled": false, "count": 2, "ratio": 1.5, "missing": null, "tools": ["Read"]})
        );
    }

    #[test]
    fn rejects_non_finite_json_numbers() {
        for yaml in ["extra: .nan", "extra: .inf", "extra: -.inf"] {
            assert_eq!(code(&format!("---\n{yaml}\n---\n")), "yaml_number_range");
        }
    }

    #[test]
    fn bounds_document_frontmatter_and_scalar_sizes() {
        assert_eq!(
            code(&"x".repeat(MAX_DOCUMENT_BYTES + 1)),
            "document_size_limit"
        );
        assert_eq!(
            code(&format!(
                "---\n{}\n---\n",
                " ".repeat(MAX_FRONTMATTER_BYTES)
            )),
            "frontmatter_size_limit"
        );
        assert_eq!(
            code(&format!(
                "---\nname: '{}'\n---\n",
                "x".repeat(MAX_SCALAR_BYTES + 1)
            )),
            "yaml_scalar_limit"
        );
    }

    #[test]
    fn bounds_nesting_before_materialization() {
        let yaml = format!("extra: {}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert_eq!(code(&format!("---\n{yaml}\n---\n")), "yaml_depth_limit");
        let yaml = format!(
            "extra: {}0{}",
            "[".repeat(MAX_DEPTH - 1),
            "]".repeat(MAX_DEPTH - 1)
        );
        assert!(parse_frontmatter(&format!("---\n{yaml}\n---\n")).is_ok());
    }

    #[test]
    fn bounds_nodes_before_materialization() {
        let yaml = format!("extra: [{}]", vec!["0"; MAX_NODES].join(","));
        assert_eq!(code(&format!("---\n{yaml}\n---\n")), "yaml_node_limit");
    }

    #[test]
    fn diagnostics_never_echo_source_values() {
        for yaml in [
            "secret-value: [invalid",
            "secret-value: 1\nsecret-value: 2",
            "extra: !secret-value contents",
        ] {
            let error = parse_frontmatter(&format!("---\n{yaml}\n---\n")).unwrap_err();
            assert!(!error.to_string().contains("secret-value"));
            assert!(!format!("{error:?}").contains("secret-value"));
            assert!(error.message.len() <= 1024);
        }
    }
}
