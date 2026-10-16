//! Pure, explicit HTTP-dialect body rendering shared by transport and preflight.

use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    ChatMessage, EffortValue, ProviderRequest, SamplingParameters, ToolDefinition,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpDialect {
    OpenAiCompatible,
    AnthropicMessages,
    Ollama,
}

/// Borrows body inputs only. Endpoint, authentication and transport stay separate.
#[derive(Clone, Copy)]
pub struct RequestBodyInput<'a> {
    pub(crate) model: &'a str,
    pub(crate) fallback_input: &'a [u8],
    pub(crate) messages: Option<&'a [ChatMessage]>,
    pub(crate) tools: &'a [ToolDefinition],
    pub(crate) sampling: &'a SamplingParameters,
    pub(crate) effort: Option<&'a EffortValue>,
}

impl<'a> From<&'a ProviderRequest> for RequestBodyInput<'a> {
    fn from(request: &'a ProviderRequest) -> Self {
        Self {
            model: &request.route.expected_model,
            fallback_input: request.input.expose(),
            messages: request.messages.as_deref(),
            tools: &request.tools,
            sampling: &request.sampling,
            effort: request.effort.as_ref(),
        }
    }
}

/// Identifies the literal output-cap field sent on the wire, not a model limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireOutputField {
    MaxTokens,
    OllamaNumPredict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireOutputCap {
    pub field: WireOutputField,
    pub value: u64,
}

/// Owns rendered content without an implicit content-bearing Debug/Serialize API.
pub struct RenderedRequestBody {
    dialect: HttpDialect,
    json: Value,
    output_cap: WireOutputCap,
}

impl RenderedRequestBody {
    pub fn as_json(&self) -> &Value {
        &self.json
    }

    pub fn dialect(&self) -> HttpDialect {
        self.dialect
    }

    pub fn output_cap(&self) -> WireOutputCap {
        self.output_cap
    }
}

/// Render the same JSON shape used by the concrete adapter, without I/O.
pub fn render_request_body(
    dialect: HttpDialect,
    input: RequestBodyInput<'_>,
) -> Result<RenderedRequestBody, AdapterError> {
    if let Some(effort) = input.effort {
        match dialect {
            HttpDialect::OpenAiCompatible => effort.validate_for_openai(),
            HttpDialect::AnthropicMessages => effort.validate_for_anthropic(),
            HttpDialect::Ollama => effort.validate_for_ollama(),
        }
        .map_err(AdapterError::ProviderConfigurationInvalid)?;
    }
    let json = match dialect {
        HttpDialect::OpenAiCompatible => crate::openai::render_body(input),
        HttpDialect::AnthropicMessages => crate::anthropic::render_body(input),
        HttpDialect::Ollama => crate::ollama::render_body(input),
    }?;
    Ok(RenderedRequestBody {
        dialect,
        json,
        output_cap: WireOutputCap {
            field: match dialect {
                HttpDialect::OpenAiCompatible | HttpDialect::AnthropicMessages => {
                    WireOutputField::MaxTokens
                }
                HttpDialect::Ollama => WireOutputField::OllamaNumPredict,
            },
            value: input.sampling.max_output_tokens,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbit_adapter::types::{ChatRole, ContentBlock, Sha256Digest, ToolCallMessage};
    use serde_json::json;

    const DIALECTS: [HttpDialect; 3] = [
        HttpDialect::OpenAiCompatible,
        HttpDialect::AnthropicMessages,
        HttpDialect::Ollama,
    ];

    fn sampling() -> SamplingParameters {
        SamplingParameters {
            temperature_milliunits: 0,
            top_p_millionths: 0,
            max_output_tokens: 73,
        }
    }

    fn input<'a>(sampling: &'a SamplingParameters) -> RequestBodyInput<'a> {
        RequestBodyInput {
            model: "fixture-model",
            fallback_input: b"fallback prompt",
            messages: None,
            tools: &[],
            sampling,
            effort: None,
        }
    }

    fn message(role: ChatRole, content: &str) -> ChatMessage {
        ChatMessage {
            role,
            content: content.into(),
            blocks: None,
            tool_calls: None,
            tool_call_id: None,
            tool_result: None,
            origin_model: None,
            origin_provider: None,
        }
    }

    fn call(id: &str, arguments: &str) -> ToolCallMessage {
        ToolCallMessage {
            id: id.into(),
            name: "inspect".into(),
            arguments: arguments.into(),
        }
    }

    fn tool() -> ToolDefinition {
        ToolDefinition {
            name: "inspect".into(),
            description: "Inspect one path".into(),
            parameters: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            schema_digest: Sha256Digest("internal-digest-not-a-wire-field".into()),
        }
    }

    fn body(dialect: HttpDialect, input: RequestBodyInput<'_>) -> Value {
        render_request_body(dialect, input).unwrap().json
    }

    #[test]
    fn fallback_minimal_bodies_have_exact_serialized_bytes() {
        let sampling = sampling();
        let expected: [&[u8]; 3] = [
            br#"{"max_tokens":73,"messages":[{"content":"fallback prompt","role":"user"}],"model":"fixture-model","stream":true,"stream_options":{"include_usage":true}}"#,
            br#"{"max_tokens":73,"messages":[{"content":[{"text":"fallback prompt","type":"text"}],"role":"user"}],"model":"fixture-model","stream":true,"thinking":{"type":"adaptive"}}"#,
            br#"{"messages":[{"content":"fallback prompt","role":"user"}],"model":"fixture-model","options":{"num_predict":73},"stream":true}"#,
        ];
        for (dialect, expected) in DIALECTS.into_iter().zip(expected) {
            let rendered = render_request_body(dialect, input(&sampling)).unwrap();
            assert_eq!(serde_json::to_vec(rendered.as_json()).unwrap(), expected);
            assert_eq!(rendered.dialect(), dialect);
            assert_eq!(rendered.output_cap().value, 73);
            assert_eq!(
                rendered.output_cap().field,
                if dialect == HttpDialect::Ollama {
                    WireOutputField::OllamaNumPredict
                } else {
                    WireOutputField::MaxTokens
                }
            );
        }
    }

    #[test]
    fn present_empty_transcript_never_reintroduces_fallback_input() {
        let sampling = sampling();
        for dialect in DIALECTS {
            let rendered = body(
                dialect,
                RequestBodyInput {
                    messages: Some(&[]),
                    ..input(&sampling)
                },
            );
            assert_eq!(rendered["messages"], json!([]));
            assert!(!rendered.to_string().contains("fallback prompt"));
        }
    }

    #[test]
    fn fallback_retains_lossy_utf8_conversion_for_each_dialect() {
        let sampling = sampling();
        for dialect in DIALECTS {
            let rendered = body(
                dialect,
                RequestBodyInput {
                    fallback_input: b"a\xffb",
                    ..input(&sampling)
                },
            );
            let content = if dialect == HttpDialect::AnthropicMessages {
                &rendered["messages"][0]["content"][0]["text"]
            } else {
                &rendered["messages"][0]["content"]
            };
            assert_eq!(content, "a\u{fffd}b");
        }
    }

    #[test]
    fn output_metadata_keeps_full_u64_and_zero_wire_values() {
        for value in [0, u64::from(u32::MAX) + 1, u64::MAX] {
            let sampling = SamplingParameters {
                max_output_tokens: value,
                ..sampling()
            };
            for dialect in DIALECTS {
                let rendered = render_request_body(dialect, input(&sampling)).unwrap();
                let sent = if dialect == HttpDialect::Ollama {
                    &rendered.as_json()["options"]["num_predict"]
                } else {
                    &rendered.as_json()["max_tokens"]
                };
                assert_eq!(sent.as_u64(), Some(value));
                assert_eq!(rendered.output_cap().value, value);
            }
        }
    }

    #[test]
    fn public_projection_borrows_body_fields_and_uses_explicit_dialect_only() {
        let route = serde_json::from_value(json!({
            "provider_id":"fixture", "deployment_id":"fixture", "region_id":"local",
            "adapter_kind":"LocalProcessV1", "adapter_implementation_digest":"implementation",
            "adapter_profile_digest":"profile", "endpoint_digest":"endpoint",
            "expected_model":"fixture-model", "pricing_digest":"pricing",
            "endpoint_host":"127.0.0.1", "endpoint_port":11434,
            "endpoint_scheme":"HttpLoopback", "endpoint_path":"/api"
        }))
        .unwrap();
        let mut request = orbit_adapter::conformance::canonical_request(&route, b"fallback prompt");
        request.sampling = sampling();
        let projected = RequestBodyInput::from(&request);
        assert!(std::ptr::eq(
            projected.fallback_input.as_ptr(),
            request.input.expose().as_ptr()
        ));
        assert!(std::ptr::eq(projected.sampling, &request.sampling));
        let original = body(HttpDialect::OpenAiCompatible, projected);
        assert_eq!(
            original,
            json!({
                "model":"fixture-model", "stream":true, "stream_options":{"include_usage":true},
                "max_tokens":73, "messages":[{"role":"user","content":"fallback prompt"}]
            })
        );

        request.route.endpoint_host = "unrelated.invalid".into();
        request.route.endpoint_query = Some("unrelated=route-value".into());
        request.connect_timeout_ms = 1;
        request.first_byte_timeout_ms = 2;
        request.idle_timeout_ms = 3;
        request.metadata.input_bytes = u64::MAX;
        request.metadata.tools_count = u32::MAX;
        request.output = orbit_adapter::types::OutputRequirements::JsonSchema {
            digest: Sha256Digest("unrelated-output-digest".into()),
        };
        assert_eq!(
            body(
                HttpDialect::OpenAiCompatible,
                RequestBodyInput::from(&request)
            ),
            original
        );
    }

    #[test]
    fn openai_system_tools_sampling_and_effort_keep_existing_shape() {
        let sampling = SamplingParameters {
            temperature_milliunits: 375,
            top_p_millionths: 812_500,
            ..sampling()
        };
        let messages = [
            message(ChatRole::System, "directive"),
            message(ChatRole::User, "question"),
        ];
        let tools = [tool()];
        let effort = EffortValue::Level("high".into());
        assert_eq!(
            body(
                HttpDialect::OpenAiCompatible,
                RequestBodyInput {
                    messages: Some(&messages),
                    tools: &tools,
                    effort: Some(&effort),
                    ..input(&sampling)
                }
            ),
            json!({
                "model":"fixture-model", "stream":true, "stream_options":{"include_usage":true}, "max_tokens":73,
                "messages":[{"role":"system","content":"directive"},{"role":"user","content":"question"}],
                "tools":[{"type":"function","function":{"name":"inspect","description":"Inspect one path","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}],
                "tool_choice":"auto", "reasoning_effort":"high", "temperature":0.375, "top_p":0.8125
            })
        );
    }

    #[test]
    fn structured_user_blocks_win_without_flattened_content_duplication() {
        let sampling = sampling();
        let mut user = message(ChatRole::User, "flattened must not repeat");
        user.blocks = Some(vec![
            ContentBlock::Text {
                text: "first".into(),
            },
            ContentBlock::Image {
                data: "cGl4ZWxz".into(),
                media_type: "image/png".into(),
            },
            ContentBlock::Text {
                text: "second".into(),
            },
        ]);
        let messages = [user];
        let expected = [
            json!([{"role":"user","content":[{"type":"text","text":"first"},{"type":"image_url","image_url":{"url":"data:image/png;base64,cGl4ZWxz"}},{"type":"text","text":"second"}]}]),
            json!([{"role":"user","content":[{"type":"text","text":"first"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"cGl4ZWxz"}},{"type":"text","text":"second"}]}]),
            json!([{"role":"user","content":"firstsecond","images":["cGl4ZWxz"]}]),
        ];
        for (dialect, expected) in DIALECTS.into_iter().zip(expected) {
            let rendered = body(
                dialect,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                },
            );
            assert_eq!(rendered["messages"], expected);
            assert!(!rendered.to_string().contains("flattened must not repeat"));
        }
    }

    #[test]
    fn empty_structured_blocks_retain_dialect_specific_fallbacks() {
        let sampling = sampling();
        let mut user = message(ChatRole::User, "flattened fallback");
        user.blocks = Some(vec![]);
        let messages = [user];
        let expected = [
            json!([]),
            json!([{"type":"text","text":"flattened fallback"}]),
            json!(""),
        ];
        for (dialect, expected) in DIALECTS.into_iter().zip(expected) {
            assert_eq!(
                body(
                    dialect,
                    RequestBodyInput {
                        messages: Some(&messages),
                        ..input(&sampling)
                    }
                )["messages"][0]["content"],
                expected
            );
        }
    }

    #[test]
    fn openai_tool_calls_and_results_keep_raw_arguments_ids_and_one_result() {
        let sampling = sampling();
        let mut assistant = message(ChatRole::Assistant, "");
        assistant.tool_calls = Some(vec![call("call-1", "{ \"path\": \"x\" }")]);
        let mut result = message(ChatRole::Tool, "flattened result must not repeat");
        result.tool_call_id = Some("call-1".into());
        result.tool_result = Some("exact result".into());
        let mut fallback = message(ChatRole::Tool, "legacy result");
        fallback.tool_call_id = Some("call-2".into());
        let messages = [assistant, result, fallback];
        assert_eq!(
            body(
                HttpDialect::OpenAiCompatible,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"inspect","arguments":"{ \"path\": \"x\" }"}}]},
                {"role":"tool","content":"exact result","tool_call_id":"call-1"},
                {"role":"tool","content":"legacy result","tool_call_id":"call-2"}
            ])
        );
    }

    #[test]
    fn anthropic_system_tools_effort_and_ignored_sampling_keep_existing_shape() {
        let sampling = SamplingParameters {
            temperature_milliunits: 777,
            top_p_millionths: 123_456,
            ..sampling()
        };
        let mut first = message(ChatRole::System, "first directive");
        first.blocks = Some(vec![ContentBlock::Text {
            text: "ignored system block".into(),
        }]);
        let messages = [
            first,
            message(ChatRole::System, ""),
            message(ChatRole::System, "second directive"),
            message(ChatRole::User, "question"),
        ];
        let tools = [tool()];
        let effort = EffortValue::Level("max".into());
        assert_eq!(
            body(
                HttpDialect::AnthropicMessages,
                RequestBodyInput {
                    messages: Some(&messages),
                    tools: &tools,
                    effort: Some(&effort),
                    ..input(&sampling)
                }
            ),
            json!({
                "model":"fixture-model", "stream":true, "max_tokens":73, "thinking":{"type":"adaptive"},
                "output_config":{"effort":"max"},
                "system":[{"type":"text","text":"first directive\n\nsecond directive","cache_control":{"type":"ephemeral"}}],
                "messages":[{"role":"user","content":[{"type":"text","text":"question"}]}],
                "tools":[{"name":"inspect","description":"Inspect one path","input_schema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}],
                "tool_choice":{"type":"auto"}
            })
        );
    }

    #[test]
    fn anthropic_signed_opaque_blocks_replay_in_order_without_text_conversion() {
        let sampling = sampling();
        let mut assistant = message(ChatRole::Assistant, "visible answer");
        assistant.blocks = Some(vec![
            ContentBlock::Opaque { json: r#"{"type":"thinking","thinking":"private synthetic thought","signature":"signed-fixture"}"#.into() },
            ContentBlock::Text { text: "unused structured copy".into() },
            ContentBlock::Opaque { json: r#"{"type":"redacted_thinking","data":"opaque-fixture"}"#.into() },
        ]);
        assistant.tool_calls = Some(vec![call("call-1", r#"{"path":"x"}"#)]);
        let messages = [assistant];
        assert_eq!(
            body(
                HttpDialect::AnthropicMessages,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"assistant","content":[
                    {"type":"thinking","thinking":"private synthetic thought","signature":"signed-fixture"},
                    {"type":"redacted_thinking","data":"opaque-fixture"},
                    {"type":"text","text":"visible answer"},
                    {"type":"tool_use","id":"call-1","name":"inspect","input":{"path":"x"}}
                ]}
            ])
        );
    }

    #[test]
    fn anthropic_retains_existing_malformed_opaque_and_call_argument_fallbacks() {
        let sampling = sampling();
        let mut empty = message(ChatRole::Assistant, "");
        empty.blocks = Some(vec![ContentBlock::Opaque {
            json: "invalid JSON".into(),
        }]);
        let mut called = message(ChatRole::Assistant, "");
        called.tool_calls = Some(vec![call("call-1", "invalid JSON")]);
        let messages = [empty, called];
        assert_eq!(
            body(
                HttpDialect::AnthropicMessages,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"inspect","input":{}}]}
            ])
        );
    }

    #[test]
    fn anthropic_tool_images_and_typed_error_use_the_selected_result_once() {
        let sampling = sampling();
        let mut result = message(ChatRole::Tool, "flattened result must not repeat");
        result.tool_call_id = Some("call-1".into());
        result.tool_result = Some(r#"{"ok":false,"error":"synthetic failure"}"#.into());
        result.blocks = Some(vec![
            ContentBlock::Text {
                text: "unused block copy".into(),
            },
            ContentBlock::Image {
                data: "cGl4ZWxz".into(),
                media_type: "image/jpeg".into(),
            },
        ]);
        let fallback = message(ChatRole::Tool, "legacy plain result");
        let messages = [result, fallback];
        assert_eq!(
            body(
                HttpDialect::AnthropicMessages,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","is_error":true,"content":[
                    {"type":"text","text":"{\"ok\":false,\"error\":\"synthetic failure\"}"},
                    {"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"cGl4ZWxz"}}
                ]}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"","is_error":false,"content":"legacy plain result"}]}
            ])
        );
    }

    #[test]
    fn anthropic_unmapped_user_blocks_fall_back_to_flattened_content() {
        let sampling = sampling();
        let mut user = message(ChatRole::User, "fallback text");
        user.blocks = Some(vec![ContentBlock::Opaque {
            json: r#"{"type":"thinking"}"#.into(),
        }]);
        let messages = [user];
        assert_eq!(
            body(
                HttpDialect::AnthropicMessages,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"user","content":[{"type":"text","text":"fallback text"}]}
            ])
        );
    }

    #[test]
    fn ollama_system_tools_sampling_and_boolean_effort_keep_existing_shape() {
        let sampling = SamplingParameters {
            temperature_milliunits: 375,
            top_p_millionths: 812_500,
            ..sampling()
        };
        let messages = [
            message(ChatRole::System, "directive"),
            message(ChatRole::User, "question"),
        ];
        let tools = [tool()];
        let effort = EffortValue::Bool(false);
        assert_eq!(
            body(
                HttpDialect::Ollama,
                RequestBodyInput {
                    messages: Some(&messages),
                    tools: &tools,
                    effort: Some(&effort),
                    ..input(&sampling)
                }
            ),
            json!({
                "model":"fixture-model", "stream":true,
                "messages":[{"role":"system","content":"directive"},{"role":"user","content":"question"}],
                "options":{"num_predict":73,"temperature":0.375,"top_p":0.8125}, "think":false,
                "tools":[{"type":"function","function":{"name":"inspect","description":"Inspect one path","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}]
            })
        );
    }

    #[test]
    fn ollama_calls_and_results_keep_native_objects_names_and_one_result() {
        let sampling = sampling();
        let mut assistant = message(ChatRole::Assistant, "");
        assistant.tool_calls = Some(vec![
            call("call-1", r#"{ "path": "x" }"#),
            call("call-2", "{}"),
        ]);
        let mut result = message(ChatRole::Tool, "flattened must not repeat");
        result.tool_call_id = Some("call-1".into());
        result.tool_result = Some("exact result".into());
        let mut fallback = message(ChatRole::Tool, "legacy result");
        fallback.tool_call_id = Some("call-2".into());
        let messages = [assistant, result, fallback];
        assert_eq!(
            body(
                HttpDialect::Ollama,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                }
            )["messages"],
            json!([
                {"role":"assistant","content":"","tool_calls":[{"function":{"name":"inspect","arguments":{"path":"x"}}},{"function":{"name":"inspect","arguments":{}}}]},
                {"role":"tool","content":"exact result","tool_name":"inspect"},
                {"role":"tool","content":"legacy result","tool_name":"inspect"}
            ])
        );
    }

    #[test]
    fn ollama_unresolved_trailing_call_and_named_effort_remain_accepted() {
        let sampling = sampling();
        let mut assistant = message(ChatRole::Assistant, "");
        assistant.tool_calls = Some(vec![call("call-1", "{}")]);
        let messages = [assistant];
        let effort = EffortValue::Level("high".into());
        let rendered = body(
            HttpDialect::Ollama,
            RequestBodyInput {
                messages: Some(&messages),
                effort: Some(&effort),
                ..input(&sampling)
            },
        );
        assert_eq!(rendered["think"], "high");
        assert_eq!(
            rendered["messages"],
            json!([{"role":"assistant","content":"","tool_calls":[{"function":{"name":"inspect","arguments":{}}}]}])
        );
    }

    #[test]
    fn openai_and_ollama_refuse_opaque_and_unsupported_image_roles() {
        let sampling = sampling();
        for dialect in [HttpDialect::OpenAiCompatible, HttpDialect::Ollama] {
            for (role, block) in [
                (
                    ChatRole::Assistant,
                    ContentBlock::Opaque { json: "{}".into() },
                ),
                (
                    ChatRole::Assistant,
                    ContentBlock::Image {
                        data: "cGl4ZWxz".into(),
                        media_type: "image/png".into(),
                    },
                ),
                (
                    ChatRole::User,
                    ContentBlock::Image {
                        data: "cGl4ZWxz".into(),
                        media_type: "image/svg+xml".into(),
                    },
                ),
            ] {
                let mut message = message(role, "");
                message.blocks = Some(vec![block]);
                let messages = [message];
                let error = render_request_body(
                    dialect,
                    RequestBodyInput {
                        messages: Some(&messages),
                        ..input(&sampling)
                    },
                )
                .err()
                .expect("unsupported block must fail");
                assert!(matches!(error, AdapterError::CapabilityMismatch(_)));
            }
        }
    }

    #[test]
    fn openai_and_ollama_keep_tool_identity_and_structured_result_refusals() {
        let sampling = sampling();
        for dialect in [HttpDialect::OpenAiCompatible, HttpDialect::Ollama] {
            let messages = [message(ChatRole::Tool, "result")];
            let error = render_request_body(
                dialect,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                },
            )
            .err()
            .expect("missing identity must fail");
            if dialect == HttpDialect::OpenAiCompatible {
                assert!(matches!(error, AdapterError::RequestInvalidOrTooLarge(_)));
            } else {
                assert!(matches!(error, AdapterError::ProtocolOrStreamViolation(_)));
            }
            let mut result = message(ChatRole::Tool, "result");
            result.tool_call_id = Some("call-1".into());
            result.blocks = Some(vec![]);
            let messages = [result];
            let error = render_request_body(
                dialect,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                },
            )
            .err()
            .expect("structured result must fail");
            assert!(matches!(error, AdapterError::CapabilityMismatch(_)));
        }
    }

    #[test]
    fn ollama_keeps_object_argument_and_matching_call_refusals() {
        let sampling = sampling();
        for arguments in ["invalid JSON", "[]", "null"] {
            let mut assistant = message(ChatRole::Assistant, "");
            assistant.tool_calls = Some(vec![call("call-1", arguments)]);
            let messages = [assistant];
            let error = render_request_body(
                HttpDialect::Ollama,
                RequestBodyInput {
                    messages: Some(&messages),
                    ..input(&sampling)
                },
            )
            .err()
            .expect("non-object arguments must fail");
            assert!(matches!(error, AdapterError::ProtocolOrStreamViolation(_)));
        }
        let mut result = message(ChatRole::Tool, "result");
        result.tool_call_id = Some("unknown-call".into());
        let messages = [result];
        let error = render_request_body(
            HttpDialect::Ollama,
            RequestBodyInput {
                messages: Some(&messages),
                ..input(&sampling)
            },
        )
        .err()
        .expect("unmatched result must fail");
        assert!(matches!(error, AdapterError::ProtocolOrStreamViolation(_)));
    }

    #[test]
    fn invalid_effort_precedes_body_mapping_errors_for_pure_callers() {
        let sampling = sampling();
        let mut unsupported = message(ChatRole::Assistant, "");
        unsupported.blocks = Some(vec![ContentBlock::Opaque { json: "{}".into() }]);
        let messages = [unsupported];
        for dialect in DIALECTS {
            let effort = EffortValue::Level("default".into());
            let error = render_request_body(
                dialect,
                RequestBodyInput {
                    messages: Some(&messages),
                    effort: Some(&effort),
                    ..input(&sampling)
                },
            )
            .err()
            .expect("invalid effort must fail");
            assert!(matches!(
                error,
                AdapterError::ProviderConfigurationInvalid(_)
            ));
        }
    }
}
