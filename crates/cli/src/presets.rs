//! Provider presets (`orbit provider add`): the well-known providers'
//! endpoints, credential env-var conventions and public model facts, so
//! setup is a picker instead of a research task.
//!
//! Presets carry NO secrets — only the *name* of the env var the user is
//! expected to export. Values are read at request time by the adapters,
//! never stored here or in providers.toml.
//!
//! Model facts (pricing, windows) are static fallbacks from public rate
//! cards as of October 2026; live discovery (Anthropic's per-model
//! detail endpoint) overrides them where available.

use crate::config::{ModelEntry, Pricing};

/// One provider preset.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderPreset {
    /// The preset id the user types: `orbit provider add anthropic`.
    pub id: &'static str,
    /// One-line description shown in the picker.
    pub blurb: &'static str,
    /// Adapter kind for providers.toml.
    pub kind: &'static str,
    /// Default base URL.
    pub url: &'static str,
    /// Alternate URL(s) offered as a choice (regional endpoints).
    pub alt_urls: &'static [(&'static str, &'static str)],
    /// Suggested credential env-var name.
    pub env: &'static str,
    /// Known models with static facts. Empty = discover only.
    pub models: &'static [PresetModel],
}

/// A preset's model facts.
#[derive(Debug, Clone, PartialEq)]
pub struct PresetModel {
    pub id: &'static str,
    pub label: &'static str,
    /// (input, output, cache_read) microdollars per million tokens.
    pub pricing: (u64, u64, Option<u64>),
    /// Context window in tokens, when public.
    pub context_window: Option<u64>,
    /// Max output tokens, when public.
    pub max_output_tokens: Option<u32>,
}

/// Every built-in preset, in picker order.
pub fn presets() -> Vec<ProviderPreset> {
    vec![
        ProviderPreset {
            id: "anthropic",
            blurb: "Anthropic — Claude models over the native Messages API",
            kind: "anthropic",
            url: "https://api.anthropic.com",
            alt_urls: &[],
            env: "ANTHROPIC_API_KEY",
            models: &[
                PresetModel {
                    id: "claude-opus-5-5",
                    label: "Opus 5.5 — the main brain",
                    pricing: (4_000_000, 20_000_000, Some(200_000)),
                    context_window: Some(200_000),
                    max_output_tokens: Some(128_000),
                },
                PresetModel {
                    id: "claude-sonnet-5-5",
                    label: "Sonnet 5.5 — fast main agent / coding subagent",
                    pricing: (2_000_000, 10_000_000, Some(200_000)),
                    context_window: Some(200_000),
                    max_output_tokens: Some(128_000),
                },
                PresetModel {
                    id: "claude-haiku-4-5",
                    label: "Haiku 4.5 — explore, extraction, summaries",
                    pricing: (1_000_000, 5_000_000, Some(100_000)),
                    context_window: Some(200_000),
                    max_output_tokens: Some(64_000),
                },
            ],
        },
        ProviderPreset {
            id: "openai",
            blurb: "OpenAI — GPT models over the chat completions API",
            kind: "openai-compatible",
            url: "https://api.openai.com/v1",
            alt_urls: &[],
            env: "OPENAI_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "openrouter",
            blurb: "OpenRouter — one key, many providers' models",
            kind: "openai-compatible",
            url: "https://openrouter.ai/api/v1",
            alt_urls: &[],
            env: "OPENROUTER_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "qwen",
            blurb: "Qwen (DashScope international endpoint)",
            kind: "openai-compatible",
            url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            alt_urls: &[("cn", "https://dashscope.aliyuncs.com/compatible-mode/v1")],
            env: "DASHSCOPE_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "zai",
            blurb: "Z.ai — GLM models (OpenAI-compatible surface)",
            kind: "openai-compatible",
            url: "https://api.z.ai/api/paas/v4",
            alt_urls: &[],
            env: "ZAI_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "gemini",
            blurb: "Google Gemini — via its OpenAI-compatible endpoint",
            kind: "openai-compatible",
            url: "https://generativelanguage.googleapis.com/v1beta/openai",
            alt_urls: &[],
            env: "GEMINI_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "deepseek",
            blurb: "DeepSeek",
            kind: "openai-compatible",
            url: "https://api.deepseek.com/v1",
            alt_urls: &[],
            env: "DEEPSEEK_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "groq",
            blurb: "Groq — fast inference for open models",
            kind: "openai-compatible",
            url: "https://api.groq.com/openai/v1",
            alt_urls: &[],
            env: "GROQ_API_KEY",
            models: &[],
        },
        ProviderPreset {
            id: "ollama",
            blurb: "Ollama — local models at http://127.0.0.1:11434",
            kind: "ollama",
            url: "http://127.0.0.1:11434",
            alt_urls: &[],
            env: "",
            models: &[],
        },
        ProviderPreset {
            id: "custom",
            blurb: "Any OpenAI-compatible, Anthropic-compatible or Ollama endpoint",
            kind: "openai-compatible",
            url: "",
            alt_urls: &[],
            env: "ORBIT_GATE_TOKEN",
            models: &[],
        },
    ]
}

/// Look one preset up by id (case-insensitive).
pub fn preset_by_id(id: &str) -> Option<ProviderPreset> {
    presets()
        .into_iter()
        .find(|p| p.id.eq_ignore_ascii_case(id))
}

/// The preset's facts for one model id, if any. `preset.models` is
/// `&'static`, so the returned reference outlives the preset handle.
pub fn preset_model(preset: &ProviderPreset, model_id: &str) -> Option<&'static PresetModel> {
    preset.models.iter().find(|m| m.id == model_id)
}

/// Build a ModelEntry from preset facts; unset fields stay None so live
/// discovery or the defaults apply.
pub fn preset_model_entry(preset: &ProviderPreset, model_id: &str) -> ModelEntry {
    let fact = preset_model(preset, model_id);
    ModelEntry {
        id: model_id.to_string(),
        label: fact.map(|f| f.label.to_string()),
        sampling: None,
        pricing: fact
            .map(|f| Pricing {
                input_per_million_microdollars: f.pricing.0,
                output_per_million_microdollars: f.pricing.1,
                cache_read_per_million_microdollars: f.pricing.2,
                ..Default::default()
            })
            .unwrap_or_default(),
        max_output_tokens: fact.and_then(|f| f.max_output_tokens),
        context_window: fact.and_then(|f| f.context_window),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_have_unique_ids() {
        let all = presets();
        let mut ids: Vec<&str> = all.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "preset ids must be unique");
    }

    #[test]
    fn preset_urls_parse() {
        for p in presets() {
            if p.url.is_empty() {
                assert_eq!(p.id, "custom");
                continue;
            }
            let u = url::Url::parse(p.url).unwrap_or_else(|e| panic!("{}: {e}", p.id));
            if p.id == "ollama" {
                assert_eq!(u.scheme(), "http", "ollama is loopback http");
                continue;
            }
            assert_eq!(u.scheme(), "https", "{} must be https", p.id);
        }
    }

    #[test]
    fn anthropic_facts_match_the_rate_card() {
        let p = preset_by_id("anthropic").unwrap();
        let opus = preset_model(&p, "claude-opus-5-5").unwrap();
        assert_eq!(opus.pricing, (4_000_000, 20_000_000, Some(200_000)));
        assert_eq!(opus.context_window, Some(200_000));
        let entry = preset_model_entry(&p, "claude-haiku-4-5");
        assert_eq!(entry.max_output_tokens, Some(64_000));
        assert_eq!(
            entry.pricing.input_per_million_microdollars, 1_000_000,
            "microdollars: $1/M input"
        );
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(preset_by_id("Anthropic").is_some());
        assert!(preset_by_id("NOPE").is_none());
    }
}
