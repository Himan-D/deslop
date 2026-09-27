use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmProvider {
    Gemini,
    OpenAI,
    Anthropic,
    OpenRouter,
    Offline,
}

/// Abstraction over text-completion backends. `LlmClient` implements this for
/// cloud providers; tests and offline paths can substitute a stub without
/// touching call sites.
pub trait CompletionProvider {
    fn provider_name(&self) -> &'static str;
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> anyhow::Result<String>;
}

pub struct LlmClient {
    pub provider: LlmProvider,
    pub api_key: Option<String>,
    pub model: String,
    http_client: reqwest::blocking::Client,
}

impl LlmClient {
    /// Detects available API keys from environment variables
    pub fn auto_detect() -> Self {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        if let Ok(key) = env::var("GEMINI_API_KEY").or_else(|_| env::var("GOOGLE_API_KEY")) {
            if !key.trim().is_empty() {
                return Self {
                    provider: LlmProvider::Gemini,
                    api_key: Some(key),
                    model: "gemini-2.5-flash".to_string(),
                    http_client,
                };
            }
        }

        if let Ok(key) = env::var("OPENAI_API_KEY") {
            if !key.trim().is_empty() {
                return Self {
                    provider: LlmProvider::OpenAI,
                    api_key: Some(key),
                    model: "gpt-4o-mini".to_string(),
                    http_client,
                };
            }
        }

        if let Ok(key) = env::var("ANTHROPIC_API_KEY") {
            if !key.trim().is_empty() {
                return Self {
                    provider: LlmProvider::Anthropic,
                    api_key: Some(key),
                    model: "claude-3-5-sonnet-20241022".to_string(),
                    http_client,
                };
            }
        }

        if let Ok(key) = env::var("OPENROUTER_API_KEY") {
            if !key.trim().is_empty() {
                return Self {
                    provider: LlmProvider::OpenRouter,
                    api_key: Some(key),
                    model: "google/gemini-2.5-flash".to_string(),
                    http_client,
                };
            }
        }

        Self {
            provider: LlmProvider::Offline,
            api_key: None,
            model: "offline-deterministic".to_string(),
            http_client,
        }
    }

    pub fn is_offline(&self) -> bool {
        self.provider == LlmProvider::Offline
    }

    /// Explains one finding with actionable narrative. Uses the configured LLM
    /// when online; otherwise renders a deterministic explanation from the
    /// finding itself so the output is always useful, never a mode notice.
    pub fn explain(&self, title: &str, description: &str, remediation: &str) -> String {
        if self.is_offline() {
            return offline_explanation(title, description, remediation);
        }
        let system = "You are a principal software engineer. Explain the architectural finding below in 3-5 sentences: why it hurts maintainability, then concrete fix steps. Be specific, no preamble.";
        let user = format!(
            "Finding: {}\nProblem: {}\nSuggested fix: {}",
            title, description, remediation
        );
        match self.complete(system, &user) {
            Ok(text) => text,
            Err(e) => {
                // API errors can dump full JSON bodies; keep one short line.
                let short = e
                    .to_string()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let short: String = short.chars().take(160).collect();
                format!(
                    "{}\n\n(LLM request via {} failed: {}. Showing deterministic guidance.)",
                    offline_explanation(title, description, remediation),
                    self.provider_name(),
                    short
                )
            }
        }
    }
}

/// Deterministic fallback: structured guidance derived from the finding.
fn offline_explanation(title: &str, description: &str, remediation: &str) -> String {
    format!(
        "{}\nProblem: {}\nRecommended fix: {}\nTip: set GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY for AI-synthesized rationale.",
        title, description, remediation
    )
}

impl CompletionProvider for LlmClient {
    fn provider_name(&self) -> &'static str {
        match self.provider {
            LlmProvider::Gemini => "Gemini",
            LlmProvider::OpenAI => "OpenAI",
            LlmProvider::Anthropic => "Anthropic",
            LlmProvider::OpenRouter => "OpenRouter",
            LlmProvider::Offline => "Offline",
        }
    }

    /// Queries the LLM with a targeted prompt, or returns deterministic guidance if offline
    fn complete(&self, system_prompt: &str, user_prompt: &str) -> anyhow::Result<String> {
        let key = match &self.api_key {
            Some(k) if self.provider != LlmProvider::Offline => k,
            _ => {
                return Ok(
                    "Running in Offline Deterministic Mode (no API key detected).".to_string(),
                )
            }
        };

        match self.provider {
            LlmProvider::Gemini => {
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
                    self.model, key
                );

                let body = serde_json::json!({
                    "systemInstruction": {
                        "parts": [{ "text": system_prompt }]
                    },
                    "contents": [{
                        "parts": [{ "text": user_prompt }]
                    }],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 2048
                    }
                });

                let res = self.http_client.post(&url).json(&body).send()?;
                if !res.status().is_success() {
                    let err = res.text().unwrap_or_default();
                    anyhow::bail!("Gemini API error: {}", err);
                }

                let json: serde_json::Value = res.json()?;
                let text = json["candidates"][0]["content"]["parts"][0]["text"]
                    .as_str()
                    .unwrap_or("No response generated")
                    .to_string();

                Ok(text)
            }
            LlmProvider::OpenAI | LlmProvider::OpenRouter => {
                let url = if self.provider == LlmProvider::OpenRouter {
                    "https://openrouter.ai/api/v1/chat/completions"
                } else {
                    "https://api.openai.com/v1/chat/completions"
                };

                let body = serde_json::json!({
                    "model": self.model,
                    "messages": [
                        { "role": "system", "content": system_prompt },
                        { "role": "user", "content": user_prompt }
                    ],
                    "temperature": 0.2
                });

                let res = self
                    .http_client
                    .post(url)
                    .bearer_auth(key)
                    .json(&body)
                    .send()?;

                if !res.status().is_success() {
                    let err = res.text().unwrap_or_default();
                    anyhow::bail!("OpenAI/OpenRouter API error: {}", err);
                }

                let json: serde_json::Value = res.json()?;
                let text = json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("No response generated")
                    .to_string();

                Ok(text)
            }
            LlmProvider::Anthropic => {
                let url = "https://api.anthropic.com/v1/messages";
                let body = serde_json::json!({
                    "model": self.model,
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [
                        { "role": "user", "content": user_prompt }
                    ],
                    "temperature": 0.2
                });

                let res = self
                    .http_client
                    .post(url)
                    .header("x-api-key", key)
                    .header("anthropic-version", "2023-06-01")
                    .json(&body)
                    .send()?;

                if !res.status().is_success() {
                    let err = res.text().unwrap_or_default();
                    anyhow::bail!("Anthropic API error: {}", err);
                }

                let json: serde_json::Value = res.json()?;
                let text = json["content"][0]["text"]
                    .as_str()
                    .unwrap_or("No response generated")
                    .to_string();

                Ok(text)
            }
            LlmProvider::Offline => Ok("Offline deterministic mode.".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_client() -> LlmClient {
        LlmClient {
            provider: LlmProvider::Offline,
            api_key: None,
            model: "offline-deterministic".to_string(),
            http_client: reqwest::blocking::Client::new(),
        }
    }

    #[test]
    fn provider_names_cover_all_backends() {
        let mut client = offline_client();
        assert_eq!(client.provider_name(), "Offline");
        client.provider = LlmProvider::Gemini;
        assert_eq!(client.provider_name(), "Gemini");
    }

    #[test]
    fn offline_explain_is_actionable_not_a_mode_notice() {
        let client = offline_client();
        let text = client.explain(
            "Tollbooth Wrapper: `scan`",
            "thin pass-through",
            "inline it",
        );
        assert!(text.contains("Tollbooth Wrapper: `scan`"));
        assert!(text.contains("thin pass-through"));
        assert!(text.contains("inline it"));
    }

    #[test]
    fn offline_complete_stays_deterministic() {
        let client = offline_client();
        let out = client.complete("sys", "user").expect("offline complete");
        assert!(!out.is_empty());
    }
}
