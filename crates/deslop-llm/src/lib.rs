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

    /// Queries the LLM with a targeted prompt, or returns deterministic guidance if offline
    pub fn complete(&self, system_prompt: &str, user_prompt: &str) -> anyhow::Result<String> {
        let key = match &self.api_key {
            Some(k) if self.provider != LlmProvider::Offline => k,
            _ => return Ok("Running in Offline Deterministic Mode (no API key detected).".to_string()),
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
