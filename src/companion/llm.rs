//! A blocking HTTP client for OpenAI-compatible and Anthropic-compatible chat endpoints.

use std::cell::Cell;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::companion::store::{Protocol, Settings};
use crate::companion::tokens::Calibration;

const LIST_TIMEOUT: Duration = Duration::from_secs(5);
const ANTHROPIC_VERSION: &str = "2023-06-01";
const ERROR_BODY_CHARS: usize = 200;

#[derive(Debug)]
pub enum LlmError {
    Unreachable(String),
    Timeout,
    Http { status: u16, body: String },
    BadResponse(String),
}

impl LlmError {
    /// Worth one more try: the network, the server or its rate limit may recover.
    pub fn is_retryable(&self) -> bool {
        match self {
            LlmError::Unreachable(_) | LlmError::Timeout => true,
            LlmError::Http { status, .. } => matches!(status, 408 | 409 | 429 | 500..=599),
            LlmError::BadResponse(_) => false,
        }
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::Unreachable(reason) => write!(f, "Unreachable: {reason}"),
            LlmError::Timeout => write!(f, "Timeout"),
            LlmError::Http { status, body } => {
                let body: String = body.chars().take(ERROR_BODY_CHARS).collect();
                write!(f, "HTTP {status}: {body}")
            }
            LlmError::BadResponse(reason) => write!(f, "Bad response: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelInfo {
    pub id: String,
    pub max_input_tokens: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

pub struct ChatRequest<'a> {
    pub system: &'a str,
    pub turns: &'a [(Role, &'a str)],
    pub max_tokens: u32,
    pub json: bool,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ChatResponse {
    pub text: String,
    pub truncated: bool,
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ModelList {
    data: Vec<ModelEntry>,
}

#[derive(Deserialize)]
struct ModelEntry {
    id: String,
    max_input_tokens: Option<u32>,
}

/// The models or chat route below the base URL, one trailing `/` of the base trimmed.
fn route(settings: &Settings, chat: bool) -> String {
    let base = settings.endpoint_url.trim();
    let base = base.strip_suffix('/').unwrap_or(base);
    let path = match (settings.protocol, chat) {
        (Protocol::OpenAi, false) => "models",
        (Protocol::OpenAi, true) => "chat/completions",
        (Protocol::Anthropic, false) => "v1/models?limit=1000",
        (Protocol::Anthropic, true) => "v1/messages",
    };
    format!("{base}/{path}")
}

/// Auth, protocol and user-configured headers; `extra_headers` that are not a JSON object are ignored.
fn headers(settings: &Settings) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match settings.protocol {
        Protocol::OpenAi if !settings.api_key.is_empty() => {
            out.push(("Authorization".to_string(), format!("Bearer {}", settings.api_key)));
        }
        Protocol::Anthropic => {
            out.push(("x-api-key".to_string(), settings.api_key.clone()));
            out.push(("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()));
        }
        Protocol::OpenAi => {}
    }
    if let Ok(Value::Object(extra)) = serde_json::from_str(&settings.extra_headers) {
        for (name, value) in extra {
            if let Some(value) = value.as_str() {
                out.push((name, value.to_string()));
            }
        }
    }
    out
}

fn map_error(e: ureq::Error) -> LlmError {
    match e {
        ureq::Error::Timeout(_) => LlmError::Timeout,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => LlmError::Timeout,
        ureq::Error::Protocol(_) | ureq::Error::Http(_) | ureq::Error::BadUri(_) => {
            LlmError::BadResponse(e.to_string())
        }
        other => LlmError::Unreachable(other.to_string()),
    }
}

/// One request; `body` makes it a JSON POST. Returns the body of a non-error response.
fn send(settings: &Settings, url: &str, body: Option<&str>, timeout: Duration) -> Result<String, LlmError> {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let mut config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .tls_config(tls);
    if !settings.user_agent.is_empty() {
        config = config.user_agent(settings.user_agent.as_str());
    }
    let agent = ureq::Agent::new_with_config(config.build());
    let headers = headers(settings);
    let result = match body {
        None => {
            let mut r = agent.get(url);
            for (k, v) in &headers {
                r = r.header(k, v);
            }
            r.call()
        }
        Some(body) => {
            let mut r = agent.post(url).header("Content-Type", "application/json");
            for (k, v) in &headers {
                r = r.header(k, v);
            }
            r.send(body)
        }
    };
    let mut response = result.map_err(map_error)?;
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().map_err(map_error)?;
    if status >= 400 {
        return Err(LlmError::Http { status, body: text });
    }
    Ok(text)
}

pub fn list_models(settings: &Settings) -> Result<Vec<ModelInfo>, LlmError> {
    let text = send(settings, &route(settings, false), None, LIST_TIMEOUT)?;
    let list: ModelList = serde_json::from_str(&text).map_err(|e| LlmError::BadResponse(e.to_string()))?;
    let mut models: Vec<ModelInfo> = list
        .data
        .into_iter()
        .map(|m| ModelInfo {
            id: m.id,
            max_input_tokens: m.max_input_tokens,
        })
        .collect();
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models.dedup_by(|a, b| a.id == b.id);
    Ok(models)
}

/// `list_models` under the name the settings dialog uses.
pub fn probe(settings: &Settings) -> Result<Vec<ModelInfo>, LlmError> {
    list_models(settings)
}

fn parse_chat(protocol: Protocol, text: &str) -> Result<ChatResponse, LlmError> {
    let bad = |what: &str| LlmError::BadResponse(what.to_string());
    let v: Value = serde_json::from_str(text).map_err(|e| LlmError::BadResponse(e.to_string()))?;
    let count = |p: &str| v.pointer(p).and_then(Value::as_u64).map(|n| n as u32);
    if protocol == Protocol::OpenAi {
        let content = v.pointer("/choices/0/message/content").and_then(Value::as_str);
        Ok(ChatResponse {
            text: content.ok_or_else(|| bad("no message content"))?.to_string(),
            truncated: v.pointer("/choices/0/finish_reason").and_then(Value::as_str) == Some("length"),
            prompt_tokens: count("/usage/prompt_tokens"),
            completion_tokens: count("/usage/completion_tokens"),
        })
    } else {
        let blocks = v
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("no content"))?;
        let text: String = blocks
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect();
        Ok(ChatResponse {
            text,
            truncated: v.get("stop_reason").and_then(Value::as_str) == Some("max_tokens"),
            prompt_tokens: count("/usage/input_tokens"),
            completion_tokens: count("/usage/output_tokens"),
        })
    }
}

/// Used from one thread at a time.
pub struct Client {
    settings: Settings,
    retry_delay: Duration,
    calibration: Cell<Calibration>,
    json_rejected: Cell<bool>,
    completion_param: Cell<bool>,
    /// the model's input window from the endpoint's listing, when known
    context_window: Cell<Option<u32>>,
}

impl Client {
    pub fn new(settings: Settings) -> Client {
        Self::with_retry_delay(settings, Duration::from_secs(5))
    }

    pub fn with_retry_delay(settings: Settings, retry_delay: Duration) -> Client {
        Client {
            settings,
            retry_delay,
            calibration: Cell::new(Calibration::default()),
            json_rejected: Cell::new(false),
            completion_param: Cell::new(false),
            context_window: Cell::new(None),
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn calibration(&self) -> Calibration {
        self.calibration.get()
    }

    /// Remembers the model's input window, e.g. Anthropic's `max_input_tokens` from the probe listing.
    pub fn set_context_window(&self, window: Option<u32>) {
        self.context_window.set(window);
    }

    /// The window from the listing; the `context_window` setting takes precedence over it.
    pub fn context_window(&self) -> Option<u32> {
        self.context_window.get()
    }

    /// One retry after the retry delay on a retryable error.
    pub fn chat(&self, req: &ChatRequest) -> Result<ChatResponse, LlmError> {
        match self.chat_once(req) {
            Err(e) if e.is_retryable() => {
                log::warn!("companion request failed, retrying once: {e}");
                std::thread::sleep(self.retry_delay);
                self.chat_once(req)
            }
            other => other,
        }
    }

    /// OpenAI-compatible servers may reject `response_format` or `max_tokens` (reasoning models
    /// want `max_completion_tokens`) with a 400 naming it: resend without or with the other
    /// name, and remember that for the session.
    fn chat_once(&self, req: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut json_mode = req.json && self.settings.protocol == Protocol::OpenAi && !self.json_rejected.get();
        let mut completion_param = self.completion_param.get();
        let mut result = self.post_chat(req, json_mode, completion_param);
        for _ in 0..2 {
            let Err(LlmError::Http { status: 400, body }) = &result else {
                break;
            };
            if self.settings.protocol != Protocol::OpenAi {
                break;
            }
            if json_mode && body.contains("response_format") {
                self.json_rejected.set(true);
                json_mode = false;
            } else if !completion_param && body.contains("max_tokens") {
                self.completion_param.set(true);
                completion_param = true;
            } else {
                break;
            }
            result = self.post_chat(req, json_mode, completion_param);
        }
        result
    }

    fn post_chat(&self, req: &ChatRequest, json_mode: bool, completion_param: bool) -> Result<ChatResponse, LlmError> {
        let role = |r: Role| if r == Role::User { "user" } else { "assistant" };
        let turns = req
            .turns
            .iter()
            .map(|&(r, text)| json!({"role": role(r), "content": text}));
        let limit = if completion_param {
            "max_completion_tokens"
        } else {
            "max_tokens"
        };
        let mut body = json!({"model": self.settings.model, limit: req.max_tokens});
        if self.settings.protocol == Protocol::OpenAi {
            // an empty system prompt is left out on both protocols
            let system = (!req.system.is_empty()).then(|| json!({"role": "system", "content": req.system}));
            body["messages"] = Value::Array(system.into_iter().chain(turns).collect());
            if json_mode {
                body["response_format"] = json!({"type": "json_object"});
            }
        } else {
            if !req.system.is_empty() {
                body["system"] = json!(req.system);
            }
            body["messages"] = Value::Array(turns.collect());
        }
        let text = send(
            &self.settings,
            &route(&self.settings, true),
            Some(&body.to_string()),
            req.timeout,
        )?;
        let response = parse_chat(self.settings.protocol, &text)?;
        let chars = req.system.chars().count() + req.turns.iter().map(|(_, t)| t.chars().count()).sum::<usize>();
        if let Some(tokens) = response.prompt_tokens {
            let mut calibration = self.calibration.get();
            calibration.observe(chars, tokens);
            self.calibration.set(calibration);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::fake_llm::*;

    fn settings(url: &str, protocol: Protocol) -> Settings {
        Settings {
            endpoint_url: url.to_string(),
            protocol,
            api_key: "k".into(),
            api_key_from_env: false,
            user_agent: "factum-test".into(),
            extra_headers: String::new(),
            model: "m".into(),
            context_window: None,
            global_guideline: String::new(),
            enabled: true,
        }
    }

    fn openai(fake: &FakeLlm) -> Settings {
        settings(&format!("{}/v1", fake.url), Protocol::OpenAi)
    }

    fn client(s: Settings) -> Client {
        Client::with_retry_delay(s, Duration::ZERO)
    }

    fn req<'a>(turns: &'a [(Role, &'a str)], json: bool) -> ChatRequest<'a> {
        ChatRequest {
            system: "sys",
            turns,
            max_tokens: 100,
            json,
            timeout: Duration::from_secs(5),
        }
    }

    fn has_header(r: &FakeRequest, name: &str, value: &str) -> bool {
        r.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case(name) && v == value)
    }

    #[test]
    fn list_models_openai_sorts_and_dedups() {
        let fake = FakeLlm::start();
        fake.push(200, &openai_models(&["b", "a", "b"]));
        let ids: Vec<_> = list_models(&openai(&fake)).unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(ids, ["a", "b"]);
        let r = &fake.requests()[0];
        assert_eq!(r.path, "/v1/models");
        assert!(has_header(r, "authorization", "Bearer k"));
    }

    #[test]
    fn list_models_anthropic_headers_and_window() {
        let fake = FakeLlm::start();
        fake.push(200, &anthropic_models(&[("claude-x", 200000)]));
        let models = list_models(&settings(&fake.url, Protocol::Anthropic)).unwrap();
        assert_eq!(models[0].max_input_tokens, Some(200000));
        let r = &fake.requests()[0];
        assert_eq!(r.path.split('?').next(), Some("/v1/models"));
        assert!(has_header(r, "x-api-key", "k"));
        assert!(has_header(r, "anthropic-version", "2023-06-01"));
    }

    #[test]
    fn user_agent_and_extra_headers_are_sent() {
        let fake = FakeLlm::start();
        let mut s = openai(&fake);
        s.extra_headers = r#"{"X-Lab":"1"}"#.into();
        list_models(&s).unwrap();
        let r = &fake.requests()[0];
        assert!(has_header(r, "user-agent", "factum-test"));
        assert!(has_header(r, "x-lab", "1"));
    }

    #[test]
    fn chat_openai_json_mode_falls_back_on_400() {
        let fake = FakeLlm::start();
        fake.push(400, r#"{"error":{"message":"unknown parameter: response_format"}}"#);
        fake.push(200, &openai_chat("{\"a\":1}", "stop", 10));
        fake.push(200, &openai_chat("{\"a\":2}", "stop", 10));
        let c = client(openai(&fake));
        let turns = [(Role::User, "hi")];
        assert_eq!(c.chat(&req(&turns, true)).unwrap().text, "{\"a\":1}");
        c.chat(&req(&turns, true)).unwrap();
        let reqs = fake.requests();
        assert!(reqs[0].body.contains("json_object"));
        assert!(!reqs[1].body.contains("json_object"));
        assert!(!reqs[2].body.contains("json_object"));
    }

    #[test]
    fn chat_openai_falls_back_to_max_completion_tokens() {
        let fake = FakeLlm::start();
        fake.push(400, r#"{"error":{"message":"Unsupported parameter: 'max_tokens'"}}"#);
        fake.push(200, &openai_chat("ok", "stop", 1));
        let turns = [(Role::User, "hi")];
        assert_eq!(client(openai(&fake)).chat(&req(&turns, false)).unwrap().text, "ok");
        let reqs = fake.requests();
        assert!(reqs[1].body.contains("max_completion_tokens"));
        assert!(!reqs[1].body.contains("\"max_tokens\""));
    }

    #[test]
    fn chat_reports_truncation() {
        let fake = FakeLlm::start();
        fake.push(200, &openai_chat("partial", "length", 5));
        let turns = [(Role::User, "hi")];
        assert!(client(openai(&fake)).chat(&req(&turns, false)).unwrap().truncated);
    }

    #[test]
    fn chat_anthropic_sends_system_and_turns_without_prefill() {
        let fake = FakeLlm::start();
        fake.push(200, &anthropic_message("done", "end_turn"));
        let turns = [(Role::User, "one"), (Role::Assistant, "two"), (Role::User, "three")];
        let r = client(settings(&fake.url, Protocol::Anthropic))
            .chat(&req(&turns, true))
            .unwrap();
        assert_eq!(r.text, "done");
        let sent = &fake.requests()[0];
        assert_eq!(sent.path, "/v1/messages");
        let body: serde_json::Value = serde_json::from_str(&sent.body).unwrap();
        assert_eq!(body["system"], "sys");
        let roles: Vec<_> = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["role"].as_str().unwrap())
            .collect();
        assert_eq!(roles, ["user", "assistant", "user"]);
    }

    #[test]
    fn retryable_error_is_retried_once() {
        let fake = FakeLlm::start();
        fake.push(503, "busy");
        fake.push(200, &openai_chat("ok", "stop", 1));
        let turns = [(Role::User, "hi")];
        assert_eq!(client(openai(&fake)).chat(&req(&turns, false)).unwrap().text, "ok");
    }

    #[test]
    fn non_retryable_error_is_not_retried() {
        let fake = FakeLlm::start();
        fake.push(401, "no");
        let turns = [(Role::User, "hi")];
        assert!(matches!(
            client(openai(&fake)).chat(&req(&turns, false)),
            Err(LlmError::Http { status: 401, .. })
        ));
        assert_eq!(fake.requests().len(), 1);
    }

    #[test]
    fn unreachable_host_is_unreachable() {
        let s = settings("http://127.0.0.1:1/v1", Protocol::OpenAi);
        assert!(matches!(list_models(&s), Err(LlmError::Unreachable(_))));
    }

    #[test]
    fn calibration_updates_from_usage() {
        let fake = FakeLlm::start();
        fake.push(200, &openai_chat("ok", "stop", 100));
        let c = client(openai(&fake));
        let prompt = "x".repeat(240 - 3);
        let turns = [(Role::User, prompt.as_str())];
        c.chat(&req(&turns, false)).unwrap(); // 237 + 3 chars of system = 240
        assert!((c.calibration().chars_per_token - 2.4).abs() < 0.01);
    }
}
