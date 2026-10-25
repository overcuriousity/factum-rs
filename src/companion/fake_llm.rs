//! A tiny in-process HTTP endpoint for tests: queued canned responses, recorded requests.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::json;

/// One request as the fake endpoint saw it.
#[derive(Clone, Debug)]
pub struct FakeRequest {
    pub method: String,
    /// including any query string
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<(u16, String)>>,
    requests: Mutex<Vec<FakeRequest>>,
    stop: AtomicBool,
}

/// Serves on `127.0.0.1:0` until dropped.
pub struct FakeLlm {
    /// `http://127.0.0.1:<port>`
    pub url: String,
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl FakeLlm {
    pub fn start() -> FakeLlm {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake endpoint");
        let addr = listener.local_addr().expect("local address");
        let shared = Arc::new(Shared::default());
        let thread = {
            let shared = shared.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if shared.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        let _ = serve(stream, &shared);
                    }
                }
            })
        };
        FakeLlm {
            url: format!("http://{addr}"),
            addr,
            shared,
            thread: Some(thread),
        }
    }

    /// Queues the answer to the next request (FIFO). With an empty queue a model listing
    /// answers `GET …/models` and everything else gets a 500.
    pub fn push(&self, status: u16, body: &str) {
        self.shared.queue.lock().unwrap().push_back((status, body.to_string()));
    }

    pub fn requests(&self) -> Vec<FakeRequest> {
        self.shared.requests.lock().unwrap().clone()
    }
}

impl Drop for FakeLlm {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // unblocks accept
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(mut stream: TcpStream, shared: &Shared) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let Some((k, v)) = line.trim_end().split_once(':') else {
            break;
        };
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let listing = method == "GET" && path.split('?').next().is_some_and(|p| p.ends_with("/models"));
    shared.requests.lock().unwrap().push(FakeRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let (status, body) = shared.queue.lock().unwrap().pop_front().unwrap_or_else(|| {
        if listing {
            (200, openai_models(&["model-a", "model-b"]))
        } else {
            (500, "{}".to_string())
        }
    });
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

/// An OpenAI `chat/completions` answer.
pub fn openai_chat(text: &str, finish_reason: &str, prompt_tokens: u32) -> String {
    json!({
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 3}
    })
    .to_string()
}

/// An Anthropic `messages` answer.
pub fn anthropic_message(text: &str, stop_reason: &str) -> String {
    json!({
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "usage": {"input_tokens": 10, "output_tokens": 3}
    })
    .to_string()
}

pub fn openai_models(ids: &[&str]) -> String {
    json!({"data": ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>()}).to_string()
}

pub fn anthropic_models(ids_and_windows: &[(&str, u32)]) -> String {
    json!({"data": ids_and_windows.iter().map(|(id, w)| json!({"id": id, "max_input_tokens": w})).collect::<Vec<_>>()})
        .to_string()
}
