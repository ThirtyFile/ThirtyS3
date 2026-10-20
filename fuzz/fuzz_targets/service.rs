#![no_main]

use std::sync::OnceLock;

use bytes::Bytes;
use http_body_util::Full;
use libfuzzer_sys::fuzz_target;
use thirtys3_core::sigv4::STREAMING_UNSIGNED_PAYLOAD_TRAILER;
use thirtys3_core::{Credentials, Request, Signer, Timestamp, sha256_hex};
use thirtys3_server::memory::MemoryBackend;
use thirtys3_server::{S3Service, ServerConfig};

fn service() -> &'static (S3Service<MemoryBackend>, tokio::runtime::Runtime) {
    static SERVICE: OnceLock<(S3Service<MemoryBackend>, tokio::runtime::Runtime)> = OnceLock::new();
    SERVICE.get_or_init(|| {
        let backend = MemoryBackend::new().with_bucket("bucket").with_key("AKIAFUZZ", "secret");
        backend.insert("bucket", "k", b"hello");
        let config = ServerConfig { region: "us-east-1".to_owned(), max_object_size: 1 << 20, ..ServerConfig::default() };
        (S3Service::new(backend, config), tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap())
    })
}

// A request is written as "METHOD target", the lines of its headers, an empty line and its body. The first byte chooses how it is signed: not at all, or
// as a client would, with the body signed as it is or sent in the framing of `aws-chunked`. Signed, it gets deep into the operations.
fuzz_target!(|data: &[u8]| {
    let [mode, rest @ ..] = data else { return };
    let text = String::from_utf8_lossy(rest).into_owned();
    let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("GET /").split(' ');
    let method = first.next().unwrap_or("GET").to_owned();
    let target = first.next().unwrap_or("/").to_owned();
    let mut headers: Vec<(String, String)> = vec![("host".to_owned(), "localhost".to_owned())];
    headers.extend(lines.filter_map(|line| line.split_once(':')).map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned())));
    headers.retain(|(name, _)| !matches!(name.as_str(), "authorization" | "content-length" | "x-amz-date" | "x-amz-content-sha256") && !name.is_empty());
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let mut body = body.as_bytes().to_vec();

    let payload = match mode % 3 {
        1 => sha256_hex(&body),
        2 => {
            headers.push(("content-encoding".to_owned(), "aws-chunked".to_owned()));
            headers.push(("x-amz-decoded-content-length".to_owned(), body.len().to_string()));
            let mut wire = format!("{:x}\r\n", body.len()).into_bytes();
            wire.extend_from_slice(&body);
            wire.extend_from_slice(b"\r\n0\r\n\r\n");
            body = wire;
            STREAMING_UNSIGNED_PAYLOAD_TRAILER.to_owned()
        }
        _ => "UNSIGNED-PAYLOAD".to_owned(),
    };
    headers.push(("content-length".to_owned(), body.len().to_string()));
    if mode & 0x80 == 0 {
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let request = Request { method: &method, path, query, headers: &borrowed };
        let signer = Signer::new(Credentials::new("AKIAFUZZ", "secret"), "us-east-1");
        if let Ok(signed) = signer.sign(&request, &payload, Timestamp::now()) {
            headers.extend(signed.headers);
        }
    }

    let mut builder = http::Request::builder().method(method.as_str()).uri(target.as_str());
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let Ok(request) = builder.body(Full::new(Bytes::from(body))) else { return };
    let (service, runtime) = service();
    runtime.block_on(async {
        let response = service.handle(request).await;
        assert_ne!(response.status().as_u16(), 500, "an internal error");
    });
});
