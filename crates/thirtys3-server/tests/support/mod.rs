//! A server on the local machine, over the memory backend, and ways to talk to it: with the client of this project and with raw requests.
#![allow(dead_code, unused_imports)]

mod req;
mod watched;

pub use req::{Req, req, request_head, signed_headers, tag, tags};
pub use watched::Watched;

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client as HttpClient;
use hyper_util::rt::{TokioExecutor, TokioIo};
use thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
use thirtys3_core::{Credentials, Request as SigRequest, Signer, Timestamp, sha256_hex};
use thirtys3_server::memory::MemoryBackend;
use thirtys3_server::{Backend, S3Service, ServerConfig};
use tokio::net::TcpListener;

pub const ACCESS_KEY: &str = "AKIATESTKEY";
pub const SECRET_KEY: &str = "test+secret/key";
pub const READ_ONLY_KEY: &str = "AKIAREADONLY";
pub const READ_ONLY_SECRET: &str = "read-only-secret";
pub const BUCKET: &str = "bucket";
pub const REGION: &str = "test-region";

pub struct Server<B = MemoryBackend> {
    pub addr: SocketAddr,
    pub service: S3Service<B>,
    task: tokio::task::JoinHandle<()>,
}

impl<B> Drop for Server<B> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn config() -> ServerConfig {
    ServerConfig { region: REGION.to_owned(), ..ServerConfig::default() }
}

pub fn backend() -> MemoryBackend {
    MemoryBackend::new().with_bucket(BUCKET).with_bucket("other").with_key(ACCESS_KEY, SECRET_KEY).with_read_only_key(READ_ONLY_KEY, READ_ONLY_SECRET)
}

pub async fn start() -> Server {
    start_with(backend(), config()).await
}

pub async fn start_with<B: Backend>(backend: B, config: ServerConfig) -> Server<B> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = S3Service::new(backend, config);
    let shared = service.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let service = shared.clone();
            tokio::spawn(async move {
                let hyper_service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let service = service.clone();
                    async move { Ok::<_, Infallible>(service.handle(request).await) }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), hyper_service).await;
            });
        }
    });
    Server { addr, service, task }
}

impl<B> Server<B> {
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }
}

/// A client of this project for the server.
pub fn client<B>(server: &Server<B>) -> thirtys3_client::Client {
    client_with(server, ACCESS_KEY, SECRET_KEY, BUCKET)
}

pub fn client_with<B>(server: &Server<B>, access: &str, secret: &str, bucket: &str) -> thirtys3_client::Client {
    let mut config = thirtys3_client::ClientConfig::new(bucket, thirtys3_client::Credentials::new(access, secret)).endpoint(server.endpoint()).region(REGION);
    config.allow_http = true;
    config.backoff_initial = std::time::Duration::from_millis(2);
    config.backoff_max = std::time::Duration::from_millis(20);
    config.part_size = 5 * 1024 * 1024;
    thirtys3_client::Client::new(config).unwrap()
}

/// What came back.
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// Sends a request as it is, without signing it.
pub async fn send_raw<B>(server: &Server<B>, method: Method, target: &str, headers: &[(&str, String)], body: Bytes) -> Answer {
    let client: HttpClient<_, Full<Bytes>> = HttpClient::builder(TokioExecutor::new()).build_http();
    let mut request = http::Request::builder().method(method).uri(format!("http://{}{}", server.addr, target));
    for (name, value) in headers {
        request = request.header(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
    }
    let response = client.request(request.body(Full::new(body)).unwrap()).await.unwrap();
    let (parts, incoming) = response.into_parts();
    Answer { status: parts.status, headers: parts.headers, body: incoming.collect().await.unwrap().to_bytes() }
}

pub fn signer() -> Signer {
    signer_for(ACCESS_KEY, SECRET_KEY)
}

pub fn signer_for(access: &str, secret: &str) -> Signer {
    Signer::new(Credentials::new(access, secret), REGION)
}

/// Signs and sends a request with the payload hash of its body.
pub async fn send<B>(server: &Server<B>, method: Method, target: &str, extra: &[(&str, &str)], body: &[u8]) -> Answer {
    send_signed(server, &signer(), Timestamp::now(), method, target, extra, body, &sha256_hex(body)).await
}

#[allow(clippy::too_many_arguments)]
pub async fn send_signed<B>(
    server: &Server<B>,
    signer: &Signer,
    time: Timestamp,
    method: Method,
    target: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    payload_hash: &str,
) -> Answer {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(&str, &str)> = vec![("host", ""), ("content-length", "")];
    headers.retain(|_| false);
    let host = server.host();
    let length = body.len().to_string();
    headers.push(("host", &host));
    headers.extend(extra.iter().copied());
    if !body.is_empty() || method == Method::PUT || method == Method::POST {
        headers.push(("content-length", &length));
    }
    let sig = SigRequest { method: method.as_str(), path, query, headers: &headers };
    let signed = signer.sign(&sig, payload_hash, time).unwrap();
    let mut all: Vec<(&str, String)> = headers.iter().filter(|(name, _)| *name != "host").map(|(name, value)| (*name, (*value).to_owned())).collect();
    all.extend(signed.headers.iter().map(|(name, value)| (name.as_str(), value.clone())));
    send_raw(server, method, target, &all, Bytes::copy_from_slice(body)).await
}

/// Signs a GET of the empty payload.
pub async fn get<B>(server: &Server<B>, target: &str) -> Answer {
    send_signed(server, &signer(), Timestamp::now(), Method::GET, target, &[], b"", EMPTY_PAYLOAD_SHA256).await
}

/// A presigned URL (path and query) for a request.
pub fn presign<B>(server: &Server<B>, method: &str, target: &str, expires: u64, time: Timestamp) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let host = server.host();
    let headers = [("host", host.as_str())];
    let request = SigRequest { method, path, query, headers: &headers };
    let signed_query = signer().presign(&request, time, expires).unwrap();
    format!("{path}?{signed_query}")
}
