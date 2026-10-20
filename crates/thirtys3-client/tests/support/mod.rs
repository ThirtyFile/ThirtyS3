//! An S3 service in memory for the tests of the client, which checks everything the client sends and can be made to fail in the ways a real one does.
//!
//! It is a fixture, not the server of this project: it knows only what the tests need. Every request is authenticated with the Signature Version 4
//! code of `thirtys3-core`, the payload hash is checked against the body, `Content-MD5` and `x-amz-checksum-*` against the data, and what the
//! client sends is kept in a log for the tests to look at.
#![allow(dead_code, clippy::result_large_err)] // a fixture: its functions answer with the S3 error itself

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_encode};
use thirtys3_core::etag::{ETagCondition, etag_from_md5, md5_digest, multipart_etag};
use thirtys3_core::model::*;
use thirtys3_core::s3_error::code;
use thirtys3_core::{PayloadHash, Request as SigRequest, S3Error, Timestamp, parse_request_auth, sha256_hex};
use tokio::net::TcpListener;

pub const ACCESS_KEY: &str = "AKIATESTKEY";
pub const SECRET_KEY: &str = "test+secret/key";
pub const BUCKET: &str = "bucket";
pub const REGION: &str = "test-region";

type Body = BoxBody<Bytes, io::Error>;

#[derive(Clone)]
pub struct Object {
    pub data: Bytes,
    pub etag: String,
    pub modified: Timestamp,
    pub content_type: String,
    pub metadata: BTreeMap<String, String>,
    pub checksums: Vec<(ChecksumAlgorithm, String)>,
    pub storage_class: Option<String>,
}

struct Upload {
    key: String,
    parts: BTreeMap<u32, (Bytes, String)>,
    checksum_algorithm: Option<ChecksumAlgorithm>,
    content_type: String,
    metadata: BTreeMap<String, String>,
}

/// What a request that matches a rule gets instead of the normal answer.
#[derive(Clone, Debug)]
pub enum Fault {
    /// An S3 error with this status and code.
    Status(u16, &'static str),
    /// The connection is closed without an answer.
    Drop,
    /// The answer to a `GET` that has a body stops after this many bytes of it, and the connection is closed.
    Truncate(usize),
    /// The answer comes after this long.
    Delay(Duration),
    /// The status 200 and an `<Error>` document with this code, as a `CompleteMultipartUpload` can have.
    OkWithError(&'static str),
    /// A `GET` with a `Range` header gets everything from its start to the end of the object, as a careless service might answer.
    OverrunRange,
    /// A `GET` with a `Range` header is answered with the whole object and the status 200, as a service without ranges does.
    IgnoreRange,
    /// The bytes of the body of a `GET` are sent one at a time with this wait between them, so the client sees a stalled download.
    Stall(Duration),
    /// The body of a `GET` is sent in pieces of this many bytes with this wait between them, which is a download that goes on steadily and slowly, and
    /// the connection breaks after this many bytes of it.
    Paced(usize, Duration, usize),
    /// The request is carried out as it should be, and then the connection is closed without an answer: the service did it and the client does not
    /// know.
    ApplyThenDrop,
}

#[derive(Clone, Default)]
pub struct Rule {
    pub method: Option<Method>,
    pub path_contains: Option<String>,
    pub query_contains: Option<String>,
    /// How many matching requests go by before it begins to apply.
    pub skip: usize,
    /// How many requests it applies to; 0 is none left.
    pub remaining: usize,
    pub fault: Option<Fault>,
}

#[derive(Clone, Debug)]
pub struct Logged {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
    pub body: Bytes,
    /// Whether the signature and the payload hash were right.
    pub authenticated: bool,
}

impl Logged {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(candidate, _)| candidate.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

#[derive(Default)]
pub struct State {
    pub objects: BTreeMap<String, Object>,
    uploads: BTreeMap<String, Upload>,
    pub log: Vec<Logged>,
    rules: Vec<Rule>,
    next_id: u64,
    /// Seconds the service's clock is ahead of the real one.
    pub clock_offset: i64,
    inflight: usize,
    pub max_inflight: usize,
}

/// Settings for a client of this server: path-style over plain HTTP, the right keys, short waits so the tests that fail things are quick.
pub fn config(server: &TestServer) -> thirtys3_client::ClientConfig {
    use std::time::Duration;
    let mut config =
        thirtys3_client::ClientConfig::new(BUCKET, thirtys3_client::Credentials::new(ACCESS_KEY, SECRET_KEY)).endpoint(server.endpoint()).region(REGION);
    config.allow_http = true;
    config.backoff_initial = Duration::from_millis(2);
    config.backoff_max = Duration::from_millis(20);
    config.read_timeout = Duration::from_secs(5);
    config.connect_timeout = Duration::from_secs(5);
    config.retry_timeout = Duration::from_secs(30);
    config
}

pub fn client(server: &TestServer) -> thirtys3_client::Client {
    thirtys3_client::Client::new(config(server)).unwrap()
}

pub struct TestServer {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let state = shared.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| handle(state.clone(), request));
                    let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                });
            }
        });
        Self { addr, state, task }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Makes the next `times` requests that match behave badly.
    pub fn fault(&self, method: Option<Method>, path_contains: Option<&str>, query_contains: Option<&str>, times: usize, fault: Fault) {
        self.fault_after(0, method, path_contains, query_contains, times, fault);
    }

    /// Makes `times` requests that match behave badly, after `skip` of them have gone by.
    pub fn fault_after(&self, skip: usize, method: Option<Method>, path_contains: Option<&str>, query_contains: Option<&str>, times: usize, fault: Fault) {
        self.state.lock().unwrap().rules.push(Rule {
            method,
            path_contains: path_contains.map(str::to_owned),
            query_contains: query_contains.map(str::to_owned),
            skip,
            remaining: times,
            fault: Some(fault),
        });
    }

    pub fn requests(&self) -> Vec<Logged> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn requests_matching(&self, method: Method, path_contains: &str) -> Vec<Logged> {
        self.requests().into_iter().filter(|logged| logged.method == method && logged.path.contains(path_contains)).collect()
    }

    pub fn clear_log(&self) {
        self.state.lock().unwrap().log.clear();
    }

    pub fn put_object(&self, key: &str, data: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .objects
            .insert(key.to_owned(), new_object(Bytes::copy_from_slice(data), "application/octet-stream".to_owned(), BTreeMap::new(), Vec::new(), None));
    }

    pub fn object(&self, key: &str) -> Option<Object> {
        self.state.lock().unwrap().objects.get(key).cloned()
    }

    pub fn keys(&self) -> Vec<String> {
        self.state.lock().unwrap().objects.keys().cloned().collect()
    }

    pub fn open_uploads(&self) -> usize {
        self.state.lock().unwrap().uploads.len()
    }

    pub fn max_inflight(&self) -> usize {
        self.state.lock().unwrap().max_inflight
    }

    pub fn set_clock_offset(&self, seconds: i64) {
        self.state.lock().unwrap().clock_offset = seconds;
    }
}

fn new_object(
    data: Bytes,
    content_type: String,
    metadata: BTreeMap<String, String>,
    checksums: Vec<(ChecksumAlgorithm, String)>,
    storage_class: Option<String>,
) -> Object {
    Object { etag: etag_from_md5(&md5_digest(&data)), data, modified: Timestamp::now(), content_type, metadata, checksums, storage_class }
}

fn full(data: impl Into<Bytes>) -> Body {
    Full::new(data.into()).map_err(|never| match never {}).boxed()
}

fn xml_response(status: u16, xml: String) -> Response<Body> {
    Response::builder().status(status).header("content-type", "application/xml").body(full(xml)).unwrap()
}

fn error_response(error: S3Error) -> Response<Body> {
    xml_response(error.status, error.to_xml())
}

fn s3_error(code: &str, message: &str) -> Response<Body> {
    error_response(S3Error::new(code, message))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn query_pairs(query: &str) -> Vec<(String, String)> {
    thirtys3_core::encoding::query_params(query)
        .into_iter()
        .map(|(name, value)| (String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned()))
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(candidate, _)| candidate == name).map(|(_, value)| value.as_str())
}

async fn handle(state: Arc<Mutex<State>>, request: hyper::Request<Incoming>) -> Result<Response<Body>, io::Error> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.map_err(io::Error::other)?.to_bytes();
    let path = parts.uri.path().to_owned();
    let query = parts.uri.query().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> =
        parts.headers.iter().map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned())).collect();

    // A rule that matches is used up by this request.
    let fault = {
        let mut state = state.lock().unwrap();
        let mut found = None;
        for rule in &mut state.rules {
            let matches = rule.remaining > 0
                && rule.method.as_ref().is_none_or(|method| *method == parts.method)
                && rule.path_contains.as_deref().is_none_or(|text| path.contains(text))
                && rule.query_contains.as_deref().is_none_or(|text| query.contains(text));
            if matches && rule.skip > 0 {
                rule.skip -= 1;
            } else if matches {
                rule.remaining -= 1;
                found = rule.fault.clone();
                break;
            }
        }
        found
    };
    let offset = {
        let mut state = state.lock().unwrap();
        state.inflight += 1;
        state.max_inflight = state.max_inflight.max(state.inflight);
        state.clock_offset
    };
    let _guard = Inflight(state.clone());
    let now = Timestamp(Timestamp::now().0 + offset);

    let authenticated = authenticate(&parts.method, &path, &query, &headers, &body, now);
    state.lock().unwrap().log.push(Logged {
        method: parts.method.clone(),
        path: path.clone(),
        query: query.clone(),
        headers,
        body_len: body.len(),
        body: body.clone(),
        authenticated: authenticated.is_ok(),
    });

    match &fault {
        Some(Fault::Drop) => return Err(io::Error::other("dropped on purpose")),
        Some(Fault::Delay(wait)) => tokio::time::sleep(*wait).await,
        Some(Fault::Status(status, code)) => {
            let mut error = S3Error::new(*code, "failed on purpose");
            error.status = *status;
            return Ok(error_response(error));
        }
        _ => {}
    }
    if let Err(error) = authenticated {
        let mut response = error_response(error);
        response.headers_mut().insert("date", HeaderValue::from_str(&now.http_date()).unwrap());
        return Ok(response);
    }
    let mut response = route(&state, &parts.method, &path, &query, &parts.headers, body, &fault);
    if matches!(fault, Some(Fault::ApplyThenDrop)) {
        return Err(io::Error::other("dropped after the request was carried out"));
    }
    response.headers_mut().insert("date", HeaderValue::from_str(&now.http_date()).unwrap());
    Ok(response)
}

/// Counts a request as finished when the answer to it is done, wherever the function returns.
struct Inflight(Arc<Mutex<State>>);

impl Drop for Inflight {
    fn drop(&mut self) {
        self.0.lock().unwrap().inflight -= 1;
    }
}

fn authenticate(method: &Method, path: &str, query: &str, headers: &[(String, String)], body: &Bytes, now: Timestamp) -> Result<(), S3Error> {
    let borrowed: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let request = SigRequest { method: method.as_str(), path, query, headers: &borrowed };
    let auth =
        parse_request_auth(&request).map_err(|e| S3Error::from(&e))?.ok_or_else(|| S3Error::new(code::ACCESS_DENIED, "Anonymous requests are not accepted"))?;
    if auth.access_key_id != ACCESS_KEY {
        return Err(S3Error::new(code::INVALID_ACCESS_KEY_ID, "The AWS access key ID you provided does not exist in our records."));
    }
    if auth.scope.region != REGION {
        return Err(S3Error::new(code::AUTHORIZATION_HEADER_MALFORMED, "the region is wrong").with_detail("Region", REGION));
    }
    let verified = auth.verify(&request, SECRET_KEY, now).map_err(|e| S3Error::from(&e))?;
    if let PayloadHash::Sha256(expected) = &verified.payload_hash
        && *expected != sha256_hex(body)
    {
        return Err(S3Error::new(code::X_AMZ_CONTENT_SHA256_MISMATCH, "The provided 'x-amz-content-sha256' header does not match what was computed."));
    }
    Ok(())
}

/// The key of the object a request is about, if it is about one: the first segment of the path is the bucket (path-style).
fn split_path(path: &str, host: Option<&str>) -> (String, Option<String>) {
    let decoded = String::from_utf8_lossy(&thirtys3_core::encoding::percent_decode(path, false)).into_owned();
    let rest = decoded.strip_prefix('/').unwrap_or(&decoded);
    // Virtual-hosted style: the bucket is the first label of the host name and the whole path is the key.
    if let Some(label) = host.and_then(|host| host.split(':').next()).and_then(|name| name.strip_prefix(&format!("{BUCKET}."))).filter(|rest| !rest.is_empty()) {
        let _ = label;
        return (BUCKET.to_owned(), (!rest.is_empty()).then(|| rest.to_owned()));
    }
    match rest.split_once('/') {
        Some((bucket, key)) if !key.is_empty() => (bucket.to_owned(), Some(key.to_owned())),
        Some((bucket, _)) => (bucket.to_owned(), None),
        None => (rest.to_owned(), None),
    }
}

fn route(state: &Arc<Mutex<State>>, method: &Method, path: &str, query: &str, headers: &HeaderMap, body: Bytes, fault: &Option<Fault>) -> Response<Body> {
    let (bucket, key) = split_path(path, header(headers, "host"));
    if bucket != BUCKET {
        return error_response(S3Error::new(code::NO_SUCH_BUCKET, "The specified bucket does not exist").with_detail("BucketName", bucket));
    }
    let pairs = query_pairs(query);
    let mut state = state.lock().unwrap();
    match (method.as_str(), key.as_deref()) {
        ("GET", None) if param(&pairs, "list-type") == Some("2") => list(&state, &pairs),
        ("GET", None) => s3_error(code::NOT_IMPLEMENTED, "only ListObjectsV2 here"),
        ("POST", None) if pairs.iter().any(|(name, _)| name == "delete") => delete_objects(&mut state, headers, &body, fault),
        ("GET" | "HEAD", Some(key)) => get(&state, method, key, headers, fault),
        ("PUT", Some(key)) if param(&pairs, "partNumber").is_some() => put_part(&mut state, key, &pairs, headers, body),
        ("PUT", Some(key)) => put(&mut state, key, headers, body),
        ("DELETE", Some(_)) if param(&pairs, "uploadId").is_some() => match state.uploads.remove(param(&pairs, "uploadId").unwrap()) {
            Some(_) => Response::builder().status(204).body(full(Bytes::new())).unwrap(),
            None => error_response(S3Error::new(code::NO_SUCH_UPLOAD, "The specified upload does not exist.")),
        },
        ("DELETE", Some(key)) => {
            state.objects.remove(key);
            Response::builder().status(204).body(full(Bytes::new())).unwrap()
        }
        ("POST", Some(key)) if pairs.iter().any(|(name, _)| name == "uploads") => create_upload(&mut state, key, headers),
        ("POST", Some(key)) if param(&pairs, "uploadId").is_some() => complete_upload(&mut state, key, param(&pairs, "uploadId").unwrap(), &body, fault),
        _ => s3_error(code::METHOD_NOT_ALLOWED, "not here"),
    }
}

fn checksum_headers(headers: &HeaderMap) -> Vec<(ChecksumAlgorithm, String)> {
    ChecksumAlgorithm::ALL.into_iter().filter_map(|algorithm| header(headers, algorithm.header_name()).map(|value| (algorithm, value.to_owned()))).collect()
}

fn metadata_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| name.as_str().strip_prefix("x-amz-meta-").map(|name| (name.to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned())))
        .collect()
}

fn put(state: &mut State, key: &str, headers: &HeaderMap, body: Bytes) -> Response<Body> {
    if key.len() > 1024 {
        return s3_error(code::KEY_TOO_LONG, "Your key is too long");
    }
    let existing = state.objects.get(key);
    if header(headers, "if-none-match") == Some("*") && existing.is_some() {
        return s3_error(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold").with_status(412);
    }
    if let Some(condition) = header(headers, "if-match").and_then(ETagCondition::parse)
        && !existing.is_some_and(|object| condition.matches(&object.etag, true))
    {
        return s3_error(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold").with_status(412);
    }
    let checksums = checksum_headers(headers);
    for (algorithm, claimed) in &checksums {
        if algorithm.checksum_base64(&body) != *claimed {
            return error_response(S3Error::new(code::BAD_DIGEST, "The checksum you specified did not match what we received."));
        }
    }
    let content_type = header(headers, "content-type").unwrap_or("binary/octet-stream").to_owned();
    let object = new_object(body, content_type, metadata_headers(headers), checksums.clone(), header(headers, "x-amz-storage-class").map(str::to_owned));
    let mut response = Response::builder().status(200).header("etag", object.etag.clone());
    for (algorithm, value) in &checksums {
        response = response.header(algorithm.header_name(), value.clone());
    }
    state.objects.insert(key.to_owned(), object);
    response.body(full(Bytes::new())).unwrap()
}

trait WithStatus {
    fn with_status(self, status: u16) -> Self;
}

impl WithStatus for Response<Body> {
    fn with_status(mut self, status: u16) -> Self {
        *self.status_mut() = StatusCode::from_u16(status).unwrap();
        self
    }
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let spec = value.strip_prefix("bytes=")?;
    let (first, last) = spec.split_once('-')?;
    let (start, end) = match (first, last) {
        ("", suffix) => {
            let suffix: u64 = suffix.parse().ok()?;
            (size.saturating_sub(suffix), size.checked_sub(1)?)
        }
        (first, "") => (first.parse().ok()?, size.checked_sub(1)?),
        (first, last) => (first.parse().ok()?, last.parse::<u64>().ok()?.min(size.saturating_sub(1))),
    };
    (start <= end && start < size).then_some((start, end))
}

fn get(state: &State, method: &Method, key: &str, headers: &HeaderMap, fault: &Option<Fault>) -> Response<Body> {
    let Some(object) = state.objects.get(key) else {
        return if *method == Method::HEAD {
            Response::builder().status(404).body(full(Bytes::new())).unwrap()
        } else {
            error_response(S3Error::new(code::NO_SUCH_KEY, "The specified key does not exist.").with_detail("Key", key))
        };
    };
    if let Some(condition) = header(headers, "if-match").and_then(ETagCondition::parse)
        && !condition.matches(&object.etag, true)
    {
        return s3_error(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold").with_status(412);
    }
    if let Some(condition) = header(headers, "if-none-match").and_then(ETagCondition::parse)
        && condition.matches(&object.etag, false)
    {
        return Response::builder().status(304).header("etag", object.etag.clone()).body(full(Bytes::new())).unwrap();
    }
    let size = object.data.len() as u64;
    let range = header(headers, "range").filter(|_| !matches!(fault, Some(Fault::IgnoreRange)));
    let (status, start, end) = match range {
        Some(range) => match parse_range(range, size) {
            Some((start, _)) if matches!(fault, Some(Fault::OverrunRange)) => (206, start, size),
            Some((start, end)) => (206, start, end + 1),
            None => return error_response(S3Error::new(code::INVALID_RANGE, "The requested range is not satisfiable")).with_status(416),
        },
        None => (200, 0, size),
    };
    let mut response = Response::builder()
        .status(status)
        .header("etag", object.etag.clone())
        .header("last-modified", object.modified.http_date())
        .header("content-type", object.content_type.clone())
        .header("content-length", end - start)
        .header("accept-ranges", "bytes");
    if status == 206 {
        response = response.header("content-range", format!("bytes {start}-{}/{size}", end - 1));
    }
    for (name, value) in &object.metadata {
        response = response.header(format!("x-amz-meta-{name}"), value.clone());
    }
    for (algorithm, value) in &object.checksums {
        response = response.header(algorithm.header_name(), value.clone());
    }
    if let Some(class) = &object.storage_class {
        response = response.header("x-amz-storage-class", class.clone());
    }
    let data = object.data.slice(start as usize..end as usize);
    if *method == Method::HEAD {
        return response.body(full(Bytes::new())).unwrap();
    }
    let body: Body = match fault {
        Some(Fault::Truncate(after)) if *after < data.len() => {
            // The head and the first bytes are sent, and after a moment the connection is broken: without the wait the error would come before
            // anything was written and the client would see a failure of the request, not of the download.
            let first = data.slice(..*after);
            let frames = stream::iter(if first.is_empty() { None } else { Some(Ok(Frame::data(first))) }).chain(stream::once(async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Err(io::Error::other("cut on purpose"))
            }));
            BodyExt::boxed(StreamBody::new(frames))
        }
        Some(Fault::Paced(piece, wait, after)) if *after < data.len() => {
            let (piece, wait, after) = (*piece, *wait, *after);
            let pieces: Vec<Bytes> = (0..after).step_by(piece).map(|at| data.slice(at..(at + piece).min(after))).collect();
            let frames = stream::iter(pieces).then(move |piece| async move {
                tokio::time::sleep(wait).await;
                Ok(Frame::data(piece))
            });
            let broken = stream::once(async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Err(io::Error::other("cut on purpose"))
            });
            BodyExt::boxed(StreamBody::new(frames.chain(broken)))
        }
        Some(Fault::Stall(_)) if !data.is_empty() => {
            let first = data.slice(..1);
            let frames = stream::once(async move { Ok(Frame::data(first)) }).chain(stream::once(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(Frame::data(Bytes::new()))
            }));
            BodyExt::boxed(StreamBody::new(frames))
        }
        _ => full(data),
    };
    response.body(body).unwrap()
}

use futures_util::StreamExt;

fn list(state: &State, pairs: &[(String, String)]) -> Response<Body> {
    let prefix = param(pairs, "prefix").unwrap_or_default();
    let delimiter = param(pairs, "delimiter").filter(|d| !d.is_empty());
    let max_keys: usize = param(pairs, "max-keys").and_then(|n| n.parse().ok()).unwrap_or(1000);
    let start_after =
        param(pairs, "continuation-token").map(|token| token.strip_prefix("after:").unwrap_or(token)).or(param(pairs, "start-after")).unwrap_or_default().to_owned();
    let url = param(pairs, "encoding-type") == Some("url");

    let mut contents = Vec::new();
    let mut prefixes: Vec<String> = Vec::new();
    let mut last = String::new();
    let mut truncated = false;
    for (key, object) in &state.objects {
        if !key.starts_with(prefix) || key.as_str() <= start_after.as_str() {
            continue;
        }
        let rolled = delimiter.and_then(|d| key[prefix.len()..].find(d).map(|at| key[..prefix.len() + at + d.len()].to_owned()));
        if let Some(group) = &rolled
            && (prefixes.last() == Some(group) || group.as_str() <= start_after.as_str())
        {
            continue;
        }
        if contents.len() + prefixes.len() >= max_keys {
            truncated = true;
            break;
        }
        match rolled {
            Some(group) => {
                last = group.clone();
                prefixes.push(group);
            }
            None => {
                last = key.clone();
                let mut entry = ObjectEntry::new(key.clone(), object.modified, object.etag.clone(), object.data.len() as u64);
                entry.storage_class = object.storage_class.clone().unwrap_or_else(|| "STANDARD".to_owned());
                contents.push(entry);
            }
        }
    }
    let result = ListObjectsV2Result {
        name: BUCKET.to_owned(),
        prefix: prefix.to_owned(),
        delimiter: delimiter.map(str::to_owned),
        max_keys: max_keys as u32,
        key_count: (contents.len() + prefixes.len()) as u32,
        is_truncated: truncated,
        continuation_token: param(pairs, "continuation-token").map(str::to_owned),
        next_continuation_token: truncated.then(|| format!("after:{last}")),
        start_after: param(pairs, "start-after").map(str::to_owned),
        contents,
        common_prefixes: prefixes,
        url_encoded: url,
    };
    xml_response(200, result.to_xml())
}

fn delete_objects(state: &mut State, headers: &HeaderMap, body: &Bytes, fault: &Option<Fault>) -> Response<Body> {
    if let Some(Fault::OkWithError(code)) = fault {
        let mut error = S3Error::new(*code, "failed on purpose, after the 200");
        error.status = 200;
        return xml_response(200, error.to_xml());
    }
    match header(headers, "content-md5") {
        Some(md5) if md5 == base64_encode(&md5_digest(body)) => {}
        _ => return error_response(S3Error::new(code::BAD_DIGEST, "The Content-MD5 you specified did not match what we received.")),
    }
    let request = match DeleteRequest::from_xml(body) {
        Ok(request) => request,
        Err(error) => return error_response((&error).into()),
    };
    if request.objects.len() > 1000 {
        return s3_error(code::MALFORMED_XML, "too many keys");
    }
    let mut result = DeleteResult::default();
    for object in request.objects {
        if object.key.contains("undeletable") {
            result.errors.push(DeleteFailure { key: object.key, version_id: None, code: "AccessDenied".into(), message: "Access Denied".into() });
        } else {
            state.objects.remove(&object.key);
            if !request.quiet {
                result.deleted.push(Deleted::new(object.key));
            }
        }
    }
    xml_response(200, result.to_xml())
}

fn create_upload(state: &mut State, key: &str, headers: &HeaderMap) -> Response<Body> {
    state.next_id += 1;
    let id = format!("upload-{}", state.next_id);
    state.uploads.insert(
        id.clone(),
        Upload {
            key: key.to_owned(),
            parts: BTreeMap::new(),
            checksum_algorithm: header(headers, "x-amz-checksum-algorithm").and_then(ChecksumAlgorithm::from_name),
            content_type: header(headers, "content-type").unwrap_or("binary/octet-stream").to_owned(),
            metadata: metadata_headers(headers),
        },
    );
    xml_response(200, InitiateMultipartUploadResult { bucket: BUCKET.to_owned(), key: key.to_owned(), upload_id: id }.to_xml())
}

fn put_part(state: &mut State, key: &str, pairs: &[(String, String)], headers: &HeaderMap, body: Bytes) -> Response<Body> {
    let Some(upload) = param(pairs, "uploadId").and_then(|id| state.uploads.get_mut(id)) else {
        return error_response(S3Error::new(code::NO_SUCH_UPLOAD, "The specified upload does not exist."));
    };
    let number: u32 = param(pairs, "partNumber").and_then(|n| n.parse().ok()).unwrap_or(0);
    if upload.key != key || !(1..=10_000).contains(&number) {
        return s3_error(code::INVALID_ARGUMENT, "bad part number or key");
    }
    for (algorithm, claimed) in checksum_headers(headers) {
        if algorithm.checksum_base64(&body) != claimed {
            return error_response(S3Error::new(code::BAD_DIGEST, "The checksum you specified did not match what we received."));
        }
    }
    if let Some(algorithm) = upload.checksum_algorithm
        && header(headers, algorithm.header_name()).is_none()
    {
        return s3_error(code::INVALID_REQUEST, "Checksum Type mismatch occurred, expected checksum Type was not provided");
    }
    let etag = etag_from_md5(&md5_digest(&body));
    upload.parts.insert(number, (body, etag.clone()));
    Response::builder().status(200).header("etag", etag).body(full(Bytes::new())).unwrap()
}

fn complete_upload(state: &mut State, key: &str, id: &str, body: &Bytes, fault: &Option<Fault>) -> Response<Body> {
    if let Some(Fault::OkWithError(code)) = fault {
        let mut error = S3Error::new(*code, "failed on purpose, after the 200");
        error.status = 200;
        return xml_response(200, error.to_xml());
    }
    let Some(upload) = state.uploads.get(id) else {
        return error_response(S3Error::new(code::NO_SUCH_UPLOAD, "The specified upload does not exist."));
    };
    let request = match CompleteMultipartUploadRequest::from_xml(body) {
        Ok(request) => request,
        Err(error) => return error_response((&error).into()),
    };
    if request.parts.is_empty() || upload.key != key {
        return s3_error(code::MALFORMED_XML, "no parts");
    }
    let mut data = Vec::new();
    let mut md5s = Vec::new();
    let count = request.parts.len();
    for (index, part) in request.parts.iter().enumerate() {
        if index > 0 && part.part_number <= request.parts[index - 1].part_number {
            return s3_error(code::INVALID_PART_ORDER, "The list of parts was not in ascending order.");
        }
        let Some((bytes, etag)) = upload.parts.get(&part.part_number) else {
            return s3_error(code::INVALID_PART, "One or more of the specified parts could not be found.");
        };
        if part.etag.as_deref().map(thirtys3_core::etag::unquote) != Some(thirtys3_core::etag::unquote(etag)) {
            return s3_error(code::INVALID_PART, "One or more of the specified parts could not be found.");
        }
        if index + 1 < count && bytes.len() < 5 * 1024 * 1024 {
            return s3_error(code::ENTITY_TOO_SMALL, "Your proposed upload is smaller than the minimum allowed size");
        }
        md5s.push(md5_digest(bytes));
        data.extend_from_slice(bytes);
    }
    let upload = state.uploads.remove(id).unwrap();
    let mut object = new_object(Bytes::from(data), upload.content_type, upload.metadata, Vec::new(), None);
    object.etag = multipart_etag(&md5s);
    let etag = object.etag.clone();
    state.objects.insert(key.to_owned(), object);
    xml_response(
        200,
        CompleteMultipartUploadResult {
            location: format!("http://test/{BUCKET}/{key}"),
            bucket: BUCKET.to_owned(),
            key: key.to_owned(),
            etag,
            checksums: Checksums::default(),
            checksum_type: None,
        }
        .to_xml(),
    )
}
