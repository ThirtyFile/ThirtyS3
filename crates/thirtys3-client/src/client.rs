//! The client: signing, sending, repeating what failed, and turning failures into [`Error`]s.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::Method;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use thirtys3_core::Request as SignedRequestParts;
use thirtys3_core::encoding::uri_encode;
use thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
use thirtys3_core::{S3Error, Signer, Timestamp, sha256_hex};

use crate::config::{ClientConfig, Target};
use crate::error::Error;
use crate::meta::error_for_status;
use crate::retry::Backoff;
use crate::transport::{Transport, body_error};

/// The longest error body that is read.
const MAX_ERROR_BODY: usize = 256 * 1024;

/// A request before it is signed: everything but the signature, so that it can be signed again for each try.
#[derive(Debug, Clone)]
pub(crate) struct Spec {
    pub(crate) method: Method,
    /// The path on the wire, encoded.
    pub(crate) path: String,
    /// The query on the wire, encoded.
    pub(crate) query: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Bytes,
    /// The value of `x-amz-content-sha256`.
    pub(crate) payload_hash: String,
}

impl Spec {
    pub(crate) fn new(method: Method, path: String) -> Self {
        Self { method, path, query: String::new(), headers: Vec::new(), body: Bytes::new(), payload_hash: EMPTY_PAYLOAD_SHA256.to_owned() }
    }

    /// Sets the query from parameters; a parameter with an empty value is written as its name alone, as the SDKs write `?uploads`.
    pub(crate) fn query(mut self, parameters: &[(&str, &str)]) -> Self {
        self.query = parameters
            .iter()
            .map(|(name, value)| {
                if value.is_empty() {
                    uri_encode(name.as_bytes(), true)
                } else {
                    format!("{}={}", uri_encode(name.as_bytes(), true), uri_encode(value.as_bytes(), true))
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        self
    }

    pub(crate) fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    pub(crate) fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers.extend(headers);
        self
    }

    pub(crate) fn body(mut self, body: Bytes) -> Self {
        if !body.is_empty() {
            self.payload_hash = sha256_hex(&body);
        }
        self.body = body;
        self
    }
}

/// An error and, when the response had a `Date` header, the time the service says it is.
type Failure = (Error, Option<Timestamp>);

pub(crate) struct Inner {
    pub(crate) target: Target,
    pub(crate) signer: Signer,
    pub(crate) transport: Transport,
    pub(crate) user_agent: String,
    pub(crate) bucket: String,
    pub(crate) max_retries: u32,
    pub(crate) retry_timeout: Duration,
    pub(crate) backoff: Backoff,
    pub(crate) part_size: usize,
    pub(crate) multipart_concurrency: usize,
    pub(crate) bulk_delete: bool,
    /// Seconds to add to the clock of this machine to get the time of the service, learnt from `RequestTimeTooSkewed`.
    clock_offset: AtomicI64,
}

/// A client for one bucket. It is cheap to clone: the clones share the connections.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.inner.target.authority)
            .field("base_path", &self.inner.target.base_path)
            .field("bucket", &self.inner.bucket)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the bucket in the settings. Nothing is sent yet.
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        let target = Target::resolve(&config)?;
        if config.part_size < 5 * 1024 * 1024 || config.part_size as u64 > 5 * 1024 * 1024 * 1024 {
            return Err(Error::Config("part_size has to be between 5 MiB and 5 GiB".to_owned()));
        }
        if config.multipart_concurrency == 0 {
            return Err(Error::Config("multipart_concurrency has to be at least 1".to_owned()));
        }
        let region = if config.region.trim().is_empty() { "us-east-1" } else { config.region.trim() };
        let user_agent = match &config.user_agent {
            Some(extra) => format!("thirtys3-client/{} {extra}", env!("CARGO_PKG_VERSION")),
            None => format!("thirtys3-client/{}", env!("CARGO_PKG_VERSION")),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                transport: Transport::new(&config)?,
                signer: Signer::new(config.credentials.clone(), region),
                target,
                user_agent,
                bucket: config.bucket.trim().to_owned(),
                max_retries: config.max_retries,
                retry_timeout: config.retry_timeout,
                backoff: Backoff { initial: config.backoff_initial, max: config.backoff_max },
                part_size: config.part_size,
                multipart_concurrency: config.multipart_concurrency,
                bulk_delete: config.bulk_delete,
                clock_offset: AtomicI64::new(0),
            }),
        })
    }

    /// The name of the bucket.
    pub fn bucket(&self) -> &str {
        &self.inner.bucket
    }

    /// The path of an object, checking the key.
    pub(crate) fn object_path(&self, key: &str) -> Result<String, Error> {
        if key.is_empty() {
            return Err(Error::InvalidInput("a key cannot be empty".to_owned()));
        }
        if key.len() > 1024 {
            return Err(Error::InvalidInput(format!("a key is at most 1024 bytes, this one is {}", key.len())));
        }
        Ok(self.inner.target.object_path(key))
    }

    /// The path of the bucket.
    pub(crate) fn bucket_path(&self) -> String {
        self.inner.target.bucket_path()
    }

    fn now(&self) -> Timestamp {
        Timestamp(Timestamp::now().0 + self.inner.clock_offset.load(Ordering::Relaxed))
    }

    /// The request as it is sent: the headers of the caller, the host, the user agent and the signature.
    fn build(&self, spec: &Spec, time: Timestamp) -> Result<http::Request<Full<Bytes>>, Error> {
        let target = &self.inner.target;
        let mut headers: Vec<(String, String)> = vec![("host".to_owned(), target.authority.clone()), ("user-agent".to_owned(), self.inner.user_agent.clone())];
        headers.extend(spec.headers.iter().cloned());
        // A request that stores something has a Content-Length even when the body is empty, as S3 requires and hyper does not add.
        if spec.body.is_empty() && (spec.method == Method::PUT || spec.method == Method::POST) {
            headers.push(("content-length".to_owned(), "0".to_owned()));
        }
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let parts = SignedRequestParts { method: spec.method.as_str(), path: &spec.path, query: &spec.query, headers: &borrowed };
        let signed = self.inner.signer.sign(&parts, &spec.payload_hash, time).map_err(|error| Error::InvalidInput(error.to_string()))?;
        headers.extend(signed.headers);

        let scheme = if target.https { "https" } else { "http" };
        let uri = if spec.query.is_empty() {
            format!("{scheme}://{}{}", target.authority, spec.path)
        } else {
            format!("{scheme}://{}{}?{}", target.authority, spec.path, spec.query)
        };
        let mut request = http::Request::builder().method(spec.method.clone()).uri(uri);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request.body(Full::new(spec.body.clone())).map_err(|error| Error::InvalidInput(format!("the request is not valid: {error}")))
    }

    /// One try: signs, sends, and returns the response if it is a success.
    async fn attempt(&self, spec: &Spec) -> Result<http::Response<Incoming>, Failure> {
        let request = self.build(spec, self.now()).map_err(|error| (error, None))?;
        let response = self.inner.transport.send(request).await.map_err(|error| (error, None))?;
        if response.status().is_success() {
            return Ok(response);
        }
        let server_time = response.headers().get(http::header::DATE).and_then(|date| date.to_str().ok()).and_then(Timestamp::parse_http_date);
        let status = response.status().as_u16();
        let head_only = spec.method == Method::HEAD;
        let body = if head_only { Bytes::new() } else { self.read_limited(response.into_body(), MAX_ERROR_BODY).await.map_err(|error| (error, server_time))?.0 };
        Err((error_from_body(status, &body, head_only), server_time))
    }

    /// Reads a body up to a limit. A body that is longer is not read to its end (which may never come): the bytes up to the limit are returned,
    /// and `true` says there was more.
    async fn read_limited(&self, mut body: Incoming, limit: usize) -> Result<(Bytes, bool), Error> {
        let mut data = BytesMut::new();
        loop {
            match tokio::time::timeout(self.inner.transport.read_timeout, body.frame()).await {
                Err(_) => return Err(Error::Timeout("the response stopped coming".to_owned())),
                Ok(None) => return Ok((data.freeze(), false)),
                Ok(Some(Err(error))) => return Err(body_error(&error)),
                Ok(Some(Ok(frame))) => {
                    if let Ok(chunk) = frame.into_data() {
                        let room = limit - data.len();
                        if chunk.len() > room {
                            data.extend_from_slice(&chunk[..room]);
                            return Ok((data.freeze(), true));
                        }
                        data.extend_from_slice(&chunk);
                    }
                }
            }
        }
    }

    /// Sends a request and returns the response if it is a success. What fails in a way that can pass is repeated, up to `max_retries` times and
    /// within `retry_timeout` of the start, with a wait that grows between the tries. A request that was refused for the time of this machine
    /// being out of step with the service is sent again at once with the time of the service.
    pub(crate) async fn execute(&self, spec: &Spec) -> Result<http::Response<Incoming>, Error> {
        let started = Instant::now();
        let mut repeats = 0_u32;
        let mut clock_corrected = false;
        loop {
            let (error, server_time) = match self.attempt(spec).await {
                Ok(response) => return Ok(response),
                Err(failure) => failure,
            };
            if let (Error::Service(s3), Some(server_time), false) = (&error, server_time, clock_corrected)
                && s3.code == "RequestTimeTooSkewed"
            {
                clock_corrected = true;
                self.inner.clock_offset.store(server_time.0 - Timestamp::now().0, Ordering::Relaxed);
                tracing::debug!("the clock is {} seconds off the service, signing with its time", server_time.0 - Timestamp::now().0);
                continue;
            }
            if !error.is_retryable() || repeats >= self.inner.max_retries || started.elapsed() >= self.inner.retry_timeout {
                return Err(error);
            }
            let wait = self.inner.backoff.delay(repeats);
            tracing::debug!("request failed ({error}); trying again in {wait:?}");
            tokio::time::sleep(wait).await;
            repeats += 1;
        }
    }

    /// Sends a request and reads its whole (small) body. A body longer than `limit` is an error: no answer of S3 to the calls that use this is so long.
    pub(crate) async fn execute_for_body(&self, spec: &Spec, limit: usize) -> Result<(http::response::Parts, Bytes), Error> {
        let (parts, body) = self.execute(spec).await?.into_parts();
        let (bytes, more) = self.read_limited(body, limit).await?;
        if more {
            return Err(Error::Protocol(format!("the response has more than the {limit} bytes it can have")));
        }
        Ok((parts, bytes))
    }

    /// Sends a request whose answer has no body that matters (an empty one, in S3). What it does have is not read past a limit.
    pub(crate) async fn execute_ignoring_body(&self, spec: &Spec) -> Result<http::response::Parts, Error> {
        let (parts, body) = self.execute(spec).await?.into_parts();
        self.read_limited(body, 64 * 1024).await?;
        Ok(parts)
    }
}

/// The error for a failed response: the S3 error document in its body, or when it is not one, what can be told from the status.
pub(crate) fn error_from_body(status: u16, body: &[u8], head_only: bool) -> Error {
    if !head_only && !body.is_empty() {
        return match S3Error::from_xml(body, status) {
            Ok(error) => Error::Service(Box::new(error)),
            Err(_) => Error::UnexpectedResponse { status, body: String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned() },
        };
    }
    Error::Service(Box::new(error_for_status(status, if head_only { "no body in an answer to HEAD" } else { "empty body" })))
}
