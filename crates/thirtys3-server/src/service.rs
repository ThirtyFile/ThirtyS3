//! The service: authentication, the plan for the checks on an upload, and the answer to a request.

use std::convert::Infallible;
use std::future::Future;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_decode, base64_encode};
use thirtys3_core::s3_error::code;
use thirtys3_core::{PayloadHash, Request as SigRequest, S3Error, SigError, Timestamp, Verified, parse_request_auth};

use crate::backend::{AuthInfo, AuthOutcome, Backend, Ctx};
use crate::body::{BodyPlan, BoxError, Digests, Framing, IncomingBody};
use crate::config::ServerConfig;
use crate::route::{self, Route};

/// The body of an answer.
pub type ResponseBody = UnsyncBoxBody<Bytes, std::io::Error>;

pub(crate) struct Inner<B> {
    pub(crate) backend: B,
    pub(crate) config: ServerConfig,
}

/// An S3 service over a [`Backend`]. It answers the requests of S3 clients: give it every request to the host (and the paths) that it serves.
///
/// It is a [`tower_service::Service`] for any request body, and has [`handle`](Self::handle) for code that calls it directly. It is cheap to clone.
pub struct S3Service<B> {
    pub(crate) inner: Arc<Inner<B>>,
}

impl<B> Clone for S3Service<B> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<B> std::fmt::Debug for S3Service<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Service").field("config", &self.inner.config).finish_non_exhaustive()
    }
}

/// What a request proved about itself.
pub(crate) struct Authenticated {
    pub(crate) access_key: String,
    pub(crate) verified: Verified,
    pub(crate) presigned: bool,
}

/// A request ID in the form S3 uses: 16 upper-case hex digits.
fn request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // RandomState is seeded from the operating system; the counter keeps two IDs apart whatever the random numbers are.
    let random = RandomState::new().build_hasher().finish();
    format!("{:016X}", random ^ COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(0x9E37_79B9_7F4A_7C15))
}

pub(crate) fn full(data: impl Into<Bytes>) -> ResponseBody {
    Full::new(data.into()).map_err(|never: Infallible| match never {}).boxed_unsync()
}

/// Sets a header, leaving it out if the value cannot be one.
pub(crate) fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
        headers.insert(name, value);
    }
}

/// An answer with an XML document.
pub(crate) fn xml_response(xml: String) -> Response<ResponseBody> {
    let mut response = Response::new(full(xml));
    response.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    response
}

pub(crate) fn empty_response(status: StatusCode) -> Response<ResponseBody> {
    let mut response = Response::new(full(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// The text of a header.
pub(crate) fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn failed(error: S3Error) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(error.status).ok().filter(|status| status.as_u16() >= 300).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = xml_response(error.to_xml());
    *response.status_mut() = status;
    response
}

impl<B: Backend> S3Service<B> {
    /// A service over a backend.
    pub fn new(backend: B, config: ServerConfig) -> Self {
        Self { inner: Arc::new(Inner { backend, config }) }
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.inner.backend
    }

    /// The settings.
    pub fn config(&self) -> &ServerConfig {
        &self.inner.config
    }

    /// Answers a request. This never fails: whatever goes wrong is an S3 error document in the answer.
    ///
    /// What the code that mounts the service puts in the extensions of the request (the address of the client, for one) is passed on to the
    /// backend in [`Ctx::extensions`] and [`AuthInfo::extensions`].
    pub async fn handle<Body>(&self, request: http::Request<Body>) -> Response<ResponseBody>
    where
        Body: http_body::Body<Data = Bytes> + Send + 'static,
        Body::Error: Into<BoxError>,
    {
        let id = request_id();
        let (parts, body) = request.into_parts();
        let body: IncomingBody = body.map_err(Into::into).boxed_unsync();
        let mut response = match self.process(&id, &parts, body).await {
            Ok(response) => response,
            Err(mut error) => {
                error.request_id.get_or_insert_with(|| id.clone());
                error.host_id.get_or_insert_with(|| id.clone());
                if error.resource.is_none() && !error.code.is_empty() {
                    error.resource = Some(parts.uri.path().to_owned());
                }
                let mut response = failed(error);
                if parts.method == Method::HEAD {
                    // A HEAD has no body; the status says what happened.
                    *response.body_mut() = full(Bytes::new());
                    response.headers_mut().remove(http::header::CONTENT_TYPE);
                }
                response
            }
        };
        let headers = response.headers_mut();
        set_header(headers, "x-amz-request-id", &id);
        set_header(headers, "x-amz-id-2", &id);
        headers.entry(http::header::SERVER).or_insert(HeaderValue::from_static("thirtys3"));
        set_header(headers, "date", &Timestamp::now().http_date());
        response
    }

    async fn process(&self, id: &str, parts: &Parts, body: IncomingBody) -> Result<Response<ResponseBody>, S3Error> {
        // Authentication goes before everything else, the routing included: a request that has not proved who it is learns nothing about what
        // the service does.
        let route = route::route(parts, &self.inner.config);
        let auth = self.authenticate(parts).await?;
        let route = route?;
        if self.inner.config.reject_unsupported_headers
            && route.key.is_some()
            && let Some(name) = route::unsupported_header(parts)
        {
            return Err(route::unsupported_header_error(&name));
        }
        let ctx = Ctx {
            access_key: &auth.access_key,
            request_id: id,
            presigned: auth.presigned,
            region: &self.inner.config.region,
            method: &parts.method,
            uri: &parts.uri,
            headers: &parts.headers,
            extensions: &parts.extensions,
        };
        self.dispatch(&ctx, &route, &auth, parts, body).await
    }

    /// Checks who sent the request. Anonymous requests are never accepted.
    async fn authenticate(&self, parts: &Parts) -> Result<Authenticated, S3Error> {
        let owned: Vec<(String, String)> =
            parts.headers.iter().map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned())).collect();
        let borrowed: Vec<(&str, &str)> = owned.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let request = SigRequest { method: parts.method.as_str(), path: parts.uri.path(), query: parts.uri.query().unwrap_or_default(), headers: &borrowed };
        let parsed = parse_request_auth(&request).map_err(|error| S3Error::from(&error))?.ok_or_else(|| S3Error::new(code::ACCESS_DENIED, "Access Denied"))?;
        let config = &self.inner.config;
        if config.enforce_region && parsed.scope.region != config.region {
            return Err(S3Error::new(code::AUTHORIZATION_HEADER_MALFORMED, format!("the region '{}' is wrong; expecting '{}'", parsed.scope.region, config.region))
                .with_detail("Region", config.region.clone()));
        }
        let now = Timestamp::now();
        // A clock that is out of step is no attempt to guess a key, and is refused before anything is counted.
        parsed.check_time(now).map_err(|error| S3Error::from(&error))?;
        let info = AuthInfo { access_key: &parsed.access_key_id, uri: &parts.uri, headers: &parts.headers, extensions: &parts.extensions };
        let backend = &self.inner.backend;
        backend.before_authentication(&info).await?;
        let credential = match backend.secret_key(&parsed.access_key_id).await {
            Ok(Some(credential)) => credential,
            Ok(None) => {
                backend.after_authentication(&info, AuthOutcome::UnknownKey).await;
                return Err(S3Error::new(code::INVALID_ACCESS_KEY_ID, "The AWS access key ID you provided does not exist in our records.")
                    .with_detail("AWSAccessKeyId", parsed.access_key_id.clone()));
            }
            Err(error) => {
                backend.after_authentication(&info, AuthOutcome::Refused).await;
                return Err(error);
            }
        };
        if let Some(expected) = &credential.session_token
            && parsed.session_token.as_ref() != Some(expected)
        {
            backend.after_authentication(&info, AuthOutcome::Failed).await;
            return Err(S3Error::new("InvalidToken", "The provided token is malformed or otherwise invalid."));
        }
        match parsed.verify(&request, &credential.secret_access_key, now) {
            Ok(verified) => {
                backend.after_authentication(&info, AuthOutcome::Verified).await;
                Ok(Authenticated { access_key: parsed.access_key_id.clone(), verified, presigned: parsed.kind == thirtys3_core::AuthKind::Query })
            }
            Err(error) => {
                let outcome = if error == SigError::SignatureDoesNotMatch { AuthOutcome::BadSignature } else { AuthOutcome::Failed };
                backend.after_authentication(&info, outcome).await;
                let mut error = S3Error::from(&error);
                if outcome == AuthOutcome::BadSignature {
                    error = error.with_detail("AWSAccessKeyId", parsed.access_key_id.clone());
                }
                Err(error)
            }
        }
    }

    /// The checks for the body of a request that stores something: how its data comes, how long it is, and what it has to hash to.
    pub(crate) fn body_plan(&self, parts: &Parts, auth: &Authenticated, max_size: u64) -> Result<BodyPlan, S3Error> {
        let headers = &parts.headers;
        let invalid = |message: String| S3Error::new(code::INVALID_REQUEST, message);
        let (framing, payload_sha256) = match &auth.verified.payload_hash {
            PayloadHash::Unsigned => (Framing::Plain, None),
            PayloadHash::Sha256(hash) => (Framing::Plain, Some(hash.clone())),
            PayloadHash::StreamingSigned | PayloadHash::StreamingSignedTrailer => {
                let trailers = auth.verified.payload_hash == PayloadHash::StreamingSignedTrailer;
                let chain = auth.verified.chunk_chain().ok_or_else(|| S3Error::new(code::INTERNAL_ERROR, "no chunk chain"))?;
                (Framing::Chunked { signed: Some(chain), trailers }, None)
            }
            PayloadHash::StreamingUnsignedTrailer => (Framing::Chunked { signed: None, trailers: true }, None),
        };
        let chunked = matches!(framing, Framing::Chunked { .. });
        let number = |name: &str| -> Result<Option<u64>, S3Error> {
            match header_text(headers, name) {
                None => Ok(None),
                Some(text) => text.trim().parse::<u64>().map(Some).map_err(|_| invalid(format!("the header {name} is not a number"))),
            }
        };
        let length = if chunked { number("x-amz-decoded-content-length")? } else { number("content-length")? };
        if let Some(length) = length
            && length > max_size
        {
            return Err(S3Error::new(code::ENTITY_TOO_LARGE, "Your proposed upload exceeds the maximum allowed size")
                .with_detail("ProposedSize", length.to_string())
                .with_detail("MaxSizeAllowed", max_size.to_string()));
        }
        let content_md5 = match header_text(headers, "content-md5") {
            None => None,
            Some(text) => Some(
                base64_decode(text)
                    .filter(|digest| digest.len() == 16)
                    .ok_or_else(|| S3Error::new(code::INVALID_DIGEST, "The Content-MD5 you specified is not valid."))?,
            ),
        };
        let mut checksums = Vec::new();
        for algorithm in ChecksumAlgorithm::ALL {
            if let Some(text) = header_text(headers, algorithm.header_name()) {
                let digest = algorithm
                    .decode_value(text)
                    .ok_or_else(|| S3Error::new(code::INVALID_REQUEST, format!("The value of {} is not valid.", algorithm.header_name())))?;
                checksums.push((algorithm, digest));
            }
        }
        let mut trailer_checksums = Vec::new();
        if let Some(text) = header_text(headers, "x-amz-trailer") {
            for name in text.split(',').map(str::trim).filter(|name| !name.is_empty()) {
                match ChecksumAlgorithm::from_header_name(name) {
                    Some(algorithm) => trailer_checksums.push(algorithm),
                    None => return Err(invalid(format!("the trailing header {name} is not one that is accepted"))),
                }
            }
        }
        if !trailer_checksums.is_empty() && !matches!(framing, Framing::Chunked { trailers: true, .. }) {
            return Err(invalid("x-amz-trailer is for a body in aws-chunked chunks with trailing headers".to_owned()));
        }
        Ok(BodyPlan {
            framing,
            length,
            payload_sha256,
            content_md5,
            checksums,
            trailer_checksums,
            max_size,
            max_chunk: self.inner.config.max_chunk_size,
            idle_timeout: self.inner.config.body_idle_timeout,
        })
    }

    /// The headers that report the checksums of data that was received: the algorithms the request named, with what was worked out.
    pub(crate) fn checksum_headers(digests: &Digests, headers: &mut HeaderMap) {
        for (algorithm, digest) in &digests.checksums {
            set_header(headers, algorithm.header_name(), &base64_encode(digest));
        }
    }

    /// The error for a backend that returned before the whole body had been read and checked.
    pub(crate) fn unchecked() -> S3Error {
        tracing::error!("a backend returned before it had read the whole body; the upload is not acknowledged");
        S3Error::new(code::INTERNAL_ERROR, "We encountered an internal error. Please try again.")
    }

    /// The route of a request, for the code that wants to know without handling it.
    pub fn route(&self, parts: &Parts) -> Result<Route, S3Error> {
        route::route(parts, &self.inner.config)
    }
}

impl<B, Body> tower_service::Service<http::Request<Body>> for S3Service<B>
where
    B: Backend,
    Body: http_body::Body<Data = Bytes> + Send + 'static,
    Body::Error: Into<BoxError>,
{
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { Ok(service.handle(request).await) })
    }
}
