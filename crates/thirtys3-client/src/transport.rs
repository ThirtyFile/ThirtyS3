//! One HTTP request over a connection, with the timeouts: the TLS setup, the pool of connections and nothing about S3.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::time::Instant;

use crate::config::ClientConfig;
use crate::error::Error;

#[cfg(feature = "aws-lc-rs")]
fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!("thirtys3-client needs one of the features `aws-lc-rs` and `ring` for TLS");

/// The TLS configuration: the provider chosen by the features and the certificate verification of the operating system. The connector sets
/// the protocols (HTTP/1.1).
fn tls_config() -> Result<rustls::ClientConfig, Error> {
    let tls = |error: rustls::Error| Error::Config(format!("TLS could not be set up: {error}"));
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_safe_default_protocol_versions()
        .map_err(tls)?
        .with_platform_verifier()
        .map_err(tls)?
        .with_no_client_auth();
    Ok(config)
}

/// The text of an error and of what caused it.
fn describe(error: &(dyn StdError + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// How much of a request has been sent, for the timeout that watches for silence.
struct Progress {
    start: Instant,
    /// Milliseconds after `start` of the last sign of life: the start of the request, or a piece of the body handed to the connection.
    last: AtomicU64,
}

impl Progress {
    fn new() -> Self {
        Self { start: Instant::now(), last: AtomicU64::new(0) }
    }

    fn touch(&self) {
        self.last.fetch_max(u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// When the last sign of life was.
    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last.load(Ordering::Relaxed))
    }
}

/// The largest piece of a request body that is handed to the connection at once.
const PIECE: usize = 64 * 1024;

/// The body of a request, handed to the connection in pieces. The connection asks for the next piece when it has written the one before, so the
/// time between pieces says whether the upload is going on, however long it takes in all.
struct Tracked {
    data: Bytes,
    progress: Arc<Progress>,
}

impl Body for Tracked {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.progress.touch();
        if self.data.is_empty() {
            return Poll::Ready(None);
        }
        let length = self.data.len().min(PIECE);
        let piece = self.data.split_to(length);
        Poll::Ready(Some(Ok(Frame::data(piece))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.len() as u64)
    }
}

pub(crate) struct Transport {
    client: HyperClient<HttpsConnector<HttpConnector>, Tracked>,
    pub(crate) read_timeout: Duration,
}

impl Transport {
    pub(crate) fn new(config: &ClientConfig) -> Result<Self, Error> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_connect_timeout(Some(config.connect_timeout));
        let https = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls_config()?).https_or_http().enable_http1().wrap_connector(http);
        // A connection that has been idle for a while is likely closed by the other side, so it is not reused after 20 seconds.
        let client = HyperClient::builder(TokioExecutor::new()).pool_idle_timeout(Duration::from_secs(20)).build(https);
        Ok(Self { client, read_timeout: config.read_timeout })
    }

    /// Sends the request and waits for the start of the response (the status and the headers). The body of the response is read by the caller.
    ///
    /// The timeout is for silence: it runs out when nothing has been sent or received for `read_timeout`, not when the whole takes that long. A
    /// request body is written as the connection takes it, so an upload on a slow link goes on as long as it moves; and after its last byte the
    /// service has `read_timeout` to answer.
    pub(crate) async fn send(&self, request: http::Request<Bytes>) -> Result<http::Response<Incoming>, Error> {
        let progress = Arc::new(Progress::new());
        let (parts, data) = request.into_parts();
        let request = http::Request::from_parts(parts, Tracked { data, progress: progress.clone() });
        let response = self.client.request(request);
        tokio::pin!(response);
        loop {
            let deadline = progress.last() + self.read_timeout;
            tokio::select! {
                result = &mut response => return result.map_err(|error| classify(&error)),
                () = tokio::time::sleep_until(deadline) => {
                    if progress.last() + self.read_timeout <= Instant::now() {
                        return Err(Error::Timeout(format!("no answer within {} seconds", self.read_timeout.as_secs_f32())));
                    }
                }
            }
        }
    }
}

/// Whether `rustls` is the cause of an error, which is so for a certificate that is not trusted, a name that does not match and a server that does
/// not speak TLS.
fn is_tls_error(error: &(dyn StdError + 'static)) -> bool {
    let mut current: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(cause) = current {
        if cause.is::<rustls::Error>() {
            return true;
        }
        // `io::Error::source` skips the error it wraps, so that one is looked at by hand.
        if let Some(inner) = cause.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref)
            && is_tls_error(inner)
        {
            return true;
        }
        current = cause.source();
    }
    false
}

/// The error for a request that could not be made.
fn classify(error: &hyper_util::client::legacy::Error) -> Error {
    if is_tls_error(error) {
        Error::Tls(describe(error))
    } else if error.is_connect() && describe(error).contains("timed out") {
        Error::Timeout(describe(error))
    } else {
        Error::Transport(describe(error))
    }
}

/// The text of an error from reading a response body.
pub(crate) fn body_error(error: &hyper::Error) -> Error {
    Error::Transport(describe(error))
}
