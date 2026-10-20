//! One HTTP request over a connection, with the timeouts: the TLS setup, the pool of connections and nothing about S3.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls_platform_verifier::BuilderVerifierExt;

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

pub(crate) struct Transport {
    client: HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>,
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
    pub(crate) async fn send(&self, request: http::Request<Full<Bytes>>) -> Result<http::Response<Incoming>, Error> {
        match tokio::time::timeout(self.read_timeout, self.client.request(request)).await {
            Err(_) => Err(Error::Timeout(format!("no answer within {} seconds", self.read_timeout.as_secs_f32()))),
            Ok(Err(error)) if error.is_connect() => {
                Err(if describe(&error).contains("timed out") { Error::Timeout(describe(&error)) } else { Error::Transport(describe(&error)) })
            }
            Ok(Err(error)) => Err(Error::Transport(describe(&error))),
            Ok(Ok(response)) => Ok(response),
        }
    }
}

/// The text of an error from reading a response body.
pub(crate) fn body_error(error: &hyper::Error) -> Error {
    Error::Transport(describe(error))
}
