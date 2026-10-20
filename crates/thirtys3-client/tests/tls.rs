//! Reaching a service with a certificate of a private authority: it is refused until the authority is given, and then it is checked as always.
//!
//! The service here is a TLS server made for the test, with a certificate from an authority made for the test.

#![cfg(feature = "aws-lc-rs")]

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use thirtys3_client::{Client, ClientConfig, Credentials, Error};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// An authority that can sign certificates.
struct Authority {
    certificate: rcgen::Certificate,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl Authority {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.clone().self_signed(&key).unwrap();
        Self { certificate, issuer: rcgen::Issuer::new(params, key) }
    }

    fn pem(&self) -> String {
        self.certificate.pem()
    }

    /// A certificate for these names, signed by the authority, and its key.
    fn server_certificate(&self, names: &[&str]) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(names.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>()).unwrap();
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        (certificate.der().clone(), rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap())
    }
}

/// A service over TLS that answers every request with the headers of a small object. Returns its address.
async fn serve(certificate: rustls::pki_types::CertificateDer<'static>, key: rustls::pki_types::PrivateKeyDer<'static>) -> u16 {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else { return };
                let service = service_fn(|_request: http::Request<hyper::body::Incoming>| async {
                    Ok::<_, Infallible>(http::Response::builder().header("etag", "\"e\"").header("content-length", "5").body(Full::new(Bytes::new())).unwrap())
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    port
}

fn config(host: &str, port: u16) -> ClientConfig {
    let mut config = ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).endpoint(format!("https://{host}:{port}")).region("us-east-1");
    config.max_retries = 2;
    config.backoff_initial = Duration::from_millis(2);
    config.read_timeout = Duration::from_secs(5);
    config
}

#[tokio::test]
async fn a_service_with_a_private_certificate_is_refused_until_its_authority_is_trusted() {
    let authority = Authority::new("an authority made for the test");
    let (certificate, key) = authority.server_certificate(&["localhost"]);
    let port = serve(certificate, key).await;

    // As it is, the system does not know the authority, and trying again changes nothing.
    let error = Client::new(config("localhost", port)).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, Error::Tls(_)), "{error:?}");

    // With the authority, it is a connection like any other.
    let trusted = config("localhost", port).root_certificates_pem(&authority.pem()).unwrap();
    let meta = Client::new(trusted).unwrap().head("k").await.unwrap();
    assert_eq!((meta.size, meta.etag.as_deref()), (5, Some("\"e\"")));

    // The same through the DER of the certificate.
    let mut der = config("localhost", port);
    der.root_certificates.push(authority.certificate.der().to_vec());
    assert_eq!(Client::new(der).unwrap().head("k").await.unwrap().size, 5);
}

#[tokio::test]
async fn the_certificate_is_still_checked_against_the_name_and_the_authority() {
    let authority = Authority::new("the authority that is trusted");
    let stranger = Authority::new("an authority that is not");

    // A certificate for another name.
    let (certificate, key) = authority.server_certificate(&["somewhere-else.test"]);
    let port = serve(certificate, key).await;
    let error = Client::new(config("localhost", port).root_certificates_pem(&authority.pem()).unwrap()).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, Error::Tls(_)), "a certificate for another name: {error:?}");

    // A certificate from an authority that was not given.
    let (certificate, key) = stranger.server_certificate(&["localhost"]);
    let port = serve(certificate, key).await;
    let error = Client::new(config("localhost", port).root_certificates_pem(&authority.pem()).unwrap()).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, Error::Tls(_)), "a certificate from another authority: {error:?}");
}

#[test]
fn pem_text_that_has_no_certificate_is_refused_when_it_is_given() {
    let base = || ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret"));
    for text in ["", "not a certificate", "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"] {
        assert!(matches!(base().root_certificates_pem(text), Err(Error::Config(_))), "{text:?}");
    }
    // Several certificates in one text are all taken.
    let (first, second) = (Authority::new("one").pem(), Authority::new("two").pem());
    assert_eq!(base().root_certificates_pem(&format!("{first}\n{second}")).unwrap().root_certificates.len(), 2);
}
