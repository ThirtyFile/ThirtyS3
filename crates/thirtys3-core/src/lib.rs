//! The shared parts of ThirtyS3: Signature Version 4 signing and verification, S3 XML, errors, ETags and checksums.
//!
//! - Signature Version 4: [`sigv4`] (building and signing requests and presigned URLs), [`auth`] (reading and checking the authentication of an
//!   incoming request), [`chunk`] (the signatures of an `aws-chunked` body) and [`encoding`] (the URI encoding they depend on).
//! - Documents: [`xml`] (a reader with limits and a writer), [`model`] (the request and result documents of the operations a file service offers)
//!   and [`s3_error`] (the `<Error>` document and the table of error codes).
//! - Integrity: [`checksum`] (the ten algorithms of S3, streaming) and [`etag`] (ETags and `If-Match` / `If-None-Match`).
//!
//! ```
//! use thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
//! use thirtys3_core::{Credentials, Request, Signer, Timestamp, parse_request_auth};
//!
//! // A client signs a request ...
//! let signer = Signer::new(Credentials::new("ACCESS_KEY", "SECRET_KEY"), "us-east-1");
//! let host = [("host", "s3.example.com")];
//! let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &host };
//! let signed = signer.sign(&request, EMPTY_PAYLOAD_SHA256, Timestamp::now()).unwrap();
//!
//! // ... and a server checks it, with the secret it finds for the access key.
//! let headers: Vec<(&str, &str)> = host.iter().copied().chain(signed.headers.iter().map(|(name, value)| (name.as_str(), value.as_str()))).collect();
//! let received = Request { method: "GET", path: "/bucket/key", query: "", headers: &headers };
//! let auth = parse_request_auth(&received).unwrap().expect("the request is signed");
//! assert_eq!(auth.access_key_id, "ACCESS_KEY");
//! assert!(auth.verify(&received, "SECRET_KEY", Timestamp::now()).is_ok());
//! assert!(auth.verify(&received, "OTHER_SECRET", Timestamp::now()).is_err());
//! ```
//!
//! Every module names the pages of the AWS documentation it follows. Some of those pages are no longer in the current documentation; where that
//! is so, the module says which archived version it uses.

pub mod auth;
pub mod checksum;
pub mod chunk;
pub mod encoding;
pub mod error;
pub mod etag;
pub mod model;
pub mod s3_error;
pub mod sigv4;
pub mod time;
pub mod xml;

pub use auth::{AuthKind, ParsedAuth, PayloadHash, Verified, parse_request_auth};
pub use chunk::ChunkChain;
pub use error::SigError;
pub use s3_error::S3Error;
pub use sigv4::{Credentials, Request, Scope, SignedRequest, Signer, SigningKey, constant_time_eq, sha256_hex};
pub use time::Timestamp;
