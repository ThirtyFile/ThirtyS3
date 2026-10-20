//! The shared parts of ThirtyS3: Signature Version 4 signing and verification, S3 XML, errors, ETags and checksums.
//!
//! Signature Version 4 is in [`sigv4`] (building and signing requests and presigned URLs), [`auth`] (reading and checking the authentication of
//! an incoming request) and [`chunk`] (the signatures of an `aws-chunked` body). [`encoding`] has the URI encoding they depend on.

pub mod auth;
pub mod chunk;
pub mod encoding;
pub mod error;
pub mod sigv4;
pub mod time;

pub use auth::{AuthKind, ParsedAuth, PayloadHash, Verified, parse_request_auth};
pub use chunk::ChunkChain;
pub use error::SigError;
pub use sigv4::{Credentials, Request, Scope, SignedRequest, Signer, SigningKey, sha256_hex};
pub use time::Timestamp;
