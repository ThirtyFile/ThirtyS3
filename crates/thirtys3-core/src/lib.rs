//! The shared parts of ThirtyS3: Signature Version 4 signing and verification, S3 XML, errors, ETags and checksums.
//!
//! - Signature Version 4: [`sigv4`] (building and signing requests and presigned URLs), [`auth`] (reading and checking the authentication of an
//!   incoming request), [`chunk`] (the signatures of an `aws-chunked` body) and [`encoding`] (the URI encoding they depend on).
//! - Documents: [`xml`] (a reader with limits and a writer), [`model`] (the request and result documents of the operations a file service offers)
//!   and [`s3_error`] (the `<Error>` document and the table of error codes).
//! - Integrity: [`checksum`] (the ten algorithms of S3, streaming) and [`etag`] (ETags and `If-Match` / `If-None-Match`).
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
pub use sigv4::{Credentials, Request, Scope, SignedRequest, Signer, SigningKey, sha256_hex};
pub use time::Timestamp;
