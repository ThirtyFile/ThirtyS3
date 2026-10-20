//! The ways signing and verifying a request can fail.

use crate::time::Timestamp;

/// Why a request could not be signed, or why its signature was not accepted. The server layer turns these into S3 error responses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    /// The `Authorization` header is not a well-formed Signature Version 4 header.
    #[error("the Authorization header is malformed: {0}")]
    MalformedAuthorization(String),
    /// The authentication query parameters of a presigned URL are missing or malformed.
    #[error("the authentication query parameters are malformed: {0}")]
    MalformedQuery(String),
    /// The request carries both an `Authorization` header and authentication query parameters.
    #[error("the request has both an Authorization header and authentication query parameters")]
    ConflictingAuthentication,
    /// The `Authorization` header names a signing algorithm other than `AWS4-HMAC-SHA256` (Signature Version 2, for one).
    #[error("unsupported authorization type {0:?}")]
    UnsupportedAlgorithm(String),
    /// A header the signature needs is not in the request.
    #[error("the request has no {0} header")]
    MissingHeader(String),
    /// A header named in `SignedHeaders` is not in the request.
    #[error("the signed header {0:?} is not in the request")]
    SignedHeaderMissing(String),
    /// `x-amz-*` headers are in the request but not among the signed headers.
    #[error("these headers are in the request but were not signed: {}", .0.join(", "))]
    HeadersNotSigned(Vec<String>),
    /// `x-amz-content-sha256` is not a SHA-256 in hex, `UNSIGNED-PAYLOAD` or one of the streaming values.
    #[error("invalid x-amz-content-sha256 value {0:?}")]
    InvalidPayloadHash(String),
    /// `x-amz-date` or `X-Amz-Date` is not `YYYYMMDDTHHMMSSZ`.
    #[error("invalid date {0:?}, expected YYYYMMDDTHHMMSSZ")]
    InvalidDate(String),
    /// `X-Amz-Expires` is not a whole number of seconds from 1 to 604800 (seven days).
    #[error("invalid X-Amz-Expires {0:?}, expected 1 to 604800 seconds")]
    InvalidExpires(String),
    /// The date of the request is too far from the time of the server.
    #[error("the request time {request_time:?} is too far from the server time {server_time:?}")]
    RequestTimeTooSkewed {
        /// The time the request says it was made.
        request_time: Timestamp,
        /// The time the server checked against.
        server_time: Timestamp,
    },
    /// A presigned URL is past its expiry.
    #[error("the presigned URL expired at {0:?}")]
    Expired(Timestamp),
    /// The signature in the request is not the one computed from it.
    #[error("the request signature does not match the signature computed from the request")]
    SignatureDoesNotMatch,
}
