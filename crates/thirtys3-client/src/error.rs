//! What can go wrong when a request is made, and a coarse classification of it for the code that decides what to do.

use thirtys3_core::S3Error;
use thirtys3_core::xml::XmlError;

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The configuration cannot be used.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// An argument of the call cannot be used (a key that is too long, a range with nothing in it, a header value that is not text).
    #[error("invalid argument: {0}")]
    InvalidInput(String),
    /// The service answered with an S3 error.
    #[error("{0}")]
    Service(Box<S3Error>),
    /// The service answered with something that is not an S3 error document: a proxy, a gateway, another kind of server.
    #[error("unexpected response, status {status}: {body}")]
    UnexpectedResponse {
        /// The HTTP status.
        status: u16,
        /// The start of the body, as text.
        body: String,
    },
    /// The service could not be reached or the connection broke.
    #[error("could not reach the service: {0}")]
    Transport(String),
    /// The TLS connection could not be made: the certificate is not trusted or does not match the host, or the other side does not speak TLS. Trying
    /// again does not help.
    #[error("TLS failed: {0}")]
    Tls(String),
    /// Nothing came from the service for longer than the read timeout, or the connect timeout passed.
    #[error("timed out: {0}")]
    Timeout(String),
    /// A response is not what S3 sends (a header missing or malformed, a range that was not honoured).
    #[error("the response is not what S3 sends: {0}")]
    Protocol(String),
    /// The XML of a response could not be read.
    #[error("could not read the XML of the response: {0}")]
    Xml(#[from] XmlError),
    /// The object changed between the first byte of a download and the break that had to be resumed.
    #[error("the object changed while it was being downloaded")]
    ObjectChanged,
    /// Reading the data to upload failed.
    #[error("could not read the data to upload: {0}")]
    Source(#[from] std::io::Error),
}

/// What an [`Error`] means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The object (or the bucket) does not exist.
    NotFound,
    /// The keys are not accepted: not known, not allowed to do this, or the signature is not right (HTTP 401 and 403).
    PermissionDenied,
    /// A condition (`If-Match`, `If-None-Match`) did not hold: the object exists already, or is not the one that was read.
    PreconditionFailed,
    /// The object has not changed since the version the caller has (a conditional `GET`).
    NotModified,
    /// The range asked for is outside the object.
    InvalidRange,
    /// The service did not answer, answered too slowly or failed on its side: worth trying again later.
    Unavailable,
    /// The request was wrong, or the service does not do it.
    Rejected,
    /// The caller's arguments or the configuration are wrong; nothing was sent.
    InvalidInput,
    /// Anything else.
    Other,
}

impl Error {
    /// What the error means for the caller.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Config(_) | Self::InvalidInput(_) => ErrorKind::InvalidInput,
            Self::Tls(_) => ErrorKind::Other,
            Self::Transport(_) | Self::Timeout(_) => ErrorKind::Unavailable,
            Self::ObjectChanged => ErrorKind::PreconditionFailed,
            Self::Service(error) => match (error.status, error.code.as_str()) {
                (404, _) | (_, "NoSuchKey" | "NoSuchBucket" | "NoSuchUpload") => ErrorKind::NotFound,
                (304, _) => ErrorKind::NotModified,
                (412, _) | (409, "ConditionalRequestConflict") => ErrorKind::PreconditionFailed,
                (416, _) | (_, "InvalidRange") => ErrorKind::InvalidRange,
                (401 | 403, _) | (_, "AccessDenied" | "InvalidAccessKeyId" | "SignatureDoesNotMatch" | "ExpiredToken") => ErrorKind::PermissionDenied,
                (501, _) | (_, "NotImplemented") => ErrorKind::Rejected,
                (500..=599 | 429, _) | (_, "SlowDown" | "RequestTimeout" | "InternalError" | "ServiceUnavailable") => ErrorKind::Unavailable,
                (400..=499, _) => ErrorKind::Rejected,
                _ => ErrorKind::Other,
            },
            Self::UnexpectedResponse { status, .. } => match status {
                401 | 403 => ErrorKind::PermissionDenied,
                404 => ErrorKind::NotFound,
                304 => ErrorKind::NotModified,
                412 => ErrorKind::PreconditionFailed,
                416 => ErrorKind::InvalidRange,
                501 => ErrorKind::Rejected,
                408 | 429 | 500..=599 => ErrorKind::Unavailable,
                400..=499 => ErrorKind::Rejected,
                _ => ErrorKind::Other,
            },
            Self::Protocol(_) | Self::Xml(_) | Self::Source(_) => ErrorKind::Other,
        }
    }

    /// Whether the object or bucket is not there.
    pub fn is_not_found(&self) -> bool {
        self.kind() == ErrorKind::NotFound
    }

    /// Whether the same request can work if it is made again after a while.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Timeout(_) => true,
            Self::Service(error) => error.is_retryable() || error.status == 429,
            Self::UnexpectedResponse { status, .. } => matches!(status, 408 | 429 | 500 | 502 | 503 | 504),
            _ => false,
        }
    }
}
