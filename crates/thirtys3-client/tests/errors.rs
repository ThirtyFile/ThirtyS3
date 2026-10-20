//! What an error means for the caller.

use thirtys3_client::{Error, ErrorKind, S3Error};

fn service(code: &str, status: u16) -> Error {
    let mut error = S3Error::new(code, "m");
    error.status = status;
    Error::Service(Box::new(error))
}

#[test]
fn the_kind_of_a_service_error() {
    for (code, status, kind) in [
        ("NoSuchKey", 404, ErrorKind::NotFound),
        ("NoSuchBucket", 404, ErrorKind::NotFound),
        ("NoSuchUpload", 404, ErrorKind::NotFound),
        ("NotFound", 404, ErrorKind::NotFound),
        ("AccessDenied", 403, ErrorKind::PermissionDenied),
        ("InvalidAccessKeyId", 403, ErrorKind::PermissionDenied),
        ("SignatureDoesNotMatch", 403, ErrorKind::PermissionDenied),
        ("ExpiredToken", 400, ErrorKind::PermissionDenied),
        ("Unauthorized", 401, ErrorKind::PermissionDenied),
        ("PreconditionFailed", 412, ErrorKind::PreconditionFailed),
        ("ConditionalRequestConflict", 409, ErrorKind::PreconditionFailed),
        ("NotModified", 304, ErrorKind::NotModified),
        ("InvalidRange", 416, ErrorKind::InvalidRange),
        ("SlowDown", 503, ErrorKind::Unavailable),
        ("InternalError", 500, ErrorKind::Unavailable),
        ("RequestTimeout", 400, ErrorKind::Unavailable),
        ("ServiceUnavailable", 503, ErrorKind::Unavailable),
        ("TooManyRequests", 429, ErrorKind::Unavailable),
        ("BadDigest", 400, ErrorKind::Rejected),
        ("InvalidArgument", 400, ErrorKind::Rejected),
        ("BucketNotEmpty", 409, ErrorKind::Rejected),
        ("NotImplemented", 501, ErrorKind::Unavailable),
    ] {
        assert_eq!(service(code, status).kind(), kind, "{code} {status}");
    }
}

#[test]
fn which_errors_are_worth_trying_again() {
    for retryable in [
        service("SlowDown", 503),
        service("InternalError", 500),
        service("Anything", 502),
        service("Anything", 504),
        service("TooManyRequests", 429),
        Error::Transport("x".into()),
        Error::Timeout("x".into()),
    ] {
        assert!(retryable.is_retryable(), "{retryable:?}");
    }
    let unexpected = |status| Error::UnexpectedResponse { status, body: String::new() };
    for status in [408, 429, 500, 502, 503, 504] {
        assert!(unexpected(status).is_retryable(), "{status}");
    }
    for fatal in [
        service("NoSuchKey", 404),
        service("AccessDenied", 403),
        service("BadDigest", 400),
        service("NotImplemented", 501),
        unexpected(400),
        unexpected(404),
        Error::Config("x".into()),
        Error::InvalidInput("x".into()),
        Error::Protocol("x".into()),
        Error::ObjectChanged,
    ] {
        assert!(!fatal.is_retryable(), "{fatal:?}");
    }
}

#[test]
fn the_kind_of_the_other_errors() {
    assert_eq!(Error::Config("x".into()).kind(), ErrorKind::InvalidInput);
    assert_eq!(Error::InvalidInput("x".into()).kind(), ErrorKind::InvalidInput);
    assert_eq!(Error::Transport("x".into()).kind(), ErrorKind::Unavailable);
    assert_eq!(Error::Timeout("x".into()).kind(), ErrorKind::Unavailable);
    assert_eq!(Error::ObjectChanged.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(Error::Protocol("x".into()).kind(), ErrorKind::Other);
    let unexpected = |status| Error::UnexpectedResponse { status, body: "<html>".into() };
    assert_eq!(unexpected(404).kind(), ErrorKind::NotFound);
    assert_eq!(unexpected(403).kind(), ErrorKind::PermissionDenied);
    assert_eq!(unexpected(502).kind(), ErrorKind::Unavailable);
    assert_eq!(unexpected(400).kind(), ErrorKind::Rejected);
    assert!(unexpected(404).is_not_found());
}

#[test]
fn errors_print_something_useful() {
    assert_eq!(service("NoSuchKey", 404).to_string(), "NoSuchKey (404): m");
    assert!(Error::UnexpectedResponse { status: 502, body: "Bad Gateway".into() }.to_string().contains("502"));
    assert!(Error::Transport("connection refused".into()).to_string().contains("connection refused"));
}
