//! The error document, the table of codes and the mapping from authentication failures.
//!
//! The fixtures are the examples on the archived `ErrorResponses` page and on `API_CompleteMultipartUpload.html`.

use std::collections::HashSet;

use thirtys3_core::s3_error::{ERROR_STATUS, code, status_of};
use thirtys3_core::xml::XmlError;
use thirtys3_core::{S3Error, SigError, Timestamp};

#[test]
fn the_sample_error_of_the_documentation() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>\n <Code>NoSuchKey</Code>\n <Message>The resource you requested does not exist</Message>\n <Resource>/mybucket/myfoto.jpg</Resource> \n <RequestId>4442587FB7D0A2F9</RequestId>\n</Error>";
    let error = S3Error::from_xml(xml.as_bytes(), 404).unwrap();
    assert_eq!(error.code, "NoSuchKey");
    assert_eq!(error.message, "The resource you requested does not exist");
    assert_eq!(error.resource.as_deref(), Some("/mybucket/myfoto.jpg"));
    assert_eq!(error.request_id.as_deref(), Some("4442587FB7D0A2F9"));
    assert_eq!(error.status, 404);
    assert_eq!(error.host_id, None);
}

#[test]
fn the_error_of_complete_multipart_upload_with_a_host_id() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n <Error>\n <Code>InternalError</Code>\n <Message>We encountered an internal error. Please try again.</Message>\n <RequestId>656c76696e6727732072657175657374</RequestId>\n <HostId>Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg==</HostId>\n </Error>";
    let error = S3Error::from_xml(xml.as_bytes(), 200).unwrap();
    assert_eq!(error.code, "InternalError");
    assert_eq!(error.host_id.as_deref(), Some("Uuag1LuByRx9e6j5Onimru9pO4ZVKnJ2Qz7/C1NPcfTWAtRPfTaOFg=="));
    // The status is the one the response had, 200 here; the code says what happened.
    assert_eq!(error.status, 200);
    assert!(error.is_retryable());
}

#[test]
fn the_document_has_code_message_details_resource_and_request_id_in_that_order() {
    let error = S3Error::new(code::BAD_DIGEST, "The Content-MD5 you specified did not match what we received.")
        .with_detail("ExpectedDigest", "abc")
        .with_detail("CalculatedDigest", "def")
        .with_resource("/b/k")
        .with_request_id("R1");
    assert_eq!(
        error.to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>BadDigest</Code><Message>The Content-MD5 you specified did not match what we received.</Message><ExpectedDigest>abc</ExpectedDigest><CalculatedDigest>def</CalculatedDigest><Resource>/b/k</Resource><RequestId>R1</RequestId></Error>"
    );
    assert_eq!(error.status, 400);
}

#[test]
fn an_error_reads_back_what_was_written() {
    let mut error =
        S3Error::new(code::NO_SUCH_KEY, "The specified key does not exist. <&>").with_detail("Key", "a & b").with_resource("/b/a & b").with_request_id("R");
    error.host_id = Some("H".into());
    assert_eq!(S3Error::from_xml(error.to_xml().as_bytes(), 404).unwrap(), error);
    assert_eq!(error.detail("Key"), Some("a & b"));
    assert_eq!(error.detail("Other"), None);
}

#[test]
fn details_cannot_overwrite_the_standard_elements_or_break_the_document() {
    let error = S3Error::new(code::INVALID_ARGUMENT, "m")
        .with_detail("Code", "AccessDenied")
        .with_detail("Resource", "/x")
        .with_detail("bad name", "x")
        .with_detail("a<b", "x")
        .with_detail("ArgumentName", "max-keys")
        .with_detail("ArgumentValue", "-1");
    let xml = error.to_xml();
    assert_eq!(xml.matches("<Code>").count(), 1, "{xml}");
    assert!(
        xml.contains("<Code>InvalidArgument</Code>") && !xml.contains("AccessDenied") && !xml.contains("/x") && !xml.contains("bad name") && !xml.contains("a<b"),
        "{xml}"
    );
    assert!(xml.contains("<ArgumentName>max-keys</ArgumentName><ArgumentValue>-1</ArgumentValue>"), "{xml}");
    assert!(S3Error::from_xml(xml.as_bytes(), 400).is_ok());
}

#[test]
fn something_that_is_not_an_error_document_is_refused() {
    for body in ["", "<html><body>502 Bad Gateway</body></html>", "<Error><Message>no code</Message></Error>", "not xml"] {
        assert!(S3Error::from_xml(body.as_bytes(), 502).is_err(), "{body:?}");
    }
    assert!(matches!(S3Error::from_xml(b"<Error><Message>m</Message></Error>", 400).unwrap_err(), XmlError::Missing { name: "Code", .. }));
}

#[test]
fn an_error_without_a_message_has_an_empty_one() {
    let error = S3Error::from_xml(b"<Error><Code>NoSuchBucket</Code></Error>", 404).unwrap();
    assert_eq!(error.message, "");
}

#[test]
fn the_table_has_the_status_codes_of_the_documentation() {
    for (code, status) in [
        ("AccessDenied", 403),
        ("BadDigest", 400),
        ("BucketAlreadyOwnedByYou", 409),
        ("EntityTooSmall", 400),
        ("InternalError", 500),
        ("InvalidRange", 416),
        ("MissingContentLength", 411),
        ("MethodNotAllowed", 405),
        ("NoSuchBucket", 404),
        ("NoSuchKey", 404),
        ("NoSuchUpload", 404),
        ("NotImplemented", 501),
        ("NotModified", 304),
        ("PreconditionFailed", 412),
        ("RequestTimeTooSkewed", 403),
        ("SignatureDoesNotMatch", 403),
        ("SlowDown", 503),
        ("ServiceUnavailable", 503),
        ("XAmzContentSHA256Mismatch", 400),
    ] {
        assert_eq!(status_of(code), Some(status), "{code}");
        assert_eq!(S3Error::new(code, "m").status, status);
    }
    assert_eq!(status_of("NoSuchThing"), None);
    assert_eq!(S3Error::new("NoSuchThing", "m").status, 500);
}

#[test]
fn the_table_has_each_code_once_and_a_real_http_status() {
    let mut seen = HashSet::new();
    for (code, status) in ERROR_STATUS {
        assert!(seen.insert(*code), "{code} is in the table twice");
        assert!((300..600).contains(status), "{code}: {status}");
        assert!(!code.is_empty() && !code.contains(' '), "{code:?}");
    }
    assert!(ERROR_STATUS.len() >= 120);
}

#[test]
fn the_named_codes_are_in_the_table() {
    for named in [
        code::ACCESS_DENIED,
        code::AUTHORIZATION_HEADER_MALFORMED,
        code::AUTHORIZATION_QUERY_PARAMETERS_ERROR,
        code::BAD_DIGEST,
        code::BUCKET_ALREADY_EXISTS,
        code::BUCKET_NOT_EMPTY,
        code::CONDITIONAL_REQUEST_CONFLICT,
        code::ENTITY_TOO_LARGE,
        code::ENTITY_TOO_SMALL,
        code::EXPIRED_TOKEN,
        code::INCOMPLETE_BODY,
        code::INTERNAL_ERROR,
        code::INVALID_ACCESS_KEY_ID,
        code::INVALID_ARGUMENT,
        code::INVALID_BUCKET_NAME,
        code::INVALID_DIGEST,
        code::INVALID_PART,
        code::INVALID_PART_ORDER,
        code::INVALID_RANGE,
        code::INVALID_REQUEST,
        code::KEY_TOO_LONG,
        code::MALFORMED_XML,
        code::METHOD_NOT_ALLOWED,
        code::MISSING_CONTENT_LENGTH,
        code::MISSING_SECURITY_HEADER,
        code::NOT_IMPLEMENTED,
        code::NOT_MODIFIED,
        code::NO_SUCH_BUCKET,
        code::NO_SUCH_KEY,
        code::NO_SUCH_UPLOAD,
        code::PERMANENT_REDIRECT,
        code::PRECONDITION_FAILED,
        code::REQUEST_TIMEOUT,
        code::REQUEST_TIME_TOO_SKEWED,
        code::SERVICE_UNAVAILABLE,
        code::SIGNATURE_DOES_NOT_MATCH,
        code::SLOW_DOWN,
        code::X_AMZ_CONTENT_SHA256_MISMATCH,
    ] {
        assert!(status_of(named).is_some(), "{named} is not in the table");
    }
}

#[test]
fn which_errors_are_worth_trying_again() {
    for retryable in [("SlowDown", "m"), ("InternalError", "m"), ("ServiceUnavailable", "m"), ("RequestTimeout", "m"), ("Throttling", "m")] {
        assert!(S3Error::new(retryable.0, retryable.1).is_retryable(), "{}", retryable.0);
    }
    let mut gateway = S3Error::new("SomethingElse", "m");
    for status in [500, 502, 503, 504] {
        gateway.status = status;
        assert!(gateway.is_retryable(), "{status}");
    }
    for fatal in ["NoSuchKey", "AccessDenied", "BadDigest", "SignatureDoesNotMatch", "PreconditionFailed", "InvalidRange", "NotImplemented", "RequestTimeTooSkewed"]
    {
        assert!(!S3Error::new(fatal, "m").is_retryable(), "{fatal}");
    }
    gateway.status = 404;
    assert!(!gateway.is_retryable());
}

#[test]
fn the_error_prints_code_status_and_message() {
    assert_eq!(S3Error::new(code::NO_SUCH_KEY, "gone").to_string(), "NoSuchKey (404): gone");
}

#[test]
fn authentication_failures_become_the_s3_errors_of_the_documentation() {
    let at = Timestamp(1_369_353_600);
    let cases: Vec<(SigError, &str, u16)> = vec![
        (SigError::MalformedAuthorization("x".into()), "AuthorizationHeaderMalformed", 400),
        (SigError::InvalidDate("x".into()), "AuthorizationHeaderMalformed", 400),
        (SigError::MalformedQuery("x".into()), "AuthorizationQueryParametersError", 400),
        (SigError::InvalidExpires("x".into()), "AuthorizationQueryParametersError", 400),
        (SigError::ConflictingAuthentication, "InvalidArgument", 400),
        (SigError::UnsupportedAlgorithm("AWS".into()), "InvalidArgument", 400),
        (SigError::InvalidPayloadHash("x".into()), "InvalidArgument", 400),
        (SigError::MissingHeader("x-amz-date".into()), "MissingSecurityHeader", 400),
        (SigError::SignedHeaderMissing("range".into()), "SignatureDoesNotMatch", 403),
        (SigError::SignatureDoesNotMatch, "SignatureDoesNotMatch", 403),
        (SigError::HeadersNotSigned(vec!["x-amz-meta-a".into()]), "AccessDenied", 403),
        (SigError::RequestTimeTooSkewed { request_time: at, server_time: Timestamp(at.0 + 3600) }, "RequestTimeTooSkewed", 403),
        (SigError::Expired(at), "AccessDenied", 403),
    ];
    for (error, code, status) in cases {
        let s3 = S3Error::from(&error);
        assert_eq!((s3.code.as_str(), s3.status), (code, status), "{error:?}");
        assert!(S3Error::from_xml(s3.to_xml().as_bytes(), s3.status).is_ok());
    }
}

#[test]
fn the_skew_error_says_the_times_and_the_limit() {
    let at = Timestamp(1_369_353_600);
    let error = S3Error::from(&SigError::RequestTimeTooSkewed { request_time: at, server_time: Timestamp(at.0 + 3600) });
    assert_eq!(error.detail("RequestTime"), Some("2013-05-24T00:00:00.000Z"));
    assert_eq!(error.detail("ServerTime"), Some("2013-05-24T01:00:00.000Z"));
    assert_eq!(error.detail("MaxAllowedSkewMilliseconds"), Some("900000"));
}

#[test]
fn a_missing_header_is_named_and_unsigned_headers_are_listed() {
    assert_eq!(S3Error::from(&SigError::MissingHeader("x-amz-date".into())).detail("MissingHeaderName"), Some("x-amz-date"));
    assert_eq!(S3Error::from(&SigError::HeadersNotSigned(vec!["x-amz-a".into(), "x-amz-b".into()])).detail("HeadersNotSigned"), Some("x-amz-a, x-amz-b"));
}

#[test]
fn a_body_that_cannot_be_read_is_malformed_xml() {
    let error = S3Error::from(&XmlError::DocType);
    assert_eq!((error.code.as_str(), error.status), ("MalformedXML", 400));
}
