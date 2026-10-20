//! Things a review found that a signed request could still get away with. Each test failed before the change that fixed it.

use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, UNSIGNED_PAYLOAD};
use thirtys3_core::{Credentials, Request, SigError, Signer, Timestamp, parse_request_auth};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn signer() -> Signer {
    Signer::new(Credentials::new("AKIAIOSFODNN7EXAMPLE", SECRET), "us-east-1")
}

fn verify(request: &Request<'_>, now: Timestamp) -> Result<(), SigError> {
    parse_request_auth(request)?.expect("the request is signed").verify(request, SECRET, now).map(|_| ())
}

/// A presigned `PUT` of /bucket/key for `host` alone, and the query of its URL.
fn presigned(now: Timestamp) -> String {
    let headers = [("host", "s3.example.com")];
    let request = Request { method: "PUT", path: "/bucket/key", query: "", headers: &headers };
    signer().presign(&request, now, 300).unwrap()
}

#[test]
fn a_presigned_url_does_not_take_x_amz_headers_that_were_not_signed() {
    let now = Timestamp::now();
    let query = presigned(now);
    let plain = [("host", "s3.example.com")];
    let request = Request { method: "PUT", path: "/bucket/key", query: &query, headers: &plain };
    assert_eq!(verify(&request, now), Ok(()));
    // Whoever holds the URL turns the upload into a copy of something else, or changes what is stored.
    for (name, value) in
        [("x-amz-copy-source", "other-bucket/secret"), ("x-amz-acl", "public-read"), ("X-Amz-Meta-A", "b"), ("x-amz-server-side-encryption", "AES256")]
    {
        let headers = [("host", "s3.example.com"), (name, value)];
        let request = Request { method: "PUT", path: "/bucket/key", query: &query, headers: &headers };
        match verify(&request, now) {
            Err(SigError::HeadersNotSigned(names)) => assert_eq!(names, [name.to_ascii_lowercase()]),
            other => panic!("{name}: {other:?}"),
        }
    }
    // The hash of the payload is signed with the rest, so it can be there.
    let headers = [("host", "s3.example.com"), ("x-amz-content-sha256", UNSIGNED_PAYLOAD)];
    let request = Request { method: "PUT", path: "/bucket/key", query: &query, headers: &headers };
    assert_eq!(verify(&request, now), Ok(()));
}

#[test]
fn a_presigned_url_with_the_headers_signed_takes_them() {
    let now = Timestamp::now();
    let headers = [("host", "s3.example.com"), ("x-amz-meta-a", "b")];
    let request = Request { method: "PUT", path: "/bucket/key", query: "", headers: &headers };
    let query = signer().presign(&request, now, 300).unwrap();
    let request = Request { method: "PUT", path: "/bucket/key", query: &query, headers: &headers };
    assert_eq!(verify(&request, now), Ok(()));
}

#[test]
fn a_query_that_has_a_signature_is_never_an_anonymous_request() {
    let now = Timestamp::now();
    let query = presigned(now);
    let plain = [("host", "s3.example.com")];
    // The names of the parameters have an exact spelling. Without it the request is refused, and is not served as if nobody had signed it.
    for damaged in [
        query.replace("X-Amz-Algorithm", "x-amz-algorithm"),
        query.replace("X-Amz-Signature", "x-amz-signature"),
        query.replace("X-Amz-Credential", "X-AMZ-CREDENTIAL"),
    ] {
        let request = Request { method: "PUT", path: "/bucket/key", query: &damaged, headers: &plain };
        assert!(matches!(parse_request_auth(&request), Err(SigError::MalformedQuery(_))), "{damaged}");
    }
    // And a second signature of another spelling does not make a second URL out of the first.
    let twice = format!("{query}&x-amz-signature=zzz");
    let request = Request { method: "PUT", path: "/bucket/key", query: &twice, headers: &plain };
    assert!(matches!(parse_request_auth(&request), Err(SigError::MalformedQuery(_))));
}

#[test]
fn a_date_that_cannot_be_read_in_a_presigned_url_is_a_query_error() {
    let now = Timestamp::now();
    let query = presigned(now).replace(&now.amz_date(), "yesterday");
    let plain = [("host", "s3.example.com")];
    let request = Request { method: "PUT", path: "/bucket/key", query: &query, headers: &plain };
    assert!(matches!(parse_request_auth(&request), Err(SigError::MalformedQuery(_))));
    let _ = EMPTY_PAYLOAD_SHA256;
}

// ---- the chain of an aws-chunked body ----

fn signed_chunked_request(signer: &Signer, time: Timestamp) -> thirtys3_core::SignedRequest {
    let headers = [("host", "s3.example.com")];
    let request = Request { method: "PUT", path: "/bucket/key", query: "", headers: &headers };
    signer.sign(&request, thirtys3_core::sigv4::STREAMING_SIGNED_PAYLOAD_TRAILER, time).unwrap()
}

#[test]
fn the_chain_has_to_reach_the_chunk_with_no_data_before_the_trailer_and_ends_there() {
    let signer = signer();
    let signed = signed_chunked_request(&signer, Timestamp::now());
    let mut sender = signer.chunk_chain(&signed);
    let mut receiver = signer.chunk_chain(&signed);
    let data = thirtys3_core::sha256_hex(b"data");
    let first = sender.sign_chunk(&data);
    let last = sender.sign_chunk(EMPTY_PAYLOAD_SHA256);
    let trailer = sender.sign_trailer(&thirtys3_core::sha256_hex(b"x-amz-checksum-crc32:AAAAAA==\n"));

    // A body cut off after the first chunk: every chunk that came was right, and the trailer cannot be right either.
    assert_eq!(receiver.verify_chunk(&data, &first), Ok(()));
    assert!(!receiver.is_finished());
    assert_eq!(receiver.verify_trailer(&thirtys3_core::sha256_hex(b"x-amz-checksum-crc32:AAAAAA==\n"), &trailer), Err(SigError::SignatureDoesNotMatch));

    // A sender that goes from the first chunk to the trailer, and leaves out the chunk with no data: its trailer is signed at the place the receiver is
    // at, and still it is not the end.
    let mut skipping = signer.chunk_chain(&signed);
    let skipped_trailer = {
        let mut chain = signer.chunk_chain(&signed);
        chain.sign_chunk(&data);
        chain.sign_trailer(&thirtys3_core::sha256_hex(
            b"x-amz-checksum-crc32:AAAAAA==
",
        ))
    };
    skipping.verify_chunk(&data, &first).unwrap();
    assert_eq!(
        skipping.verify_trailer(
            &thirtys3_core::sha256_hex(
                b"x-amz-checksum-crc32:AAAAAA==
"
            ),
            &skipped_trailer
        ),
        Err(SigError::SignatureDoesNotMatch)
    );

    // The whole body.
    assert_eq!(receiver.verify_chunk(EMPTY_PAYLOAD_SHA256, &last), Ok(()));
    assert!(receiver.is_finished());
    assert_eq!(receiver.verify_trailer(&thirtys3_core::sha256_hex(b"x-amz-checksum-crc32:AAAAAA==\n"), &trailer), Ok(()));
    // And nothing comes after the end.
    let mut again = signer.chunk_chain(&signed);
    again.verify_chunk(&data, &first).unwrap();
    again.verify_chunk(EMPTY_PAYLOAD_SHA256, &last).unwrap();
    assert_eq!(again.verify_chunk(&data, &sender.sign_chunk(&data)), Err(SigError::SignatureDoesNotMatch));
}

// ---- small things in what is read ----

#[test]
fn an_offset_of_a_time_is_made_of_digits() {
    for good in ["2019-12-11T23:32:47+01:30", "2019-12-11T23:32:47-00:00", "2019-12-11T23:32:47.123+05:00"] {
        assert!(Timestamp::parse_iso8601(good).is_some(), "{good}");
    }
    for bad in ["2019-12-11T23:32:47+-1:30", "2019-12-11T23:32:47++1:30", "2019-12-11T23:32:47+1 :30", "2019-12-11T23:32:47+01:-1", "2019-12-11T23:32:47+0x:00"] {
        assert_eq!(Timestamp::parse_iso8601(bad), None, "{bad}");
    }
}

#[test]
fn a_no_break_space_in_a_signed_header_is_not_a_space() {
    let signer = signer();
    let now = Timestamp::now();
    let headers = [("host", "s3.example.com"), ("content-type", "a b")];
    let request = Request { method: "PUT", path: "/bucket/key", query: "", headers: &headers };
    let signed = signer.sign(&request, EMPTY_PAYLOAD_SHA256, now).unwrap();
    let with = |content_type: &str| -> Result<(), SigError> {
        let all: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (*name, if *name == "content-type" { content_type } else { value }))
            .chain(signed.headers.iter().map(|(name, value)| (name.as_str(), value.as_str())))
            .collect();
        let request = Request { method: "PUT", path: "/bucket/key", query: "", headers: &all };
        verify(&request, now)
    };
    assert_eq!(with("a b"), Ok(()));
    // Spaces are folded as the signer folds them.
    assert_eq!(with("  a   b "), Ok(()));
    assert_eq!(with("a\u{a0}b"), Err(SigError::SignatureDoesNotMatch));
}

// ---- documents ----

#[test]
fn an_etag_or_a_version_with_white_space_around_it_is_the_etag_or_the_version() {
    use thirtys3_core::model::{CompleteMultipartUploadRequest, DeleteRequest, InitiateMultipartUploadResult};
    let complete =
        "<CompleteMultipartUpload>\n  <Part>\n    <PartNumber>1</PartNumber>\n    <ETag>\n      \"abc\"\n    </ETag>\n  </Part>\n</CompleteMultipartUpload>";
    assert_eq!(CompleteMultipartUploadRequest::from_xml(complete.as_bytes()).unwrap().parts[0].etag.as_deref(), Some("\"abc\""));
    let delete = "<Delete><Object><Key> keeps its spaces </Key><VersionId>\n v1\n</VersionId><ETag> \"e\" </ETag></Object></Delete>";
    let object = &DeleteRequest::from_xml(delete.as_bytes()).unwrap().objects[0];
    assert_eq!((object.key.as_str(), object.version_id.as_deref(), object.etag.as_deref()), (" keeps its spaces ", Some("v1"), Some("\"e\"")));
    let initiated = "<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>\n  u1\n</UploadId></InitiateMultipartUploadResult>";
    assert_eq!(InitiateMultipartUploadResult::from_xml(initiated.as_bytes()).unwrap().upload_id, "u1");
}

#[test]
fn a_delete_document_with_more_elements_than_a_delete_can_have_is_refused_before_it_is_built() {
    use thirtys3_core::model::DeleteRequest;
    use thirtys3_core::xml::XmlError;
    let many = format!("<Delete>{}</Delete>", "<Object><Key>a</Key></Object>".repeat(5001));
    assert!(matches!(DeleteRequest::from_xml(many.as_bytes()), Err(XmlError::TooManyElements(_))));
    let thousand = format!("<Delete>{}</Delete>", "<Object><Key>a</Key></Object>".repeat(1000));
    assert_eq!(DeleteRequest::from_xml(thousand.as_bytes()).unwrap().objects.len(), 1000);
    let deep = "<Delete><Object><Key><a><b/></a></Key></Object></Delete>";
    assert!(matches!(DeleteRequest::from_xml(deep.as_bytes()), Err(XmlError::TooDeep(_))));
}

#[test]
fn what_is_printed_of_an_error_leaves_out_what_was_signed() {
    use thirtys3_core::S3Error;
    let mut error = S3Error::new("SignatureDoesNotMatch", "The request signature we calculated does not match");
    error.details = vec![
        ("AWSAccessKeyId".into(), "AKIAEXAMPLE".into()),
        ("StringToSign".into(), "AWS4-HMAC-SHA256\nx-amz-security-token:TOKEN-VALUE".into()),
        ("CanonicalRequest".into(), "GET\n/\n\nx-amz-security-token:TOKEN-VALUE".into()),
    ];
    let printed = format!("{error:?} {error:#?}");
    assert!(!printed.contains("TOKEN-VALUE"), "{printed}");
    assert!(printed.contains("AKIAEXAMPLE") && printed.contains("SignatureDoesNotMatch"));
    // The error itself still has them, for whoever needs them.
    assert!(error.details[1].1.contains("TOKEN-VALUE"));
}

#[test]
fn a_throttled_or_timed_out_status_is_worth_trying_again() {
    use thirtys3_core::S3Error;
    for status in [408, 429, 500, 502, 503, 504] {
        let mut error = S3Error::new("Odd", "x");
        error.status = status;
        assert!(error.is_retryable(), "{status}");
    }
    let mut error = S3Error::new("Odd", "x");
    error.status = 400;
    assert!(!error.is_retryable());
}

#[test]
fn secrets_are_compared_without_stopping_at_the_first_difference() {
    use thirtys3_core::constant_time_eq;
    assert!(constant_time_eq(b"token", b"token"));
    assert!(!constant_time_eq(b"token", b"tokeN"));
    assert!(!constant_time_eq(b"token", b"token2"));
    assert!(!constant_time_eq(b"", b"x"));
    assert!(constant_time_eq(b"", b""));
}
