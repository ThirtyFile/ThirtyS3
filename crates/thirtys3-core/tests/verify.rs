//! Signing a request and checking it again, and what must be refused.

use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, MAX_PRESIGNED_EXPIRES, STREAMING_SIGNED_PAYLOAD, UNSIGNED_PAYLOAD};
use thirtys3_core::{AuthKind, Credentials, PayloadHash, Request, SigError, Signer, Timestamp, parse_request_auth, sha256_hex};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const NOW: Timestamp = Timestamp(1_369_353_600); // 2013-05-24T00:00:00Z

fn signer() -> Signer {
    Signer::new(Credentials::new("AKIAIOSFODNN7EXAMPLE", SECRET), "us-east-1")
}

/// Signs a GET of `/photos/a b.jpg` and returns the headers to send.
fn signed_get(now: Timestamp) -> Vec<(String, String)> {
    let request = Request { method: "GET", path: "/bucket/photos/a%20b.jpg", query: "versionId=3&acl", headers: &[("Host", "s3.example.com")] };
    let mut headers = vec![("Host".to_owned(), "s3.example.com".to_owned())];
    headers.extend(signer().sign(&request, EMPTY_PAYLOAD_SHA256, now).unwrap().headers);
    headers
}

fn borrowed(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect()
}

fn verify(method: &str, path: &str, query: &str, headers: &[(String, String)], now: Timestamp) -> Result<thirtys3_core::Verified, SigError> {
    let headers = borrowed(headers);
    let request = Request { method, path, query, headers: &headers };
    let auth = parse_request_auth(&request)?.expect("the request is signed");
    auth.verify(&request, SECRET, now)
}

#[test]
fn a_signed_request_verifies() {
    let headers = signed_get(NOW);
    let verified = verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, NOW).unwrap();
    assert_eq!(verified.access_key_id, "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(verified.scope.to_string(), "20130524/us-east-1/s3/aws4_request");
    assert_eq!(verified.kind, AuthKind::Header);
    assert_eq!(verified.payload_hash, PayloadHash::Sha256(EMPTY_PAYLOAD_SHA256.to_owned()));
}

#[test]
fn the_path_may_be_encoded_in_another_way_than_it_was_signed() {
    // `a%20b.jpg` was signed; a client may send `!` or `~` encoded or not, and the signature must hold.
    let request = Request { method: "GET", path: "/bucket/a!b~c.txt", query: "", headers: &[("Host", "s3.example.com")] };
    let mut headers = vec![("Host".to_owned(), "s3.example.com".to_owned())];
    headers.extend(signer().sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap().headers);
    verify("GET", "/bucket/a!b~c.txt", "", &headers, NOW).unwrap();
    verify("GET", "/bucket/a%21b%7Ec.txt", "", &headers, NOW).unwrap();
}

#[test]
fn a_changed_request_does_not_verify() {
    let headers = signed_get(NOW);
    for (method, path, query) in [
        ("PUT", "/bucket/photos/a%20b.jpg", "versionId=3&acl"),
        ("GET", "/bucket/photos/a%20c.jpg", "versionId=3&acl"),
        ("GET", "/bucket/photos/a%20b.jpg", "versionId=4&acl"),
        ("GET", "/bucket/photos/a%20b.jpg", "versionId=3"),
        ("GET", "/bucket/photos//a%20b.jpg", "versionId=3&acl"),
    ] {
        assert_eq!(verify(method, path, query, &headers, NOW).unwrap_err(), SigError::SignatureDoesNotMatch, "{method} {path}?{query}");
    }
    let mut other_host = headers.clone();
    other_host[0].1 = "evil.example.com".to_owned();
    assert_eq!(verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &other_host, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn the_wrong_secret_does_not_verify() {
    let owned = signed_get(NOW);
    let headers = borrowed(&owned);
    let request = Request { method: "GET", path: "/bucket/photos/a%20b.jpg", query: "versionId=3&acl", headers: &headers };
    let auth = parse_request_auth(&request).unwrap().unwrap();
    assert_eq!(auth.verify(&request, "not the secret", NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn query_parameter_order_and_encoding_do_not_matter() {
    let headers = signed_get(NOW);
    verify("GET", "/bucket/photos/a%20b.jpg", "acl&versionId=3", &headers, NOW).unwrap();
    verify("GET", "/bucket/photos/a%20b.jpg", "acl=&%76ersionId=3", &headers, NOW).unwrap();
}

#[test]
fn clock_skew_of_fifteen_minutes_is_allowed_and_a_second_more_is_not() {
    let headers = signed_get(NOW);
    for offset in [-900, 900] {
        verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, Timestamp(NOW.0 + offset)).unwrap();
    }
    for offset in [-901, 901] {
        let error = verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, Timestamp(NOW.0 + offset)).unwrap_err();
        assert!(matches!(error, SigError::RequestTimeTooSkewed { .. }), "{error:?}");
    }
}

#[test]
fn x_amz_headers_that_were_not_signed_are_refused() {
    let mut headers = signed_get(NOW);
    headers.push(("x-amz-meta-sneaky".to_owned(), "1".to_owned()));
    assert_eq!(
        verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, NOW).unwrap_err(),
        SigError::HeadersNotSigned(vec!["x-amz-meta-sneaky".to_owned()])
    );
}

#[test]
fn a_header_that_was_signed_but_is_missing_is_refused() {
    let headers: Vec<_> = signed_get(NOW).into_iter().filter(|(name, _)| name != "x-amz-date").collect();
    assert!(
        matches!(verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, NOW).unwrap_err(), SigError::MissingHeader(name) if name == "x-amz-date")
    );
}

#[test]
fn a_missing_payload_hash_header_is_refused() {
    let headers: Vec<_> = signed_get(NOW).into_iter().filter(|(name, _)| name != "x-amz-content-sha256").collect();
    assert!(
        matches!(verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, NOW).unwrap_err(), SigError::MissingHeader(name) if name == "x-amz-content-sha256")
    );
}

#[test]
fn headers_are_found_whatever_the_case_and_values_are_cleaned() {
    // Signed with two spaces inside a value and a header that appears twice; sent with other case and spacing.
    let request =
        Request { method: "GET", path: "/b/k", query: "", headers: &[("Host", "h"), ("x-amz-meta-a", "one  two"), ("X-Amz-Meta-B", "x"), ("x-amz-meta-b", " y ")] };
    let mut headers: Vec<(String, String)> = request.headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect();
    headers.extend(signer().sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap().headers);
    verify("GET", "/b/k", "", &headers, NOW).unwrap();
    // The two values of the repeated header are joined with a comma, in the order they came, so the order is part of the signature.
    let mut swapped = headers.clone();
    let (first, second) = (swapped.iter().position(|(n, _)| n == "X-Amz-Meta-B").unwrap(), swapped.iter().position(|(n, _)| n == "x-amz-meta-b").unwrap());
    swapped.swap(first, second);
    assert_eq!(verify("GET", "/b/k", "", &swapped, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn temporary_credentials_sign_the_session_token() {
    let signer = Signer::new(Credentials { session_token: Some("TOKEN".to_owned()), ..Credentials::new("AKIA", SECRET) }, "eu-west-1");
    let request = Request { method: "GET", path: "/b", query: "", headers: &[("Host", "h")] };
    let signed = signer.sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap();
    assert!(signed.signed_headers.contains(&"x-amz-security-token".to_owned()));
    let mut headers = vec![("Host".to_owned(), "h".to_owned())];
    headers.extend(signed.headers);
    let verified = verify("GET", "/b", "", &headers, NOW).unwrap();
    assert_eq!(verified.session_token.as_deref(), Some("TOKEN"));
    assert_eq!(verified.scope.region, "eu-west-1");
}

#[test]
fn an_anonymous_request_has_no_authentication() {
    let request = Request { method: "GET", path: "/b/k", query: "prefix=x", headers: &[("Host", "h")] };
    assert_eq!(parse_request_auth(&request).unwrap(), None);
}

#[test]
fn signature_version_2_and_other_schemes_are_unsupported() {
    for value in ["AWS AKIAIOSFODNN7EXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=", "Bearer abc", "AWS4-HMAC-SHA512 Credential=x"] {
        let request = Request { method: "GET", path: "/b", query: "", headers: &[("Host", "h"), ("Authorization", value)] };
        assert!(matches!(parse_request_auth(&request).unwrap_err(), SigError::UnsupportedAlgorithm(_)), "{value}");
    }
}

#[test]
fn malformed_authorization_headers_are_refused() {
    let good = "AWS4-HMAC-SHA256 Credential=AKIA/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=";
    let sig = "0".repeat(64);
    let cases = [
        format!("{good}{sig}"), // this one is fine
        "AWS4-HMAC-SHA256".to_owned(),
        format!("{good}{sig}, Extra=1"),
        format!("{good}{sig}, Signature={sig}"),
        format!("{good}xyz"),
        format!("{}Signature={sig}", good.replace("/s3/", "/ec2/").trim_end_matches("Signature=")),
        format!("{}Signature={sig}", good.replace("20130524/us-east-1", "2013/us-east-1").trim_end_matches("Signature=")),
        format!("{}Signature={sig}", good.replace("host;x-amz-date", "x-amz-date").trim_end_matches("Signature=")),
        format!("{}Signature={sig}", good.replace("aws4_request", "aws5_request").trim_end_matches("Signature=")),
        format!("{}Signature={sig}", good.replace("Credential=AKIA/", "Credential=").trim_end_matches("Signature=")),
    ];
    let outcomes: Vec<bool> = cases
        .iter()
        .map(|value| {
            let request = Request { method: "GET", path: "/b", query: "", headers: &[("Host", "h"), ("x-amz-date", "20130524T000000Z"), ("Authorization", value)] };
            parse_request_auth(&request).is_ok()
        })
        .collect();
    assert_eq!(outcomes, [true, false, false, false, false, false, false, false, false, false]);
}

#[test]
fn the_date_must_be_on_the_day_of_the_scope() {
    let value = format!("AWS4-HMAC-SHA256 Credential=AKIA/20130524/us-east-1/s3/aws4_request,SignedHeaders=host,Signature={}", "0".repeat(64));
    for date in ["20130525T000000Z", "2013-05-24T00:00:00Z", "20130524T000060Z", "20130230T000000Z"] {
        let request = Request { method: "GET", path: "/b", query: "", headers: &[("Host", "h"), ("x-amz-date", date), ("Authorization", &value)] };
        assert!(matches!(parse_request_auth(&request).unwrap_err(), SigError::InvalidDate(_)), "{date}");
    }
}

#[test]
fn an_authorization_header_together_with_a_presigned_query_is_refused() {
    let request =
        Request { method: "GET", path: "/b", query: "X-Amz-Algorithm=AWS4-HMAC-SHA256", headers: &[("Host", "h"), ("Authorization", "AWS4-HMAC-SHA256 x")] };
    assert_eq!(parse_request_auth(&request).unwrap_err(), SigError::ConflictingAuthentication);
}

#[test]
fn two_authorization_headers_are_refused() {
    let request = Request { method: "GET", path: "/b", query: "", headers: &[("Host", "h"), ("Authorization", "a"), ("authorization", "b")] };
    assert!(matches!(parse_request_auth(&request).unwrap_err(), SigError::MalformedAuthorization(_)));
}

// ---- presigned URLs ----

fn presigned(method: &str, query: &str, expires: u64) -> String {
    let request = Request { method, path: "/bucket/some key", query, headers: &[("Host", "s3.example.com")] };
    signer().presign(&request, NOW, expires).unwrap()
}

fn verify_presigned(method: &str, query: &str, now: Timestamp) -> Result<thirtys3_core::Verified, SigError> {
    let request = Request { method, path: "/bucket/some%20key", query, headers: &[("Host", "s3.example.com")] };
    parse_request_auth(&request)?.expect("the URL is presigned").verify(&request, SECRET, now)
}

#[test]
fn a_presigned_url_verifies_until_it_expires() {
    let query = presigned("GET", "response-content-type=text%2Fplain", 60);
    let verified = verify_presigned("GET", &query, NOW).unwrap();
    assert_eq!(verified.kind, AuthKind::Query);
    assert_eq!(verified.payload_hash, PayloadHash::Unsigned);
    verify_presigned("GET", &query, Timestamp(NOW.0 + 60)).unwrap();
    assert_eq!(verify_presigned("GET", &query, Timestamp(NOW.0 + 61)).unwrap_err(), SigError::Expired(Timestamp(NOW.0 + 60)));
}

#[test]
fn a_presigned_url_is_not_yet_valid_more_than_fifteen_minutes_before_its_date() {
    let query = presigned("GET", "", 60);
    verify_presigned("GET", &query, Timestamp(NOW.0 - 900)).unwrap();
    assert!(matches!(verify_presigned("GET", &query, Timestamp(NOW.0 - 901)).unwrap_err(), SigError::RequestTimeTooSkewed { .. }));
}

#[test]
fn a_presigned_url_is_only_good_for_the_method_it_was_made_for() {
    let query = presigned("PUT", "", 60);
    verify_presigned("PUT", &query, NOW).unwrap();
    assert_eq!(verify_presigned("GET", &query, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn changing_a_presigned_url_breaks_it() {
    let query = presigned("GET", "", 60);
    // A longer expiry, another signed header list, another key and an extra parameter all change what was signed.
    for changed in [
        query.replace("X-Amz-Expires=60", "X-Amz-Expires=600"),
        format!("{query}&extra=1"),
        query.replace("X-Amz-SignedHeaders=host", "X-Amz-SignedHeaders=host%3Brange"),
    ] {
        let error = verify_presigned("GET", &changed, NOW).unwrap_err();
        assert!(matches!(error, SigError::SignatureDoesNotMatch | SigError::SignedHeaderMissing(_)), "{changed}: {error:?}");
    }
    let request = Request { method: "GET", path: "/bucket/other", query: &query, headers: &[("Host", "s3.example.com")] };
    let auth = parse_request_auth(&request).unwrap().unwrap();
    assert_eq!(auth.verify(&request, SECRET, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn presigning_keeps_the_query_it_was_given_and_signs_it() {
    let query = presigned("GET", "response-content-disposition=attachment%3B%20filename%3D%22a.txt%22&uploads", 60);
    assert!(query.contains("response-content-disposition=attachment%3B%20filename%3D%22a.txt%22"), "{query}");
    assert!(query.contains("uploads="), "{query}");
    verify_presigned("GET", &query, NOW).unwrap();
    let tampered = query.replace("a.txt", "b.txt");
    assert_eq!(verify_presigned("GET", &tampered, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn the_expiry_is_between_one_second_and_seven_days() {
    let request = Request { method: "GET", path: "/b/k", query: "", headers: &[("Host", "h")] };
    for expires in [0, MAX_PRESIGNED_EXPIRES + 1] {
        assert!(matches!(signer().presign(&request, NOW, expires).unwrap_err(), SigError::InvalidExpires(_)));
    }
    signer().presign(&request, NOW, 1).unwrap();
    signer().presign(&request, NOW, MAX_PRESIGNED_EXPIRES).unwrap();
    for bad in ["0", "604801", "-5", "abc", "", "1.5"] {
        let query = presigned("GET", "", 60).replace("X-Amz-Expires=60", &format!("X-Amz-Expires={bad}"));
        assert!(matches!(verify_presigned("GET", &query, NOW).unwrap_err(), SigError::InvalidExpires(_)), "{bad:?}");
    }
}

#[test]
fn a_presigned_url_with_a_missing_or_repeated_parameter_is_refused() {
    let query = presigned("GET", "", 60);
    for name in ["X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"] {
        let without: String = query.split('&').filter(|pair| !pair.starts_with(name)).collect::<Vec<_>>().join("&");
        assert!(matches!(verify_presigned("GET", &without, NOW).unwrap_err(), SigError::MalformedQuery(_)), "without {name}");
    }
    let twice = format!("{query}&X-Amz-Date=20130524T000001Z");
    assert!(matches!(verify_presigned("GET", &twice, NOW).unwrap_err(), SigError::MalformedQuery(_)));
}

#[test]
fn a_presigned_url_cannot_be_made_from_a_query_that_has_amz_parameters() {
    let request = Request { method: "GET", path: "/b/k", query: "X-Amz-Signature=abc", headers: &[("Host", "h")] };
    assert!(matches!(signer().presign(&request, NOW, 60).unwrap_err(), SigError::MalformedQuery(_)));
}

#[test]
fn presigned_urls_carry_the_session_token_in_the_query() {
    let signer = Signer::new(Credentials { session_token: Some("a+b/c=".to_owned()), ..Credentials::new("AKIA", SECRET) }, "us-east-1");
    let request = Request { method: "GET", path: "/b/k", query: "", headers: &[("Host", "h")] };
    let query = signer.presign(&request, NOW, 60).unwrap();
    assert!(query.contains("X-Amz-Security-Token=a%2Bb%2Fc%3D"), "{query}");
    let request = Request { query: &query, ..request };
    let verified = parse_request_auth(&request).unwrap().unwrap().verify(&request, SECRET, NOW).unwrap();
    assert_eq!(verified.session_token.as_deref(), Some("a+b/c="));
}

// ---- the body ----

#[test]
fn the_payload_hash_values_are_told_apart() {
    assert_eq!(PayloadHash::parse(UNSIGNED_PAYLOAD).unwrap(), PayloadHash::Unsigned);
    assert_eq!(PayloadHash::parse(STREAMING_SIGNED_PAYLOAD).unwrap(), PayloadHash::StreamingSigned);
    assert_eq!(PayloadHash::parse("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER").unwrap(), PayloadHash::StreamingSignedTrailer);
    assert_eq!(PayloadHash::parse("STREAMING-UNSIGNED-PAYLOAD-TRAILER").unwrap(), PayloadHash::StreamingUnsignedTrailer);
    assert_eq!(PayloadHash::parse(&EMPTY_PAYLOAD_SHA256.to_uppercase()).unwrap(), PayloadHash::Sha256(EMPTY_PAYLOAD_SHA256.to_owned()));
    for bad in ["", "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", "abc", &"g".repeat(64), &"a".repeat(63)] {
        assert!(matches!(PayloadHash::parse(bad), Err(SigError::InvalidPayloadHash(_))), "{bad:?}");
    }
}

#[test]
fn a_request_with_signed_chunks_gives_the_receiver_a_chain_that_checks_what_the_sender_signed() {
    let request =
        Request { method: "PUT", path: "/b/k", query: "", headers: &[("Host", "h"), ("Content-Encoding", "aws-chunked"), ("x-amz-decoded-content-length", "11")] };
    let signed = signer().sign(&request, STREAMING_SIGNED_PAYLOAD, NOW).unwrap();
    let mut headers: Vec<(String, String)> = request.headers.iter().map(|(n, v)| ((*n).to_owned(), (*v).to_owned())).collect();
    headers.extend(signed.headers.clone());
    let verified = verify("PUT", "/b/k", "", &headers, NOW).unwrap();
    assert_eq!(verified.payload_hash, PayloadHash::StreamingSigned);

    let hashes = [sha256_hex(b"hello "), sha256_hex(b"world"), EMPTY_PAYLOAD_SHA256.to_owned()];
    let mut sender = signer().chunk_chain(&signed);
    let signatures: Vec<String> = hashes.iter().map(|hash| sender.sign_chunk(hash)).collect();

    let mut receiver = verified.chunk_chain().expect("signed chunks");
    for (hash, signature) in hashes.iter().zip(&signatures) {
        receiver.verify_chunk(hash, signature).unwrap();
    }

    // A chunk with other data, a chunk out of order and a chunk skipped are all refused, and a refusal does not move the chain on.
    let mut receiver = verified.chunk_chain().unwrap();
    assert_eq!(receiver.verify_chunk(&sha256_hex(b"HELLO "), &signatures[0]).unwrap_err(), SigError::SignatureDoesNotMatch);
    assert_eq!(receiver.verify_chunk(&hashes[1], &signatures[1]).unwrap_err(), SigError::SignatureDoesNotMatch);
    receiver.verify_chunk(&hashes[0], &signatures[0]).unwrap();
    assert_eq!(receiver.verify_chunk(&hashes[2], &signatures[2]).unwrap_err(), SigError::SignatureDoesNotMatch);
    receiver.verify_chunk(&hashes[1], &signatures[1]).unwrap();
    receiver.verify_chunk(&hashes[2], &signatures[2]).unwrap();
}

#[test]
fn only_signed_chunked_bodies_have_a_chunk_chain() {
    let headers = signed_get(NOW);
    assert!(verify("GET", "/bucket/photos/a%20b.jpg", "versionId=3&acl", &headers, NOW).unwrap().chunk_chain().is_none());
}

#[test]
fn credentials_do_not_show_their_secrets_when_printed() {
    let credentials = Credentials { session_token: Some("SECRET-TOKEN".to_owned()), ..Credentials::new("AKIA", SECRET) };
    let printed = format!("{credentials:?} {:?}", signer());
    assert!(!printed.contains(SECRET) && !printed.contains("SECRET-TOKEN"), "{printed}");
    assert!(printed.contains("AKIA"));
}

#[test]
fn signing_needs_a_host_header() {
    let request = Request { method: "GET", path: "/b", query: "", headers: &[("Range", "bytes=0-1")] };
    assert!(matches!(signer().sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap_err(), SigError::MissingHeader(name) if name == "host"));
    assert!(matches!(signer().presign(&request, NOW, 60).unwrap_err(), SigError::MissingHeader(name) if name == "host"));
}

#[test]
fn headers_that_proxies_change_are_not_signed() {
    let request = Request {
        method: "GET",
        path: "/b",
        query: "",
        headers: &[("Host", "h"), ("User-Agent", "x"), ("Connection", "keep-alive"), ("Expect", "100-continue"), ("Content-Type", "text/plain")],
    };
    let signed = signer().sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap();
    assert_eq!(signed.signed_headers.join(";"), "content-type;host;x-amz-content-sha256;x-amz-date");
}
