//! `ParsedAuth::check_time`: the clock check a server does before it counts a request as an attempt to guess a key.

use thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
use thirtys3_core::{Credentials, Request, SigError, Signer, Timestamp, parse_request_auth};

const NOW: Timestamp = Timestamp(1_700_000_000);

fn signer() -> Signer {
    Signer::new(Credentials::new("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "us-east-1")
}

/// The result of the time check of a request signed at `signed` and looked at at `now`.
fn header_request(signed: Timestamp, now: Timestamp) -> Result<(), SigError> {
    let headers = [("host", "s3.example.com")];
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &headers };
    let signed_request = signer().sign(&request, EMPTY_PAYLOAD_SHA256, signed).unwrap();
    let all: Vec<(&str, &str)> = headers.iter().copied().chain(signed_request.headers.iter().map(|(name, value)| (name.as_str(), value.as_str()))).collect();
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &all };
    parse_request_auth(&request).unwrap().expect("signed").check_time(now)
}

fn query_request(signed: Timestamp, expires: u64, now: Timestamp) -> Result<(), SigError> {
    let headers = [("host", "s3.example.com")];
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &headers };
    let query = signer().presign(&request, signed, expires).unwrap();
    let request = Request { method: "GET", path: "/bucket/key", query: &query, headers: &headers };
    parse_request_auth(&request).unwrap().expect("signed").check_time(now)
}

#[test]
fn a_header_signature_is_good_for_15_minutes_either_way() {
    assert_eq!(header_request(NOW, NOW), Ok(()));
    assert_eq!(header_request(Timestamp(NOW.0 - 900), NOW), Ok(()));
    assert_eq!(header_request(Timestamp(NOW.0 + 900), NOW), Ok(()));
    for signed in [NOW.0 - 901, NOW.0 + 901] {
        assert_eq!(header_request(Timestamp(signed), NOW), Err(SigError::RequestTimeTooSkewed { request_time: Timestamp(signed), server_time: NOW }));
    }
}

#[test]
fn a_presigned_url_is_good_from_15_minutes_before_its_date_until_it_expires() {
    assert_eq!(query_request(NOW, 60, NOW), Ok(()));
    assert_eq!(query_request(NOW, 60, Timestamp(NOW.0 + 60)), Ok(()));
    assert_eq!(query_request(NOW, 60, Timestamp(NOW.0 + 61)), Err(SigError::Expired(Timestamp(NOW.0 + 60))));
    // A URL made by a clock that is ahead is good as soon as the clock of the server is within 15 minutes of it.
    assert_eq!(query_request(Timestamp(NOW.0 + 900), 60, NOW), Ok(()));
    assert_eq!(query_request(Timestamp(NOW.0 + 901), 60, NOW), Err(SigError::RequestTimeTooSkewed { request_time: Timestamp(NOW.0 + 901), server_time: NOW }));
    // And a long URL is not limited to 15 minutes after its date.
    assert_eq!(query_request(NOW, 86400, Timestamp(NOW.0 + 3600)), Ok(()));
}
