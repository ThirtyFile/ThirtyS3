//! The `Date` header as the time of a request that has no `x-amz-date`, which Signature Version 4 allows and older clients use.
//!
//! ThirtyFile accepts such requests today, so a server built on this crate has to, with the same 15 minutes of clock skew.

use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, Scope, SigningKey, canonical_request, string_to_sign};
use thirtys3_core::{Credentials, Request, SigError, Signer, Timestamp, Verified, parse_request_auth};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const NOW: Timestamp = Timestamp(1_369_353_600); // 2013-05-24T00:00:00Z

fn verify(headers: &[(String, String)], now: Timestamp) -> Result<Verified, SigError> {
    let borrowed: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &borrowed };
    parse_request_auth(&request)?.expect("the request is signed").verify(&request, SECRET, now)
}

/// Signs a GET the way a client does that sends a `Date` header and no `x-amz-date`: the time in the string to sign is the `Date` as ISO 8601.
fn signed_with_date(date_header: &str, time: Timestamp) -> Vec<(String, String)> {
    let headers = [("Host", "s3.example.com"), ("Date", date_header), ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)];
    let names: Vec<String> = ["date", "host", "x-amz-content-sha256"].iter().map(|name| (*name).to_owned()).collect();
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &headers };
    let canonical = canonical_request(&request, &names, EMPTY_PAYLOAD_SHA256, false).unwrap();
    let scope = Scope::new(time, "us-east-1");
    let signature = SigningKey::derive(SECRET, &scope).sign_hex(string_to_sign(&time.amz_date(), &scope, &canonical).as_bytes());
    let authorization = format!("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/{scope},SignedHeaders=date;host;x-amz-content-sha256,Signature={signature}");
    headers.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).chain([("Authorization".to_owned(), authorization)]).collect()
}

fn set(headers: &mut [(String, String)], name: &str, value: &str) {
    headers.iter_mut().find(|(candidate, _)| candidate == name).unwrap().1 = value.to_owned();
}

#[test]
fn a_request_signed_with_the_date_header_and_no_x_amz_date_verifies() {
    let headers = signed_with_date(&NOW.http_date(), NOW);
    assert!(headers.iter().all(|(name, _)| !name.eq_ignore_ascii_case("x-amz-date")));
    let verified = verify(&headers, NOW).unwrap();
    assert_eq!(verified.amz_date, "20130524T000000Z");
    assert_eq!(verified.scope.date, "20130524");
}

#[test]
fn the_date_header_in_the_other_http_date_forms_verifies_too() {
    for date in ["Friday, 24-May-13 00:00:00 GMT", "Fri May 24 00:00:00 2013"] {
        verify(&signed_with_date(date, NOW), NOW).unwrap_or_else(|error| panic!("{date}: {error}"));
    }
}

#[test]
fn the_clock_skew_of_fifteen_minutes_applies_to_the_date_header_too() {
    let headers = signed_with_date(&NOW.http_date(), NOW);
    for offset in [-900, 900] {
        verify(&headers, Timestamp(NOW.0 + offset)).unwrap();
    }
    for offset in [-901, 901, 3600] {
        let error = verify(&headers, Timestamp(NOW.0 + offset)).unwrap_err();
        assert!(matches!(error, SigError::RequestTimeTooSkewed { .. }), "{offset}: {error:?}");
    }
}

#[test]
fn a_changed_date_does_not_verify() {
    let mut headers = signed_with_date(&NOW.http_date(), NOW);
    set(&mut headers, "Date", &Timestamp(NOW.0 + 1).http_date());
    assert_eq!(verify(&headers, NOW).unwrap_err(), SigError::SignatureDoesNotMatch);
}

#[test]
fn x_amz_date_is_used_when_both_are_there_and_a_wrong_one_is_not_replaced_by_the_date() {
    // Both there: x-amz-date is the time, whatever Date says.
    let request = Request { method: "GET", path: "/bucket/key", query: "", headers: &[("Host", "s3.example.com")] };
    let signer = Signer::new(Credentials::new("AKIAIOSFODNN7EXAMPLE", SECRET), "us-east-1");
    let mut headers = vec![("Host".to_owned(), "s3.example.com".to_owned()), ("Date".to_owned(), "Sun, 06 Nov 1994 08:49:37 GMT".to_owned())];
    headers.extend(signer.sign(&request, EMPTY_PAYLOAD_SHA256, NOW).unwrap().headers);
    verify(&headers, NOW).unwrap();
    // A malformed x-amz-date is an error even with a good Date next to it, as in ThirtyFile.
    let mut broken = headers.clone();
    set(&mut broken, "x-amz-date", "2013-05-24");
    set(&mut broken, "Date", &NOW.http_date());
    assert!(matches!(verify(&broken, NOW).unwrap_err(), SigError::InvalidDate(_)));
}

#[test]
fn a_missing_or_malformed_date_is_refused() {
    let headers = signed_with_date(&NOW.http_date(), NOW);
    let without_date: Vec<_> = headers.iter().filter(|(name, _)| name != "Date").cloned().collect();
    assert!(matches!(verify(&without_date, NOW).unwrap_err(), SigError::MissingHeader(name) if name == "x-amz-date"));
    for bad in ["yesterday", "", "2013-05-24T00:00:00Z", "Fri, 24 May 2013 00:00:00"] {
        let mut broken = headers.clone();
        set(&mut broken, "Date", bad);
        assert!(matches!(verify(&broken, NOW).unwrap_err(), SigError::InvalidDate(_)), "{bad:?}");
    }
}

#[test]
fn the_date_must_be_on_the_day_of_the_scope() {
    // Signed for 24 May, but the Date is a day later.
    let mut headers = signed_with_date(&NOW.http_date(), NOW);
    set(&mut headers, "Date", &Timestamp(NOW.0 + 86400).http_date());
    assert!(matches!(verify(&headers, NOW).unwrap_err(), SigError::InvalidDate(_)));
}
