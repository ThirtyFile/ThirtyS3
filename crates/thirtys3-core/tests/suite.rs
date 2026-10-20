//! AWS's own signing test suite (`tests/aws-signing-test-suite/`, see the README there), run against the low-level functions.
//!
//! The suite signs for a service called `service` and does not add `x-amz-content-sha256`, so it cannot go through `Signer`, which is for S3;
//! it goes through `canonical_request`, `string_to_sign` and `SigningKey`, which are the same code `Signer` uses.

use std::fs;
use std::path::Path;

use thirtys3_core::encoding::uri_encode;
use thirtys3_core::sigv4::{Scope, SigningKey, canonical_request, string_to_sign};
use thirtys3_core::{Request, Timestamp, sha256_hex};

const SUITE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/aws-signing-test-suite/v4");

/// The cases of the suite from before it had a `context.json`; they are for services that encode the path twice, which S3 does not.
const DOUBLE_ENCODING_CASES: &[&str] = &["double-encode-path", "double-url-encode"];

/// The suite's cases that expect `.`, `..` and `//` in the path to be normalised, with the case that has the same request and expects
/// the path as it is, which is what S3 does.
const NORMALISING_CASES: &[(&str, &str)] = &[
    ("get-relative-normalized", "get-relative-unnormalized"),
    ("get-relative-relative-normalized", "get-relative-relative-unnormalized"),
    ("get-slash-dot-slash-normalized", "get-slash-dot-slash-unnormalized"),
    ("get-slash-normalized", "get-slash-unnormalized"),
    ("get-slash-pointless-dot-normalized", "get-slash-pointless-dot-unnormalized"),
    ("get-slashes-normalized", "get-slashes-unnormalized"),
];

struct Case {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
    time: Timestamp,
    scope: Scope,
    access_key_id: String,
    secret: String,
    token: Option<String>,
    expires: u64,
    sign_body: bool,
    omit_session_token: bool,
}

fn read(case: &str, file: &str) -> String {
    fs::read_to_string(Path::new(SUITE).join(case).join(file)).unwrap_or_else(|error| panic!("{case}/{file}: {error}"))
}

fn load(name: &str) -> Case {
    let context: serde_json::Value = serde_json::from_str(&read(name, "context.json")).unwrap();
    let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();
    let request = read(name, "request.txt");
    let (head, body) = request.split_once("\n\n").unwrap_or((request.trim_end(), ""));
    let mut lines = head.lines();
    let request_line = lines.next().unwrap();
    let (method, target) = request_line.strip_suffix(" HTTP/1.1").unwrap().split_once(' ').unwrap();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            // A continuation line belongs to the value before it.
            let last = headers.last_mut().unwrap();
            last.1.push(' ');
            last.1.push_str(line);
        } else {
            let (header, value) = line.split_once(':').unwrap();
            headers.push((header.to_owned(), value.to_owned()));
        }
    }
    let timestamp = text(&context["timestamp"]).replace(['-', ':'], "");
    let time = Timestamp::parse_amz_date(&timestamp).unwrap();
    let credentials = &context["credentials"];
    Case {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body: body.to_owned(),
        scope: Scope { date: time.date(), region: text(&context["region"]), service: text(&context["service"]) },
        time,
        access_key_id: text(&credentials["access_key_id"]),
        secret: text(&credentials["secret_access_key"]),
        token: credentials.get("token").map(text),
        expires: context["expiration_in_seconds"].as_u64().unwrap(),
        sign_body: context["sign_body"].as_bool().unwrap(),
        omit_session_token: context.get("omit_session_token").and_then(serde_json::Value::as_bool).unwrap_or(false),
    }
}

/// The canonical request, the string to sign and the signature, as the suite builds them for a signature in the header.
fn header_variant(case: &Case) -> (String, String, String) {
    let mut headers = case.headers.clone();
    headers.push(("x-amz-date".to_owned(), case.time.amz_date()));
    if let (Some(token), false) = (&case.token, case.omit_session_token) {
        headers.push(("x-amz-security-token".to_owned(), token.clone()));
    }
    let payload_hash = sha256_hex(case.body.as_bytes());
    if case.sign_body {
        headers.push(("x-amz-content-sha256".to_owned(), payload_hash.clone()));
    }
    let mut names: Vec<String> = headers.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    names.sort();
    names.dedup();
    let pairs: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let request = Request { method: &case.method, path: &case.path, query: &case.query, headers: &pairs };
    let canonical = canonical_request(&request, &names, &payload_hash, false).unwrap();
    let to_sign = string_to_sign(&case.time.amz_date(), &case.scope, &canonical);
    let signature = SigningKey::derive(&case.secret, &case.scope).sign_hex(to_sign.as_bytes());
    (canonical, to_sign, signature)
}

/// The same for a signature in the query string.
fn query_variant(case: &Case) -> (String, String, String) {
    let mut names: Vec<String> = case.headers.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    names.sort();
    names.dedup();
    let mut query = case.query.clone();
    let mut add = |name: &str, value: &str| {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&format!("{name}={}", uri_encode(value.as_bytes(), true)));
    };
    add("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    add("X-Amz-Credential", &format!("{}/{}", case.access_key_id, case.scope));
    add("X-Amz-Date", &case.time.amz_date());
    add("X-Amz-Expires", &case.expires.to_string());
    add("X-Amz-SignedHeaders", &names.join(";"));
    if let (Some(token), false) = (&case.token, case.omit_session_token) {
        add("X-Amz-Security-Token", token);
    }
    let pairs: Vec<(&str, &str)> = case.headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let request = Request { method: &case.method, path: &case.path, query: &query, headers: &pairs };
    let canonical = canonical_request(&request, &names, &sha256_hex(case.body.as_bytes()), false).unwrap();
    let to_sign = string_to_sign(&case.time.amz_date(), &case.scope, &canonical);
    let signature = SigningKey::derive(&case.secret, &case.scope).sign_hex(to_sign.as_bytes());
    (canonical, to_sign, signature)
}

fn cases() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(SUITE).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

#[test]
fn the_suite_is_all_there() {
    // 38 cases with a context.json and the two older ones. If the copy loses a case, this says so instead of the others passing on less.
    assert_eq!(cases().len(), 40);
    assert_eq!(cases().iter().filter(|name| Path::new(SUITE).join(name).join("context.json").exists()).count(), 38);
}

#[test]
fn signatures_in_the_header() {
    let mut checked = 0;
    for name in cases() {
        if DOUBLE_ENCODING_CASES.contains(&name.as_str()) {
            continue;
        }
        let case = load(&name);
        let (canonical, to_sign, signature) = header_variant(&case);
        // A case that expects the path normalised is checked against the twin that expects it as it is.
        let reference = NORMALISING_CASES.iter().find(|(normalising, _)| *normalising == name).map_or(name.as_str(), |(_, twin)| twin);
        if reference != name {
            assert_eq!(read(&name, "request.txt"), read(reference, "request.txt"), "{name} and {reference} are the same request");
        }
        assert_eq!(canonical, read(reference, "header-canonical-request.txt").trim_end(), "{name}: canonical request");
        assert_eq!(to_sign, read(reference, "header-string-to-sign.txt").trim_end(), "{name}: string to sign");
        assert_eq!(signature, read(reference, "header-signature.txt").trim(), "{name}: signature");
        checked += 1;
    }
    assert_eq!(checked, 38);
}

#[test]
fn signatures_in_the_query() {
    let mut checked = 0;
    for name in cases() {
        if DOUBLE_ENCODING_CASES.contains(&name.as_str()) {
            continue;
        }
        let case = load(&name);
        let (canonical, to_sign, signature) = query_variant(&case);
        let reference = NORMALISING_CASES.iter().find(|(normalising, _)| *normalising == name).map_or(name.as_str(), |(_, twin)| twin);
        assert_eq!(canonical, read(reference, "query-canonical-request.txt").trim_end(), "{name}: canonical request");
        assert_eq!(to_sign, read(reference, "query-string-to-sign.txt").trim_end(), "{name}: string to sign");
        assert_eq!(signature, read(reference, "query-signature.txt").trim(), "{name}: signature");
        checked += 1;
    }
    assert_eq!(checked, 38);
}
