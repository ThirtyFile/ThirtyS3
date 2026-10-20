#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_decode};
use thirtys3_core::encoding::{canonical_query, canonical_uri, hex_decode, percent_decode, query_params};
use thirtys3_core::etag::ETagCondition;
use thirtys3_core::{Request, Timestamp, parse_request_auth};
use thirtys3_server::conditions::{Conditions, parse_range};

// The values of headers and the like: text from a stranger.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some(spec) = parse_range(&text) {
        for size in [0, 1, 1000, u64::MAX] {
            if let Ok(range) = spec.resolve(size) {
                assert!(range.start < range.end && range.end <= size);
            }
        }
    }
    if let Some(condition) = ETagCondition::parse(&text) {
        let _ = condition.matches("\"abc\"", true);
        let _ = condition.matches("W/\"abc\"", false);
    }
    let _ = Timestamp::parse_amz_date(&text);
    let _ = Timestamp::parse_iso8601(&text);
    let _ = Timestamp::parse_http_date(&text);
    let _ = base64_decode(&text);
    let _ = hex_decode(&text);
    let _ = percent_decode(&text, true);
    let _ = percent_decode(&text, false);
    let _ = canonical_uri(&text);
    let _ = canonical_query(&text, |_| false);
    let _ = query_params(&text);
    for algorithm in ChecksumAlgorithm::ALL {
        let _ = algorithm.decode_value(&text);
    }
    let _ = ChecksumAlgorithm::from_header_name(&text);
    let _ = parse_request_auth(&Request { method: "GET", path: "/", query: &text, headers: &[("host", "example.com")] });
    let mut headers = HeaderMap::new();
    for name in ["if-match", "if-none-match", "if-modified-since", "if-unmodified-since"] {
        if let Ok(value) = HeaderValue::from_bytes(data) {
            headers.insert(HeaderName::from_static(name), value);
        }
    }
    let _ = Conditions::from_headers(&headers, false).evaluate("\"abc\"", Timestamp(0));
});
