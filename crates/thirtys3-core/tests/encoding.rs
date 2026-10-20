//! URI encoding and the canonical path and query: the rules of `UriEncode()` and the cases where implementations tend to differ.

use thirtys3_core::encoding::{canonical_query, canonical_uri, hex_decode, hex_encode, percent_decode, query_params, uri_encode};

fn encode(text: &str) -> String {
    uri_encode(text.as_bytes(), true)
}

#[test]
fn unreserved_characters_are_kept_and_everything_else_is_encoded_with_upper_case_hex() {
    assert_eq!(encode("AZaz09-._~"), "AZaz09-._~");
    assert_eq!(encode("a b"), "a%20b");
    assert_eq!(encode("a+b"), "a%2Bb");
    assert_eq!(encode("!*'();:@&=$,/?#[]"), "%21%2A%27%28%29%3B%3A%40%26%3D%24%2C%2F%3F%23%5B%5D");
    assert_eq!(encode("é"), "%C3%A9");
    assert_eq!(encode("中文"), "%E4%B8%AD%E6%96%87");
    assert_eq!(encode("😀"), "%F0%9F%98%80");
    assert_eq!(encode("\u{1a}\u{7f}"), "%1A%7F");
    assert_eq!(uri_encode(&[0xff, 0x00], true), "%FF%00");
}

#[test]
fn the_slash_is_encoded_only_when_asked() {
    assert_eq!(uri_encode(b"photos/Jan/sample.jpg", false), "photos/Jan/sample.jpg");
    assert_eq!(uri_encode(b"photos/Jan/sample.jpg", true), "photos%2FJan%2Fsample.jpg");
}

#[test]
fn an_empty_path_is_a_slash() {
    assert_eq!(canonical_uri(""), "/");
    assert_eq!(canonical_uri("/"), "/");
}

#[test]
fn the_path_is_encoded_once_and_never_normalised() {
    // S3 keys may contain these, so unlike other services S3 does not collapse them.
    assert_eq!(canonical_uri("//a//b"), "//a//b");
    assert_eq!(canonical_uri("/a/./b/../c/"), "/a/./b/../c/");
    assert_eq!(canonical_uri("/bucket/a%20b"), "/bucket/a%20b");
    assert_eq!(canonical_uri("/bucket/a b"), "/bucket/a%20b");
    assert_eq!(canonical_uri("/bucket/a+b"), "/bucket/a%2Bb");
    assert_eq!(canonical_uri("/bucket/a%2Bb"), "/bucket/a%2Bb");
    assert_eq!(canonical_uri("/bucket/%7Euser/%21"), "/bucket/~user/%21");
    assert_eq!(canonical_uri("/bucket/%E4%B8%AD"), "/bucket/%E4%B8%AD");
}

#[test]
fn a_percent_that_starts_no_escape_is_a_literal_percent() {
    assert_eq!(canonical_uri("/b/100%"), "/b/100%25");
    assert_eq!(canonical_uri("/b/%zz"), "/b/%25zz");
    assert_eq!(canonical_uri("/b/%4"), "/b/%254");
    assert_eq!(percent_decode("%4", false), b"%4");
    assert_eq!(percent_decode("%41%", false), b"A%");
}

#[test]
fn bytes_that_are_not_utf8_survive_the_round_trip() {
    assert_eq!(canonical_uri("/b/%FF%FE"), "/b/%FF%FE");
    assert_eq!(percent_decode("%FF%fe", false), [0xff, 0xfe]);
}

#[test]
fn the_query_is_sorted_by_name_and_then_by_value_after_encoding() {
    assert_eq!(canonical_query("prefix=somePrefix&marker=someMarker&max-keys=20", |_| false), "marker=someMarker&max-keys=20&prefix=somePrefix");
    assert_eq!(canonical_query("a=2&a=1&a=10", |_| false), "a=1&a=10&a=2");
    assert_eq!(canonical_query("b=1&B=2&a=3", |_| false), "B=2&a=3&b=1");
    // The sorting is on the encoded names, as the documentation says: `/` becomes `%2F`, and `%` (0x25) sorts before `-` (0x2D), `.` (0x2E) and `a`.
    assert_eq!(canonical_query("a=1&/=2&.=3&-=4", |_| false), "%2F=2&-=4&.=3&a=1");
}

#[test]
fn a_parameter_without_a_value_has_an_empty_one() {
    assert_eq!(canonical_query("acl", |_| false), "acl=");
    assert_eq!(canonical_query("uploads&prefix=a", |_| false), "prefix=a&uploads=");
    assert_eq!(canonical_query("a=", |_| false), "a=");
    assert_eq!(canonical_query("", |_| false), "");
    assert_eq!(canonical_query("&&a=1&", |_| false), "a=1");
    assert_eq!(canonical_query("a==b", |_| false), "a=%3Db");
}

#[test]
fn a_plus_in_a_query_is_a_space_and_an_encoded_plus_is_a_plus() {
    assert_eq!(canonical_query("prefix=a+b", |_| false), "prefix=a%20b");
    assert_eq!(canonical_query("prefix=a%2Bb", |_| false), "prefix=a%2Bb");
    assert_eq!(canonical_query("prefix=a%20b", |_| false), "prefix=a%20b");
    assert_eq!(canonical_query("prefix=~", |_| false), "prefix=~");
    assert_eq!(canonical_query("prefix=%7E", |_| false), "prefix=~");
}

#[test]
fn query_values_with_unicode_and_reserved_characters_are_encoded() {
    assert_eq!(canonical_query("prefix=%E4%B8%AD/%E6%96%87&delimiter=%2F", |_| false), "delimiter=%2F&prefix=%E4%B8%AD%2F%E6%96%87");
    assert_eq!(canonical_query("prefix=中文", |_| false), "prefix=%E4%B8%AD%E6%96%87");
    assert_eq!(canonical_query("x-id=a;b", |_| false), "x-id=a%3Bb");
}

#[test]
fn skipped_parameters_are_left_out() {
    let skip = |name: &[u8]| name.eq_ignore_ascii_case(b"X-Amz-Signature");
    assert_eq!(canonical_query("a=1&X-Amz-Signature=abc&b=2", skip), "a=1&b=2");
    assert_eq!(canonical_query("x-amz-signature=abc", skip), "");
    assert_eq!(canonical_query("%58-Amz-Signature=abc&a=1", skip), "a=1");
}

#[test]
fn query_params_are_decoded_in_order() {
    assert_eq!(query_params("b=%41&a&c=x+y&&"), [(b"b".to_vec(), b"A".to_vec()), (b"a".to_vec(), Vec::new()), (b"c".to_vec(), b"x y".to_vec())]);
}

#[test]
fn hex_round_trips_in_either_case() {
    assert_eq!(hex_encode(&[0x00, 0xab, 0xff]), "00abff");
    assert_eq!(hex_decode("00abFF"), Some(vec![0x00, 0xab, 0xff]));
    assert_eq!(hex_decode(""), Some(vec![]));
    assert_eq!(hex_decode("abc"), None);
    assert_eq!(hex_decode("zz"), None);
    assert_eq!(hex_decode("+1"), None);
    assert_eq!(hex_decode("é1"), None);
}
