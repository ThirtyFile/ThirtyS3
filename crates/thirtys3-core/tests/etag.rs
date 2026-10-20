//! ETags and the conditions that compare them.

use thirtys3_core::etag::{ETagCondition, EntityTag, etag_from_md5, md5_digest, multipart_etag, unquote};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_etag_of_one_request_is_the_md5_in_hex_and_quotes() {
    assert_eq!(etag_from_md5(&md5_digest(b"")), "\"d41d8cd98f00b204e9800998ecf8427e\"");
    assert_eq!(etag_from_md5(&md5_digest(b"abc")), "\"900150983cd24fb0d6963f7d28e17f72\"");
}

#[test]
fn the_etag_of_parts_is_the_md5_of_their_md5s_with_a_dash_and_the_count() {
    let parts = [md5_digest(b"aaaaa"), md5_digest(b"bbbbb"), md5_digest(b"c")];
    assert_eq!(hex(&parts[0]), "594f803b380a41396ed63dca39503542");
    // Worked out with another implementation.
    assert_eq!(multipart_etag(&parts), "\"7f6a87eb8f486f0176013cf025601f57-3\"");
    assert_eq!(multipart_etag(&[parts[0]]), format!("\"{}-1\"", hex(&md5_digest(&parts[0]))));
    let as_vectors: Vec<Vec<u8>> = parts.iter().map(|part| part.to_vec()).collect();
    assert_eq!(multipart_etag(&as_vectors), multipart_etag(&parts));
}

#[test]
fn unquoting() {
    assert_eq!(unquote("\"abc\""), "abc");
    assert_eq!(unquote("W/\"abc\""), "abc");
    assert_eq!(unquote("abc"), "abc");
    assert_eq!(unquote("  \"abc\"  "), "abc");
    assert_eq!(unquote("\"abc"), "\"abc");
    assert_eq!(unquote("\"\""), "");
}

#[test]
fn a_star_matches_anything() {
    let any = ETagCondition::parse(" * ").unwrap();
    assert_eq!(any, ETagCondition::Any);
    assert!(any.matches("\"x\"", true) && any.matches("", false));
}

#[test]
fn a_list_of_tags() {
    let condition = ETagCondition::parse("\"a\", \"b\",\"c,d\" , W/\"e\"").unwrap();
    assert_eq!(
        condition,
        ETagCondition::Tags(vec![
            EntityTag { weak: false, value: "a".into() },
            EntityTag { weak: false, value: "b".into() },
            EntityTag { weak: false, value: "c,d".into() },
            EntityTag { weak: true, value: "e".into() },
        ])
    );
    for matching in ["\"a\"", "a", "\"b\"", "\"c,d\""] {
        assert!(condition.matches(matching, true), "{matching}");
    }
    assert!(!condition.matches("\"x\"", true));
    assert!(!condition.matches("\"x\"", false));
}

#[test]
fn a_weak_tag_matches_only_in_the_weak_comparison() {
    let condition = ETagCondition::parse("W/\"e\"").unwrap();
    assert!(!condition.matches("\"e\"", true), "If-Match never matches a weak tag");
    assert!(condition.matches("\"e\"", false), "If-None-Match ignores weakness");
}

#[test]
fn tags_without_quotes_are_taken_as_they_are() {
    let condition = ETagCondition::parse("abc, def").unwrap();
    assert!(condition.matches("\"abc\"", true) && condition.matches("\"def\"", true));
}

#[test]
fn nothing_usable_is_none() {
    for text in ["", "   ", ",", " , , ", "\"abc", "W/\"abc"] {
        assert_eq!(ETagCondition::parse(text), None, "{text:?}");
    }
}

#[test]
fn matching_compares_the_whole_tag() {
    let condition = ETagCondition::parse("\"abc\"").unwrap();
    assert!(!condition.matches("\"abcd\"", true));
    assert!(!condition.matches("\"ab\"", true));
    assert!(!condition.matches("\"ABC\"", true));
    assert!(condition.matches("W/\"abc\"", false));
}
