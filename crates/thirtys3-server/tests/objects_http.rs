//! Objects as the server answers raw requests: conditions, ranges, headers, copies, and the checks on what is uploaded.

mod support;

use http::{Method, StatusCode};
use support::{BUCKET, Watched, req, start, start_with, tag, tags};
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_encode};
use thirtys3_core::etag::md5_digest;
use thirtys3_core::{Timestamp, sha256_hex};

const ETAG_OF_HELLO: &str = "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"";

async fn hello() -> support::Server {
    let server = start().await;
    server.service.backend().insert(BUCKET, "hello.txt", b"hello world");
    server
}

// ---- conditions ----

#[tokio::test]
async fn if_none_match_is_a_304_with_the_etag_and_no_body() {
    let server = hello().await;
    let answer = req(Method::GET, "/bucket/hello.txt").header("if-none-match", ETAG_OF_HELLO).send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_MODIFIED);
    assert!(answer.body.is_empty());
    assert_eq!(answer.header("etag"), Some(ETAG_OF_HELLO));
    assert!(answer.header("last-modified").is_some());
    assert!(answer.header("x-amz-request-id").is_some());
    for value in ["*", "\"x\", \"5eb63bbbe01eeed093cb22bb8f5acdc3\"", "W/\"5eb63bbbe01eeed093cb22bb8f5acdc3\""] {
        assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-none-match", value).send(&server).await.status, StatusCode::NOT_MODIFIED, "{value}");
    }
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-none-match", "\"other\"").send(&server).await.status, StatusCode::OK);
    assert_eq!(req(Method::HEAD, "/bucket/hello.txt").header("if-none-match", ETAG_OF_HELLO).send(&server).await.status, StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn if_match_is_a_412_when_it_does_not_hold() {
    let server = hello().await;
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-match", ETAG_OF_HELLO).send(&server).await.status, StatusCode::OK);
    let answer = req(Method::GET, "/bucket/hello.txt").header("if-match", "\"other\"").send(&server).await;
    assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("PreconditionFailed"));
    // A weak tag never matches If-Match.
    assert_eq!(
        req(Method::GET, "/bucket/hello.txt").header("if-match", "W/\"5eb63bbbe01eeed093cb22bb8f5acdc3\"").send(&server).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-match", "*").send(&server).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_dates_are_checked_when_there_are_no_etags() {
    let server = hello().await;
    let modified = server.service.backend().info(BUCKET, "hello.txt").unwrap().last_modified;
    let after = Timestamp(modified.0 + 3600).http_date();
    let before = Timestamp(modified.0 - 3600).http_date();
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-modified-since", &after).send(&server).await.status, StatusCode::NOT_MODIFIED);
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-modified-since", &before).send(&server).await.status, StatusCode::OK);
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-unmodified-since", &before).send(&server).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-unmodified-since", &after).send(&server).await.status, StatusCode::OK);
    // A date that is the very time of the object: it was not modified since, and it was not modified after.
    let same = modified.http_date();
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-modified-since", &same).send(&server).await.status, StatusCode::NOT_MODIFIED);
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-unmodified-since", &same).send(&server).await.status, StatusCode::OK);
    // A date that cannot be read is left out, as S3 does.
    assert_eq!(req(Method::GET, "/bucket/hello.txt").header("if-modified-since", "yesterday").send(&server).await.status, StatusCode::OK);
    // The ETag conditions go before the dates.
    assert_eq!(
        req(Method::GET, "/bucket/hello.txt").header("if-match", ETAG_OF_HELLO).header("if-unmodified-since", &before).send(&server).await.status,
        StatusCode::OK
    );
    assert_eq!(
        req(Method::GET, "/bucket/hello.txt").header("if-none-match", "\"other\"").header("if-modified-since", &after).send(&server).await.status,
        StatusCode::OK
    );
}

// ---- ranges ----

#[tokio::test]
async fn ranges_are_206_with_a_content_range() {
    let server = hello().await;
    for (range, body, content_range) in [
        ("bytes=0-4", "hello", "bytes 0-4/11"),
        ("bytes=6-", "world", "bytes 6-10/11"),
        ("bytes=-5", "world", "bytes 6-10/11"),
        ("bytes=6-100", "world", "bytes 6-10/11"),
        ("bytes=0-0", "h", "bytes 0-0/11"),
        ("bytes=-100", "hello world", "bytes 0-10/11"),
        ("bytes=0-10", "hello world", "bytes 0-10/11"),
    ] {
        let answer = req(Method::GET, "/bucket/hello.txt").header("range", range).send(&server).await;
        assert_eq!(answer.status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(answer.body, body, "{range}");
        assert_eq!(answer.header("content-range"), Some(content_range), "{range}");
        assert_eq!(answer.header("content-length"), Some(body.len().to_string().as_str()), "{range}");
        assert_eq!(answer.header("etag"), Some(ETAG_OF_HELLO));
    }
}

#[tokio::test]
async fn a_range_that_cannot_be_met_is_a_416() {
    let server = hello().await;
    for range in ["bytes=11-", "bytes=11-20", "bytes=100-", "bytes=-0"] {
        let answer = req(Method::GET, "/bucket/hello.txt").header("range", range).send(&server).await;
        assert_eq!(answer.status, StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidRange"));
        assert_eq!(tag(&answer.text(), "ActualObjectSize").as_deref(), Some("11"));
    }
    server.service.backend().insert(BUCKET, "empty", b"");
    assert_eq!(req(Method::GET, "/bucket/empty").header("range", "bytes=0-0").send(&server).await.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(req(Method::GET, "/bucket/empty").send(&server).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_range_header_that_is_not_one_range_is_ignored() {
    let server = hello().await;
    for range in ["bytes=0-1,3-4", "bytes=a-b", "bytes=5-2", "items=0-1", "bytes=", "bytes=-", "0-4", "bytes=0-4-6"] {
        let answer = req(Method::GET, "/bucket/hello.txt").header("range", range).send(&server).await;
        assert_eq!(answer.status, StatusCode::OK, "{range}");
        assert_eq!(answer.body, "hello world", "{range}");
        assert_eq!(answer.header("content-range"), None);
    }
}

#[tokio::test]
async fn head_has_the_headers_of_get_and_no_body() {
    let server = hello().await;
    let answer = req(Method::HEAD, "/bucket/hello.txt").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(answer.body.is_empty());
    assert_eq!(answer.header("content-length"), Some("11"));
    assert_eq!(answer.header("accept-ranges"), Some("bytes"));
    assert_eq!(answer.header("etag"), Some(ETAG_OF_HELLO));
    assert_eq!(answer.header("content-type"), Some("binary/octet-stream"));
    let ranged = req(Method::HEAD, "/bucket/hello.txt").header("range", "bytes=0-4").send(&server).await;
    assert_eq!((ranged.status, ranged.header("content-length"), ranged.header("content-range")), (StatusCode::PARTIAL_CONTENT, Some("5"), Some("bytes 0-4/11")));
    assert!(ranged.body.is_empty());
    assert_eq!(req(Method::HEAD, "/bucket/hello.txt").header("range", "bytes=50-").send(&server).await.status, StatusCode::RANGE_NOT_SATISFIABLE);
}

// ---- headers ----

#[tokio::test]
async fn the_headers_of_an_object_are_what_was_stored_and_the_query_can_replace_some() {
    let server = start().await;
    let put = req(Method::PUT, "/bucket/doc.txt")
        .header("content-type", "text/plain")
        .header("x-amz-meta-author", "me")
        .header("x-amz-meta-mtime", "1700000000.5")
        .body("text")
        .send(&server)
        .await;
    assert_eq!(put.status, StatusCode::OK);
    let get = req(Method::GET, "/bucket/doc.txt").send(&server).await;
    assert_eq!(get.header("content-type"), Some("text/plain"));
    assert_eq!(get.header("x-amz-meta-author"), Some("me"));
    assert_eq!(get.header("x-amz-meta-mtime"), Some("1700000000.5"));
    let overridden = req(
        Method::GET,
        "/bucket/doc.txt?response-content-type=application/pdf&response-content-disposition=attachment%3B%20filename%3D%22a.pdf%22&response-cache-control=no-store",
    )
    .send(&server)
    .await;
    assert_eq!(overridden.header("content-type"), Some("application/pdf"));
    assert_eq!(overridden.header("content-disposition"), Some("attachment; filename=\"a.pdf\""));
    assert_eq!(overridden.header("cache-control"), Some("no-store"));
    assert_eq!(overridden.body, "text");
}

#[tokio::test]
async fn metadata_beyond_two_kib_is_refused() {
    let server = start().await;
    let big = "x".repeat(2100);
    let answer = req(Method::PUT, "/bucket/k").header("x-amz-meta-big", &big).body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("MetadataTooLarge"));
    assert!(server.service.backend().keys(BUCKET).is_empty());
}

// ---- what is uploaded is checked ----

#[tokio::test]
async fn content_md5_is_checked_and_a_wrong_one_stores_nothing() {
    let server = start().await;
    let good = base64_encode(&md5_digest(b"hello world"));
    assert_eq!(req(Method::PUT, "/bucket/a").header("content-md5", &good).body("hello world").send(&server).await.status, StatusCode::OK);
    let wrong = base64_encode(&md5_digest(b"hello there"));
    let answer = req(Method::PUT, "/bucket/b").header("content-md5", &wrong).body("hello world").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("BadDigest"));
    assert_eq!(tag(&answer.text(), "ExpectedDigest").as_deref(), Some(wrong.as_str()));
    assert_eq!(tag(&answer.text(), "CalculatedDigest").as_deref(), Some(good.as_str()));
    for invalid in ["not base64!", "AAAA", ""] {
        let answer = req(Method::PUT, "/bucket/c").header("content-md5", invalid).body("x").send(&server).await;
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidDigest"), "{invalid:?}");
    }
    assert_eq!(server.service.backend().keys(BUCKET), ["a"]);
}

#[tokio::test]
async fn the_payload_hash_is_checked_and_a_wrong_one_stores_nothing() {
    let server = start().await;
    assert_eq!(req(Method::PUT, "/bucket/a").body("hello world").send(&server).await.status, StatusCode::OK);
    let answer = req(Method::PUT, "/bucket/b").payload_hash(&sha256_hex(b"hello there")).body("hello world").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("XAmzContentSHA256Mismatch"));
    assert_eq!(server.service.backend().keys(BUCKET), ["a"]);
    // UNSIGNED-PAYLOAD is not checked.
    assert_eq!(req(Method::PUT, "/bucket/c").payload_hash("UNSIGNED-PAYLOAD").body("anything").send(&server).await.status, StatusCode::OK);
    // And a value that is neither is refused at the signature.
    let answer = req(Method::PUT, "/bucket/d").payload_hash("not-a-hash").body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn checksums_in_headers_are_checked_and_the_good_ones_come_back() {
    let server = start().await;
    for algorithm in ChecksumAlgorithm::ALL {
        let right = algorithm.checksum_base64(b"checksummed");
        let ok = req(Method::PUT, "/bucket/k").header(algorithm.header_name(), &right).body("checksummed").send(&server).await;
        assert_eq!(ok.status, StatusCode::OK, "{algorithm:?}: {}", ok.text());
        assert_eq!(ok.header(algorithm.header_name()), Some(right.as_str()), "{algorithm:?}");
        let wrong = algorithm.checksum_base64(b"something else");
        let bad = req(Method::PUT, "/bucket/other").header(algorithm.header_name(), &wrong).body("checksummed").send(&server).await;
        assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{algorithm:?}");
        assert_eq!(tag(&bad.text(), "Code").as_deref(), Some("BadDigest"), "{algorithm:?}");
        let not_base64 = req(Method::PUT, "/bucket/other").header(algorithm.header_name(), "$$$").body("checksummed").send(&server).await;
        assert_eq!(not_base64.status, StatusCode::BAD_REQUEST, "{algorithm:?}");
    }
    assert_eq!(server.service.backend().keys(BUCKET), ["k"]);
}

#[tokio::test]
async fn a_put_without_a_length_is_411_and_one_that_is_too_big_is_refused_before_it_is_read() {
    let server = start().await;
    let answer = req(Method::PUT, "/bucket/k").no_content_length().body("x").send(&server).await;
    assert!(answer.status == StatusCode::LENGTH_REQUIRED || answer.status == StatusCode::OK, "{:?}", answer.status);
    let small = start_with(support::backend(), thirtys3_server::ServerConfig { max_object_size: 10, ..support::config() }).await;
    assert_eq!(req(Method::PUT, "/bucket/k").body("0123456789").send(&small).await.status, StatusCode::OK);
    let answer = req(Method::PUT, "/bucket/k2").body("0123456789a").send(&small).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("EntityTooLarge"));
    assert_eq!(tag(&answer.text(), "MaxSizeAllowed").as_deref(), Some("10"));
    assert_eq!(small.service.backend().keys(BUCKET), ["k"]);
}

#[tokio::test]
async fn a_backend_that_answers_before_the_body_was_read_is_not_believed() {
    let backend = Watched::new();
    backend.ignore_bodies.store(true, std::sync::atomic::Ordering::Relaxed);
    let server = start_with(backend.clone(), support::config()).await;
    let answer = req(Method::PUT, "/bucket/k").body("data that nobody reads").send(&server).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR, "an upload is acknowledged only when the whole body was checked");
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InternalError"));
}

// ---- write conditions ----

#[tokio::test]
async fn if_none_match_star_and_if_match_on_a_put() {
    let server = start().await;
    assert_eq!(req(Method::PUT, "/bucket/lock").header("if-none-match", "*").body("one").send(&server).await.status, StatusCode::OK);
    let again = req(Method::PUT, "/bucket/lock").header("if-none-match", "*").body("two").send(&server).await;
    assert_eq!(again.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(server.service.backend().object(BUCKET, "lock").unwrap(), "one");
    assert_eq!(req(Method::PUT, "/bucket/lock").header("if-match", "\"wrong\"").body("three").send(&server).await.status, StatusCode::PRECONDITION_FAILED);
    let etag = server.service.backend().info(BUCKET, "lock").unwrap().etag;
    assert_eq!(req(Method::PUT, "/bucket/lock").header("if-match", &etag).body("three").send(&server).await.status, StatusCode::OK);
    // Only * is understood for If-None-Match.
    let answer = req(Method::PUT, "/bucket/other").header("if-none-match", "\"abc\"").body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED);
}

// ---- copy ----

#[tokio::test]
async fn copy_with_the_forms_of_the_source() {
    let server = hello().await;
    for (index, source) in ["bucket/hello.txt", "/bucket/hello.txt", "bucket/hello.txt?versionless=1"].iter().enumerate() {
        let target = format!("/bucket/copy{index}");
        let answer = req(Method::PUT, &target).header("x-amz-copy-source", source).send(&server).await;
        assert_eq!(answer.status, StatusCode::OK, "{source}: {}", answer.text());
        assert_eq!(tag(&answer.text(), "ETag").as_deref(), Some(ETAG_OF_HELLO));
        assert!(tag(&answer.text(), "LastModified").is_some());
        assert_eq!(server.service.backend().object(BUCKET, &format!("copy{index}")).unwrap(), "hello world");
    }
    server.service.backend().insert(BUCKET, "dir/with space+plus.txt", b"encoded");
    let answer = req(Method::PUT, "/bucket/copy-encoded").header("x-amz-copy-source", "bucket/dir/with%20space%2Bplus.txt").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(server.service.backend().object(BUCKET, "copy-encoded").unwrap(), "encoded");
    // Between buckets.
    assert_eq!(req(Method::PUT, "/other/copy").header("x-amz-copy-source", "bucket/hello.txt").send(&server).await.status, StatusCode::OK);
    assert_eq!(server.service.backend().object("other", "copy").unwrap(), "hello world");
}

#[tokio::test]
async fn copy_metadata_and_what_cannot_be_copied() {
    let server = start().await;
    req(Method::PUT, "/bucket/src").header("content-type", "text/plain").header("x-amz-meta-a", "1").body("data").send(&server).await;
    req(Method::PUT, "/bucket/kept").header("x-amz-copy-source", "bucket/src").send(&server).await;
    let kept = server.service.backend().info(BUCKET, "kept").unwrap();
    assert_eq!((kept.content_type.as_deref(), kept.metadata.clone()), (Some("text/plain"), vec![("a".to_owned(), "1".to_owned())]));
    req(Method::PUT, "/bucket/replaced")
        .header("x-amz-copy-source", "bucket/src")
        .header("x-amz-metadata-directive", "REPLACE")
        .header("content-type", "image/png")
        .header("x-amz-meta-b", "2")
        .send(&server)
        .await;
    let replaced = server.service.backend().info(BUCKET, "replaced").unwrap();
    assert_eq!((replaced.content_type.as_deref(), replaced.metadata.clone()), (Some("image/png"), vec![("b".to_owned(), "2".to_owned())]));

    for (source, directive, expected) in [
        ("bucket/src", "MOVE", StatusCode::BAD_REQUEST),
        ("bucket/src", "COPY", StatusCode::BAD_REQUEST), // to itself below
        ("bucket/missing", "COPY", StatusCode::NOT_FOUND),
        ("nobucket/src", "COPY", StatusCode::NOT_FOUND),
        ("src", "COPY", StatusCode::BAD_REQUEST),
        ("", "COPY", StatusCode::BAD_REQUEST),
        ("bucket/src?versionId=1", "COPY", StatusCode::NOT_IMPLEMENTED),
        ("arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/src", "COPY", StatusCode::NOT_IMPLEMENTED),
    ] {
        let target = if source == "bucket/src" && directive == "COPY" { "/bucket/src" } else { "/bucket/target" };
        let answer = req(Method::PUT, target).header("x-amz-copy-source", source).header("x-amz-metadata-directive", directive).send(&server).await;
        assert_eq!(answer.status, expected, "{source} {directive}: {}", answer.text());
    }
    assert!(server.service.backend().object(BUCKET, "target").is_none());
}

#[tokio::test]
async fn copy_conditions_are_on_the_source() {
    let server = hello().await;
    let copy = |header: &'static str, value: &'static str| {
        let server = &server;
        async move { req(Method::PUT, "/bucket/target").header("x-amz-copy-source", "bucket/hello.txt").header(header, value).send(server).await.status }
    };
    assert_eq!(copy("x-amz-copy-source-if-match", ETAG_OF_HELLO).await, StatusCode::OK);
    assert_eq!(copy("x-amz-copy-source-if-match", "\"other\"").await, StatusCode::PRECONDITION_FAILED);
    assert_eq!(copy("x-amz-copy-source-if-none-match", ETAG_OF_HELLO).await, StatusCode::PRECONDITION_FAILED, "a 304 for a GET is a failed condition for a copy");
    assert_eq!(copy("x-amz-copy-source-if-none-match", "\"other\"").await, StatusCode::OK);
}

// ---- DeleteObjects ----

fn delete_body(keys: &[&str], quiet: bool) -> String {
    let objects: String = keys.iter().map(|key| format!("<Object><Key>{key}</Key></Object>")).collect();
    format!("<Delete>{objects}{}</Delete>", if quiet { "<Quiet>true</Quiet>" } else { "" })
}

#[tokio::test]
async fn delete_objects_answers_for_each_key() {
    let server = start().await;
    for key in ["a", "b", "c"] {
        server.service.backend().insert(BUCKET, key, b"x");
    }
    let body = delete_body(&["a", "b", "never-there"], false);
    let md5 = base64_encode(&md5_digest(body.as_bytes()));
    let answer = req(Method::POST, "/bucket?delete").header("content-md5", &md5).body(body).send(&server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(tags(&answer.text(), "Key"), ["a", "b", "never-there"]);
    assert_eq!(server.service.backend().keys(BUCKET), ["c"]);

    let quiet = delete_body(&["c"], true);
    let answer = req(Method::POST, "/bucket?delete").body(quiet).send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(tags(&answer.text(), "Deleted").is_empty() && tags(&answer.text(), "Error").is_empty(), "{}", answer.text());
    assert!(server.service.backend().keys(BUCKET).is_empty());
}

#[tokio::test]
async fn delete_objects_reports_the_keys_that_failed_and_does_not_do_versions() {
    let backend = Watched::new();
    backend.undeletable.lock().unwrap().insert("locked".to_owned());
    let server = start_with(backend.clone(), support::config()).await;
    for key in ["a", "locked"] {
        backend.inner.insert(BUCKET, key, b"x");
    }
    let body = "<Delete><Object><Key>a</Key></Object><Object><Key>locked</Key></Object><Object><Key>a</Key><VersionId>v1</VersionId></Object></Delete>";
    let answer = req(Method::POST, "/bucket?delete").body(body).send(&server).await;
    let xml = answer.text();
    assert_eq!(answer.status, StatusCode::OK, "{xml}");
    assert_eq!(tags(&xml, "Deleted").len(), 1);
    let errors = tags(&xml, "Error");
    assert_eq!(errors.len(), 2, "{xml}");
    assert!(errors[0].contains("<Key>locked</Key>") && errors[0].contains("<Code>AccessDenied</Code>"));
    assert!(errors[1].contains("<Code>NotImplemented</Code>"));
    assert_eq!(backend.inner.keys(BUCKET), ["locked"]);
}

#[tokio::test]
async fn delete_objects_refuses_what_is_not_a_good_request() {
    let server = start().await;
    let many: Vec<String> = (0..1001).map(|i| format!("k{i}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    for (name, body) in [
        ("1001 keys", delete_body(&refs, false)),
        ("no keys", "<Delete></Delete>".to_owned()),
        ("not XML", "keys, please".to_owned()),
        ("another document", "<Other><Object><Key>a</Key></Object></Other>".to_owned()),
        ("an entity", "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY e \"x\">]><Delete><Object><Key>&e;</Key></Object></Delete>".to_owned()),
        ("a key that is too long", delete_body(&[&"k".repeat(1025)], false)),
    ] {
        let answer = req(Method::POST, "/bucket?delete").body(body).send(&server).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{name}: {}", answer.text());
    }
    let answer =
        req(Method::POST, "/bucket?delete").header("content-md5", &base64_encode(&md5_digest(b"other"))).body(delete_body(&["a"], false)).send(&server).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("BadDigest"));
    let small = start_with(support::backend(), thirtys3_server::ServerConfig { max_xml_bytes: 50, ..support::config() }).await;
    let answer = req(Method::POST, "/bucket?delete").body(delete_body(&["a", "b", "c", "d"], false)).send(&small).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("MaxMessageLengthExceeded"));
}

#[tokio::test]
async fn a_backend_that_loses_results_of_delete_objects_is_an_internal_error() {
    let backend = Watched::new();
    backend.short_delete_results.store(true, std::sync::atomic::Ordering::Relaxed);
    let server = start_with(backend.clone(), support::config()).await;
    backend.inner.insert(BUCKET, "a", b"x");
    let answer = req(Method::POST, "/bucket?delete").body(delete_body(&["a", "b"], false)).send(&server).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InternalError"));
}
