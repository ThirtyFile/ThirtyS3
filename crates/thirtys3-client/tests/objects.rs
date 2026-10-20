//! Storing, downloading, looking at and deleting single objects, against the in-memory service, which checks every signature.

mod support;

use bytes::Bytes;
use futures_util::StreamExt;
use http::Method;
use support::{TestServer, client};
use thirtys3_client::{ChecksumAlgorithm, ErrorKind, GetOptions, GetRange, PutOptions};

fn data(length: usize) -> Bytes {
    Bytes::from((0..length).map(|i| (i * 7 + i / 251) as u8).collect::<Vec<u8>>())
}

#[tokio::test]
async fn an_object_goes_in_and_comes_out() {
    let server = TestServer::start().await;
    let client = client(&server);
    let result =
        client.put("hello.txt", Bytes::from_static(b"hello world"), &PutOptions { content_type: Some("text/plain".into()), ..PutOptions::default() }).await.unwrap();
    assert_eq!(result.etag.as_deref(), Some("\"5eb63bbbe01eeed093cb22bb8f5acdc3\""));

    let object = client.get("hello.txt", &GetOptions::default()).await.unwrap();
    assert_eq!(object.meta.size, 11);
    assert_eq!(object.meta.etag.as_deref(), Some("\"5eb63bbbe01eeed093cb22bb8f5acdc3\""));
    assert_eq!(object.meta.content_type.as_deref(), Some("text/plain"));
    assert!(object.meta.last_modified.is_some());
    assert_eq!(object.range, 0..11);
    assert_eq!(object.body.len(), 11);
    assert_eq!(object.body.bytes().await.unwrap(), "hello world");

    // Every request was signed in a way the service accepted.
    assert!(server.requests().iter().all(|request| request.authenticated));
}

#[tokio::test]
async fn the_object_is_signed_as_a_path_style_request() {
    let server = TestServer::start().await;
    let client = client(&server);
    client.put("a/b c.txt", Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap();
    let request = &server.requests()[0];
    assert_eq!((request.method.clone(), request.path.as_str()), (Method::PUT, "/bucket/a/b%20c.txt"));
    assert!(request.header("authorization").unwrap().starts_with("AWS4-HMAC-SHA256 Credential=AKIATESTKEY/"));
    assert!(request.header("x-amz-date").is_some() && request.header("x-amz-content-sha256").is_some());
    assert!(request.header("user-agent").unwrap().starts_with("thirtys3-client/"));
}

#[tokio::test]
async fn keys_with_awkward_characters_survive() {
    let server = TestServer::start().await;
    let client = client(&server);
    for key in [
        "a b",
        "a+b",
        "100%",
        "%41",
        "中文/文件.txt",
        "emoji 😀",
        "a//b",
        "./a",
        "../a",
        "trailing/",
        "!*'();:@&=$,?#[]",
        " leading",
        "tab\there",
        &"k".repeat(1024),
    ] {
        client.put(key, Bytes::from(key.to_owned()), &PutOptions::default()).await.unwrap_or_else(|error| panic!("put {key:?}: {error}"));
        let back = client.get(key, &GetOptions::default()).await.unwrap_or_else(|error| panic!("get {key:?}: {error}")).body.bytes().await.unwrap();
        assert_eq!(back, key.as_bytes(), "{key:?}");
        assert_eq!(client.head(key).await.unwrap().size, key.len() as u64);
    }
    assert!(server.requests().iter().all(|request| request.authenticated));
    assert!(server.keys().contains(&"中文/文件.txt".to_owned()) && server.keys().contains(&"a//b".to_owned()));
}

#[tokio::test]
async fn keys_that_cannot_be_stored_are_refused_before_anything_is_sent() {
    let server = TestServer::start().await;
    let client = client(&server);
    for key in ["".to_owned(), "k".repeat(1025)] {
        let error = client.put(&key, Bytes::new(), &PutOptions::default()).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{}", key.len());
        assert_eq!(client.head(&key).await.unwrap_err().kind(), ErrorKind::InvalidInput);
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn an_empty_object_and_a_large_one() {
    let server = TestServer::start().await;
    let client = client(&server);
    client.put("empty", Bytes::new(), &PutOptions::default()).await.unwrap();
    let empty = client.get("empty", &GetOptions::default()).await.unwrap();
    assert_eq!((empty.meta.size, empty.body.is_empty()), (0, true));
    assert_eq!(empty.body.bytes().await.unwrap().len(), 0);
    assert_eq!(server.object("empty").unwrap().etag, "\"d41d8cd98f00b204e9800998ecf8427e\"");

    let big = data(3 * 1024 * 1024 + 17);
    client.put("big", big.clone(), &PutOptions::default()).await.unwrap();
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    let mut received = Vec::new();
    let mut pieces = 0;
    let mut body = object.body;
    while let Some(piece) = body.next().await {
        received.extend_from_slice(&piece.unwrap());
        pieces += 1;
    }
    assert_eq!(received, big);
    assert!(pieces > 1, "a large body arrives in pieces, not all at once");
}

#[tokio::test]
async fn metadata_and_headers_are_stored_and_come_back() {
    let server = TestServer::start().await;
    let client = client(&server);
    let options = PutOptions {
        content_type: Some("image/png".into()),
        metadata: vec![("mtime".into(), "1700000000.5".into()), ("Source".into(), "scanner 1".into())],
        storage_class: Some("STANDARD_IA".into()),
        ..PutOptions::default()
    };
    client.put("img", Bytes::from_static(b"png"), &options).await.unwrap();
    let meta = client.head("img").await.unwrap();
    assert_eq!(meta.content_type.as_deref(), Some("image/png"));
    assert_eq!(meta.metadata.get("mtime").map(String::as_str), Some("1700000000.5"));
    assert_eq!(meta.metadata.get("source").map(String::as_str), Some("scanner 1"));
    assert_eq!(meta.storage_class.as_deref(), Some("STANDARD_IA"));
    assert_eq!(meta.key, "img");
    // The same through get.
    assert_eq!(client.get("img", &GetOptions::default()).await.unwrap().meta, meta);
}

#[tokio::test]
async fn metadata_that_cannot_be_a_header_is_refused() {
    let server = TestServer::start().await;
    let client = client(&server);
    for (name, value) in [("", "v"), ("bad name", "v"), ("na:me", "v"), ("ok", "line\nbreak"), ("ok", "非ASCII")] {
        let options = PutOptions { metadata: vec![(name.into(), value.into())], ..PutOptions::default() };
        assert_eq!(client.put("k", Bytes::new(), &options).await.unwrap_err().kind(), ErrorKind::InvalidInput, "{name:?}={value:?}");
    }
    let options = PutOptions { content_type: Some("a\nb".into()), ..PutOptions::default() };
    assert_eq!(client.put("k", Bytes::new(), &options).await.unwrap_err().kind(), ErrorKind::InvalidInput);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn every_checksum_algorithm_is_sent_verified_and_reported() {
    let server = TestServer::start().await;
    let client = client(&server);
    for algorithm in ChecksumAlgorithm::ALL {
        let options = PutOptions { checksum: Some(algorithm), ..PutOptions::default() };
        let result = client.put("sum", Bytes::from_static(b"checksummed"), &options).await.unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
        let expected = algorithm.checksum_base64(b"checksummed");
        assert_eq!(result.checksums.get(algorithm), Some(expected.as_str()), "{algorithm:?}");
        let head = client.head("sum").await.unwrap();
        assert_eq!(head.checksums.get(algorithm), Some(expected.as_str()), "{algorithm:?}");
        assert_eq!(server.requests().last().unwrap().header("x-amz-checksum-algorithm"), None);
    }
}

#[tokio::test]
async fn a_put_that_may_only_create_fails_when_the_object_exists() {
    let server = TestServer::start().await;
    let client = client(&server);
    let create = PutOptions { if_none_match: true, ..PutOptions::default() };
    client.put("once", Bytes::from_static(b"first"), &create).await.unwrap();
    let error = client.put("once", Bytes::from_static(b"second"), &create).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    assert_eq!(server.object("once").unwrap().data, "first");
    assert_eq!(server.requests_matching(Method::PUT, "once").len(), 2, "a failed condition is not tried again");
    assert_eq!(server.requests_matching(Method::PUT, "once")[0].header("if-none-match"), Some("*"));
}

#[tokio::test]
async fn a_put_that_may_only_replace_what_was_read() {
    let server = TestServer::start().await;
    let client = client(&server);
    let first = client.put("doc", Bytes::from_static(b"v1"), &PutOptions::default()).await.unwrap();
    let replace = |etag: Option<String>| PutOptions { if_match: etag, ..PutOptions::default() };
    client.put("doc", Bytes::from_static(b"v2"), &replace(first.etag.clone())).await.unwrap();
    // The ETag of v1 is not the object's any more.
    assert_eq!(client.put("doc", Bytes::from_static(b"v3"), &replace(first.etag)).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(client.put("missing", Bytes::new(), &replace(Some("\"abc\"".into()))).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(server.object("doc").unwrap().data, "v2");
}

#[tokio::test]
#[allow(clippy::reversed_empty_ranges)] // 6..5 is on purpose: a range that has nothing in it has to be refused
async fn ranges() {
    let server = TestServer::start().await;
    let client = client(&server);
    let content = data(1000);
    client.put("r", content.clone(), &PutOptions::default()).await.unwrap();
    let get = |range: GetRange| {
        let client = client.clone();
        async move { client.get("r", &GetOptions { range: Some(range), ..GetOptions::default() }).await }
    };
    for (range, covered) in [
        (GetRange::Bounded(10..20), 10..20),
        (GetRange::Bounded(0..1), 0..1),
        (GetRange::Bounded(990..1000), 990..1000),
        (GetRange::Bounded(990..5000), 990..1000),
        (GetRange::From(900), 900..1000),
        (GetRange::Suffix(5), 995..1000),
        (GetRange::Suffix(5000), 0..1000),
    ] {
        let object = get(range.clone()).await.unwrap_or_else(|error| panic!("{range:?}: {error}"));
        assert_eq!(object.range, covered, "{range:?}");
        assert_eq!(object.meta.size, 1000, "the size is the object's, not the range's");
        assert_eq!(object.body.bytes().await.unwrap(), content.slice(covered.start as usize..covered.end as usize), "{range:?}");
    }
    assert_eq!(get(GetRange::From(1000)).await.unwrap_err().kind(), ErrorKind::InvalidRange);
    assert_eq!(get(GetRange::Bounded(5000..6000)).await.unwrap_err().kind(), ErrorKind::InvalidRange);
    for empty in [GetRange::Bounded(5..5), GetRange::Bounded(6..5), GetRange::Suffix(0)] {
        assert_eq!(get(empty.clone()).await.unwrap_err().kind(), ErrorKind::InvalidInput, "{empty:?}");
    }
}

#[tokio::test]
async fn conditional_gets() {
    let server = TestServer::start().await;
    let client = client(&server);
    let put = client.put("c", Bytes::from_static(b"content"), &PutOptions::default()).await.unwrap();
    let etag = put.etag.unwrap();
    let with = |if_match: Option<&str>, if_none_match: Option<&str>| GetOptions {
        if_match: if_match.map(str::to_owned),
        if_none_match: if_none_match.map(str::to_owned),
        ..GetOptions::default()
    };
    assert!(client.get("c", &with(Some(&etag), None)).await.is_ok());
    assert_eq!(client.get("c", &with(Some("\"other\""), None)).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(client.get("c", &with(None, Some(&etag))).await.unwrap_err().kind(), ErrorKind::NotModified);
    assert!(client.get("c", &with(None, Some("\"other\""))).await.is_ok());
}

#[tokio::test]
async fn what_is_not_there_is_not_found_and_the_other_errors_are_what_they_say() {
    let server = TestServer::start().await;
    let client = client(&server);
    let error = client.get("nothing", &GetOptions::default()).await.unwrap_err();
    assert!(error.is_not_found());
    assert!(matches!(&error, thirtys3_client::Error::Service(s3) if s3.code == "NoSuchKey" && s3.detail("Key") == Some("nothing")), "{error:?}");
    let error = client.head("nothing").await.unwrap_err();
    assert!(error.is_not_found(), "a HEAD has no body to say why: {error:?}");
    assert!(!error.is_retryable());
    assert_eq!(server.requests().len(), 2, "not found is not tried again");
}

#[tokio::test]
async fn delete_removes_and_deleting_what_is_gone_is_fine() {
    let server = TestServer::start().await;
    let client = client(&server);
    client.put("d", Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap();
    client.delete("d").await.unwrap();
    assert!(server.object("d").is_none());
    client.delete("d").await.unwrap();
    client.delete("never-there").await.unwrap();
    assert_eq!(client.head("d").await.unwrap_err().kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn wrong_keys_are_permission_denied_and_not_tried_again() {
    let server = TestServer::start().await;
    let mut config = support::config(&server);
    config.credentials = thirtys3_client::Credentials::new("AKIATESTKEY", "the wrong secret");
    let client = thirtys3_client::Client::new(config).unwrap();
    let error = client.put("k", Bytes::new(), &PutOptions::default()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert!(matches!(&error, thirtys3_client::Error::Service(s3) if s3.code == "SignatureDoesNotMatch"));
    let mut config = support::config(&server);
    config.credentials = thirtys3_client::Credentials::new("AKIAOTHER", "x");
    let error = thirtys3_client::Client::new(config).unwrap().head("k").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(server.requests().len(), 2, "no repeats of a refusal");
}

#[tokio::test]
async fn a_wrong_bucket_is_not_found() {
    let server = TestServer::start().await;
    let mut config = support::config(&server);
    config.bucket = "other".into();
    let error = thirtys3_client::Client::new(config).unwrap().head("k").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[tokio::test]
async fn a_service_that_answers_404_to_deleting_what_is_gone_is_fine_too() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.fault(Some(Method::DELETE), None, None, 2, support::Fault::Status(404, "NoSuchKey"));
    client.delete("gone").await.unwrap();
    // And the same when the keys are deleted one by one.
    let mut config = support::config(&server);
    config.bulk_delete = false;
    let one_by_one = thirtys3_client::Client::new(config).unwrap();
    assert!(one_by_one.delete_many(&["gone".to_owned()]).await.unwrap().is_empty());
    assert_eq!(server.requests_matching(Method::DELETE, "/gone").len(), 2, "a 404 is not repeated");
}
