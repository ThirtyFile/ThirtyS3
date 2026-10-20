//! Listings and multipart uploads as the server answers raw requests.

mod support;

use bytes::Bytes;
use http::{Method, StatusCode};
use support::{BUCKET, req, start, tag, tags};
use thirtys3_core::checksum::base64_encode;
use thirtys3_core::etag::md5_digest;

async fn with_keys(keys: &[&str]) -> support::Server {
    let server = start().await;
    for key in keys {
        server.service.backend().insert(BUCKET, key, key.as_bytes());
    }
    server
}

// ---- listing ----

#[tokio::test]
async fn version_2_in_the_form_of_the_documentation() {
    let server = with_keys(&["a.txt", "b/c.txt"]).await;
    let answer = req(Method::GET, "/bucket?list-type=2").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
    let xml = answer.text();
    assert!(xml.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"), "{xml}");
    assert_eq!(tag(&xml, "Name").as_deref(), Some("bucket"));
    assert_eq!((tag(&xml, "KeyCount").as_deref(), tag(&xml, "MaxKeys").as_deref(), tag(&xml, "IsTruncated").as_deref()), (Some("2"), Some("1000"), Some("false")));
    assert_eq!(tags(&xml, "Key"), ["a.txt", "b/c.txt"]);
    assert_eq!(tags(&xml, "Size"), ["5", "7"]);
    assert_eq!(tags(&xml, "StorageClass"), ["STANDARD", "STANDARD"]);
    let modified = tag(&xml, "LastModified").unwrap();
    assert!(modified.ends_with(".000Z") && modified.len() == 24, "{modified}");
    assert!(tag(&xml, "ETag").unwrap().starts_with('"'));
    assert!(!xml.contains("NextContinuationToken") && !xml.contains("EncodingType"), "{xml}");
}

#[tokio::test]
async fn pages_with_continuation_tokens() {
    let server = with_keys(&["k1", "k2", "k3", "k4", "k5"]).await;
    let mut keys = Vec::new();
    let mut token = String::new();
    let mut pages = 0;
    loop {
        let target = if token.is_empty() {
            "/bucket?list-type=2&max-keys=2".to_owned()
        } else {
            format!("/bucket?list-type=2&max-keys=2&continuation-token={}", token.replace('+', "%2B").replace('=', "%3D"))
        };
        let xml = req(Method::GET, &target).send(&server).await.text();
        pages += 1;
        keys.extend(tags(&xml, "Key"));
        if token.is_empty() {
            assert!(tag(&xml, "ContinuationToken").is_none());
        } else {
            assert_eq!(tag(&xml, "ContinuationToken").as_deref(), Some(token.as_str()), "the token that was sent is echoed");
        }
        match tag(&xml, "NextContinuationToken") {
            Some(next) => {
                assert_eq!(tag(&xml, "IsTruncated").as_deref(), Some("true"));
                token = next;
            }
            None => {
                assert_eq!(tag(&xml, "IsTruncated").as_deref(), Some("false"));
                break;
            }
        }
    }
    assert_eq!((pages, keys), (3, vec!["k1", "k2", "k3", "k4", "k5"].into_iter().map(String::from).collect::<Vec<_>>()));
}

#[tokio::test]
async fn max_keys_is_a_number_of_at_most_1000() {
    let server = with_keys(&["a", "b", "c"]).await;
    for bad in ["abc", "-1", "1.5", "99999999999999999999"] {
        let answer = req(Method::GET, &format!("/bucket?list-type=2&max-keys={bad}")).send(&server).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidArgument"), "{bad}");
        assert_eq!(tag(&answer.text(), "ArgumentName").as_deref(), Some("max-keys"));
    }
    let zero = req(Method::GET, "/bucket?list-type=2&max-keys=0").send(&server).await.text();
    assert!(tags(&zero, "Key").is_empty() && tag(&zero, "IsTruncated").as_deref() == Some("false"), "{zero}");
    let big = req(Method::GET, "/bucket?list-type=2&max-keys=5000").send(&server).await.text();
    assert_eq!(tag(&big, "MaxKeys").as_deref(), Some("1000"), "more than 1000 is 1000");
    assert_eq!(tags(&big, "Key").len(), 3);
}

#[tokio::test]
async fn prefix_delimiter_and_start_after() {
    let server = with_keys(&["photos/2020/a", "photos/2020/b", "photos/2021/c", "photos/readme", "z"]).await;
    let xml = req(Method::GET, "/bucket?list-type=2&prefix=photos/&delimiter=/").send(&server).await.text();
    assert_eq!(tags(&xml, "Key"), ["photos/readme"]);
    assert_eq!(tags(&xml, "Prefix"), ["photos/", "photos/2020/", "photos/2021/"], "the Prefix of the request, then the common prefixes");
    assert_eq!(tag(&xml, "Delimiter").as_deref(), Some("/"));
    assert_eq!(tag(&xml, "KeyCount").as_deref(), Some("3"));
    let after = req(Method::GET, "/bucket?list-type=2&start-after=photos/2021/c").send(&server).await.text();
    assert_eq!(tags(&after, "Key"), ["photos/readme", "z"]);
    assert_eq!(tag(&after, "StartAfter").as_deref(), Some("photos/2021/c"));
}

#[tokio::test]
async fn url_encoding_of_the_keys_the_prefix_and_the_delimiter() {
    let server = with_keys(&["中文 # %/a.txt", "plain"]).await;
    let xml = req(Method::GET, "/bucket?list-type=2&prefix=%E4%B8%AD%E6%96%87%20%23%20%25/&delimiter=/&encoding-type=url").send(&server).await.text();
    let encoded = "%E4%B8%AD%E6%96%87%20%23%20%25%2F";
    assert_eq!(tag(&xml, "EncodingType").as_deref(), Some("url"));
    assert_eq!(tag(&xml, "Delimiter").as_deref(), Some("%2F"));
    assert_eq!(tags(&xml, "Key"), [format!("{encoded}a%2Etxt")]);
    assert_eq!(tags(&xml, "Prefix")[0], encoded);
    // Without it the characters are the characters, escaped as XML.
    let plain = req(Method::GET, "/bucket?list-type=2&prefix=%E4%B8%AD").send(&server).await.text();
    assert_eq!(tags(&plain, "Key"), ["中文 # %/a.txt"]);
    let answer = req(Method::GET, "/bucket?list-type=2&encoding-type=base64").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn version_1_with_a_marker() {
    let server = with_keys(&["k1", "k2", "k3"]).await;
    let first = req(Method::GET, "/bucket?max-keys=2").send(&server).await.text();
    assert_eq!(tags(&first, "Key"), ["k1", "k2"]);
    assert_eq!(
        (tag(&first, "IsTruncated").as_deref(), tag(&first, "NextMarker").as_deref(), tag(&first, "Marker").as_deref()),
        (Some("true"), Some("k2"), Some(""))
    );
    assert!(!first.contains("KeyCount") && !first.contains("ContinuationToken"), "{first}");
    let second = req(Method::GET, "/bucket?max-keys=2&marker=k2").send(&server).await.text();
    assert_eq!(tags(&second, "Key"), ["k3"]);
    assert_eq!((tag(&second, "IsTruncated").as_deref(), tag(&second, "Marker").as_deref()), (Some("false"), Some("k2")));
    assert!(tag(&second, "NextMarker").is_none());
}

#[tokio::test]
async fn limits_on_what_is_asked_for() {
    let server = with_keys(&["a"]).await;
    let long = "p".repeat(1025);
    for target in [
        format!("/bucket?list-type=2&prefix={long}"),
        format!("/bucket?list-type=2&start-after={long}"),
        format!("/bucket?marker={long}"),
        format!("/bucket?list-type=2&delimiter={}", "d".repeat(65)),
        "/bucket?list-type=2&continuation-token=not-one-of-ours".to_owned(),
    ] {
        let answer = req(Method::GET, &target).send(&server).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", &target[..40.min(target.len())]);
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidArgument"));
    }
    assert_eq!(req(Method::GET, &format!("/bucket?list-type=2&prefix={}", "p".repeat(1024))).send(&server).await.status, StatusCode::OK);
    assert_eq!(req(Method::GET, "/missing?list-type=2").send(&server).await.status, StatusCode::NOT_FOUND);
}

// ---- multipart ----

fn complete_body(parts: &[(u32, &str)]) -> String {
    let parts: String = parts.iter().map(|(number, etag)| format!("<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>")).collect();
    format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")
}

async fn create(server: &support::Server, key: &str) -> String {
    let answer = req(Method::POST, &format!("/bucket/{key}?uploads")).send(server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    tag(&answer.text(), "UploadId").unwrap()
}

async fn part(server: &support::Server, key: &str, id: &str, number: u32, data: Vec<u8>) -> String {
    let answer = req(Method::PUT, &format!("/bucket/{key}?partNumber={number}&uploadId={id}")).body(Bytes::from(data)).send(server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    answer.header("etag").unwrap().to_owned()
}

#[tokio::test]
async fn an_upload_in_parts_from_start_to_end() {
    let server = start().await;
    let created = req(Method::POST, "/bucket/dir/big.bin?uploads").header("content-type", "video/mp4").header("x-amz-meta-note", "n").send(&server).await;
    assert!(created.text().contains("<InitiateMultipartUploadResult xmlns="));
    assert_eq!((tag(&created.text(), "Bucket").as_deref(), tag(&created.text(), "Key").as_deref()), (Some("bucket"), Some("dir/big.bin")));
    let id = tag(&created.text(), "UploadId").unwrap();
    let first = part(&server, "dir/big.bin", &id, 1, vec![1; 5 << 20]).await;
    let second = part(&server, "dir/big.bin", &id, 2, vec![2; 100]).await;
    assert_eq!(second, format!("\"{}\"", thirtys3_core::encoding::hex_encode(&md5_digest(&[2; 100]))));
    let done = req(Method::POST, &format!("/bucket/dir/big.bin?uploadId={id}")).body(complete_body(&[(1, &first), (2, &second)])).send(&server).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    let xml = done.text();
    assert_eq!((tag(&xml, "Bucket").as_deref(), tag(&xml, "Key").as_deref()), (Some("bucket"), Some("dir/big.bin")));
    assert!(tag(&xml, "ETag").unwrap().ends_with("-2\""));
    assert!(tag(&xml, "Location").unwrap().ends_with("/bucket/dir/big.bin"));
    let info = server.service.backend().info(BUCKET, "dir/big.bin").unwrap();
    assert_eq!((info.size, info.content_type.as_deref(), info.metadata), (5 * 1024 * 1024 + 100, Some("video/mp4"), vec![("note".to_owned(), "n".to_owned())]));
    assert_eq!(server.service.backend().open_uploads(), 0);
}

#[tokio::test]
async fn the_checksum_algorithm_of_an_upload_is_told_back_and_must_be_known() {
    let server = start().await;
    let answer = req(Method::POST, "/bucket/k?uploads").header("x-amz-checksum-algorithm", "CRC32C").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.header("x-amz-checksum-algorithm"), Some("CRC32C"));
    let answer = req(Method::POST, "/bucket/k?uploads").header("x-amz-checksum-algorithm", "ROT13").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(req(Method::POST, "/bucket/folder/?uploads").send(&server).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn parts_with_numbers_or_uploads_that_cannot_be_right() {
    let server = start().await;
    let id = create(&server, "k").await;
    for number in ["0", "10001", "-1", "abc", "1.5", ""] {
        let answer = req(Method::PUT, &format!("/bucket/k?partNumber={number}&uploadId={id}")).body("x").send(&server).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{number:?}");
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidArgument"), "{number:?}");
    }
    let answer = req(Method::PUT, "/bucket/k?partNumber=1&uploadId=nope").body("x").send(&server).await;
    assert_eq!((answer.status, tag(&answer.text(), "Code").as_deref().map(str::to_owned)), (StatusCode::NOT_FOUND, Some("NoSuchUpload".to_owned())));
    let answer = req(Method::PUT, &format!("/bucket/other-key?partNumber=1&uploadId={id}")).body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "an upload belongs to its key");
    let answer = req(Method::PUT, "/bucket/k?partNumber=1&uploadId=").body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    let answer = req(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={id}")).header("x-amz-copy-source", "bucket/x").send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "UploadPartCopy");
}

#[tokio::test]
async fn a_part_is_checked_like_an_object() {
    let server = start().await;
    let id = create(&server, "k").await;
    let wrong = base64_encode(&md5_digest(b"other"));
    let answer = req(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={id}")).header("content-md5", &wrong).body("data").send(&server).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("BadDigest"));
    let listed = req(Method::GET, &format!("/bucket/k?uploadId={id}")).send(&server).await.text();
    assert!(tags(&listed, "Part").is_empty(), "the part that failed its check is not kept: {listed}");
    let good = req(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={id}"))
        .header("x-amz-checksum-crc32", &thirtys3_core::checksum::ChecksumAlgorithm::Crc32.checksum_base64(b"data"))
        .body("data")
        .send(&server)
        .await;
    assert_eq!(good.status, StatusCode::OK);
    assert_eq!(good.header("x-amz-checksum-crc32"), Some(thirtys3_core::checksum::ChecksumAlgorithm::Crc32.checksum_base64(b"data").as_str()));
}

#[tokio::test]
async fn the_end_of_an_upload_refuses_what_is_not_right() {
    let server = start().await;
    let id = create(&server, "k").await;
    let big = part(&server, "k", &id, 1, vec![1; 5 << 20]).await;
    let small = part(&server, "k", &id, 2, vec![2; 10]).await;
    let target = format!("/bucket/k?uploadId={id}");
    for (name, body, code) in [
        ("out of order", complete_body(&[(2, &small), (1, &big)]), "InvalidPartOrder"),
        ("twice", complete_body(&[(1, &big), (1, &big)]), "InvalidPartOrder"),
        ("a part that is not there", complete_body(&[(1, &big), (3, &small)]), "InvalidPart"),
        ("another ETag", complete_body(&[(1, "\"0123456789abcdef0123456789abcdef\""), (2, &small)]), "InvalidPart"),
        ("a small part that is not the last", complete_body(&[(2, &small), (4, &small)]), "InvalidPart"),
        ("no parts", "<CompleteMultipartUpload></CompleteMultipartUpload>".to_owned(), "MalformedXML"),
        ("not XML", "parts".to_owned(), "MalformedXML"),
        (
            "a part number that is not a number",
            "<CompleteMultipartUpload><Part><PartNumber>one</PartNumber><ETag>x</ETag></Part></CompleteMultipartUpload>".to_owned(),
            "MalformedXML",
        ),
    ] {
        let answer = req(Method::POST, &target).body(body).send(&server).await;
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some(code), "{name}: {}", answer.text());
    }
    let small_first = part(&server, "k", &id, 3, vec![3; 10]).await;
    let answer = req(Method::POST, &target).body(complete_body(&[(2, &small), (3, &small_first)])).send(&server).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("EntityTooSmall"));
    assert_eq!(server.service.backend().open_uploads(), 1, "an upload that failed to end is still there to try again");
    assert!(server.service.backend().object(BUCKET, "k").is_none());
    let done = req(Method::POST, &target).body(complete_body(&[(1, &big), (2, &small)])).send(&server).await;
    assert_eq!(done.status, StatusCode::OK);
}

#[tokio::test]
async fn the_end_of_an_upload_can_be_conditional() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "k", b"already");
    let id = create(&server, "k").await;
    let only = part(&server, "k", &id, 1, vec![1; 10]).await;
    let answer = req(Method::POST, &format!("/bucket/k?uploadId={id}")).header("if-none-match", "*").body(complete_body(&[(1, &only)])).send(&server).await;
    assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(server.service.backend().object(BUCKET, "k").unwrap(), "already");
    let answer = req(Method::POST, &format!("/bucket/k?uploadId={id}")).body(complete_body(&[(1, &only)])).send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn parts_are_listed_in_pages() {
    let server = start().await;
    let id = create(&server, "k").await;
    for number in [1, 2, 3, 4, 5] {
        part(&server, "k", &id, number, vec![number as u8; 10]).await;
    }
    let first = req(Method::GET, &format!("/bucket/k?uploadId={id}&max-parts=2")).send(&server).await.text();
    assert_eq!(tags(&first, "PartNumber"), ["1", "2"]);
    assert_eq!(
        (tag(&first, "IsTruncated").as_deref(), tag(&first, "NextPartNumberMarker").as_deref(), tag(&first, "MaxParts").as_deref()),
        (Some("true"), Some("2"), Some("2"))
    );
    assert_eq!(
        (tag(&first, "Bucket").as_deref(), tag(&first, "Key").as_deref(), tag(&first, "UploadId").as_deref()),
        (Some("bucket"), Some("k"), Some(id.as_str()))
    );
    let next = req(Method::GET, &format!("/bucket/k?uploadId={id}&max-parts=2&part-number-marker=2")).send(&server).await.text();
    assert_eq!(tags(&next, "PartNumber"), ["3", "4"]);
    assert_eq!(tag(&next, "PartNumberMarker").as_deref(), Some("2"));
    let last = req(Method::GET, &format!("/bucket/k?uploadId={id}&part-number-marker=4")).send(&server).await.text();
    assert_eq!((tags(&last, "PartNumber"), tag(&last, "IsTruncated").as_deref()), (vec!["5".to_owned()], Some("false")));
    assert_eq!(tags(&last, "Size"), ["10"]);
    assert_eq!(req(Method::GET, &format!("/bucket/k?uploadId={id}&max-parts=-1")).send(&server).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(req(Method::GET, "/bucket/k?uploadId=nope").send(&server).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uploads_in_progress_are_listed() {
    let server = start().await;
    let a = create(&server, "docs/a.txt").await;
    let b = create(&server, "docs/b.txt").await;
    let c = create(&server, "z.bin").await;
    let all = req(Method::GET, "/bucket?uploads").send(&server).await.text();
    assert_eq!(tags(&all, "Key"), ["docs/a.txt", "docs/b.txt", "z.bin"]);
    assert_eq!(tags(&all, "UploadId"), [a.as_str(), b.as_str(), c.as_str()]);
    let folders = req(Method::GET, "/bucket?uploads&delimiter=/").send(&server).await.text();
    assert_eq!(
        (tags(&folders, "Key"), tags(&folders, "Prefix")),
        (vec!["z.bin".to_owned()], vec![String::new(), "docs/".to_owned()]),
        "the Prefix of the request (empty), then the common prefixes"
    );
    let paged = req(Method::GET, "/bucket?uploads&max-uploads=1").send(&server).await.text();
    assert_eq!(
        (tag(&paged, "IsTruncated").as_deref(), tag(&paged, "NextKeyMarker").as_deref(), tag(&paged, "NextUploadIdMarker").as_deref()),
        (Some("true"), Some("docs/a.txt"), Some(a.as_str()))
    );
    let next = req(Method::GET, &format!("/bucket?uploads&max-uploads=1&key-marker=docs/a.txt&upload-id-marker={a}")).send(&server).await.text();
    assert_eq!(tags(&next, "Key"), ["docs/b.txt"]);
    assert_eq!(tags(&req(Method::GET, "/bucket?uploads&prefix=z").send(&server).await.text(), "Key"), ["z.bin"]);
}

#[tokio::test]
async fn an_upload_that_is_aborted_is_gone() {
    let server = start().await;
    let id = create(&server, "k").await;
    part(&server, "k", &id, 1, vec![1; 10]).await;
    assert_eq!(req(Method::DELETE, &format!("/bucket/k?uploadId={id}")).send(&server).await.status, StatusCode::NO_CONTENT);
    assert_eq!(server.service.backend().open_uploads(), 0);
    let again = req(Method::DELETE, &format!("/bucket/k?uploadId={id}")).send(&server).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(tag(&again.text(), "Code").as_deref(), Some("NoSuchUpload"));
    assert_eq!(req(Method::POST, &format!("/bucket/k?uploadId={id}")).body(complete_body(&[(1, "\"x\"")])).send(&server).await.status, StatusCode::NOT_FOUND);
}
