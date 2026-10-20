//! The client of this project against the server over the memory backend: every call the client makes, through real signatures and a real
//! connection.

mod support;

use bytes::Bytes;
use futures_util::StreamExt;
use support::{BUCKET, Server, client, client_with};
use thirtys3_client::{ChecksumAlgorithm, ErrorKind, GetOptions, GetRange, ListOptions, PutOptions};
use thirtys3_core::etag::{md5_digest, multipart_etag};
use thirtys3_server::memory::MemoryBackend;

fn data(length: usize) -> Bytes {
    Bytes::from((0..length).map(|i| (i * 7 + i / 251) as u8).collect::<Vec<u8>>())
}

fn backend(server: &Server) -> &MemoryBackend {
    server.service.backend()
}

#[tokio::test]
async fn put_get_head_delete() {
    let server = support::start().await;
    let client = client(&server);
    let options = PutOptions {
        content_type: Some("text/plain".into()),
        metadata: vec![("mtime".into(), "1700000000.5".into()), ("Source".into(), "scanner 1".into())],
        ..PutOptions::default()
    };
    let put = client.put("dir/hello.txt", Bytes::from_static(b"hello world"), &options).await.unwrap();
    assert_eq!(put.etag.as_deref(), Some("\"5eb63bbbe01eeed093cb22bb8f5acdc3\""));

    let head = client.head("dir/hello.txt").await.unwrap();
    assert_eq!((head.size, head.content_type.as_deref()), (11, Some("text/plain")));
    assert_eq!(head.metadata.get("mtime").map(String::as_str), Some("1700000000.5"));
    assert_eq!(head.metadata.get("source").map(String::as_str), Some("scanner 1"));
    assert!(head.last_modified.is_some());
    let object = client.get("dir/hello.txt", &GetOptions::default()).await.unwrap();
    assert_eq!(object.meta, head);
    assert_eq!(object.body.bytes().await.unwrap(), "hello world");

    client.delete("dir/hello.txt").await.unwrap();
    client.delete("dir/hello.txt").await.unwrap();
    assert!(client.head("dir/hello.txt").await.unwrap_err().is_not_found());
    assert!(client.get("dir/hello.txt", &GetOptions::default()).await.unwrap_err().is_not_found());
}

#[tokio::test]
async fn keys_with_awkward_characters() {
    let server = support::start().await;
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
        assert!(backend(&server).object(BUCKET, key).is_some(), "stored under the key as it is: {key:?}");
    }
}

#[tokio::test]
async fn large_objects_stream_through() {
    let server = support::start().await;
    let client = client(&server);
    let big = data(20 * 1024 * 1024 + 3);
    client.put("big", big.clone(), &PutOptions::default()).await.unwrap();
    let back = client.get("big", &GetOptions::default()).await.unwrap().body.bytes().await.unwrap();
    assert!(back == big);
    let empty = client.put("empty", Bytes::new(), &PutOptions::default()).await.unwrap();
    assert_eq!(empty.etag.as_deref(), Some("\"d41d8cd98f00b204e9800998ecf8427e\""));
    let object = client.get("empty", &GetOptions::default()).await.unwrap();
    assert_eq!(object.meta.size, 0);
    assert!(object.body.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn ranges() {
    let server = support::start().await;
    let client = client(&server);
    let content = data(1000);
    client.put("r", content.clone(), &PutOptions::default()).await.unwrap();
    for (range, covered) in [
        (GetRange::Bounded(10..20), 10..20),
        (GetRange::Bounded(0..1), 0..1),
        (GetRange::Bounded(990..5000), 990..1000),
        (GetRange::From(900), 900..1000),
        (GetRange::Suffix(5), 995..1000),
        (GetRange::Suffix(5000), 0..1000),
    ] {
        let object = client.get("r", &GetOptions { range: Some(range.clone()), ..GetOptions::default() }).await.unwrap_or_else(|error| panic!("{range:?}: {error}"));
        assert_eq!((object.range.clone(), object.meta.size), (covered.clone(), 1000), "{range:?}");
        assert_eq!(object.body.bytes().await.unwrap(), content.slice(covered.start as usize..covered.end as usize), "{range:?}");
    }
    for range in [GetRange::From(1000), GetRange::Bounded(5000..6000)] {
        assert_eq!(client.get("r", &GetOptions { range: Some(range), ..GetOptions::default() }).await.unwrap_err().kind(), ErrorKind::InvalidRange);
    }
}

#[tokio::test]
async fn conditions_on_get() {
    let server = support::start().await;
    let client = client(&server);
    let etag = client.put("c", Bytes::from_static(b"content"), &PutOptions::default()).await.unwrap().etag.unwrap();
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
async fn conditional_writes_create_only_once_and_replace_only_what_was_read() {
    let server = support::start().await;
    let client = client(&server);
    let create = PutOptions { if_none_match: true, ..PutOptions::default() };
    let first = client.put("lock", Bytes::from_static(b"one"), &create).await.unwrap();
    assert_eq!(client.put("lock", Bytes::from_static(b"two"), &create).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(backend(&server).object(BUCKET, "lock").unwrap(), "one");

    let replace = |etag: Option<String>| PutOptions { if_match: etag, ..PutOptions::default() };
    client.put("lock", Bytes::from_static(b"three"), &replace(first.etag.clone())).await.unwrap();
    assert_eq!(client.put("lock", Bytes::from_static(b"four"), &replace(first.etag)).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(client.put("missing", Bytes::new(), &replace(Some("\"abc\"".into()))).await.unwrap_err().kind(), ErrorKind::PreconditionFailed);
    assert_eq!(backend(&server).object(BUCKET, "lock").unwrap(), "three");
}

#[tokio::test]
async fn every_checksum_algorithm_is_verified_and_reported() {
    let server = support::start().await;
    let client = client(&server);
    for algorithm in ChecksumAlgorithm::ALL {
        let options = PutOptions { checksum: Some(algorithm), ..PutOptions::default() };
        let result = client.put("sum", Bytes::from_static(b"checksummed"), &options).await.unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
        let expected = algorithm.checksum_base64(b"checksummed");
        assert_eq!(result.checksums.get(algorithm), Some(expected.as_str()), "{algorithm:?}");
        assert_eq!(client.head("sum").await.unwrap().checksums.get(algorithm), Some(expected.as_str()), "{algorithm:?}");
    }
}

#[tokio::test]
async fn listing_pages_folders_and_start_after() {
    let server = support::start().await;
    let client = client(&server);
    let backend = backend(&server);
    for key in ["photos/2020/a.jpg", "photos/2020/b.jpg", "photos/2021/c.jpg", "photos/readme.txt", "other.txt", "z"] {
        backend.insert(BUCKET, key, key.as_bytes());
    }
    let all: Vec<String> = client.list("", &ListOptions { page_size: Some(2), ..ListOptions::default() }).map(|entry| entry.unwrap().key).collect().await;
    assert_eq!(all, ["other.txt", "photos/2020/a.jpg", "photos/2020/b.jpg", "photos/2021/c.jpg", "photos/readme.txt", "z"]);
    let folder = client.list_with_delimiter("photos/", "/").await.unwrap();
    assert_eq!(folder.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["photos/readme.txt"]);
    assert_eq!(folder.common_prefixes, ["photos/2020/", "photos/2021/"]);
    let top = client.list_with_delimiter("", "/").await.unwrap();
    assert_eq!((top.objects.len(), top.common_prefixes), (2, vec!["photos/".to_owned()]));
    let after: Vec<String> =
        client.list("", &ListOptions { start_after: Some("photos/2021/c.jpg".into()), ..ListOptions::default() }).map(|entry| entry.unwrap().key).collect().await;
    assert_eq!(after, ["photos/readme.txt", "z"]);
    // Folders across pages: each once.
    let pages: Vec<_> = client.list_pages("", &ListOptions { delimiter: Some("/".into()), page_size: Some(1), ..ListOptions::default() }).collect().await;
    let prefixes: Vec<String> = pages.into_iter().flat_map(|page| page.unwrap().common_prefixes).collect();
    assert_eq!(prefixes, ["photos/"]);
}

#[tokio::test]
async fn awkward_keys_are_listed_through_the_url_encoding() {
    let server = support::start().await;
    let client = client(&server);
    let awkward = ["日本語/ファイル.txt", "with space/ and + plus", "per%cent/%41", "control\u{1}char", "amp&lt;/<tag>", "line\nbreak/x"];
    for key in awkward {
        backend(&server).insert(BUCKET, key, b"x");
    }
    let mut expected = awkward.to_vec();
    expected.sort();
    let listed: Vec<String> = client.list("", &ListOptions::default()).map(|entry| entry.unwrap().key).collect().await;
    assert_eq!(listed, expected);
    let folders = client.list_with_delimiter("", "/").await.unwrap();
    assert!(folders.common_prefixes.contains(&"日本語/".to_owned()) && folders.common_prefixes.contains(&"per%cent/".to_owned()));
}

#[tokio::test]
async fn multipart_upload() {
    let server = support::start().await;
    let client = client(&server);
    let content = data(11 * 1024 * 1024);
    let result = client.put_multipart("big", &content[..], &PutOptions { content_type: Some("video/mp4".into()), ..PutOptions::default() }).await.unwrap();
    let md5s = [md5_digest(&content[..5 << 20]), md5_digest(&content[5 << 20..10 << 20]), md5_digest(&content[10 << 20..])];
    assert_eq!(result.etag.as_deref(), Some(multipart_etag(&md5s).as_str()));
    assert!(backend(&server).object(BUCKET, "big").unwrap() == content);
    assert_eq!(backend(&server).info(BUCKET, "big").unwrap().content_type.as_deref(), Some("video/mp4"));
    assert_eq!(backend(&server).open_uploads(), 0);
    let back = client.get("big", &GetOptions { range: Some(GetRange::Bounded((5 << 20) - 10..(5 << 20) + 10)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(back.body.bytes().await.unwrap().len(), 20);
}

#[tokio::test]
async fn multipart_upload_by_hand_with_checksums_and_abort() {
    let server = support::start().await;
    let client = client(&server);
    let upload = client.create_multipart("k", &PutOptions { checksum: Some(ChecksumAlgorithm::Crc32c), ..PutOptions::default() }).await.unwrap();
    let one = upload.put_part(1, data(5 << 20)).await.unwrap();
    assert!(one.checksum.is_some());
    assert_eq!(backend(&server).open_uploads(), 1);
    upload.abort().await.unwrap();
    assert_eq!(backend(&server).open_uploads(), 0);
    assert!(upload.put_part(2, Bytes::new()).await.unwrap_err().is_not_found());
}

#[tokio::test]
async fn deleting_several_objects() {
    let server = support::start().await;
    let client = client(&server);
    let keys: Vec<String> = (0..25).map(|i| format!("k{i:02}")).collect();
    for key in &keys {
        backend(&server).insert(BUCKET, key, b"x");
    }
    let mut with_missing = keys.clone();
    with_missing.push("never-there".into());
    assert!(client.delete_many(&with_missing).await.unwrap().is_empty());
    assert!(backend(&server).keys(BUCKET).is_empty());
}

#[tokio::test]
async fn the_client_resumes_a_download_against_the_server() {
    let server = support::start().await;
    let client = client(&server);
    let content = data(300_000);
    client.put("big", content.clone(), &PutOptions::default()).await.unwrap();
    // Ranged requests with If-Match are what a resume sends.
    let etag = client.head("big").await.unwrap().etag.unwrap();
    let part = client.get("big", &GetOptions { range: Some(GetRange::From(100_000)), if_match: Some(etag), ..GetOptions::default() }).await.unwrap();
    assert_eq!(part.body.bytes().await.unwrap(), content.slice(100_000..));
}

#[tokio::test]
async fn errors_come_back_as_the_client_expects() {
    let server = support::start().await;
    let missing = client_with(&server, support::ACCESS_KEY, support::SECRET_KEY, "no-such-bucket");
    assert_eq!(missing.head("k").await.unwrap_err().kind(), ErrorKind::NotFound);
    let wrong_secret = client_with(&server, support::ACCESS_KEY, "not the secret", BUCKET);
    assert_eq!(wrong_secret.head("k").await.unwrap_err().kind(), ErrorKind::PermissionDenied);
    let unknown = client_with(&server, "AKIAUNKNOWN", "x", BUCKET);
    assert_eq!(unknown.head("k").await.unwrap_err().kind(), ErrorKind::PermissionDenied);
    let read_only = client_with(&server, support::READ_ONLY_KEY, support::READ_ONLY_SECRET, BUCKET);
    backend(&server).insert(BUCKET, "k", b"x");
    assert!(read_only.head("k").await.is_ok());
    assert_eq!(read_only.put("k2", Bytes::new(), &PutOptions::default()).await.unwrap_err().kind(), ErrorKind::PermissionDenied);
    assert_eq!(read_only.delete("k").await.unwrap_err().kind(), ErrorKind::PermissionDenied);
    assert!(backend(&server).object(BUCKET, "k").is_some());
}
