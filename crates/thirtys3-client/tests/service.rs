//! The client against a real S3-compatible service.
//!
//! These tests need a service and a bucket that exists, named by environment variables; without them every test here ends at once and is
//! reported as passed (the in-memory service of the other tests covers the logic, this covers what only a real service shows):
//!
//! - `THIRTYS3_TEST_ENDPOINT`, such as `http://127.0.0.1:19000`
//! - `THIRTYS3_TEST_BUCKET`
//! - `THIRTYS3_TEST_ACCESS_KEY` and `THIRTYS3_TEST_SECRET_KEY`
//! - `THIRTYS3_TEST_REGION` (default `us-east-1`)
//!
//! Every test works under a prefix of its own and removes what it made. Use a bucket for tests, not one with data in it.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use thirtys3_client::{ChecksumAlgorithm, Client, ClientConfig, Credentials, Error, ErrorKind, GetOptions, GetRange, ListOptions, PutOptions};
use thirtys3_core::etag::{md5_digest, multipart_etag};

const MIB: usize = 1024 * 1024;

fn setting(name: &str) -> Option<String> {
    std::env::var(format!("THIRTYS3_TEST_{name}")).ok().filter(|value| !value.is_empty())
}

fn config() -> Option<ClientConfig> {
    let endpoint = setting("ENDPOINT")?;
    let bucket = setting("BUCKET")?;
    let mut config = ClientConfig::new(bucket, Credentials::new(setting("ACCESS_KEY")?, setting("SECRET_KEY")?))
        .endpoint(endpoint.clone())
        .region(setting("REGION").unwrap_or_else(|| "us-east-1".to_owned()));
    config.allow_http = endpoint.starts_with("http://");
    config.part_size = 5 * MIB;
    Some(config)
}

/// A client and a prefix no other test uses, or `None` when no service is set up.
fn start(test: &str) -> Option<(Client, String)> {
    let Some(config) = config() else {
        eprintln!("skipped: THIRTYS3_TEST_* is not set");
        return None;
    };
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    Some((Client::new(config).unwrap(), format!("thirtys3-tests/{test}-{}-{nanos}/", std::process::id())))
}

async fn clean(client: &Client, prefix: &str) {
    let keys: Vec<String> = client.list(prefix, &ListOptions::default()).filter_map(|entry| async move { entry.ok().map(|entry| entry.key) }).collect().await;
    let _ = client.delete_many(&keys).await;
}

fn data(length: usize) -> Bytes {
    Bytes::from((0..length).map(|i| (i * 7 + i / 251) as u8).collect::<Vec<u8>>())
}

#[tokio::test]
async fn an_object_goes_in_and_comes_out_with_its_metadata() {
    let Some((client, prefix)) = start("roundtrip") else { return };
    let key = format!("{prefix}hello.txt");
    let options = PutOptions { content_type: Some("text/plain".into()), metadata: vec![("mtime".into(), "1700000000.5".into())], ..PutOptions::default() };
    let put = client.put(&key, Bytes::from_static(b"hello world"), &options).await.unwrap();
    assert_eq!(put.etag.as_deref(), Some("\"5eb63bbbe01eeed093cb22bb8f5acdc3\""), "the ETag of a single upload is the MD5");

    let head = client.head(&key).await.unwrap();
    assert_eq!((head.size, head.content_type.as_deref()), (11, Some("text/plain")));
    assert_eq!(head.metadata.get("mtime").map(String::as_str), Some("1700000000.5"));
    assert!(head.last_modified.is_some());
    let object = client.get(&key, &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), "hello world");

    client.delete(&key).await.unwrap();
    client.delete(&key).await.unwrap();
    assert!(client.head(&key).await.unwrap_err().is_not_found());
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn keys_with_awkward_characters() {
    let Some((client, prefix)) = start("keys") else { return };
    // Keys every S3 service takes.
    let names = ["a b", "a+b", "100%", "%41", "中文/文件.txt", "emoji 😀", "!*'();:@&=$,", "tab\there"];
    for name in names {
        let key = format!("{prefix}{name}");
        client.put(&key, Bytes::from(name.to_owned()), &PutOptions::default()).await.unwrap_or_else(|error| panic!("put {name:?}: {error}"));
        let back = client.get(&key, &GetOptions::default()).await.unwrap_or_else(|error| panic!("get {name:?}: {error}")).body.bytes().await.unwrap();
        assert_eq!(back, name.as_bytes(), "{name:?}");
    }
    let listed: Vec<String> = client.list(&prefix, &ListOptions::default()).map(|entry| entry.unwrap().key).collect().await;
    for name in names {
        assert!(listed.contains(&format!("{prefix}{name}")), "{name:?} is not in the listing {listed:?}");
    }

    // Keys that S3 takes and some other services refuse (an empty or a dot-dot part of the path). A service may say it does not take them, with a
    // 400; but if it does take them, they have to come back as they went in, which shows the request was signed and encoded right.
    for name in ["a//b", "../a", "x/./y", "trailing/"] {
        let key = format!("{prefix}{name}");
        match client.put(&key, Bytes::from(name.to_owned()), &PutOptions::default()).await {
            Ok(_) => {
                let back = client.get(&key, &GetOptions::default()).await.unwrap_or_else(|error| panic!("get {name:?}: {error}")).body.bytes().await.unwrap();
                assert_eq!(back, name.as_bytes(), "{name:?}");
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::Rejected, "{name:?}: {error}");
                eprintln!("this service does not take the key {name:?}: {error}");
            }
        }
    }
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn ranges() {
    let Some((client, prefix)) = start("ranges") else { return };
    let key = format!("{prefix}r");
    let content = data(1000);
    client.put(&key, content.clone(), &PutOptions::default()).await.unwrap();
    for (range, covered) in
        [(GetRange::Bounded(10..20), 10..20), (GetRange::From(900), 900..1000), (GetRange::Suffix(5), 995..1000), (GetRange::Bounded(990..5000), 990..1000)]
    {
        let object =
            client.get(&key, &GetOptions { range: Some(range.clone()), ..GetOptions::default() }).await.unwrap_or_else(|error| panic!("{range:?}: {error}"));
        assert_eq!((object.range.clone(), object.meta.size), (covered.clone(), 1000), "{range:?}");
        assert_eq!(object.body.bytes().await.unwrap(), content.slice(covered.start as usize..covered.end as usize));
    }
    let error = client.get(&key, &GetOptions { range: Some(GetRange::From(5000)), ..GetOptions::default() }).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidRange, "{error:?}");
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn what_is_not_there() {
    let Some((client, prefix)) = start("missing") else { return };
    let key = format!("{prefix}nothing");
    assert!(client.get(&key, &GetOptions::default()).await.unwrap_err().is_not_found());
    assert!(client.head(&key).await.unwrap_err().is_not_found());
    client.delete(&key).await.unwrap();
    assert!(client.delete_many(&[key]).await.unwrap().is_empty());
}

#[tokio::test]
async fn conditions() {
    let Some((client, prefix)) = start("conditions") else { return };
    let key = format!("{prefix}c");
    let create = PutOptions { if_none_match: true, ..PutOptions::default() };
    let first = client.put(&key, Bytes::from_static(b"one"), &create).await.unwrap();
    let error = client.put(&key, Bytes::from_static(b"two"), &create).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed, "{error:?}");

    let replace = |etag: &str| PutOptions { if_match: Some(etag.to_owned()), ..PutOptions::default() };
    client.put(&key, Bytes::from_static(b"three"), &replace(first.etag.as_deref().unwrap())).await.unwrap();
    let error = client.put(&key, Bytes::from_static(b"four"), &replace(first.etag.as_deref().unwrap())).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed, "{error:?}");

    let etag = client.head(&key).await.unwrap().etag.unwrap();
    let error = client.get(&key, &GetOptions { if_none_match: Some(etag.clone()), ..GetOptions::default() }).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotModified, "{error:?}");
    let error = client.get(&key, &GetOptions { if_match: Some("\"other\"".into()), ..GetOptions::default() }).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed, "{error:?}");
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn listing_pages_folders_and_start_after() {
    let Some((client, prefix)) = start("listing") else { return };
    let names = ["a/1", "a/2", "a/3", "b/1", "c", "d e", "日本"];
    for name in names {
        client.put(&format!("{prefix}{name}"), Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap();
    }
    let paged = ListOptions { page_size: Some(2), ..ListOptions::default() };
    let all: Vec<String> = client.list(&prefix, &paged).map(|entry| entry.unwrap().key).collect().await;
    let mut expected: Vec<String> = names.iter().map(|name| format!("{prefix}{name}")).collect();
    expected.sort();
    assert_eq!(all, expected, "all of them, in order, across pages");

    let folders = client.list_with_delimiter(&prefix, "/").await.unwrap();
    assert_eq!(folders.common_prefixes, [format!("{prefix}a/"), format!("{prefix}b/")]);
    assert_eq!(folders.objects.len(), 3);

    let after = ListOptions { start_after: Some(format!("{prefix}b/1")), ..ListOptions::default() };
    let rest: Vec<String> = client.list(&prefix, &after).map(|entry| entry.unwrap().key).collect().await;
    assert_eq!(rest.first().map(String::as_str), Some(format!("{prefix}c").as_str()));
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn a_large_object_in_one_request_and_in_parts() {
    let Some((client, prefix)) = start("large") else { return };
    let content = data(11 * MIB + 5);

    let single = format!("{prefix}single");
    client.put(&single, content.clone(), &PutOptions::default()).await.unwrap();
    let back = client.get(&single, &GetOptions::default()).await.unwrap().body.bytes().await.unwrap();
    assert!(back == content);

    let parts = format!("{prefix}parts");
    let result = client.put_multipart(&parts, &content[..], &PutOptions { content_type: Some("application/x-test".into()), ..PutOptions::default() }).await.unwrap();
    let md5s = [md5_digest(&content[..5 * MIB]), md5_digest(&content[5 * MIB..10 * MIB]), md5_digest(&content[10 * MIB..])];
    assert_eq!(
        result.etag.as_deref(),
        Some(multipart_etag(&md5s).as_str()),
        "the ETag of an upload in parts is the MD5 of the MD5s, a dash and the number of parts"
    );
    let head = client.head(&parts).await.unwrap();
    assert_eq!((head.size, head.content_type.as_deref()), (content.len() as u64, Some("application/x-test")));
    let back = client.get(&parts, &GetOptions::default()).await.unwrap().body.bytes().await.unwrap();
    assert!(back == content);
    // A range across the boundary of two parts.
    let across =
        client.get(&parts, &GetOptions { range: Some(GetRange::Bounded(5 * MIB as u64 - 10..5 * MIB as u64 + 10)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(across.body.bytes().await.unwrap(), content.slice(5 * MIB - 10..5 * MIB + 10));
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn data_that_cannot_be_read_aborts_the_upload() {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    struct Fails(usize);
    impl tokio::io::AsyncRead for Fails {
        fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
            if self.0 > 6 * MIB {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the source broke")));
            }
            let length = buffer.remaining().min(64 * 1024);
            buffer.put_slice(&vec![1; length]);
            self.0 += length;
            Poll::Ready(Ok(()))
        }
    }
    let Some((client, prefix)) = start("abort") else { return };
    let key = format!("{prefix}never");
    let error = client.put_multipart(&key, Fails(0), &PutOptions::default()).await.unwrap_err();
    assert!(matches!(error, Error::Source(_)), "{error:?}");
    assert!(client.head(&key).await.unwrap_err().is_not_found());
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn checksums_the_service_verifies() {
    let Some((client, prefix)) = start("checksums") else { return };
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Crc32c, ChecksumAlgorithm::Sha1, ChecksumAlgorithm::Sha256, ChecksumAlgorithm::Crc64Nvme] {
        let key = format!("{prefix}{}", algorithm.name());
        let options = PutOptions { checksum: Some(algorithm), ..PutOptions::default() };
        client.put(&key, Bytes::from_static(b"checksummed"), &options).await.unwrap_or_else(|error| panic!("{algorithm:?}: {error}"));
    }
    clean(&client, &prefix).await;
}

#[tokio::test]
async fn deleting_several_objects() {
    let Some((client, prefix)) = start("delete") else { return };
    let keys: Vec<String> = (0..25).map(|i| format!("{prefix}k{i:02}")).collect();
    for key in &keys {
        client.put(key, Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap();
    }
    let mut with_missing = keys.clone();
    with_missing.push(format!("{prefix}never-there"));
    assert!(client.delete_many(&with_missing).await.unwrap().is_empty());
    assert!(client.list(&prefix, &ListOptions::default()).next().await.is_none());
}

#[tokio::test]
async fn wrong_keys_and_a_wrong_bucket() {
    let Some(config) = config() else {
        eprintln!("skipped: THIRTYS3_TEST_* is not set");
        return;
    };
    let mut wrong_secret = config.clone();
    wrong_secret.credentials = Credentials::new(wrong_secret.credentials.access_key_id.clone(), "not the secret");
    let error = Client::new(wrong_secret).unwrap().head("anything").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PermissionDenied, "{error:?}");

    let mut wrong_bucket = config;
    wrong_bucket.bucket = "thirtys3-no-such-bucket-4f9a1c".into();
    let error = Client::new(wrong_bucket).unwrap().head("anything").await.unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied), "{error:?}");
}
