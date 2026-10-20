//! Multipart uploads: the parts, the end, and what happens to the upload when anything goes wrong.

mod support;

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Method;
use support::{Fault, TestServer, client, config};
use thirtys3_client::{ChecksumAlgorithm, Client, Error, ErrorKind, GetOptions, PutOptions, part_checksum};
use thirtys3_core::etag::{md5_digest, multipart_etag};
use tokio::io::{AsyncRead, ReadBuf};

const MIB: usize = 1024 * 1024;

fn content(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 31 + i / 4099) as u8).collect()
}

fn five_mib_parts(server: &TestServer) -> Client {
    let mut config = config(server);
    config.part_size = 5 * MIB;
    Client::new(config).unwrap()
}

fn log_of(server: &TestServer) -> (usize, usize, usize, usize) {
    let requests = server.requests();
    let count = |method: Method, query: &str| requests.iter().filter(|request| request.method == method && request.query.contains(query)).count();
    (count(Method::POST, "uploads"), count(Method::PUT, "partNumber"), count(Method::POST, "uploadId"), count(Method::DELETE, "uploadId"))
}

#[tokio::test]
async fn data_from_a_reader_goes_up_in_parts_and_is_put_together() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    let data = content(11 * MIB);
    let result = client.put_multipart("big", &data[..], &PutOptions { content_type: Some("video/mp4".into()), ..PutOptions::default() }).await.unwrap();

    let stored = server.object("big").unwrap();
    assert!(stored.data == data, "the object is the data");
    assert_eq!(stored.content_type, "video/mp4");
    // 5 MiB + 5 MiB + 1 MiB, and the ETag S3 makes for an upload in parts.
    let md5s = [md5_digest(&data[..5 * MIB]), md5_digest(&data[5 * MIB..10 * MIB]), md5_digest(&data[10 * MIB..])];
    assert_eq!(stored.etag, multipart_etag(&md5s));
    assert_eq!(result.etag.as_deref(), Some(stored.etag.as_str()));
    assert!(stored.etag.ends_with("-3\""));
    assert_eq!(log_of(&server), (1, 3, 1, 0));
    assert_eq!(server.open_uploads(), 0);
    assert!(server.requests().iter().all(|request| request.authenticated));
}

#[tokio::test]
async fn the_object_downloads_whole_and_by_range() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    let data = content(7 * MIB);
    client.put_multipart("k", &data[..], &PutOptions::default()).await.unwrap();
    let back = client.get("k", &GetOptions::default()).await.unwrap().body.bytes().await.unwrap();
    assert!(back == data);
    assert_eq!(client.head("k").await.unwrap().size, data.len() as u64);
}

#[tokio::test]
async fn data_that_is_an_exact_number_of_parts_has_no_empty_part_at_the_end() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    client.put_multipart("k", &content(10 * MIB)[..], &PutOptions::default()).await.unwrap();
    assert_eq!(log_of(&server), (1, 2, 1, 0));
    assert_eq!(server.object("k").unwrap().data.len(), 10 * MIB);
}

#[tokio::test]
async fn small_and_empty_data_are_one_part() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    client.put_multipart("small", &b"abc"[..], &PutOptions::default()).await.unwrap();
    assert_eq!(server.object("small").unwrap().data, "abc");
    server.clear_log();
    client.put_multipart("empty", &b""[..], &PutOptions::default()).await.unwrap();
    assert_eq!(server.object("empty").unwrap().data.len(), 0);
    assert_eq!(log_of(&server), (1, 1, 1, 0), "an upload needs a part, even an empty one");
}

#[tokio::test]
async fn parts_go_up_several_at_a_time_and_no_more_than_the_setting() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.part_size = 5 * MIB;
    config.multipart_concurrency = 2;
    let client = Client::new(config).unwrap();
    server.fault(Some(Method::PUT), None, Some("partNumber"), 100, Fault::Delay(Duration::from_millis(150)));
    let data = content(26 * MIB);
    client.put_multipart("k", &data[..], &PutOptions::default()).await.unwrap();
    assert_eq!(server.max_inflight(), 2, "two parts at a time, never three");
    assert!(server.object("k").unwrap().data == data);
    assert_eq!(log_of(&server).1, 6);
}

#[tokio::test]
async fn one_at_a_time_when_the_setting_is_one() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.part_size = 5 * MIB;
    config.multipart_concurrency = 1;
    let client = Client::new(config).unwrap();
    client.put_multipart("k", &content(11 * MIB)[..], &PutOptions::default()).await.unwrap();
    assert_eq!(server.max_inflight(), 1);
}

/// A reader that gives some data and then fails.
struct FailsAfter {
    given: usize,
    limit: usize,
}

impl AsyncRead for FailsAfter {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.given >= self.limit {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the source broke")));
        }
        let length = buffer.remaining().min(self.limit - self.given).min(64 * 1024);
        buffer.put_slice(&vec![7; length]);
        self.given += length;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn when_the_source_fails_the_upload_is_aborted_and_nothing_is_left() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    let error = client.put_multipart("k", FailsAfter { given: 0, limit: 7 * MIB }, &PutOptions::default()).await.unwrap_err();
    assert!(matches!(&error, Error::Source(source) if source.kind() == io::ErrorKind::BrokenPipe), "{error:?}");
    assert_eq!(server.open_uploads(), 0, "the parts that were uploaded are thrown away");
    assert!(server.object("k").is_none());
    let (created, _, completed, aborted) = log_of(&server);
    assert_eq!((created, completed, aborted), (1, 0, 1));
}

#[tokio::test]
async fn when_a_part_fails_for_good_the_upload_is_aborted() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    server.fault(Some(Method::PUT), None, Some("partNumber=2"), 100, Fault::Status(400, "InvalidArgument"));
    let error = client.put_multipart("k", &content(16 * MIB)[..], &PutOptions::default()).await.unwrap_err();
    assert!(matches!(&error, Error::Service(s3) if s3.code == "InvalidArgument"), "{error:?}");
    assert_eq!(server.open_uploads(), 0);
    assert!(server.object("k").is_none());
    assert_eq!(log_of(&server).3, 1);
}

#[tokio::test]
async fn a_part_that_fails_for_a_while_is_tried_again_and_the_upload_succeeds() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    server.fault(Some(Method::PUT), None, Some("partNumber=1"), 2, Fault::Status(503, "SlowDown"));
    let data = content(11 * MIB);
    client.put_multipart("k", &data[..], &PutOptions::default()).await.unwrap();
    assert!(server.object("k").unwrap().data == data);
    assert_eq!(log_of(&server).3, 0);
}

#[tokio::test]
async fn when_the_end_fails_for_good_the_upload_is_aborted() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    server.fault(Some(Method::POST), None, Some("uploadId"), 100, Fault::OkWithError("AccessDenied"));
    let error = client.put_multipart("k", &content(6 * MIB)[..], &PutOptions::default()).await.unwrap_err();
    assert!(matches!(&error, Error::Service(s3) if s3.code == "AccessDenied"), "{error:?}");
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(server.open_uploads(), 0);
    assert_eq!(log_of(&server), (1, 2, 1, 1), "not repeated, since it cannot pass");
}

#[tokio::test]
async fn an_end_that_says_200_and_then_fails_the_way_that_can_pass_is_tried_again() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    server.fault(Some(Method::POST), None, Some("uploadId"), 2, Fault::OkWithError("InternalError"));
    let data = content(6 * MIB);
    let result = client.put_multipart("k", &data[..], &PutOptions::default()).await.unwrap();
    assert!(result.etag.is_some());
    assert!(server.object("k").unwrap().data == data);
    assert_eq!(log_of(&server).2, 3, "the 200 with an error in it, again, and then the real one");
    assert_eq!(server.open_uploads(), 0);
}

#[tokio::test]
async fn an_end_that_keeps_failing_the_way_that_can_pass_gives_up_and_aborts() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.part_size = 5 * MIB;
    config.max_retries = 2;
    let client = Client::new(config).unwrap();
    server.fault(Some(Method::POST), None, Some("uploadId"), 100, Fault::OkWithError("InternalError"));
    let error = client.put_multipart("k", &content(6 * MIB)[..], &PutOptions::default()).await.unwrap_err();
    assert!(error.is_retryable(), "{error:?}");
    assert_eq!(log_of(&server).2, 3);
    assert_eq!(server.open_uploads(), 0);
}

#[tokio::test]
async fn every_part_carries_its_checksum_when_one_is_asked_for() {
    let server = TestServer::start().await;
    let client = five_mib_parts(&server);
    let data = content(11 * MIB);
    let options = PutOptions { checksum: Some(ChecksumAlgorithm::Crc32c), ..PutOptions::default() };
    client.put_multipart("k", &data[..], &options).await.unwrap();

    let create = &server.requests_matching(Method::POST, "/k")[0];
    assert_eq!(create.header("x-amz-checksum-algorithm"), Some("CRC32C"));
    let parts = server.requests_matching(Method::PUT, "/k");
    assert_eq!(parts.len(), 3);
    let mut sums: Vec<_> = parts.iter().map(|part| part.header("x-amz-checksum-crc32c").unwrap().to_owned()).collect();
    sums.sort();
    let mut expected = vec![
        part_checksum(ChecksumAlgorithm::Crc32c, &data[..5 * MIB]),
        part_checksum(ChecksumAlgorithm::Crc32c, &data[5 * MIB..10 * MIB]),
        part_checksum(ChecksumAlgorithm::Crc32c, &data[10 * MIB..]),
    ];
    expected.sort();
    assert_eq!(sums, expected);
    // And the end names each one.
    let complete = String::from_utf8(server.requests_matching(Method::POST, "/k").last().unwrap().body.to_vec()).unwrap();
    for sum in &expected {
        assert!(complete.contains(&format!("<ChecksumCRC32C>{sum}</ChecksumCRC32C>")), "{complete}");
    }
}

#[tokio::test]
async fn the_parts_of_an_upload_by_hand() {
    let server = TestServer::start().await;
    let client = client(&server);
    let upload = client.create_multipart("hand", &PutOptions { metadata: vec![("note".into(), "by hand".into())], ..PutOptions::default() }).await.unwrap();
    assert!(!upload.upload_id().is_empty());
    assert_eq!(upload.key(), "hand");
    let part_one = Bytes::from(content(5 * MIB));
    let part_two = Bytes::from_static(b"the end");
    // In the wrong order, and the end puts them in the right one.
    let second = upload.put_part(2, part_two.clone()).await.unwrap();
    let first = upload.put_part(1, part_one.clone()).await.unwrap();
    assert_eq!(first.etag, thirtys3_core::etag::etag_from_md5(&md5_digest(&part_one)));
    let result = upload.complete(vec![second, first]).await.unwrap();
    assert!(result.etag.unwrap().ends_with("-2\""));
    let stored = server.object("hand").unwrap();
    assert_eq!(stored.data.len(), 5 * MIB + 7);
    assert_eq!(stored.metadata.get("note").map(String::as_str), Some("by hand"));
}

#[tokio::test]
async fn an_upload_can_be_aborted_by_hand_and_aborting_twice_is_fine() {
    let server = TestServer::start().await;
    let client = client(&server);
    let upload = client.create_multipart("k", &PutOptions::default()).await.unwrap();
    upload.put_part(1, Bytes::from_static(b"x")).await.unwrap();
    assert_eq!(server.open_uploads(), 1);
    upload.abort().await.unwrap();
    assert_eq!(server.open_uploads(), 0);
    upload.abort().await.unwrap();
    let error = upload.put_part(2, Bytes::new()).await.unwrap_err();
    assert!(error.is_not_found(), "{error:?}");
}

#[tokio::test]
async fn arguments_that_cannot_work_are_refused_before_anything_is_sent() {
    let server = TestServer::start().await;
    let client = client(&server);
    let upload = client.create_multipart("k", &PutOptions::default()).await.unwrap();
    server.clear_log();
    for number in [0, 10_001] {
        assert_eq!(upload.put_part(number, Bytes::new()).await.unwrap_err().kind(), ErrorKind::InvalidInput, "{number}");
    }
    assert_eq!(upload.complete(vec![]).await.unwrap_err().kind(), ErrorKind::InvalidInput);
    assert!(server.requests().is_empty());
    for options in [PutOptions { if_none_match: true, ..PutOptions::default() }, PutOptions { if_match: Some("\"x\"".into()), ..PutOptions::default() }] {
        assert_eq!(client.create_multipart("k", &options).await.unwrap_err().kind(), ErrorKind::InvalidInput);
    }
    let mut config = config(&server);
    config.part_size = 1024;
    assert!(matches!(Client::new(config), Err(Error::Config(_))));
    let mut config = self::config(&server);
    config.multipart_concurrency = 0;
    assert!(matches!(Client::new(config), Err(Error::Config(_))));
}

#[tokio::test]
async fn parts_that_are_too_small_are_the_service_s_to_refuse() {
    let server = TestServer::start().await;
    let client = client(&server);
    let upload = client.create_multipart("k", &PutOptions::default()).await.unwrap();
    let one = upload.put_part(1, Bytes::from_static(b"small")).await.unwrap();
    let two = upload.put_part(2, Bytes::from_static(b"small")).await.unwrap();
    let error = upload.complete(vec![one, two]).await.unwrap_err();
    assert!(matches!(&error, Error::Service(s3) if s3.code == "EntityTooSmall"), "{error:?}");
    upload.abort().await.unwrap();
}
