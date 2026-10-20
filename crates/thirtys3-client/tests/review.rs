//! Things a review of the client found. Each test failed before the change that fixed it.

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Method;
use thirtys3_client::{Client, ClientConfig, Credentials, Error, ErrorKind, GetOptions, GetRange, ListOptions, PutOptions};
use thirtys3_core::etag::{etag_from_md5, md5_digest, multipart_etag};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use support::{Fault, TestServer, client, config};

const MIB: usize = 1024 * 1024;

fn content(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 13 + i / 251) as u8).collect()
}

// ---- a download that goes on is not cut off by the time that trouble is allowed ----

#[tokio::test]
async fn a_download_that_keeps_coming_survives_a_break_long_after_its_start() {
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.retry_timeout = Duration::from_millis(400);
    let client = Client::new(settings).unwrap();
    let data = content(600_000);
    server.put_object("big", &data);
    // 20 pieces in 1.2 seconds, three times the time allowed for trouble, and then the connection breaks.
    server.fault(Some(Method::GET), None, None, 1, Fault::Paced(20_000, Duration::from_millis(60), 400_000));
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data);
}

// ---- a slow upload is not a silent one ----

/// A service that reads a request body slowly, `pause` before each read of up to 1 MiB, and then answers `200` with no body. When `stop` is true it
/// reads nothing of the body at all.
async fn slow_reader(pause: Duration, stop: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = vec![0u8; MIB];
                let end = loop {
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..read]);
                    if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                if stop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
                let text = String::from_utf8_lossy(&head[..end]).to_ascii_lowercase();
                let length: usize = text.lines().find_map(|line| line.strip_prefix("content-length:")).and_then(|value| value.trim().parse().ok()).unwrap_or(0);
                let mut received = head.len() - end;
                while received < length {
                    tokio::time::sleep(pause).await;
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => received += read,
                    }
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\netag: \"x\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
            });
        }
    });
    endpoint
}

fn plain_client(endpoint: &str, read_timeout: Duration) -> Client {
    let mut settings = ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).endpoint(endpoint.to_owned()).region("us-east-1");
    settings.allow_http = true;
    settings.max_retries = 0;
    settings.read_timeout = read_timeout;
    settings.connect_timeout = Duration::from_secs(2);
    Client::new(settings).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_that_takes_longer_than_the_read_timeout_but_moves_is_not_cut_off() {
    // 64 MiB read at 1 MiB per 20 ms takes more than a second, and there is never a quiet moment of a second. (The socket holds some MiB that the client has
    // handed over and the service has not read yet: on Linux that is a good many, and the time they need is the margin of the timeout after the last byte.)
    let endpoint = slow_reader(Duration::from_millis(20), false).await;
    let client = plain_client(&endpoint, Duration::from_millis(800));
    let started = Instant::now();
    client.put("big", Bytes::from(content(64 * MIB)), &PutOptions::default()).await.unwrap();
    assert!(started.elapsed() > Duration::from_millis(800), "{:?}", started.elapsed());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upload_that_stops_moving_is_a_timeout() {
    let endpoint = slow_reader(Duration::from_millis(1), true).await;
    let client = plain_client(&endpoint, Duration::from_millis(400));
    // Made before the clock starts: making 64 MiB and working out its SHA-256 takes seconds in a build for tests on a slow machine
    let data = Bytes::from(content(64 * MIB));
    let started = Instant::now();
    let error = client.put("big", data, &PutOptions::default()).await.unwrap_err();
    assert!(matches!(error, Error::Timeout(_)), "{error:?}");
    // The service waits for 30 seconds: a call that ended long before is one that gave up on the silence
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
}

// ---- a request that was done and whose answer was lost ----

#[tokio::test]
async fn a_put_that_must_not_replace_is_done_when_its_lost_answer_is_followed_by_a_refusal() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.fault(Some(Method::PUT), Some("created"), None, 1, Fault::ApplyThenDrop);
    let options = PutOptions { if_none_match: true, ..PutOptions::default() };
    let result = client.put("created", Bytes::from_static(b"the data"), &options).await.unwrap();
    assert_eq!(result.etag.as_deref(), Some(etag_from_md5(&md5_digest(b"the data")).as_str()));
    assert_eq!(server.object("created").unwrap().data, "the data");
    assert_eq!(server.requests_matching(Method::PUT, "created").len(), 2);
}

#[tokio::test]
async fn a_put_refused_for_another_object_is_refused_even_after_a_lost_answer() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("taken", b"somebody else's");
    // The first try is lost before the service sees it, and the second is refused because the key is taken.
    server.fault(Some(Method::PUT), Some("taken"), None, 1, Fault::Drop);
    let options = PutOptions { if_none_match: true, ..PutOptions::default() };
    let error = client.put("taken", Bytes::from_static(b"mine"), &options).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed, "{error:?}");
    assert_eq!(server.object("taken").unwrap().data, "somebody else's");
}

#[tokio::test]
async fn an_upload_completed_by_a_try_whose_answer_was_lost_is_complete() {
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.part_size = 5 * MIB;
    let client = Client::new(settings).unwrap();
    server.fault(Some(Method::POST), None, Some("uploadId"), 1, Fault::ApplyThenDrop);
    let data = content(11 * MIB);
    let result = client.put_multipart("big", &data[..], &PutOptions::default()).await.unwrap();
    let md5s = [md5_digest(&data[..5 * MIB]), md5_digest(&data[5 * MIB..10 * MIB]), md5_digest(&data[10 * MIB..])];
    assert_eq!(result.etag.as_deref(), Some(multipart_etag(&md5s).as_str()));
    assert_eq!(server.object("big").unwrap().data, data);
    assert_eq!(server.open_uploads(), 0);
}

// ---- an upload whose caller gave up ----

/// A reader that gives 6 MiB and then never anything more.
struct Stuck {
    sent: usize,
}

impl tokio::io::AsyncRead for Stuck {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        if self.sent >= 6 * MIB {
            return std::task::Poll::Pending;
        }
        let length = buffer.remaining().min(6 * MIB - self.sent);
        buffer.put_slice(&vec![7u8; length]);
        self.sent += length;
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn an_upload_whose_future_is_dropped_is_aborted_all_the_same() {
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.part_size = 5 * MIB;
    let client = Client::new(settings).unwrap();
    let task = tokio::spawn({
        let client = client.clone();
        async move { client.put_multipart("big", Stuck { sent: 0 }, &PutOptions::default()).await }
    });
    // The first part is up and the reader has nothing more: the caller gives up.
    for _ in 0..200 {
        if !server.requests_matching(Method::PUT, "big").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.open_uploads(), 1);
    task.abort();
    for _ in 0..200 {
        if server.open_uploads() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the upload was left in the bucket");
}

// ---- answers that break off, and answers that are not S3's ----

/// A service that gives these answers to the requests that come, one connection for each, and keeps the heads of the requests.
async fn scripted(answers: Vec<Vec<u8>>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    let answers = Arc::new(Mutex::new(answers.into_iter()));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let (seen, answers) = (seen.clone(), answers.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                seen.lock().unwrap().push(String::from_utf8_lossy(&head).to_ascii_lowercase());
                let answer = answers.lock().unwrap().next();
                if let Some(answer) = answer {
                    let _ = stream.write_all(&answer).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    (endpoint, heads)
}

fn answer(status: &str, headers: &[(&str, &str)], body: &[u8], claimed_length: Option<usize>) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nconnection: close\r\ncontent-length: {}\r\n", claimed_length.unwrap_or(body.len())).into_bytes();
    for (name, value) in headers {
        bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    bytes
}

fn retrying_client(endpoint: &str) -> Client {
    let mut settings = ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).endpoint(endpoint.to_owned()).region("us-east-1");
    settings.allow_http = true;
    settings.max_retries = 3;
    settings.backoff_initial = Duration::from_millis(2);
    settings.backoff_max = Duration::from_millis(10);
    settings.read_timeout = Duration::from_secs(2);
    Client::new(settings).unwrap()
}

const LISTING: &[u8] = b"<ListBucketResult><Name>b</Name><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>a</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified><ETag>\"x\"</ETag><Size>3</Size></Contents></ListBucketResult>";

#[tokio::test]
async fn a_listing_whose_body_breaks_off_is_asked_for_again() {
    // The first answer says it has the whole document and the connection closes in the middle of it.
    let broken = answer("200 OK", &[], &LISTING[..60], Some(LISTING.len()));
    let (endpoint, heads) = scripted(vec![broken, answer("200 OK", &[], LISTING, None)]).await;
    let page = retrying_client(&endpoint).list_page("", &ListOptions::default(), None).await.unwrap();
    assert_eq!(page.0.objects[0].key, "a");
    assert_eq!(heads.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_404_that_is_not_the_missing_key_is_not_a_deletion() {
    let server = TestServer::start().await;
    let client = client(&server);
    // A key that is not there is deleted.
    server.fault(Some(Method::DELETE), None, None, 1, Fault::Status(404, "NoSuchKey"));
    client.delete("gone").await.unwrap();
    // A bucket that is not there is not a key that is not there.
    server.fault(Some(Method::DELETE), None, None, 1, Fault::Status(404, "NoSuchBucket"));
    assert!(client.delete("k").await.is_err());
    // And a 404 from something that is not S3 says nothing about the key.
    let (endpoint, _) = scripted(vec![answer("404 Not Found", &[], b"<html>nginx</html>", None)]).await;
    assert!(retrying_client(&endpoint).delete("k").await.is_err());

    let upload = client.create_multipart("k", &PutOptions::default()).await.unwrap();
    server.fault(Some(Method::DELETE), None, Some("uploadId"), 1, Fault::Status(404, "NoSuchBucket"));
    assert!(upload.abort().await.is_err());
    upload.abort().await.unwrap();
    upload.abort().await.unwrap();
}

#[tokio::test]
async fn deleting_many_reports_what_was_done_when_a_later_request_fails() {
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.max_retries = 1;
    let client = Client::new(settings).unwrap();
    let keys: Vec<String> = (0..1500).map(|i| format!("k{i:04}")).collect();
    for key in &keys {
        server.put_object(key, b"x");
    }
    // The first request of 1000 keys goes through, and the second, of 500, fails on every try.
    server.fault_after(1, Some(Method::POST), None, Some("delete"), 10, Fault::Status(500, "InternalError"));
    let failed = client.delete_many(&keys).await.unwrap();
    assert_eq!(failed.len(), 500);
    assert_eq!(failed[0].0, "k1000");
    assert!(failed.iter().all(|(_, error)| error.kind() == ErrorKind::Unavailable));
    assert_eq!(server.keys().len(), 500);
    // A failure of the first request is a failure of the call.
    server.fault(Some(Method::POST), None, Some("delete"), 10, Fault::Status(500, "InternalError"));
    assert!(client.delete_many(&keys).await.is_err());
}

// ---- a download that cannot be trusted to be one object ----

#[tokio::test]
async fn a_download_resumed_against_an_object_of_another_size_is_not_mixed() {
    // The ETag is weak, so it cannot go in If-Match; the size is what says the object is not the same.
    let first = answer("200 OK", &[("etag", "W/\"v1\""), ("last-modified", "Tue, 02 Jan 2024 03:04:05 GMT")], b"abc", Some(10));
    let second = answer("206 Partial Content", &[("etag", "W/\"v2\""), ("content-range", "bytes 3-10/11")], b"defghijk", None);
    let (endpoint, heads) = scripted(vec![first, second]).await;
    let object = retrying_client(&endpoint).get("k", &GetOptions::default()).await.unwrap();
    let error = object.body.bytes().await.unwrap_err();
    assert!(matches!(error, Error::ObjectChanged), "{error:?}");
    let heads = heads.lock().unwrap();
    assert!(heads[1].contains("range: bytes=3-9"), "{}", heads[1]);
    assert!(!heads[1].contains("if-match"), "a weak ETag is not sent: {}", heads[1]);
}

#[tokio::test]
async fn a_range_answered_from_another_byte_is_refused() {
    let wrong = answer("206 Partial Content", &[("etag", "\"e\""), ("content-range", "bytes 0-4/10")], b"01234", None);
    let (endpoint, _) = scripted(vec![wrong]).await;
    let options = GetOptions { range: Some(GetRange::Bounded(5..10)), ..GetOptions::default() };
    let error = retrying_client(&endpoint).get("k", &options).await.unwrap_err();
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");
}

// ---- the other things ----

#[tokio::test]
async fn a_head_refused_because_of_the_clock_is_sent_again_with_the_time_of_the_service() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("k", b"x");
    server.set_clock_offset(3600);
    assert_eq!(client.head("k").await.unwrap().size, 1);
}

#[tokio::test]
async fn a_service_that_does_not_speak_tls_is_not_tried_again() {
    // It answers the first bytes of the TLS handshake with a line of HTTP.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let connections = Arc::new(Mutex::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            *counter.lock().unwrap() += 1;
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 400 Bad Request
content-length: 0

",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    let mut settings = ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).endpoint(endpoint).region("us-east-1");
    settings.max_retries = 3;
    settings.backoff_initial = Duration::from_millis(2);
    settings.read_timeout = Duration::from_secs(2);
    let error = Client::new(settings).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, Error::Tls(_)), "{error:?}");
    assert!(!error.is_retryable());
    assert_eq!(*connections.lock().unwrap(), 1, "one try, since another cannot be different");
}

#[test]
fn a_user_agent_or_a_region_that_cannot_be_used_is_refused_when_the_client_is_made() {
    let base = || ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).region("us-east-1");
    let mut bad_agent = base();
    bad_agent.user_agent = Some("line\nbreak".to_owned());
    assert!(matches!(Client::new(bad_agent), Err(Error::Config(_))));
    assert!(matches!(Client::new(base().region("us-east-1.evil.example/")), Err(Error::Config(_))));
    assert!(Client::new(base()).is_ok());
}

#[test]
fn a_service_that_does_not_do_it_is_not_one_to_ask_again_later() {
    let not_implemented = |status| {
        let mut error = thirtys3_core::S3Error::new("NotImplemented", "x");
        error.status = status;
        Error::Service(Box::new(error))
    };
    assert_eq!(not_implemented(501).kind(), ErrorKind::Rejected);
    assert!(!not_implemented(501).is_retryable());
}

// ---- the budget of time for retrying ----

#[tokio::test]
async fn a_wait_that_would_end_after_the_retry_timeout_is_not_waited() {
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.max_retries = 5;
    settings.retry_timeout = Duration::from_millis(100);
    settings.backoff_initial = Duration::from_secs(3);
    settings.backoff_max = Duration::from_secs(3);
    let client = Client::new(settings).unwrap();
    server.fault(Some(Method::HEAD), None, None, 10, Fault::Status(503, "SlowDown"));
    let started = Instant::now();
    assert!(client.head("k").await.is_err());
    assert!(started.elapsed() < Duration::from_millis(1500), "it waited for a retry that was past the time allowed: {:?}", started.elapsed());
    assert_eq!(server.requests_matching(Method::HEAD, "k").len(), 1);
}

// ---- an upload that has failed stops reading its source ----

#[tokio::test]
async fn an_upload_with_a_failed_part_stops_reading_at_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = TestServer::start().await;
    let mut settings = config(&server);
    settings.part_size = 5 * MIB;
    settings.multipart_concurrency = 4;
    let client = Client::new(settings).unwrap();
    // The first part is refused for good.
    server.fault(Some(Method::PUT), None, Some("partNumber=1"), 10, Fault::Status(400, "InvalidArgument"));
    // A source of twenty parts that comes one part at a time, a little apart, through a pipe that holds little.
    let (mut writer, reader) = tokio::io::duplex(MIB);
    let written = Arc::new(AtomicUsize::new(0));
    let counter = written.clone();
    let feeder = tokio::spawn(async move {
        for _ in 0..20 {
            if writer.write_all(&vec![1u8; 5 * MIB]).await.is_err() {
                return;
            }
            counter.fetch_add(5 * MIB, Ordering::Relaxed);
            // Further apart than the first part takes to be refused, which in a build for tests is a good part of a second.
            tokio::time::sleep(Duration::from_millis(600)).await;
        }
    });
    let error = client.put_multipart("big", reader, &PutOptions::default()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Rejected, "{error:?}");
    feeder.abort();
    let parts = written.load(Ordering::Relaxed) / (5 * MIB);
    assert!(parts <= 3, "{parts} parts were read after the first one failed");
    assert_eq!(server.open_uploads(), 0);
}
