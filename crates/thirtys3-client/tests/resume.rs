//! A download that breaks off carries on from where it stopped, and never mixes two versions of an object.

mod support;

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use http::Method;
use support::{Fault, TestServer, client, config};
use thirtys3_client::{Client, Error, ErrorKind, GetOptions, GetRange, PutOptions};

fn content(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 13 + i / 97) as u8).collect()
}

fn gets(server: &TestServer) -> Vec<support::Logged> {
    server.requests().into_iter().filter(|request| request.method == Method::GET).collect()
}

#[tokio::test]
async fn a_download_that_breaks_off_goes_on_with_a_range_request() {
    let server = TestServer::start().await;
    let client = client(&server);
    let data = content(1000);
    server.put_object("big", &data);
    let etag = server.object("big").unwrap().etag;
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(100));
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data);

    let requests = gets(&server);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("range"), None);
    assert_eq!(requests[1].header("range"), Some("bytes=100-999"));
    assert_eq!(requests[1].header("if-match"), Some(etag.as_str()), "the rest has to be of the same version");
    assert!(requests.iter().all(|request| request.authenticated));
}

#[tokio::test]
async fn it_goes_on_through_several_breaks() {
    let server = TestServer::start().await;
    let client = client(&server);
    let data = content(1000);
    server.put_object("big", &data);
    server.fault(Some(Method::GET), None, None, 3, Fault::Truncate(100));
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data);
    let ranges: Vec<_> = gets(&server).iter().map(|request| request.header("range").map(str::to_owned)).collect();
    assert_eq!(ranges, [None, Some("bytes=100-999".into()), Some("bytes=200-999".into()), Some("bytes=300-999".into())]);
}

#[tokio::test]
async fn a_range_that_breaks_off_resumes_inside_the_range() {
    let server = TestServer::start().await;
    let client = client(&server);
    let data = content(1000);
    server.put_object("big", &data);
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(50));
    let object = client.get("big", &GetOptions { range: Some(GetRange::Bounded(200..700)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(object.range, 200..700);
    assert_eq!(object.body.bytes().await.unwrap(), data[200..700]);
    let requests = gets(&server);
    assert_eq!(requests[0].header("range"), Some("bytes=200-699"));
    assert_eq!(requests[1].header("range"), Some("bytes=250-699"), "to the end of the range asked for, not of the object");
}

#[tokio::test]
async fn a_suffix_range_that_breaks_off_resumes_with_absolute_positions() {
    let server = TestServer::start().await;
    let client = client(&server);
    let data = content(1000);
    server.put_object("big", &data);
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(10));
    let object = client.get("big", &GetOptions { range: Some(GetRange::Suffix(100)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data[900..]);
    assert_eq!(gets(&server)[1].header("range"), Some("bytes=910-999"));
}

#[tokio::test]
async fn a_download_that_goes_quiet_is_resumed_too() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.read_timeout = Duration::from_millis(250);
    let client = Client::new(config).unwrap();
    let data = content(500);
    server.put_object("big", &data);
    server.fault(Some(Method::GET), None, None, 1, Fault::Stall(Duration::from_secs(3600)));
    let started = Instant::now();
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    assert_eq!(gets(&server)[1].header("range"), Some("bytes=1-499"), "one byte arrived before the silence");
}

#[tokio::test]
async fn an_object_that_was_replaced_meanwhile_is_not_mixed_with_the_new_one() {
    let server = TestServer::start().await;
    let client = client(&server);
    let old = content(1000);
    server.put_object("doc", &old);
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(100));
    let object = client.get("doc", &GetOptions::default()).await.unwrap();
    let mut body = object.body;
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(first, old[..100]);
    // Somebody replaces the object before the rest is asked for.
    server.put_object("doc", &content(1000).iter().map(|byte| byte.wrapping_add(1)).collect::<Vec<u8>>());
    let error = body.next().await.unwrap().unwrap_err();
    assert!(matches!(error, Error::ObjectChanged), "{error:?}");
    assert_eq!(error.kind(), ErrorKind::PreconditionFailed);
    assert!(body.next().await.is_none(), "the stream ends after the error");
}

#[tokio::test]
async fn without_progress_it_gives_up_after_max_retries_breaks() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 3;
    let client = Client::new(config).unwrap();
    server.put_object("big", &content(1000));
    server.fault(Some(Method::GET), None, None, 100, Fault::Truncate(0));
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    let error = object.body.bytes().await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unavailable, "{error:?}");
    assert_eq!(gets(&server).len(), 1 + 3, "the first request and three tries to carry on");
}

#[tokio::test]
async fn breaks_with_progress_in_between_do_not_count_against_max_retries() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 1;
    let client = Client::new(config).unwrap();
    let data = content(1000);
    server.put_object("big", &data);
    server.fault(Some(Method::GET), None, None, 8, Fault::Truncate(100));
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data);
    assert_eq!(gets(&server).len(), 9);
}

#[tokio::test]
async fn the_retry_timeout_limits_the_whole_download() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 1000;
    config.retry_timeout = Duration::from_millis(200);
    config.backoff_initial = Duration::from_millis(40);
    config.backoff_max = Duration::from_millis(40);
    let client = Client::new(config).unwrap();
    server.put_object("big", &content(100_000));
    server.fault(Some(Method::GET), None, None, 100_000, Fault::Truncate(1));
    let started = Instant::now();
    let object = client.get("big", &GetOptions::default()).await.unwrap();
    assert!(object.body.bytes().await.is_err());
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let tries = gets(&server).len();
    assert!((3..=15).contains(&tries), "{tries}");
}

#[tokio::test]
async fn a_service_that_does_not_do_ranges_is_noticed() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("k", &content(1000));
    server.fault(Some(Method::GET), None, None, 1, Fault::IgnoreRange);
    let error = client.get("k", &GetOptions { range: Some(GetRange::Bounded(10..20)), ..GetOptions::default() }).await.unwrap_err();
    assert!(matches!(error, Error::Protocol(_)), "{error:?}");

    // But a range that is the whole object is fine with the whole object.
    server.fault(Some(Method::GET), None, None, 1, Fault::IgnoreRange);
    let object = client.get("k", &GetOptions { range: Some(GetRange::Bounded(0..1000)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap().len(), 1000);
}

#[tokio::test]
async fn an_object_that_is_deleted_while_it_is_resumed_is_not_found() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("gone", &content(1000));
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(100));
    let mut body = client.get("gone", &GetOptions::default()).await.unwrap().body;
    body.next().await.unwrap().unwrap();
    client.delete("gone").await.unwrap();
    let error = body.next().await.unwrap().unwrap_err();
    // A deleted object has no ETag to match: the service says there is no such key.
    assert_eq!(error.kind(), ErrorKind::NotFound, "{error:?}");
}

#[tokio::test]
async fn small_objects_that_break_off_are_resumed_like_big_ones() {
    let server = TestServer::start().await;
    let client = client(&server);
    client.put("small", Bytes::from_static(b"0123456789"), &PutOptions::default()).await.unwrap();
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(3));
    let object = client.get("small", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), "0123456789");
}

#[tokio::test]
async fn a_service_that_sends_more_than_the_range_asked_for_is_not_believed() {
    let server = TestServer::start().await;
    let client = client(&server);
    let data = content(1000);
    server.put_object("big", &data);
    // The first answer breaks off; the answer to the request for the rest has everything to the end of the object.
    server.fault(Some(Method::GET), None, None, 1, Fault::Truncate(100));
    server.fault(Some(Method::GET), None, None, 1, Fault::OverrunRange);
    let object = client.get("big", &GetOptions { range: Some(GetRange::Bounded(200..400)), ..GetOptions::default() }).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), data[200..400], "exactly the 200 bytes that were asked for");
    assert_eq!(gets(&server)[1].header("range"), Some("bytes=300-399"));
}
