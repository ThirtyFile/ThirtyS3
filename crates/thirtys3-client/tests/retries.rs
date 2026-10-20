//! What is repeated, how often, and what is not repeated at all.

mod support;

use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Method;
use support::{Fault, TestServer, client, config};
use thirtys3_client::{Client, ClientConfig, Credentials, ErrorKind, GetOptions, PutOptions};

#[tokio::test]
async fn a_busy_service_is_tried_again_until_it_answers() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.fault(Some(Method::PUT), None, None, 2, Fault::Status(503, "SlowDown"));
    client.put("k", Bytes::from_static(b"data"), &PutOptions::default()).await.unwrap();
    let puts = server.requests_matching(Method::PUT, "/k");
    assert_eq!(puts.len(), 3);
    // Every try was signed anew, with the same body.
    assert!(puts.iter().all(|request| request.authenticated && request.body == "data"));
    assert_eq!(server.object("k").unwrap().data, "data");
}

#[tokio::test]
async fn the_statuses_that_can_pass_are_repeated() {
    for (status, code) in [
        (500, "InternalError"),
        (502, "BadGateway"),
        (503, "ServiceUnavailable"),
        (504, "GatewayTimeout"),
        (400, "RequestTimeout"),
        (503, "SlowDown"),
        (429, "TooManyRequests"),
    ] {
        let server = TestServer::start().await;
        let client = client(&server);
        server.put_object("k", b"x");
        server.fault(Some(Method::GET), None, None, 1, Fault::Status(status, code));
        client.get("k", &GetOptions::default()).await.unwrap_or_else(|error| panic!("{status} {code}: {error}"));
        assert_eq!(server.requests().len(), 2, "{status} {code}");
    }
}

#[tokio::test]
async fn what_is_wrong_with_the_request_is_not_repeated() {
    for (status, code) in [
        (400, "InvalidArgument"),
        (400, "BadDigest"),
        (403, "AccessDenied"),
        (404, "NoSuchKey"),
        (409, "BucketNotEmpty"),
        (412, "PreconditionFailed"),
        (416, "InvalidRange"),
        (501, "NotImplemented"),
    ] {
        let server = TestServer::start().await;
        let client = client(&server);
        server.fault(Some(Method::PUT), None, None, 5, Fault::Status(status, code));
        let error = client.put("k", Bytes::new(), &PutOptions::default()).await.unwrap_err();
        assert_eq!(server.requests().len(), 1, "{status} {code}: {error}");
        assert!(!error.is_retryable(), "{status} {code}");
    }
}

#[tokio::test]
async fn a_dropped_connection_is_tried_again() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("k", b"content");
    server.fault(None, None, None, 2, Fault::Drop);
    let object = client.get("k", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), "content");
    assert_eq!(server.requests().len(), 3);
}

#[tokio::test]
async fn it_gives_up_after_max_retries_and_says_the_service_is_unavailable() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 2;
    let client = Client::new(config).unwrap();
    server.fault(None, None, None, 100, Fault::Status(503, "SlowDown"));
    let error = client.get("k", &GetOptions::default()).await.unwrap_err();
    assert_eq!(server.requests().len(), 3, "the first try and two repeats");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(error.is_retryable());
    assert!(matches!(&error, thirtys3_client::Error::Service(s3) if s3.code == "SlowDown"));
}

#[tokio::test]
async fn a_head_has_no_body_so_only_its_status_tells_what_failed() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.fault(Some(Method::HEAD), None, None, 1, Fault::Status(503, "SlowDown"));
    server.put_object("k", b"x");
    client.head("k").await.unwrap();
    server.fault(Some(Method::HEAD), None, None, 100, Fault::Status(403, "AccessDenied"));
    assert_eq!(client.head("k").await.unwrap_err().kind(), ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn no_retries_when_max_retries_is_zero() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 0;
    let client = Client::new(config).unwrap();
    server.fault(None, None, None, 100, Fault::Drop);
    assert_eq!(client.head("k").await.unwrap_err().kind(), ErrorKind::Unavailable);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn the_retry_timeout_ends_the_repeats_before_max_retries() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 1000;
    config.retry_timeout = Duration::from_millis(150);
    config.backoff_initial = Duration::from_millis(30);
    config.backoff_max = Duration::from_millis(30);
    let client = Client::new(config).unwrap();
    server.fault(None, None, None, 100_000, Fault::Status(503, "SlowDown"));
    let started = Instant::now();
    assert!(client.head("k").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    let tries = server.requests().len();
    assert!((3..=12).contains(&tries), "{tries} tries in 150 ms with waits of about 30 ms");
}

#[tokio::test]
async fn the_wait_between_repeats_grows() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.max_retries = 4;
    config.backoff_initial = Duration::from_millis(40);
    config.backoff_max = Duration::from_secs(5);
    let client = Client::new(config).unwrap();
    server.fault(None, None, None, 100, Fault::Status(503, "SlowDown"));
    let started = Instant::now();
    assert!(client.head("k").await.is_err());
    // Waits of at least half of 40, 80, 160 and 320 ms, with the variation.
    assert!(started.elapsed() >= Duration::from_millis(300), "{:?}", started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_service_that_does_not_answer_in_time_is_a_timeout_and_is_tried_again() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.read_timeout = Duration::from_millis(200);
    let client = Client::new(config).unwrap();
    server.put_object("k", b"x");
    server.fault(Some(Method::HEAD), None, None, 1, Fault::Delay(Duration::from_secs(2)));
    let started = Instant::now();
    client.head("k").await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    assert_eq!(server.requests().len(), 2);

    // And as an error when it stays silent.
    server.fault(Some(Method::HEAD), None, None, 100, Fault::Delay(Duration::from_secs(2)));
    let mut quick = self::config(&server);
    quick.read_timeout = Duration::from_millis(100);
    quick.max_retries = 1;
    let error = Client::new(quick).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, thirtys3_client::Error::Timeout(_)), "{error:?}");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
}

#[tokio::test]
async fn a_service_that_cannot_be_reached_is_unavailable_and_is_tried_again() {
    // A port nobody listens on.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut config = ClientConfig::new("bucket", Credentials::new("a", "b")).endpoint(format!("http://127.0.0.1:{port}"));
    config.allow_http = true;
    config.max_retries = 2;
    config.backoff_initial = Duration::from_millis(1);
    let error = Client::new(config).unwrap().head("k").await.unwrap_err();
    assert!(matches!(error, thirtys3_client::Error::Transport(_)), "{error:?}");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(error.is_retryable());
}

#[tokio::test]
async fn a_clock_that_is_off_is_corrected_from_the_answer_of_the_service() {
    let server = TestServer::start().await;
    server.set_clock_offset(3600);
    let client = client(&server);
    client.put("k", Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "refused once for the time, then sent again with the time of the service");
    assert!(!requests[0].authenticated && requests[1].authenticated);
    // The correction is remembered: the next request is right the first time.
    server.clear_log();
    client.head("k").await.unwrap();
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn delete_and_listing_are_repeated_like_the_rest() {
    let server = TestServer::start().await;
    let client = client(&server);
    server.put_object("k", b"x");
    server.fault(Some(Method::DELETE), None, None, 1, Fault::Status(500, "InternalError"));
    client.delete("k").await.unwrap();
    assert!(server.object("k").is_none());
    server.fault(Some(Method::GET), None, Some("list-type"), 1, Fault::Status(503, "SlowDown"));
    let page = client.list_with_delimiter("", "/").await.unwrap();
    assert!(page.objects.is_empty());
}
