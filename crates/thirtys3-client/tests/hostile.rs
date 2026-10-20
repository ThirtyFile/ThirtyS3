//! A service that answers badly: garbage, lies about lengths, headers that cannot be read, redirects, bodies that are too big, silence. The client has to
//! end every call with a result (an error, mostly) in a short time and with a bounded amount of memory, and never panic.
//!
//! `THIRTYS3_FUZZ_ITERATIONS` sets the number of random answers (300 by default) and `THIRTYS3_FUZZ_SEED` the seed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use thirtys3_client::{Client, ClientConfig, Credentials, Error, GetOptions, ListOptions, PutOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What a connection gets as an answer: the bytes, then the connection stays open for `linger` or closes.
#[derive(Clone)]
struct Answer {
    bytes: Vec<u8>,
    close: bool,
}

/// A service that answers every request with `answer` after it has read the head of the request. `connections` counts the connections.
async fn hostile(answer: Answer) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            counter.fetch_add(1, Ordering::Relaxed);
            let answer = answer.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                let _ = stream.write_all(&answer.bytes).await;
                if answer.close {
                    let _ = stream.shutdown().await;
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
    });
    (format!("http://{address}"), connections)
}

fn client(endpoint: &str) -> Client {
    let mut config = ClientConfig::new("bucket", Credentials::new("AKIATESTKEY", "secret")).endpoint(endpoint.to_owned()).region("us-east-1");
    config.allow_http = true;
    config.max_retries = 0;
    config.read_timeout = Duration::from_millis(500);
    config.connect_timeout = Duration::from_secs(2);
    config.retry_timeout = Duration::from_secs(3);
    Client::new(config).unwrap()
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Answer {
    let mut bytes = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
        bytes.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    Answer { bytes, close: true }
}

/// Every call of the client against the service, each with a time limit.
async fn everything(client: &Client) -> Vec<Result<(), Error>> {
    async fn limited<T>(future: impl std::future::Future<Output = Result<T, Error>>) -> Result<(), Error> {
        match tokio::time::timeout(Duration::from_secs(10), future).await {
            Ok(result) => result.map(|_| ()),
            Err(_) => panic!("a call did not end"),
        }
    }
    vec![
        limited(client.head("k")).await,
        limited(async {
            let result = client.get("k", &GetOptions::default()).await?;
            result.body.bytes().await
        })
        .await,
        limited(client.put("k", Bytes::from_static(b"data"), &PutOptions::default())).await,
        limited(client.delete("k")).await,
        limited(client.delete_many(&["a".to_owned(), "b".to_owned()])).await,
        limited(client.list_page("", &ListOptions::default(), None)).await,
        limited(async {
            let options = ListOptions::default();
            let mut stream = client.list("", &options);
            while let Some(entry) = stream.next().await {
                entry?;
            }
            Ok(())
        })
        .await,
        limited(async { client.create_multipart("k", &PutOptions::default()).await.map(|_| ()) }).await,
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn garbage_where_a_document_should_be_is_an_error() {
    let ok = "application/xml";
    for body in [
        b"".as_slice(),
        b"not xml at all",
        b"<ListBucketResult><Contents><Key>a</Key></ListBucketResult>",
        b"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><ListBucketResult/>",
        b"<Error><Code>X</Code>",
        &[0xff, 0xfe, 0x00, 0x3c],
    ] {
        let (endpoint, _) = hostile(response("200 OK", &[("content-type", ok)], body)).await;
        let results = everything(&client(&endpoint)).await;
        assert!(results.iter().any(Result::is_err), "{body:?}");
    }
    let deep = format!("{}{}", "<a>".repeat(50_000), "</a>".repeat(50_000));
    let (endpoint, _) = hostile(response("200 OK", &[], deep.as_bytes())).await;
    let _ = everything(&client(&endpoint)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn headers_that_cannot_be_read_are_an_error_or_are_ignored() {
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("content-length", "abc")],
        vec![("content-length", "99999999999999999999999")],
        vec![("etag", "\u{fffd}"), ("last-modified", "yesterday"), ("x-amz-meta-a", "\u{e9}")],
        vec![("last-modified", "Tue, 02 Jan 2024 25:61:61 GMT"), ("etag", "")],
        vec![("x-amz-checksum-crc32", "!!!"), ("x-amz-checksum-sha256", "")],
        vec![("content-range", "bytes 5-2/10"), ("content-length", "3")],
        vec![("content-range", "bytes */*")],
        vec![("transfer-encoding", "chunked")],
    ];
    for headers in cases {
        let (endpoint, _) = hostile(response("200 OK", &headers, b"abc")).await;
        let _ = everything(&client(&endpoint)).await;
        let (endpoint, _) = hostile(response("206 Partial Content", &headers, b"abc")).await;
        let _ = everything(&client(&endpoint)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_is_an_error_and_is_not_followed() {
    let (endpoint, connections) = hostile(response("301 Moved Permanently", &[("location", "http://127.0.0.1:1/elsewhere")], b"")).await;
    let results = everything(&client(&endpoint)).await;
    assert!(results.iter().all(Result::is_err), "{results:?}");
    // One connection for each call at most: nothing went anywhere else.
    assert!(connections.load(Ordering::Relaxed) <= results.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_error_with_a_huge_body_is_read_only_in_part() {
    let big = vec![b'x'; 20 * 1024 * 1024];
    let (endpoint, _) = hostile(response("500 Internal Server Error", &[], &big)).await;
    let client = client(&endpoint);
    let started = std::time::Instant::now();
    let error = client.head("k").await.unwrap_err();
    let _ = client.put("k", Bytes::from_static(b"x"), &PutOptions::default()).await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_that_never_ends_does_not_keep_the_client() {
    // An error with no end, and an answer to a listing, which is a document and should be short.
    for status in ["500 Internal Server Error", "200 OK"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    // No length: the body is whatever comes until the connection closes, and nothing ever closes it.
                    if stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}
connection: close

<ListBucketResult>"
                            )
                            .as_bytes(),
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let block = vec![b' '; 64 * 1024];
                    while stream.write_all(&block).await.is_ok() {}
                });
            }
        });
        let client = client(&endpoint);
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), client.list_page("", &ListOptions::default(), None)).await.expect("the call ended");
        assert!(result.is_err(), "{status}");
        assert!(started.elapsed() < Duration::from_secs(10), "{status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_that_is_longer_than_any_answer_can_be_is_an_error_even_when_it_is_well_formed() {
    let valid = b"<ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>";
    let (endpoint, _) = hostile(response("200 OK", &[], valid)).await;
    assert!(client(&endpoint).list_page("", &ListOptions::default(), None).await.is_ok());
    // The same document and then 64 MiB of white space.
    let mut long = valid.to_vec();
    long.resize(64 * 1024 * 1024, b' ');
    let (endpoint, _) = hostile(response("200 OK", &[], &long)).await;
    let error = client(&endpoint).list_page("", &ListOptions::default(), None).await.unwrap_err();
    assert!(matches!(error, Error::Protocol(_)), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_service_that_says_nothing_or_stops_halfway_is_an_error_after_the_timeout() {
    let silent = Answer { bytes: Vec::new(), close: false };
    let (endpoint, _) = hostile(silent).await;
    let results = everything(&client(&endpoint)).await;
    assert!(results.iter().all(Result::is_err), "{results:?}");
    for bytes in [b"HTTP/1.1 200 OK\r\ncontent-le".to_vec(), b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nabc".to_vec(), b"\r\n\r\n".to_vec(), vec![0; 1000]] {
        let (endpoint, _) = hostile(Answer { bytes, close: true }).await;
        let results = everything(&client(&endpoint)).await;
        assert!(results.iter().any(Result::is_err));
    }
    // A head without end.
    let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
    endless.extend(std::iter::repeat_n(*b"x-a: b\r\n", 40_000).flatten());
    let (endpoint, _) = hostile(Answer { bytes: endless, close: true }).await;
    assert!(client(&endpoint).head("k").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn random_answers_never_make_the_client_panic_or_hang() {
    let mut state = std::env::var("THIRTYS3_FUZZ_SEED").ok().and_then(|seed| seed.parse::<u64>().ok()).unwrap_or(0x5EED_5EED) | 1;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let valid = [
        response("200 OK", &[("etag", "\"abc\""), ("last-modified", "Tue, 02 Jan 2024 03:04:05 GMT"), ("content-length", "3")], b"abc"),
        response("200 OK", &[("content-type", "application/xml")], b"<ListBucketResult><Name>b</Name><KeyCount>1</KeyCount><IsTruncated>false</IsTruncated><Contents><Key>a</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified><ETag>\"x\"</ETag><Size>3</Size></Contents></ListBucketResult>"),
        response("404 Not Found", &[], b"<Error><Code>NoSuchKey</Code><Message>m</Message></Error>"),
        response("200 OK", &[], b"<DeleteResult><Deleted><Key>a</Key></Deleted><Error><Key>b</Key><Code>AccessDenied</Code><Message>m</Message></Error></DeleteResult>"),
        response("200 OK", &[], b"<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>u</UploadId></InitiateMultipartUploadResult>"),
    ];
    let iterations: usize = std::env::var("THIRTYS3_FUZZ_ITERATIONS").ok().and_then(|value| value.parse().ok()).unwrap_or(300);
    for _ in 0..iterations {
        let mut bytes = valid[(next() % valid.len() as u64) as usize].bytes.clone();
        for _ in 0..1 + next() % 4 {
            let at = (next() % bytes.len().max(1) as u64) as usize;
            match next() % 5 {
                0 => bytes[at] ^= 1 << (next() % 8),
                1 => bytes.truncate(at),
                2 => bytes[at] = next() as u8,
                3 => {
                    let piece = bytes[at..(at + 30).min(bytes.len())].to_vec();
                    bytes.splice(at..at, piece);
                }
                _ => {
                    bytes.remove(at);
                }
            }
            if bytes.is_empty() {
                bytes.push(b'H');
            }
        }
        let (endpoint, _) = hostile(Answer { bytes, close: true }).await;
        let _ = everything(&client(&endpoint)).await;
    }
}
