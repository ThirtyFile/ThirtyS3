//! Uploads that stream: `aws-chunked` with signed chunks and with trailing checksums, presigned URLs, and clients that go away in the middle.

mod support;

use std::time::Duration;

use bytes::Bytes;
use http::{Method, StatusCode};
use support::{BUCKET, Watched, req, request_head, signed_headers, start, start_with, tag};
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::encoding::hex_encode;
use thirtys3_core::sigv4::{STREAMING_SIGNED_PAYLOAD, STREAMING_SIGNED_PAYLOAD_TRAILER, STREAMING_UNSIGNED_PAYLOAD_TRAILER};
use thirtys3_core::{Timestamp, sha256_hex};
use tokio::io::AsyncWriteExt;

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 11 + i / 97) as u8).collect()
}

/// How a chunked body is made wrong, for the tests of what is refused.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    /// A byte of the second chunk is changed after it was signed.
    ChangedByte,
    /// The trailing checksum is wrong, with a signature that is right for the wrong value.
    WrongChecksum,
    /// The trailing headers are left out.
    NoTrailer,
}

struct Chunked {
    target: String,
    signed: bool,
    trailer: Option<ChecksumAlgorithm>,
    chunk: usize,
    fault: Fault,
    declared: Option<usize>,
}

impl Chunked {
    fn new(target: &str) -> Self {
        Self { target: target.to_owned(), signed: true, trailer: None, chunk: 64 * 1024, fault: Fault::None, declared: None }
    }

    /// Sends `content` as the chunked body this describes, signed as a client would.
    async fn send<B>(&self, server: &support::Server<B>, content: &[u8]) -> support::Answer {
        let payload = match (self.signed, self.trailer.is_some()) {
            (true, false) => STREAMING_SIGNED_PAYLOAD,
            (true, true) => STREAMING_SIGNED_PAYLOAD_TRAILER,
            (false, _) => STREAMING_UNSIGNED_PAYLOAD_TRAILER,
        };
        let trailer_name = self.trailer.map(|algorithm| algorithm.header_name());
        let mut wire = Vec::new();
        // The length of the body on the wire is part of the signature, so the body is made twice: once to know how long it is.
        let (headers, signed) = {
            let decoded = self.declared.unwrap_or(content.len()).to_string();
            let mut extra: Vec<(&str, &str)> = vec![("content-encoding", "aws-chunked"), ("x-amz-decoded-content-length", &decoded)];
            if let Some(name) = trailer_name {
                extra.push(("x-amz-trailer", name));
            }
            let first = self.body(content);
            signed_headers(&server.host(), "PUT", &self.target, &extra, Some(first.len()), payload, &support::signer())
        };
        let mut chain = support::signer().chunk_chain(&signed);
        wire.extend(self.body_with(&mut chain, content));
        let sent: Vec<(&str, String)> = headers.iter().filter(|(name, _)| name != "host").map(|(name, value)| (name.as_str(), value.clone())).collect();
        support::send_raw(server, Method::PUT, &self.target, &sent, Bytes::from(wire)).await
    }

    /// The body, made with a chain of no importance, for its length only.
    fn body(&self, content: &[u8]) -> Vec<u8> {
        let mut chain = support::signer().chunk_chain(&stub_signed());
        self.body_with(&mut chain, content)
    }

    fn body_with(&self, chain: &mut thirtys3_core::ChunkChain, content: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        for (index, piece) in content.chunks(self.chunk).enumerate() {
            let mut shown = piece.to_vec();
            let signature = chain.sign_chunk(&sha256_hex(piece));
            if self.fault == Fault::ChangedByte && index == 1 {
                shown[0] ^= 1;
            }
            if self.signed {
                wire.extend_from_slice(format!("{:x};chunk-signature={signature}\r\n", shown.len()).as_bytes());
            } else {
                wire.extend_from_slice(format!("{:x}\r\n", shown.len()).as_bytes());
            }
            wire.extend_from_slice(&shown);
            wire.extend_from_slice(b"\r\n");
        }
        let last = chain.sign_chunk(thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256);
        if self.signed {
            wire.extend_from_slice(format!("0;chunk-signature={last}\r\n").as_bytes());
        } else {
            wire.extend_from_slice(b"0\r\n");
        }
        match (self.trailer, self.fault) {
            (Some(algorithm), fault) if fault != Fault::NoTrailer => {
                let mut value = algorithm.checksum_base64(content);
                if fault == Fault::WrongChecksum {
                    value = algorithm.checksum_base64(b"something else");
                }
                let line = format!("{}:{value}\n", algorithm.header_name());
                wire.extend_from_slice(format!("{}:{value}\r\n", algorithm.header_name()).as_bytes());
                if self.signed {
                    wire.extend_from_slice(format!("x-amz-trailer-signature:{}\r\n", chain.sign_trailer(&sha256_hex(line.as_bytes()))).as_bytes());
                }
                wire.extend_from_slice(b"\r\n");
            }
            _ => wire.extend_from_slice(b"\r\n"),
        }
        wire
    }
}

fn stub_signed() -> thirtys3_core::SignedRequest {
    let headers = [("host", "stub")];
    let request = thirtys3_core::Request { method: "PUT", path: "/", query: "", headers: &headers };
    support::signer().sign(&request, STREAMING_SIGNED_PAYLOAD, Timestamp::now()).unwrap()
}

#[tokio::test]
async fn an_upload_in_signed_chunks() {
    let server = start().await;
    let content = data(300_000);
    let answer = Chunked::new("/bucket/streamed").send(&server, &content).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(server.service.backend().object(BUCKET, "streamed").unwrap(), content);
    assert_eq!(answer.header("etag"), Some(format!("\"{}\"", hex_encode(&thirtys3_core::etag::md5_digest(&content))).as_str()));
    // Chunks of any size, down to one byte and up to the limit, and an empty body.
    for chunk in [1, 100, 8 * 1024 * 1024] {
        let small = data(2000);
        let answer = Chunked { chunk, ..Chunked::new("/bucket/sizes") }.send(&server, &small).await;
        assert_eq!(answer.status, StatusCode::OK, "chunks of {chunk}: {}", answer.text());
        assert_eq!(server.service.backend().object(BUCKET, "sizes").unwrap(), small);
    }
    assert_eq!(Chunked::new("/bucket/empty").send(&server, b"").await.status, StatusCode::OK);
    assert_eq!(server.service.backend().object(BUCKET, "empty").unwrap().len(), 0);
}

#[tokio::test]
async fn a_chunk_that_was_changed_after_it_was_signed_stores_nothing() {
    let server = start().await;
    let answer = Chunked { fault: Fault::ChangedByte, ..Chunked::new("/bucket/k") }.send(&server, &data(300_000)).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
    assert!(server.service.backend().keys(BUCKET).is_empty());
}

#[tokio::test]
async fn signed_chunks_with_a_signed_trailing_checksum() {
    let server = start().await;
    let content = data(200_000);
    let ok = Chunked { trailer: Some(ChecksumAlgorithm::Crc32c), ..Chunked::new("/bucket/k") }.send(&server, &content).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    assert_eq!(ok.header("x-amz-checksum-crc32c"), Some(ChecksumAlgorithm::Crc32c.checksum_base64(&content).as_str()));
    assert_eq!(server.service.backend().object(BUCKET, "k").unwrap(), content);
    assert_eq!(
        server.service.backend().info(BUCKET, "k").unwrap().checksums.get(ChecksumAlgorithm::Crc32c),
        Some(ChecksumAlgorithm::Crc32c.checksum_base64(&content).as_str())
    );

    let wrong = Chunked { trailer: Some(ChecksumAlgorithm::Crc32c), fault: Fault::WrongChecksum, ..Chunked::new("/bucket/wrong") }.send(&server, &content).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&wrong.text(), "Code").as_deref(), Some("BadDigest"));
    let missing = Chunked { trailer: Some(ChecksumAlgorithm::Crc32c), fault: Fault::NoTrailer, ..Chunked::new("/bucket/missing") }.send(&server, &content).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.text());
    assert_eq!(server.service.backend().keys(BUCKET), ["k"]);
}

#[tokio::test]
async fn unsigned_chunks_with_a_trailing_checksum_which_is_what_the_sdks_send_over_tls() {
    let server = start().await;
    let content = data(150_000);
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Crc32c, ChecksumAlgorithm::Sha256, ChecksumAlgorithm::Crc64Nvme] {
        let ok = Chunked { signed: false, trailer: Some(algorithm), ..Chunked::new("/bucket/k") }.send(&server, &content).await;
        assert_eq!(ok.status, StatusCode::OK, "{algorithm:?}: {}", ok.text());
        assert_eq!(ok.header(algorithm.header_name()), Some(algorithm.checksum_base64(&content).as_str()));
        let wrong = Chunked { signed: false, trailer: Some(algorithm), fault: Fault::WrongChecksum, ..Chunked::new("/bucket/wrong") }.send(&server, &content).await;
        assert_eq!(tag(&wrong.text(), "Code").as_deref(), Some("BadDigest"), "{algorithm:?}");
    }
    assert_eq!(server.service.backend().keys(BUCKET), ["k"]);
}

#[tokio::test]
async fn the_decoded_length_is_checked() {
    let server = start().await;
    let content = data(10_000);
    for declared in [9_999, 10_001] {
        let answer = Chunked { declared: Some(declared), ..Chunked::new("/bucket/k") }.send(&server, &content).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{declared}");
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("IncompleteBody"), "{declared}");
    }
    assert!(server.service.backend().keys(BUCKET).is_empty());
}

#[tokio::test]
async fn a_chunked_upload_that_is_too_big_is_refused_as_it_arrives() {
    let small = start_with(support::backend(), thirtys3_server::ServerConfig { max_object_size: 20_000, ..support::config() }).await;
    let answer = Chunked::new("/bucket/k").send(&small, &data(30_000)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("EntityTooLarge"));
    assert!(small.service.backend().keys(BUCKET).is_empty());
    let large_chunks = start_with(support::backend(), thirtys3_server::ServerConfig { max_chunk_size: 1000, ..support::config() }).await;
    let answer = Chunked { chunk: 5000, ..Chunked::new("/bucket/k") }.send(&large_chunks, &data(8000)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_part_can_be_sent_in_chunks_too() {
    let server = start().await;
    let created = req(Method::POST, "/bucket/k?uploads").send(&server).await;
    let id = tag(&created.text(), "UploadId").unwrap();
    let content = data(5 * 1024 * 1024 + 7);
    let part = Chunked::new(&format!("/bucket/k?partNumber=1&uploadId={id}")).send(&server, &content).await;
    assert_eq!(part.status, StatusCode::OK, "{}", part.text());
    assert_eq!(part.header("etag"), Some(format!("\"{}\"", hex_encode(&thirtys3_core::etag::md5_digest(&content))).as_str()));
}

// ---- presigned URLs ----

#[tokio::test]
async fn a_presigned_url_gets_and_puts() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "dir/hello.txt", b"hello world");
    let now = Timestamp::now();
    let url = support::presign(&server, "GET", "/bucket/dir/hello.txt", 300, now);
    let get = support::send_raw(&server, Method::GET, &url, &[], Bytes::new()).await;
    assert_eq!((get.status, get.body.as_ref()), (StatusCode::OK, b"hello world".as_slice()));
    let head = support::send_raw(&server, Method::HEAD, &support::presign(&server, "HEAD", "/bucket/dir/hello.txt", 300, now), &[], Bytes::new()).await;
    assert_eq!(head.header("content-length"), Some("11"));

    let put_url = support::presign(&server, "PUT", "/bucket/uploaded.txt", 300, now);
    let put = support::send_raw(&server, Method::PUT, &put_url, &[("content-length", "8".to_owned())], Bytes::from_static(b"uploaded")).await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.text());
    assert_eq!(server.service.backend().object(BUCKET, "uploaded.txt").unwrap(), "uploaded");

    // The overrides in the query are signed with the rest.
    let named = support::presign(&server, "GET", "/bucket/dir/hello.txt?response-content-disposition=attachment%3B%20filename%3Dx.txt", 300, now);
    let get = support::send_raw(&server, Method::GET, &named, &[], Bytes::new()).await;
    assert_eq!(get.header("content-disposition"), Some("attachment; filename=x.txt"));
}

#[tokio::test]
async fn a_presigned_url_is_good_for_its_method_its_key_and_its_time() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "a", b"a");
    server.service.backend().insert(BUCKET, "b", b"b");
    let now = Timestamp::now();
    let url = support::presign(&server, "GET", "/bucket/a", 300, now);
    // Another method.
    let answer = support::send_raw(&server, Method::DELETE, &url, &[], Bytes::new()).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
    // Another key.
    let answer = support::send_raw(&server, Method::GET, &url.replace("/bucket/a", "/bucket/b"), &[], Bytes::new()).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
    // Another signature.
    let tampered = format!("{}{}", &url[..url.len() - 1], if url.ends_with('0') { '1' } else { '0' });
    assert_eq!(tag(&support::send_raw(&server, Method::GET, &tampered, &[], Bytes::new()).await.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
    // Expired.
    let old = support::presign(&server, "GET", "/bucket/a", 60, Timestamp(now.0 - 120));
    let answer = support::send_raw(&server, Method::GET, &old, &[], Bytes::new()).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AccessDenied"));
    assert!(answer.text().contains("expired"));
    // Not yet.
    let later = support::presign(&server, "GET", "/bucket/a", 60, Timestamp(now.0 + 3600));
    assert_eq!(tag(&support::send_raw(&server, Method::GET, &later, &[], Bytes::new()).await.text(), "Code").as_deref(), Some("RequestTimeTooSkewed"));
    // More than seven days.
    let long = url.replace("X-Amz-Expires=300", "X-Amz-Expires=604801");
    let answer = support::send_raw(&server, Method::GET, &long, &[], Bytes::new()).await;
    assert_eq!(
        (answer.status, tag(&answer.text(), "Code").as_deref().map(str::to_owned)),
        (StatusCode::BAD_REQUEST, Some("AuthorizationQueryParametersError".to_owned()))
    );
    // And it still works.
    assert_eq!(support::send_raw(&server, Method::GET, &url, &[], Bytes::new()).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_presigned_url_has_the_rights_of_its_key_and_no_more() {
    let server = start().await;
    let now = Timestamp::now();
    let signer = support::signer_for(support::READ_ONLY_KEY, support::READ_ONLY_SECRET);
    let host = server.host();
    let headers = [("host", host.as_str())];
    let request = thirtys3_core::Request { method: "PUT", path: "/bucket/k", query: "", headers: &headers };
    let url = format!("/bucket/k?{}", signer.presign(&request, now, 300).unwrap());
    let answer = support::send_raw(&server, Method::PUT, &url, &[("content-length", "1".to_owned())], Bytes::from_static(b"x")).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.text());
    assert!(server.service.backend().keys(BUCKET).is_empty());
}

// ---- clients that go away ----

async fn connect<B>(server: &support::Server<B>) -> tokio::net::TcpStream {
    tokio::net::TcpStream::connect(server.addr).await.unwrap()
}

async fn wait_until(mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition did not come true in 2 seconds");
}

#[tokio::test]
async fn an_upload_that_the_client_gives_up_is_not_kept() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    let (headers, _) = signed_headers(&server.host(), "PUT", "/bucket/half", &[], Some(1000), "UNSIGNED-PAYLOAD", &support::signer());
    let mut stream = connect(&server).await;
    stream.write_all(&request_head("PUT", "/bucket/half", &headers)).await.unwrap();
    stream.write_all(&[7; 300]).await.unwrap();
    stream.flush().await.unwrap();
    wait_until(|| backend.events().iter().any(|event| event == "put:half")).await;
    drop(stream);
    wait_until(|| backend.events().iter().any(|event| event.starts_with("put finished"))).await;
    assert_eq!(backend.events().last().map(String::as_str), Some("put finished:error"));
    assert!(backend.inner.keys(BUCKET).is_empty(), "300 of 1000 bytes is not an object");
}

#[tokio::test]
async fn the_sign_in_is_over_before_the_body_is_read_so_a_slow_upload_holds_no_attempt() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    let (headers, _) = signed_headers(&server.host(), "PUT", "/bucket/slow", &[], Some(1000), "UNSIGNED-PAYLOAD", &support::signer());
    let mut stream = connect(&server).await;
    stream.write_all(&request_head("PUT", "/bucket/slow", &headers)).await.unwrap();
    stream.write_all(&[1; 10]).await.unwrap();
    stream.flush().await.unwrap();
    wait_until(|| backend.events().iter().any(|event| event == "put:slow")).await;
    let events = backend.events();
    assert_eq!(events[..3], ["before:AKIATESTKEY", "after:AKIATESTKEY:Verified", "put:slow"], "{events:?}");
    assert!(!events.iter().any(|event| event.starts_with("put finished")), "the upload is still going on");
    drop(stream);
}

#[tokio::test]
async fn sha256_of_the_payload_is_checked_for_a_body_that_comes_in_several_pieces() {
    let server = start().await;
    let content = data(1_000_000);
    let (headers, _) = signed_headers(&server.host(), "PUT", "/bucket/pieces", &[], Some(content.len()), &sha256_hex(&content), &support::signer());
    let mut stream = connect(&server).await;
    stream.write_all(&request_head("PUT", "/bucket/pieces", &headers)).await.unwrap();
    for piece in content.chunks(70_000) {
        stream.write_all(piece).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let mut answer = vec![0; 4096];
    use tokio::io::AsyncReadExt;
    let read = stream.read(&mut answer).await.unwrap();
    assert!(String::from_utf8_lossy(&answer[..read]).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&answer[..read]));
    assert_eq!(server.service.backend().object(BUCKET, "pieces").unwrap(), content);
}

// ---- a complete that fails after it began to answer ----

#[tokio::test]
async fn a_failed_complete_can_be_answered_with_200_and_an_error_document_as_s3_does() {
    for (in_ok, status) in [(true, StatusCode::OK), (false, StatusCode::INTERNAL_SERVER_ERROR)] {
        let backend = Watched::new();
        let config = thirtys3_server::ServerConfig { complete_failures_in_ok_response: in_ok, ..support::config() };
        let server = start_with(backend.clone(), config).await;
        let created = req(Method::POST, "/bucket/k?uploads").send(&server).await;
        let id = tag(&created.text(), "UploadId").unwrap();
        let part = req(Method::PUT, &format!("/bucket/k?partNumber=1&uploadId={id}")).body(data(1000)).send(&server).await;
        let etag = part.header("etag").unwrap().to_owned();
        let xml = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
        let target = format!("/bucket/k?uploadId={id}");

        backend.fail_complete.store(true, std::sync::atomic::Ordering::Relaxed);
        let failed = req(Method::POST, &target).body(xml.clone()).send(&server).await;
        assert_eq!(failed.status, status, "in_ok={in_ok}");
        assert_eq!(tag(&failed.text(), "Code").as_deref(), Some("InternalError"), "in_ok={in_ok}");
        assert!(server.service.backend().inner.keys(BUCKET).is_empty());

        // Errors of the request are not hidden: they say 4xx whatever the setting.
        backend.fail_complete.store(false, std::sync::atomic::Ordering::Relaxed);
        let wrong = req(Method::POST, "/bucket/k?uploadId=nope").body(xml.clone()).send(&server).await;
        assert_eq!(wrong.status, StatusCode::NOT_FOUND, "in_ok={in_ok}");
        let done = req(Method::POST, &target).body(xml).send(&server).await;
        assert_eq!(done.status, StatusCode::OK);
        assert!(done.text().contains("CompleteMultipartUploadResult"));
    }
}
