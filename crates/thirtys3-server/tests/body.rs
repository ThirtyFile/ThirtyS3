//! The checked body of a request: aws-chunked with the signature chain and the trailing headers, and the checks on plain bodies.
//!
//! The signed examples are those of AWS's documentation of streaming uploads (the archived `sigv4-streaming.html` and
//! `sigv4-streaming-trailers.html`): the credentials, the time, a 65 KiB object of the letter 'a' in chunks of 64 KiB, 1 KiB and none.

use bytes::Bytes;
use futures_util::StreamExt;
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::sigv4::{STREAMING_SIGNED_PAYLOAD, STREAMING_SIGNED_PAYLOAD_TRAILER};
use thirtys3_core::{ChunkChain, Credentials, Request, S3Error, Signer, Timestamp, sha256_hex};
use thirtys3_server::body::{BodyPlan, BoxError, Digests, Framing, IncomingBody, RequestBody};

const TIME: Timestamp = Timestamp(1_369_353_600); // 20130524T000000Z

fn signer() -> Signer {
    Signer::new(Credentials::new("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), "us-east-1")
}

fn chain(trailer: bool) -> ChunkChain {
    let mut headers = vec![
        ("Host", "s3.amazonaws.com"),
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("Content-Encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", "66560"),
    ];
    let hash = if trailer {
        headers.push(("x-amz-trailer", "x-amz-checksum-crc32c"));
        STREAMING_SIGNED_PAYLOAD_TRAILER
    } else {
        headers.push(("Content-Length", "66824"));
        STREAMING_SIGNED_PAYLOAD
    };
    let request = Request { method: "PUT", path: "/examplebucket/chunkObject.txt", query: "", headers: &headers };
    let signed = signer().sign(&request, hash, TIME).unwrap();
    signer().chunk_chain(&signed)
}

fn body_of(pieces: Vec<Bytes>) -> IncomingBody {
    StreamBody::new(futures_util::stream::iter(pieces.into_iter().map(|piece| Ok::<_, BoxError>(Frame::data(piece))))).boxed_unsync()
}

fn split(data: &[u8], size: usize) -> Vec<Bytes> {
    data.chunks(size.max(1)).map(Bytes::copy_from_slice).collect()
}

fn plan(framing: Framing) -> BodyPlan {
    BodyPlan {
        framing,
        length: None,
        payload_sha256: None,
        content_md5: None,
        checksums: Vec::new(),
        trailer_checksums: Vec::new(),
        max_size: u64::MAX,
        max_chunk: 8 * 1024 * 1024,
        idle_timeout: None,
    }
}

fn digest_of(algorithm: ChecksumAlgorithm, data: &[u8]) -> Vec<u8> {
    let mut hasher = algorithm.hasher();
    hasher.update(data);
    hasher.finalize()
}

/// Reads a body to its end, giving the data that was delivered and how it ended.
async fn read(mut body: RequestBody) -> (Vec<u8>, Result<Digests, S3Error>) {
    let mut data = Vec::new();
    while let Some(piece) = body.next().await {
        match piece {
            Ok(piece) => data.extend_from_slice(&piece),
            Err(error) => {
                assert!(body.next().await.is_none(), "nothing follows an error");
                assert!(body.digests().is_none(), "an upload that failed has no digests");
                return (data, Err(error));
            }
        }
    }
    let digests = body.digests().cloned().expect("a body that ended well has digests");
    (data, Ok(digests))
}

fn code_of(result: Result<Digests, S3Error>) -> String {
    result.expect_err("the body should have failed").code
}

// ---- the signed example ----

const SIGNATURES: [&str; 3] = [
    "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
    "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
    "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
];

fn signed_wire() -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(format!("10000;chunk-signature={}\r\n", SIGNATURES[0]).as_bytes());
    wire.extend_from_slice(&[b'a'; 65536]);
    wire.extend_from_slice(format!("\r\n400;chunk-signature={}\r\n", SIGNATURES[1]).as_bytes());
    wire.extend_from_slice(&[b'a'; 1024]);
    wire.extend_from_slice(format!("\r\n0;chunk-signature={}\r\n\r\n", SIGNATURES[2]).as_bytes());
    wire
}

fn signed_plan() -> BodyPlan {
    BodyPlan { length: Some(66560), ..plan(Framing::Chunked { signed: Some(chain(false)), trailers: false }) }
}

async fn read_signed(wire: Vec<u8>, piece: usize) -> (Vec<u8>, Result<Digests, S3Error>) {
    read(RequestBody::new(body_of(split(&wire, piece)), signed_plan())).await
}

#[tokio::test]
async fn the_signed_example_of_the_documentation_passes() {
    let (data, result) = read_signed(signed_wire(), usize::MAX).await;
    let digests = result.unwrap();
    assert_eq!(data, vec![b'a'; 66560]);
    assert_eq!(digests.size, 66560);
    assert_eq!(digests.md5.to_vec(), digest_of(ChecksumAlgorithm::Md5, &data));
    assert_eq!(digests.etag(), format!("\"{}\"", thirtys3_core::encoding::hex_encode(&digests.md5)));
    assert_eq!(digests.sha256, None, "no payload hash to check, so none worked out");
}

#[tokio::test]
async fn however_the_bytes_arrive_the_result_is_the_same() {
    for piece in [1, 2, 3, 7, 100, 4096, 65536, 70000] {
        let (data, result) = read_signed(signed_wire(), piece).await;
        assert!(result.is_ok(), "pieces of {piece}: {:?}", result.err());
        assert_eq!(data.len(), 66560, "pieces of {piece}");
    }
}

#[tokio::test]
async fn a_changed_byte_is_found_when_its_chunk_ends() {
    let mut wire = signed_wire();
    let at = wire.len() - 200; // inside the second chunk
    wire[at] = b'b';
    let (data, result) = read_signed(wire, 4096).await;
    assert_eq!(code_of(result), "SignatureDoesNotMatch");
    assert!(data.len() >= 65536, "the bytes are handed on as they come; the stream ends with the error instead of the end");
}

#[tokio::test]
async fn a_changed_signature_is_found() {
    let mut text = String::from_utf8_lossy(&signed_wire()).into_owned();
    text = text.replacen(&SIGNATURES[0][..4], "0000", 1);
    let (_, result) = read_signed(text.into_bytes(), 1000).await;
    assert_eq!(code_of(result), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn chunks_in_another_order_are_found() {
    let first = [format!("10000;chunk-signature={}\r\n", SIGNATURES[0]).into_bytes(), vec![b'a'; 65536], b"\r\n".to_vec()].concat();
    let second = [format!("400;chunk-signature={}\r\n", SIGNATURES[1]).into_bytes(), vec![b'a'; 1024], b"\r\n".to_vec()].concat();
    let last = format!("0;chunk-signature={}\r\n\r\n", SIGNATURES[2]).into_bytes();
    let (_, result) = read_signed([second, first, last].concat(), 8192).await;
    assert_eq!(code_of(result), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn a_chunk_taken_out_is_found() {
    let first = [format!("10000;chunk-signature={}\r\n", SIGNATURES[0]).into_bytes(), vec![b'a'; 65536], b"\r\n".to_vec()].concat();
    let last = format!("0;chunk-signature={}\r\n\r\n", SIGNATURES[2]).into_bytes();
    let (_, result) = read_signed([first, last].concat(), 8192).await;
    assert_eq!(code_of(result), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn a_body_cut_short_never_ends_well() {
    let wire = signed_wire();
    let mut cuts: Vec<usize> = (0..wire.len()).step_by(997).collect();
    cuts.extend([0, 1, 5, 10, 31, 90, 91, 92, 65_600, wire.len() - 1, wire.len() - 2, wire.len() - 3, wire.len() - 60, wire.len() - 100]);
    for cut in cuts {
        let (_, result) = read_signed(wire[..cut].to_vec(), 3000).await;
        let error = result.expect_err(&format!("cut at {cut} of {}", wire.len()));
        assert!(matches!(error.code.as_str(), "IncompleteBody" | "InvalidRequest" | "SignatureDoesNotMatch"), "cut at {cut}: {error:?}");
    }
}

#[tokio::test]
async fn data_after_the_last_chunk_is_not_part_of_a_body_that_is_good() {
    let mut wire = signed_wire();
    wire.extend_from_slice(b"extra");
    let (_, result) = read_signed(wire, 1000).await;
    let error = result.expect_err("something follows the end");
    assert_eq!(error.code, "InvalidRequest", "{error:?}");
    // And the digests are not there: the upload is not acknowledged either.
    let body = RequestBody::new(
        body_of(split(&[signed_wire(), b"extra".to_vec()].concat(), 1000)),
        BodyPlan { length: Some(66560), ..plan(Framing::Chunked { signed: Some(chain(false)), trailers: false }) },
    );
    let handle = body.handle();
    let (_, result) = read(body).await;
    assert!(result.is_err());
    assert!(handle.get().is_none());
}

#[tokio::test]
async fn a_declared_length_that_is_not_the_length_of_the_data_is_incomplete_body() {
    for declared in [66559, 66561, 0] {
        let plan = BodyPlan { length: Some(declared), ..plan(Framing::Chunked { signed: Some(chain(false)), trailers: false }) };
        let (_, result) = read(RequestBody::new(body_of(split(&signed_wire(), 8192)), plan)).await;
        let error = result.expect_err("the length is wrong");
        assert_eq!(error.code, "IncompleteBody", "{declared}");
        // Too many bytes are found when they come, and too few at the end.
        if declared < 66560 {
            assert!(error.detail("NumberBytesProvided").and_then(|n| n.parse::<u64>().ok()).is_some_and(|n| n > declared && n <= 66560), "{declared}: {error:?}");
        } else {
            assert_eq!(error.detail("NumberBytesProvided"), Some("66560"));
        }
    }
}

// ---- the signed example with a trailing checksum ----

const TRAILER_SIGNATURES: [&str; 4] = [
    "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
    "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
    "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
    "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435",
];

fn trailer_wire(checksum: &str, trailer_signature: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(format!("10000;chunk-signature={}\r\n", TRAILER_SIGNATURES[0]).as_bytes());
    wire.extend_from_slice(&[b'a'; 65536]);
    wire.extend_from_slice(format!("\r\n400;chunk-signature={}\r\n", TRAILER_SIGNATURES[1]).as_bytes());
    wire.extend_from_slice(&[b'a'; 1024]);
    wire.extend_from_slice(format!("\r\n0;chunk-signature={}\r\n", TRAILER_SIGNATURES[2]).as_bytes());
    wire.extend_from_slice(format!("x-amz-checksum-crc32c:{checksum}\r\n").as_bytes());
    if !trailer_signature.is_empty() {
        wire.extend_from_slice(format!("x-amz-trailer-signature:{trailer_signature}\r\n").as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire
}

fn trailer_plan() -> BodyPlan {
    BodyPlan { length: Some(66560), trailer_checksums: vec![ChecksumAlgorithm::Crc32c], ..plan(Framing::Chunked { signed: Some(chain(true)), trailers: true }) }
}

async fn read_trailer(wire: Vec<u8>, piece: usize) -> (Vec<u8>, Result<Digests, S3Error>) {
    read(RequestBody::new(body_of(split(&wire, piece)), trailer_plan())).await
}

#[tokio::test]
async fn the_signed_example_with_a_trailing_checksum_passes() {
    for piece in [usize::MAX, 1, 13, 4096] {
        let (data, result) = read_trailer(trailer_wire("sOO8/Q==", TRAILER_SIGNATURES[3]), piece).await;
        let digests = result.unwrap_or_else(|error| panic!("pieces of {piece}: {error:?}"));
        assert_eq!(data.len(), 66560);
        let crc = digests.checksums.iter().find(|(algorithm, _)| *algorithm == ChecksumAlgorithm::Crc32c).unwrap();
        assert_eq!(thirtys3_core::checksum::base64_encode(&crc.1), "sOO8/Q==");
    }
}

#[tokio::test]
async fn a_changed_trailing_checksum_is_found_by_the_signature_of_the_trailer() {
    let (_, result) = read_trailer(trailer_wire("sOO8/Q=A", TRAILER_SIGNATURES[3]), 4096).await;
    assert_eq!(code_of(result), "SignatureDoesNotMatch");
}

#[tokio::test]
async fn a_signed_trailer_without_its_signature_is_refused() {
    let (_, result) = read_trailer(trailer_wire("sOO8/Q==", ""), 4096).await;
    assert_eq!(code_of(result), "MalformedTrailerError");
}

#[tokio::test]
async fn a_signed_body_that_ends_without_its_trailer_is_incomplete() {
    let wire = trailer_wire("sOO8/Q==", TRAILER_SIGNATURES[3]);
    let cut = wire.len() - 90;
    let (_, result) = read_trailer(wire[..cut].to_vec(), 4096).await;
    assert!(matches!(code_of(result).as_str(), "IncompleteBody" | "InvalidRequest"));
}

// ---- unsigned chunks with a trailing checksum ----

fn unsigned_plan(trailer_checksums: Vec<ChecksumAlgorithm>) -> BodyPlan {
    BodyPlan { length: Some(5), trailer_checksums, ..plan(Framing::Chunked { signed: None, trailers: true }) }
}

fn crc32_of_hello() -> String {
    thirtys3_core::checksum::base64_encode(&digest_of(ChecksumAlgorithm::Crc32, b"hello"))
}

#[tokio::test]
async fn unsigned_chunks_with_a_trailing_checksum() {
    let wire = format!("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:{}\r\n\r\n", crc32_of_hello());
    for piece in [usize::MAX, 1, 3] {
        let (data, result) = read(RequestBody::new(body_of(split(wire.as_bytes(), piece)), unsigned_plan(vec![ChecksumAlgorithm::Crc32]))).await;
        assert_eq!(data, b"hello", "pieces of {piece}");
        assert!(result.is_ok(), "pieces of {piece}");
    }
}

#[tokio::test]
async fn a_wrong_trailing_checksum_is_a_bad_digest() {
    let wire = "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
    let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from(wire)]), unsigned_plan(vec![ChecksumAlgorithm::Crc32]))).await;
    let error = result.unwrap_err();
    assert_eq!(error.code, "BadDigest");
    assert_eq!(error.detail("ExpectedDigest"), Some("AAAAAA=="));
    assert_eq!(error.detail("CalculatedDigest"), Some(crc32_of_hello().as_str()));
}

#[tokio::test]
async fn a_trailing_checksum_that_was_announced_and_did_not_come_is_refused() {
    let wire = "5\r\nhello\r\n0\r\n\r\n";
    let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from(wire)]), unsigned_plan(vec![ChecksumAlgorithm::Crc32]))).await;
    assert_eq!(code_of(result), "MalformedTrailerError");
}

#[tokio::test]
async fn a_trailing_checksum_that_was_not_announced_is_refused() {
    let wire = format!("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:{}\r\n\r\n", crc32_of_hello());
    let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from(wire)]), unsigned_plan(vec![]))).await;
    assert_eq!(code_of(result), "MalformedTrailerError");
}

#[tokio::test]
async fn a_trailing_checksum_that_is_not_base64_of_the_right_size_is_refused() {
    for value in ["", "not base64!", "AAAA", "AAAAAAAAAAA="] {
        let wire = format!("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:{value}\r\n\r\n");
        let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from(wire)]), unsigned_plan(vec![ChecksumAlgorithm::Crc32]))).await;
        assert_eq!(code_of(result), "MalformedTrailerError", "{value:?}");
    }
}

#[tokio::test]
async fn a_body_that_is_not_chunked_when_it_should_be_is_refused() {
    let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from("hello world, not chunked at all")]), unsigned_plan(vec![]))).await;
    assert!(matches!(code_of(result).as_str(), "InvalidRequest" | "IncompleteBody"));
}

#[tokio::test]
async fn chunks_larger_than_the_limit_are_refused() {
    let wire = "10\r\n0123456789abcdef\r\n0\r\n\r\n";
    let plan = BodyPlan { max_chunk: 15, ..plan(Framing::Chunked { signed: None, trailers: false }) };
    let (_, result) = read(RequestBody::new(body_of(vec![Bytes::from(wire)]), plan)).await;
    assert_eq!(code_of(result), "InvalidRequest");
    let ok = BodyPlan { max_chunk: 16, ..self::plan(Framing::Chunked { signed: None, trailers: false }) };
    assert!(read(RequestBody::new(body_of(vec![Bytes::from(wire)]), ok)).await.1.is_ok());
}

// ---- plain bodies ----

fn plain(data: &[u8], plan: BodyPlan) -> RequestBody {
    RequestBody::new(body_of(split(data, 7)), plan)
}

#[tokio::test]
async fn a_plain_body_is_hashed_for_its_etag() {
    let (data, result) = read(plain(b"hello world", BodyPlan { length: Some(11), ..plan(Framing::Plain) })).await;
    let digests = result.unwrap();
    assert_eq!(data, b"hello world");
    assert_eq!(digests.etag(), "\"5eb63bbbe01eeed093cb22bb8f5acdc3\"");
    assert_eq!(digests.size, 11);
}

#[tokio::test]
async fn an_empty_body() {
    let (data, result) = read(RequestBody::new(body_of(vec![]), BodyPlan { length: Some(0), ..plan(Framing::Plain) })).await;
    assert!(data.is_empty());
    assert_eq!(result.unwrap().etag(), "\"d41d8cd98f00b204e9800998ecf8427e\"");
}

#[tokio::test]
async fn the_hash_of_the_payload_is_checked_at_the_end() {
    let good = BodyPlan { payload_sha256: Some(sha256_hex(b"hello world")), ..plan(Framing::Plain) };
    let (_, result) = read(plain(b"hello world", good)).await;
    assert_eq!(result.unwrap().sha256.map(|hash| thirtys3_core::encoding::hex_encode(&hash)), Some(sha256_hex(b"hello world")));
    let wrong = BodyPlan { payload_sha256: Some(sha256_hex(b"hello there")), ..plan(Framing::Plain) };
    let (data, result) = read(plain(b"hello world", wrong)).await;
    assert_eq!(data, b"hello world", "the data went through; the end is what fails");
    assert_eq!(code_of(result), "XAmzContentSHA256Mismatch");
}

#[tokio::test]
async fn content_md5() {
    let md5 = digest_of(ChecksumAlgorithm::Md5, b"hello world");
    let (_, result) = read(plain(b"hello world", BodyPlan { content_md5: Some(md5), ..plan(Framing::Plain) })).await;
    assert!(result.is_ok());
    let (_, result) = read(plain(b"hello world", BodyPlan { content_md5: Some(vec![0; 16]), ..plan(Framing::Plain) })).await;
    let error = result.unwrap_err();
    assert_eq!(error.code, "BadDigest");
    assert!(error.detail("ExpectedDigest").is_some() && error.detail("CalculatedDigest").is_some());
}

#[tokio::test]
async fn every_checksum_algorithm_in_a_header_is_checked() {
    for algorithm in ChecksumAlgorithm::ALL {
        let right = digest_of(algorithm, b"hello world");
        let (_, result) = read(plain(b"hello world", BodyPlan { checksums: vec![(algorithm, right.clone())], ..plan(Framing::Plain) })).await;
        let digests = result.unwrap_or_else(|error| panic!("{algorithm:?}: {error:?}"));
        assert!(digests.checksums.iter().any(|(candidate, digest)| *candidate == algorithm && *digest == right), "{algorithm:?}");
        let (_, result) = read(plain(b"hello world", BodyPlan { checksums: vec![(algorithm, vec![0; right.len()])], ..plan(Framing::Plain) })).await;
        assert_eq!(code_of(result), "BadDigest", "{algorithm:?}");
    }
}

#[tokio::test]
async fn the_declared_length_of_a_plain_body() {
    for (declared, ok) in [(11, true), (10, false), (12, false)] {
        let (_, result) = read(plain(b"hello world", BodyPlan { length: Some(declared), ..plan(Framing::Plain) })).await;
        assert_eq!(result.is_ok(), ok, "{declared}");
        if !ok {
            assert_eq!(result.unwrap_err().code, "IncompleteBody");
        }
    }
}

#[tokio::test]
async fn the_most_bytes_are_enforced_as_they_arrive() {
    let (data, result) = read(plain(&[1; 100], BodyPlan { max_size: 40, ..plan(Framing::Plain) })).await;
    let error = result.unwrap_err();
    assert_eq!(error.code, "EntityTooLarge");
    assert_eq!(error.detail("MaxSizeAllowed"), Some("40"));
    assert!(data.len() <= 40, "no more than the limit is handed on: {}", data.len());
    // At the limit is fine.
    assert!(read(plain(&[1; 40], BodyPlan { max_size: 40, ..plan(Framing::Plain) })).await.1.is_ok());
    // The same for the data of chunks.
    let wire = format!("64\r\n{}\r\n0\r\n\r\n", "x".repeat(100).as_str());
    let (_, result) =
        read(RequestBody::new(body_of(vec![Bytes::from(wire)]), BodyPlan { max_size: 40, ..plan(Framing::Chunked { signed: None, trailers: false }) })).await;
    assert_eq!(code_of(result), "EntityTooLarge");
}

#[tokio::test]
async fn a_body_that_fails_while_it_is_read_is_incomplete() {
    let frames: Vec<Result<Frame<Bytes>, BoxError>> = vec![Ok(Frame::data(Bytes::from_static(b"abc"))), Err("the connection was reset".into())];
    let body = StreamBody::new(futures_util::stream::iter(frames)).boxed_unsync();
    let (data, result) = read(RequestBody::new(body, plan(Framing::Plain))).await;
    assert_eq!(data, b"abc");
    let error = result.unwrap_err();
    assert_eq!(error.code, "IncompleteBody");
    assert!(error.message.contains("reset"));
}

#[tokio::test]
async fn a_body_from_bytes_and_collect() {
    let (data, digests) = RequestBody::from_bytes(Bytes::from_static(b"abc")).collect().await.unwrap();
    assert_eq!((data.as_ref(), digests.size), (b"abc".as_slice(), 3));
}

#[tokio::test]
async fn a_body_that_is_longer_than_it_said_is_stopped_when_it_goes_over_and_not_at_its_end() {
    use futures_util::StreamExt;
    // 20 chunks of 8 KiB and a decoded length of 10 bytes: the first piece already is too much.
    let wire = signed_wire();
    let plan = BodyPlan { length: Some(10), ..plan(Framing::Chunked { signed: Some(chain(false)), trailers: false }) };
    let mut body = RequestBody::new(body_of(split(&wire, 8192)), plan);
    let mut delivered = 0;
    let error = loop {
        match body.next().await {
            Some(Ok(piece)) => delivered += piece.len(),
            Some(Err(error)) => break error,
            None => panic!("the body ended well"),
        }
    };
    assert_eq!(error.code, "IncompleteBody");
    assert_eq!(delivered, 0, "nothing over the declared length was handed on");
    assert!(body.digests().is_none());
}
