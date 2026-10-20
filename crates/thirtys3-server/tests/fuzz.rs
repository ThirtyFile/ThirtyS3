//! Random input for the server: the framing of `aws-chunked`, the headers that conditions and ranges are read from, the router and the whole service
//! with requests of every operation, signed and damaged. The service must answer each of them, quickly, with an S3 error when it refuses, and never with
//! an `InternalError` (which is what a broken assumption looks like).
//!
//! `THIRTYS3_FUZZ_ITERATIONS` sets the number of inputs of each test (2,000 by default) and `THIRTYS3_FUZZ_SEED` the seed.

mod support;

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, STREAMING_SIGNED_PAYLOAD, STREAMING_UNSIGNED_PAYLOAD_TRAILER};
use thirtys3_core::{Request as SigRequest, S3Error, Timestamp, sha256_hex};
use thirtys3_server::chunked::{Decoder, Event};
use thirtys3_server::conditions::{Conditions, RangeSpec, parse_range};
use thirtys3_server::{S3Service, ServerConfig, route};

struct Rng(u64);

impl Rng {
    fn new(salt: u64) -> Self {
        let seed = std::env::var("THIRTYS3_FUZZ_SEED").ok().and_then(|seed| seed.parse().ok()).unwrap_or(0x5EED_5EED_u64);
        Self(seed ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit.max(1) as u64) as usize
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }
}

fn iterations() -> usize {
    std::env::var("THIRTYS3_FUZZ_ITERATIONS").ok().and_then(|value| value.parse().ok()).unwrap_or(2000)
}

fn mutate(rng: &mut Rng, valid: &[u8]) -> Vec<u8> {
    let mut data = valid.to_vec();
    for _ in 0..1 + rng.below(3) {
        if data.is_empty() {
            data.push(b'\r');
        }
        let at = rng.below(data.len());
        match rng.below(8) {
            0 => data[at] ^= 1 << rng.below(8),
            1 => data.truncate(at),
            2 => {
                data.remove(at);
            }
            3 => data.insert(at, *rng.pick(b"\r\n;=:0123456789abcdefABCDEF -")),
            4 => {
                let end = (at + rng.below(40)).min(data.len());
                let piece = data[at..end].to_vec();
                data.splice(at..at, piece);
            }
            5 => data[at] = *rng.pick(b"0123456789abcdef"),
            6 => data[at] = *rng.pick(b"abcXYZ0123456789-"),
            _ => data[at] = rng.next() as u8,
        }
    }
    data
}

// ---- the framing of aws-chunked ----

/// A body of `aws-chunked` as a client writes it, with signatures that are made up (the decoder reads them, the body checks them).
fn chunked_body(rng: &mut Rng, signed: bool, trailer: bool) -> (Vec<u8>, Vec<u8>) {
    let signature = "0123456789abcdef".repeat(4);
    let mut data = Vec::new();
    let mut wire = Vec::new();
    for _ in 0..rng.below(5) {
        let size = if rng.chance(4) { rng.below(5) + 1 } else { rng.below(3000) + 1 };
        let chunk = rng.bytes(size);
        if signed {
            wire.extend_from_slice(format!("{size:x};chunk-signature={signature}\r\n").as_bytes());
        } else {
            wire.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        }
        wire.extend_from_slice(&chunk);
        wire.extend_from_slice(b"\r\n");
        data.extend_from_slice(&chunk);
    }
    wire.extend_from_slice(if signed { format!("0;chunk-signature={signature}\r\n").into_bytes() } else { b"0\r\n".to_vec() }.as_slice());
    if trailer {
        wire.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n");
        if signed {
            wire.extend_from_slice(format!("x-amz-trailer-signature:{signature}\r\n").as_bytes());
        }
    }
    wire.extend_from_slice(b"\r\n");
    (wire, data)
}

/// Feeds `wire` in pieces of random sizes; the data decoded, or the error.
fn decode(rng: &mut Rng, wire: &[u8], signed: bool, trailers: bool, max_chunk: u64) -> Result<Vec<u8>, String> {
    let mut decoder = Decoder::new(signed, trailers, max_chunk);
    let mut data = Vec::new();
    let mut at = 0;
    loop {
        loop {
            match decoder.next_event() {
                Ok(Some(Event::Data(bytes))) => data.extend_from_slice(&bytes),
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => return Err(error.message),
            }
        }
        if at >= wire.len() {
            break;
        }
        let limit = if rng.chance(3) { 3 } else { 700 };
        let take = (1 + rng.below(limit)).min(wire.len() - at);
        decoder.push(&wire[at..at + take]);
        at += take;
    }
    decoder.finish().map(|()| data).map_err(|error| error.message)
}

#[test]
fn a_chunked_body_decodes_the_same_whatever_the_pieces_it_comes_in() {
    let mut rng = Rng::new(1);
    for _ in 0..iterations() {
        let (signed, trailer) = (rng.chance(2), rng.chance(2));
        let (wire, expected) = chunked_body(&mut rng, signed, trailer);
        assert_eq!(decode(&mut rng, &wire, signed, trailer, 8 << 20).as_deref(), Ok(expected.as_slice()), "signed {signed}, trailer {trailer}");
    }
}

#[test]
fn a_damaged_chunked_body_is_an_error_or_a_body_and_never_a_panic_or_a_pile_of_memory() {
    let mut rng = Rng::new(2);
    for _ in 0..iterations() {
        let (signed, trailer) = (rng.chance(2), rng.chance(2));
        let (wire, _) = chunked_body(&mut rng, signed, trailer);
        let damaged = mutate(&mut rng, &wire);
        let _ = decode(&mut rng, &damaged, signed, trailer, 2000);
        // The decoder may be given the wrong kind of body.
        let _ = decode(&mut rng, &damaged, !signed, !trailer, 2000);
    }
    // Lines that never end, sizes that do not fit, and chunks that are larger than they may be.
    for wire in [
        vec![b'a'; 10_000_000],
        b"ffffffffffffffffffffff\r\n".to_vec(),
        b"7fffffffffffffff\r\n".to_vec(),
        format!("{};{}\r\n", "1", "x".repeat(1_000_000)).into_bytes(),
        format!("0\r\n{}", "h:v\r\n".repeat(100_000)).into_bytes(),
        format!("0\r\n{}:x\r\n\r\n", "n".repeat(1_000_000)).into_bytes(),
        b"-1\r\n".to_vec(),
        b"+1\r\n\r\n".to_vec(),
        b" 1\r\nx\r\n".to_vec(),
        b"1\nx\n0\n\n".to_vec(),
    ] {
        let mut decoder = Decoder::new(false, true, 1 << 20);
        let mut failed = false;
        for piece in wire.chunks(4096) {
            decoder.push(piece);
            loop {
                match decoder.next_event() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                break;
            }
            assert!(decoder.buffered() < 1 << 20, "{} bytes are being held", decoder.buffered());
        }
    }
}

// ---- headers ----

#[test]
fn ranges_and_conditions_read_any_text() {
    const PIECES: &[&str] = &[
        "bytes=",
        "bytes",
        "=",
        "-",
        ",",
        "0",
        "1",
        "9",
        "18446744073709551615",
        "18446744073709551616",
        " ",
        "\t",
        "a",
        "*",
        "\"",
        "W/",
        "x",
        "Tue, 02 Jan 2024 03:04:05 GMT",
        "2024",
    ];
    let mut rng = Rng::new(3);
    for _ in 0..iterations() * 5 {
        let value: String = (0..rng.below(8)).map(|_| *rng.pick(PIECES)).collect();
        if let Some(spec) = parse_range(&value) {
            for size in [0, 1, 5, u64::MAX] {
                if let Ok(range) = spec.resolve(size) {
                    assert!(range.start < range.end && range.end <= size, "{value:?} of {size}: {range:?}");
                }
            }
        }
        let mut headers = HeaderMap::new();
        for name in ["if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "x-amz-copy-source-if-match", "x-amz-copy-source-if-modified-since"] {
            if rng.chance(2) {
                let value = HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static("x"));
                headers.insert(HeaderName::from_static(name), value);
            }
        }
        for copy in [false, true] {
            let conditions = Conditions::from_headers(&headers, copy);
            let _ = conditions.evaluate("\"abc\"", Timestamp(1_700_000_000));
            let _ = conditions.evaluate_copy("abc", Timestamp(0));
        }
    }
    assert_eq!(parse_range("bytes=0-0"), Some(RangeSpec::Bounded(0, 0)));
}

// ---- the router ----

#[test]
fn the_router_takes_any_path_and_query() {
    const PIECES: &[&str] = &[
        "/",
        "//",
        "bucket",
        "key",
        "a b",
        "%20",
        "%",
        "%zz",
        "%00",
        "%ff",
        "..",
        ".",
        "?",
        "&",
        "=",
        "uploads",
        "uploadId",
        "partNumber",
        "delete",
        "list-type",
        "acl",
        "versions",
        "tagging",
        "location",
        "x-id",
        "\u{e9}",
        "+",
        "0",
        "2",
        "encoding-type",
        "url",
        "max-keys",
    ];
    let mut rng = Rng::new(4);
    let configs = [ServerConfig::default(), ServerConfig { virtual_host_suffixes: vec!["s3.example.com".to_owned()], ..ServerConfig::default() }];
    for _ in 0..iterations() * 5 {
        let mut target = String::from("/");
        for _ in 0..rng.below(10) {
            target.push_str(rng.pick(PIECES));
        }
        let host = if rng.chance(2) { "bucket.s3.example.com" } else { "127.0.0.1:9000" };
        let method = rng.pick(&[Method::GET, Method::PUT, Method::POST, Method::DELETE, Method::HEAD, Method::OPTIONS, Method::PATCH]).clone();
        let Ok(request) = http::Request::builder().method(method).uri(target.as_str()).header("host", host).body(()) else { continue };
        let (parts, ()) = request.into_parts();
        for config in &configs {
            let _ = route::route(&parts, config);
        }
        let _ = route::unsupported_header(&parts);
    }
}

// ---- the whole service ----

const HOST: &str = "localhost";

struct Case {
    method: Method,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    payload: String,
}

fn operations(rng: &mut Rng, real_upload: &str) -> Case {
    const KEYS: &[&str] = &["k", "dir/k", "a%20b", "a%2Bb", "%C3%A9", "dir/", "empty", "x/y/z", "k%3Fq"];
    let key = *rng.pick(KEYS);
    let upload_key = if rng.chance(8) { key } else { "mp" };
    let upload_id = if rng.chance(3) { "nope".to_owned() } else { real_upload.to_owned() };
    let part = rng.pick(&["1", "2", "0", "10001", "x", "-1", ""]);
    let (method, path, query): (Method, String, String) = match rng.below(19) {
        0 => (Method::GET, "/".into(), String::new()),
        1 => (Method::HEAD, "/bucket".into(), String::new()),
        2 => (
            Method::GET,
            "/bucket".into(),
            format!(
                "list-type=2&max-keys={}&prefix={}&delimiter=%2F&encoding-type=url",
                rng.pick(&["0", "1", "2", "1000", "5000", "x", "-1"]),
                rng.pick(&["", "dir%2F", "a"])
            ),
        ),
        3 => (Method::GET, "/bucket".into(), format!("marker={}&max-keys=2", rng.pick(&["", "k", "zzz"]))),
        4 => (Method::GET, format!("/bucket/{}", rng.pick(&["k", "dir/k"])), String::new()),
        5 => (Method::HEAD, format!("/bucket/{key}"), String::new()),
        6 => (Method::PUT, format!("/bucket/{key}"), String::new()),
        7 => (Method::DELETE, format!("/bucket/{key}"), String::new()),
        8 => (Method::PUT, format!("/bucket/{key}"), String::new()),
        9 => (Method::POST, "/bucket".into(), "delete".into()),
        10 => (Method::POST, format!("/bucket/{key}"), "uploads".into()),
        11 => (Method::PUT, format!("/bucket/{upload_key}"), format!("partNumber={part}&uploadId={upload_id}")),
        12 => (Method::POST, format!("/bucket/{upload_key}"), format!("uploadId={upload_id}")),
        13 => (Method::DELETE, format!("/bucket/{upload_key}"), format!("uploadId={upload_id}")),
        14 => (Method::GET, format!("/bucket/{upload_key}"), format!("uploadId={upload_id}&max-parts={}", rng.pick(&["1", "1000", "0", "x"]))),
        15 => (Method::GET, "/bucket".into(), "uploads".into()),
        16 => (
            Method::GET,
            format!("/bucket/{key}"),
            format!("response-content-type=x%2Fy&response-expires={}", rng.pick(&["", "bad", "Tue, 02 Jan 2024 03:04:05 GMT"])),
        ),
        17 => (
            Method::GET,
            format!("/bucket/{key}"),
            (*rng.pick(&["acl", "tagging", "versions", "versionId=1", "legal-hold", "torrent", "select&select-type=2", "attributes"])).to_owned(),
        ),
        _ => (Method::PUT, "/newbucket".into(), String::new()),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut payload = EMPTY_PAYLOAD_SHA256.to_owned();
    // Headers that operations read, with values that may be right or not.
    let extras: &[(&str, &[&str])] = &[
        ("range", &["bytes=0-1", "bytes=-1", "bytes=5-", "bytes=0-0,2-3", "bytes=9-1", "x"]),
        ("if-match", &["*", "\"nope\"", "W/\"a\""]),
        ("if-none-match", &["*", "\"nope\""]),
        ("if-modified-since", &["Tue, 02 Jan 2024 03:04:05 GMT", "x"]),
        ("x-amz-copy-source", &["bucket/k", "/bucket/dir/k", "bucket/nope", "bucket", "%", "other/k", "bucket/k?versionId=1", "nobucket/k"]),
        ("x-amz-metadata-directive", &["COPY", "REPLACE", "x"]),
        ("x-amz-meta-a", &["b", "\u{e9}"]),
        ("content-type", &["text/plain", "x"]),
        ("content-md5", &["1B2M2Y8AsgTpgAmY7PhCfg==", "AAAA", "x", ""]),
        ("x-amz-checksum-crc32", &["AAAAAA==", "x", ""]),
        ("x-amz-checksum-sha256", &["x", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]),
        ("x-amz-checksum-algorithm", &["CRC32", "SHA256", "x"]),
        ("x-amz-acl", &["private"]),
        ("x-amz-server-side-encryption", &["AES256"]),
        ("x-amz-tagging", &["a=b"]),
        ("if-none-match-x", &["*"]),
        ("x-amz-expected-bucket-owner", &["123"]),
    ];
    for (name, values) in extras {
        // The headers the service does not keep are rare, or they would hide the rest.
        let rare = matches!(*name, "x-amz-acl" | "x-amz-server-side-encryption" | "x-amz-tagging");
        if rng.chance(if rare { 60 } else { 4 }) {
            headers.push(((*name).to_owned(), (*rng.pick(values)).to_owned()));
        }
    }
    let documents: [&str; 4] = [
        "<Delete><Object><Key>k</Key></Object><Object><Key>dir/k</Key></Object></Delete>",
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"a\"</ETag></Part></CompleteMultipartUpload>",
        "<CreateBucketConfiguration><LocationConstraint>test-region</LocationConstraint></CreateBucketConfiguration>",
        "<Delete><Quiet>true</Quiet></Delete>",
    ];
    if method == Method::PUT || method == Method::POST {
        body = match rng.below(5) {
            0 => Vec::new(),
            1 => {
                let length = rng.below(5000);
                rng.bytes(length)
            }
            _ => {
                let forced = if query == "delete" {
                    Some(0)
                } else if method == Method::POST && query.starts_with("uploadId=") {
                    Some(1)
                } else {
                    None
                };
                let document = forced.map_or_else(|| *rng.pick(&documents), |index| documents[index]).as_bytes().to_vec();
                if rng.chance(2) { document } else { mutate(rng, &document) }
            }
        };
        payload = sha256_hex(&body);
    }
    Case { method, path, query, headers, body, payload }
}

/// The request as it goes to the service: signed, or not, and damaged, or not.
fn build(rng: &mut Rng, case: Case) -> http::Request<Full<Bytes>> {
    let Case { method, path, query, mut headers, mut body, mut payload } = case;
    let mut chunked = false;
    if (method == Method::PUT || method == Method::POST) && rng.chance(4) && !path.ends_with("newbucket") {
        // The same body, in the framing of the SDKs, with a signature that is right or made up.
        let signed = rng.chance(2);
        let (wire, data) = chunked_body(rng, signed, !signed);
        headers.push(("content-encoding".into(), "aws-chunked".into()));
        headers.push(("x-amz-decoded-content-length".into(), if rng.chance(4) { "7".into() } else { data.len().to_string() }));
        if !signed {
            headers.push(("x-amz-trailer".into(), "x-amz-checksum-crc32".into()));
        }
        payload = (if signed { STREAMING_SIGNED_PAYLOAD } else { STREAMING_UNSIGNED_PAYLOAD_TRAILER }).to_owned();
        body = wire;
        chunked = true;
    }
    let time = if rng.chance(20) { Timestamp(Timestamp::now().0 - 3600) } else { Timestamp::now() };
    let with_host: Vec<(String, String)> = std::iter::once(("host".to_owned(), HOST.to_owned())).chain(headers.iter().cloned()).collect();
    let borrowed: Vec<(&str, &str)> = with_host.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let wire_path = path.clone();
    let request = SigRequest { method: method.as_str(), path: &wire_path, query: &query, headers: &borrowed };
    let mut final_query = query.clone();
    let mut all = with_host.clone();
    match rng.below(10) {
        // Presigned, with the body not signed.
        0 => {
            let signed_query = support::signer().presign(&SigRequest { headers: &borrowed[..1], ..request }, time, 300).unwrap();
            final_query = if query.is_empty() { signed_query } else { format!("{query}&{signed_query}") };
            all = with_host[..1].to_vec();
            all.extend(headers.iter().cloned());
        }
        // Not signed at all, or signed with garbage.
        1 => {}
        2 => {
            all.push(("authorization".into(), "AWS4-HMAC-SHA256 Credential=AKIATESTKEY/20240102/test-region/s3/aws4_request,SignedHeaders=host,Signature=00".into()))
        }
        _ => {
            let signed = support::signer().sign(&request, &payload, time).unwrap();
            all.extend(signed.headers.iter().cloned());
        }
    }
    // Damage, after the signature.
    if rng.chance(8) && !all.is_empty() {
        let at = rng.below(all.len());
        all[at].1 = String::from_utf8_lossy(&mutate(rng, all[at].1.as_bytes())).replace(['\r', '\n', '\0'], "");
    }
    if rng.chance(12) {
        let at = rng.below(body.len() + 1);
        body.truncate(at);
    }
    if rng.chance(12) && !body.is_empty() {
        body = mutate(rng, &body);
    }
    let uri = if final_query.is_empty() { path } else { format!("{path}?{final_query}") };
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in all {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) {
            builder = builder.header(name, value);
        }
    }
    if !(rng.chance(25) || chunked && rng.chance(2)) {
        builder = builder.header("content-length", body.len().to_string());
    }
    builder.body(Full::new(Bytes::from(body))).unwrap_or_else(|_| http::Request::new(Full::new(Bytes::new())))
}

/// An upload to send parts to, started with a request of its own.
async fn new_upload(service: &S3Service<thirtys3_server::memory::MemoryBackend>) -> String {
    let headers = [("host", HOST)];
    let request = SigRequest { method: "POST", path: "/bucket/mp", query: "uploads", headers: &headers };
    let signed = support::signer().sign(&request, EMPTY_PAYLOAD_SHA256, Timestamp::now()).unwrap();
    let mut builder = http::Request::builder().method(Method::POST).uri("/bucket/mp?uploads").header("host", HOST);
    for (name, value) in &signed.headers {
        builder = builder.header(name, value);
    }
    let response = service.handle(builder.body(Full::new(Bytes::new())).unwrap()).await;
    let body = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    body.split("<UploadId>").nth(1).and_then(|rest| rest.split("</UploadId>").next()).expect("an upload ID").to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_request_gets_an_answer_and_none_gets_an_internal_error() {
    let service = S3Service::new(support::backend(), ServerConfig { region: support::REGION.to_owned(), max_object_size: 1 << 20, ..ServerConfig::default() });
    let mut rng = Rng::new(5);
    let mut upload = new_upload(&service).await;
    let mut answers = std::collections::BTreeMap::new();
    let mut codes = std::collections::BTreeMap::new();
    for iteration in 0..iterations() {
        if iteration % 25 == 0 {
            upload = new_upload(&service).await;
        }
        if iteration % 50 == 0 {
            service.backend().insert("bucket", "k", b"hello");
            service.backend().insert("bucket", "dir/k", b"hello");
        }
        let state = rng.0;
        let case = operations(&mut rng, &upload);
        let (method, uri) = (case.method.clone(), format!("{}?{}", case.path, case.query));
        let request = build(&mut rng, case);
        let description = format!("{method} {uri} (iteration {iteration}, generator state {state:#x})");
        let response = tokio::time::timeout(Duration::from_secs(10), service.handle(request)).await.unwrap_or_else(|_| panic!("no answer for {description}"));
        let status = response.status();
        let head = method == Method::HEAD;
        let body = tokio::time::timeout(Duration::from_secs(10), response.into_body().collect())
            .await
            .unwrap_or_else(|_| panic!("body never ends for {description}"))
            .unwrap()
            .to_bytes();
        *answers.entry(status.as_u16()).or_insert(0usize) += 1;
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "{description}: {}", String::from_utf8_lossy(&body));
        if status.as_u16() >= 400 && !head {
            let error = S3Error::from_xml(&body, status.as_u16()).unwrap_or_else(|error| panic!("{description}: {error}: {}", String::from_utf8_lossy(&body)));
            assert!(!error.code.is_empty(), "{description}");
            *codes.entry(error.code).or_insert(0usize) += 1;
        }
    }
    // The requests got somewhere: some were taken, some were refused for each of the usual reasons.
    assert!(answers.get(&200).copied().unwrap_or(0) > iterations() / 50, "{answers:?}");
    assert!(answers.get(&403).copied().unwrap_or(0) > 0, "{answers:?}");
    // And the refusals are of many kinds, so the requests do reach the checks. The rarer kinds are looked for only in long runs.
    let usual = [
        "NoSuchKey",
        "NoSuchUpload",
        "InvalidArgument",
        "SignatureDoesNotMatch",
        "MalformedXML",
        "PreconditionFailed",
        "NotImplemented",
        "BadDigest",
        "IncompleteBody",
        "AccessDenied",
        "NoSuchBucket",
        "RequestTimeTooSkewed",
    ];
    let rare = ["InvalidRange", "InvalidPart", "MissingContentLength"];
    let wanted: Vec<&str> = if iterations() >= 20_000 {
        usual.iter().chain(&rare).copied().collect()
    } else if iterations() >= 2000 {
        usual.to_vec()
    } else {
        Vec::new()
    };
    for code in wanted {
        assert!(codes.contains_key(code), "no request got {code}: {codes:?}");
    }
    // Whatever was stored is what the ETag says.
    for key in service.backend().keys("bucket") {
        let info = service.backend().info("bucket", &key).unwrap();
        let data = service.backend().object("bucket", &key).unwrap();
        assert_eq!(info.size, data.len() as u64, "{key}");
        if !info.etag.contains('-') {
            assert_eq!(info.etag, format!("\"{}\"", thirtys3_core::encoding::hex_encode(&thirtys3_core::etag::md5_digest(&data))), "{key}");
        }
    }
}
