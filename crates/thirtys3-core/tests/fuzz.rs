//! Random input for everything in the crate that reads what a stranger sent: no panic, no endless loop, no stack overflow, and the round trips that
//! must hold. The generator is seeded, so a failure says how to run it again.
//!
//! `THIRTYS3_FUZZ_ITERATIONS` sets the number of inputs of each test (3,000 by default) and `THIRTYS3_FUZZ_SEED` the seed.

use std::panic::{AssertUnwindSafe, catch_unwind};

use thirtys3_core::checksum::{ChecksumAlgorithm, base64_decode, base64_encode};
use thirtys3_core::encoding::{canonical_query, canonical_uri, hex_decode, hex_encode, percent_decode, query_params, uri_encode};
use thirtys3_core::etag::ETagCondition;
use thirtys3_core::model::*;
use thirtys3_core::xml::{self, Limits};
use thirtys3_core::{Credentials, PayloadHash, Request, S3Error, Signer, Timestamp, parse_request_auth};

struct Rng(u64);

impl Rng {
    fn new(salt: u64) -> Self {
        let seed = std::env::var("THIRTYS3_FUZZ_SEED").ok().and_then(|seed| seed.parse().ok()).unwrap_or(0x5EED_5EED_u64);
        Self(seed ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit.max(1) as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next() as u8).collect()
    }
}

fn iterations() -> usize {
    std::env::var("THIRTYS3_FUZZ_ITERATIONS").ok().and_then(|value| value.parse().ok()).unwrap_or(3000)
}

/// Runs `body` for every iteration and says which one panicked.
fn fuzz(name: &str, salt: u64, mut body: impl FnMut(&mut Rng, usize)) {
    let mut rng = Rng::new(salt);
    for iteration in 0..iterations() {
        let state = rng.0;
        if catch_unwind(AssertUnwindSafe(|| body(&mut rng, iteration))).is_err() {
            panic!("{name} panicked at iteration {iteration} (generator state {state:#x}; THIRTYS3_FUZZ_SEED={:?})", std::env::var("THIRTYS3_FUZZ_SEED").ok());
        }
    }
}

// ---- XML ----

const WORDS: &[&str] = &[
    "<",
    ">",
    "</",
    "/>",
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE a [<!ENTITY x \"y\">]>",
    "<![CDATA[",
    "]]>",
    "<!--",
    "-->",
    "&amp;",
    "&lt;",
    "&#x41;",
    "&#0;",
    "&#xD800;",
    "&x;",
    "&",
    ";",
    "\"",
    "'",
    "=",
    " ",
    "\r\n",
    "\u{0}",
    "\u{feff}",
    "\u{10ffff}",
    "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"",
    "xmlns:a=\"b\"",
    "a:",
    "Delete",
    "Object",
    "Key",
    "Quiet",
    "true",
    "CompleteMultipartUpload",
    "Part",
    "PartNumber",
    "ETag",
    "ChecksumCRC32",
    "ListBucketResult",
    "Contents",
    "CommonPrefixes",
    "Prefix",
    "IsTruncated",
    "KeyCount",
    "Size",
    "LastModified",
    "2024-01-02T03:04:05.000Z",
    "Error",
    "Code",
    "Message",
    "1",
    "-1",
    "99999999999999999999",
    "x",
];

fn soup(rng: &mut Rng) -> Vec<u8> {
    match rng.below(4) {
        0 => {
            let length = rng.below(300);
            rng.bytes(length)
        }
        _ => {
            let mut out = String::new();
            for _ in 0..rng.below(60) {
                out.push_str(rng.pick(WORDS));
            }
            out.into_bytes()
        }
    }
}

fn mutate(rng: &mut Rng, valid: &[u8]) -> Vec<u8> {
    let mut data = valid.to_vec();
    for _ in 0..1 + rng.below(3) {
        if data.is_empty() {
            data.push(b'<');
        }
        let at = rng.below(data.len());
        match rng.below(10) {
            // Most changes keep the document well formed, so the readers get to look at what it says.
            6..=9 => {
                let from = (at..data.len()).chain(0..at).find(|&index| data[index].is_ascii_alphanumeric()).unwrap_or(at);
                data[from] = *rng.pick(b"abcXYZ0123456789-");
            }
            0 => data[at] ^= 1 << rng.below(8),
            1 => data.truncate(at),
            2 => {
                data.remove(at);
            }
            3 => {
                let word = rng.pick(WORDS).as_bytes().to_vec();
                data.splice(at..at, word);
            }
            4 => {
                let end = (at + rng.below(40)).min(data.len());
                let piece = data[at..end].to_vec();
                data.splice(at..at, piece);
            }
            _ => data[at] = rng.next() as u8,
        }
    }
    data
}

fn corpus() -> Vec<Vec<u8>> {
    let delete = DeleteRequest {
        objects: vec![DeleteObjectId::new("a/b c"), DeleteObjectId { version_id: Some("v".into()), ..DeleteObjectId::new("k\u{e9}") }],
        quiet: true,
    };
    let complete = CompleteMultipartUploadRequest { parts: vec![CompletedPart::new(1, "\"abc\""), CompletedPart::new(2, "\"def\"")] };
    let documents = [
        delete.to_xml(),
        complete.to_xml(),
        S3Error::new("NoSuchKey", "The specified key does not exist.").with_resource("/b/k").with_detail("Key", "k").to_xml(),
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>a</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified><ETag>\"x\"</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Contents><CommonPrefixes><Prefix>d/</Prefix></CommonPrefixes></ListBucketResult>".to_owned(),
        "<ListAllMyBucketsResult><Owner><ID>i</ID></Owner><Buckets><Bucket><Name>b</Name><CreationDate>2024-01-02T03:04:05.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>".to_owned(),
        "<ListPartsResult><Bucket>b</Bucket><Key>k</Key><UploadId>u</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>1</NextPartNumberMarker><MaxParts>1</MaxParts><IsTruncated>true</IsTruncated><Part><PartNumber>1</PartNumber><LastModified>2024-01-02T03:04:05.000Z</LastModified><ETag>\"e\"</ETag><Size>5</Size></Part></ListPartsResult>".to_owned(),
        "<ListMultipartUploadsResult><Bucket>b</Bucket><MaxUploads>1</MaxUploads><IsTruncated>false</IsTruncated><Upload><Key>k</Key><UploadId>u</UploadId><Initiated>2024-01-02T03:04:05.000Z</Initiated></Upload></ListMultipartUploadsResult>".to_owned(),
        "<CopyObjectResult><ETag>\"e\"</ETag><LastModified>2024-01-02T03:04:05.000Z</LastModified><ChecksumCRC32>AAAAAA==</ChecksumCRC32></CopyObjectResult>".to_owned(),
        "<DeleteResult><Deleted><Key>a</Key></Deleted><Error><Key>b</Key><Code>AccessDenied</Code><Message>m</Message></Error></DeleteResult>".to_owned(),
        "<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>u</UploadId></InitiateMultipartUploadResult>".to_owned(),
        "<CompleteMultipartUploadResult><Location>l</Location><Bucket>b</Bucket><Key>k</Key><ETag>\"e\"</ETag></CompleteMultipartUploadResult>".to_owned(),
        "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">eu-west-1</LocationConstraint>".to_owned(),
    ];
    documents.into_iter().map(String::into_bytes).collect()
}

/// Every reader of a document; how many of them took it.
fn read_everything(data: &[u8]) -> usize {
    let limits = Limits { max_bytes: 64, max_depth: 2, max_elements: 3 };
    [
        ListAllMyBucketsResult::from_xml(data).is_ok(),
        LocationConstraint::from_xml(data).is_ok(),
        ListObjectsV2Result::from_xml(data).is_ok(),
        ListObjectsV1Result::from_xml(data).is_ok(),
        CopyObjectResult::from_xml(data).is_ok(),
        DeleteRequest::from_xml(data).is_ok(),
        DeleteResult::from_xml(data).is_ok(),
        InitiateMultipartUploadResult::from_xml(data).is_ok(),
        CompleteMultipartUploadRequest::from_xml(data).is_ok(),
        CompleteMultipartUploadResult::from_xml(data).is_ok(),
        ListPartsResult::from_xml(data).is_ok(),
        ListMultipartUploadsResult::from_xml(data).is_ok(),
        S3Error::from_xml(data, 400).is_ok(),
        xml::parse(data, &limits).is_ok(),
    ]
    .into_iter()
    .filter(|ok| *ok)
    .count()
}

#[test]
fn xml_readers_survive_noise_and_damaged_documents() {
    let corpus = corpus();
    // The documents are good as they are.
    assert!(DeleteRequest::from_xml(&corpus[0]).is_ok() && CompleteMultipartUploadRequest::from_xml(&corpus[1]).is_ok());
    assert!(S3Error::from_xml(&corpus[2], 404).is_ok() && ListObjectsV2Result::from_xml(&corpus[3]).is_ok());
    let mut reached = 0;
    fuzz("xml readers", 1, |rng, iteration| {
        let which = rng.below(corpus.len());
        let data = if iteration % 3 == 0 { soup(rng) } else { mutate(rng, &corpus[which]) };
        reached += read_everything(&data);
    });
    // The damaged documents are not all rejected at the first byte: the readers get deep into some of them.
    assert!(reached > iterations() / 20, "only {reached} readings of damaged documents worked");
}

#[test]
fn xml_that_is_deep_or_wide_or_big_is_refused_without_a_stack_overflow() {
    let limits = Limits::default();
    let deep = "<a>".repeat(200_000);
    assert!(xml::parse(deep.as_bytes(), &limits).is_err());
    let deep_closed = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
    assert!(xml::parse(deep_closed.as_bytes(), &limits).is_err());
    let wide = format!("<a>{}</a>", "<b/>".repeat(1_000_000));
    assert!(xml::parse(wide.as_bytes(), &limits).is_err());
    let entities = format!("<a>{}</a>", "&amp;".repeat(1_000_000));
    assert!(xml::parse(entities.as_bytes(), &Limits { max_bytes: 1 << 20, ..limits }).is_err());
    let attributes = format!("<a {}/>", "x=\"1\" ".repeat(100_000));
    let _ = xml::parse(attributes.as_bytes(), &limits);
    // A document with a DTD is not read, so there is no entity that grows.
    let bomb = "<!DOCTYPE a [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]><x>&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;</x>";
    match xml::parse(bomb.as_bytes(), &limits) {
        Err(_) => {}
        Ok(element) => assert!(element.text.len() < 1000, "entities were expanded"),
    }
}

fn text(rng: &mut Rng) -> String {
    const PIECES: &[&str] = &[
        "a",
        "Z",
        "0",
        " ",
        "/",
        "+",
        "%",
        "&",
        "<",
        ">",
        "\"",
        "'",
        "]]>",
        "\u{e9}",
        "\u{4e2d}",
        "\u{1f600}",
        "\t",
        "\n",
        "\r",
        "\r\n",
        "..",
        "-",
        "_",
        "~",
        "\u{7f}",
        "\u{85}",
        "\u{2028}",
    ];
    (0..rng.below(24)).map(|_| *rng.pick(PIECES)).collect()
}

#[test]
fn keys_of_any_text_survive_a_trip_through_a_document() {
    fuzz("xml round trip", 2, |rng, _| {
        let keys: Vec<String> = (0..1 + rng.below(4)).map(|_| text(rng)).collect();
        let request = DeleteRequest { objects: keys.iter().map(DeleteObjectId::new).collect(), quiet: rng.below(2) == 0 };
        let xml = request.to_xml();
        match DeleteRequest::from_xml(xml.as_bytes()) {
            Ok(back) => assert_eq!(back, request, "{xml:?}"),
            // An empty key is a document with an empty element, which is fine, and nothing else may fail.
            Err(error) => panic!("{error} for {xml:?}"),
        }
        let parts = CompleteMultipartUploadRequest { parts: keys.iter().enumerate().map(|(index, key)| CompletedPart::new(index as u32 + 1, key.trim())).collect() };
        assert_eq!(CompleteMultipartUploadRequest::from_xml(parts.to_xml().as_bytes()).unwrap(), parts);
        let error = S3Error::new("InvalidArgument", keys[0].clone()).with_detail("ArgumentValue", keys[keys.len() - 1].clone());
        let back = S3Error::from_xml(error.to_xml().as_bytes(), 400).unwrap();
        assert_eq!((back.code, back.message, back.details), (error.code, error.message, error.details));
    });
}

// ---- headers, queries and the like ----

fn header_text(rng: &mut Rng) -> String {
    const PIECES: &[&str] = &[
        "AWS4-HMAC-SHA256",
        " ",
        ",",
        "=",
        "Credential",
        "SignedHeaders",
        "Signature",
        "AKIAEXAMPLE",
        "/",
        "20240102",
        "us-east-1",
        "s3",
        "aws4_request",
        "host",
        ";",
        "x-amz-date",
        "x-amz-content-sha256",
        "0123456789abcdef",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "UNSIGNED-PAYLOAD",
        "\"",
        "W/",
        "*",
        "bytes=",
        "-",
        "0",
        "1",
        "99999999999999999999",
        "\u{e9}",
        "20240102T030405Z",
        "Tue, 02 Jan 2024 03:04:05 GMT",
        "2024-01-02T03:04:05.000Z",
    ];
    let mut out = String::new();
    for _ in 0..rng.below(24) {
        out.push_str(rng.pick(PIECES));
    }
    out
}

#[test]
fn authentication_of_any_request_is_read_or_refused() {
    let signer = Signer::new(Credentials::new("AKIAEXAMPLE", "secret"), "us-east-1");
    let host = [("host", "s3.example.com")];
    let base = Request { method: "GET", path: "/b/k", query: "", headers: &host };
    let good_header = signer.sign(&base, thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256, Timestamp::now()).unwrap();
    let good_query = signer.presign(&base, Timestamp::now(), 300).unwrap();
    fuzz("authentication", 3, |rng, _| {
        let mut headers: Vec<(String, String)> = host.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
        let mut query = String::new();
        match rng.below(3) {
            0 => {
                headers.extend(good_header.headers.iter().cloned());
                let at = rng.below(headers.len());
                headers[at].1 = String::from_utf8_lossy(&mutate(rng, headers[at].1.as_bytes())).into_owned();
            }
            1 => query = String::from_utf8_lossy(&mutate(rng, good_query.as_bytes())).into_owned(),
            _ => {
                headers.push(("authorization".into(), header_text(rng)));
                headers.push(("x-amz-date".into(), header_text(rng)));
                headers.push(("x-amz-content-sha256".into(), header_text(rng)));
                query = header_text(rng);
            }
        }
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let request = Request { method: "GET", path: "/b/k", query: &query, headers: &borrowed };
        if let Ok(Some(parsed)) = parse_request_auth(&request) {
            let _ = parsed.check_time(Timestamp::now());
            // Only a request that nobody damaged may pass. The access key is no part of what is signed, so a server finds the secret with it and the
            // signature has to be the one made for the same scope; the headers that are signed have to be what they were.
            if parsed.verify(&request, "secret", Timestamp::now()).is_ok() {
                let same_signature = parsed.signature == good_header.signature || good_query.contains(&format!("X-Amz-Signature={}", parsed.signature));
                assert!(same_signature && parsed.scope == good_header.scope, "damaged request accepted: query {query:?} headers {headers:?}");
                if parsed.kind == thirtys3_core::AuthKind::Header {
                    let others = |list: &[(String, String)]| -> Vec<(String, String)> {
                        list.iter().filter(|(name, _)| name != "authorization").map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned())).collect()
                    };
                    let mut original: Vec<(String, String)> = host.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
                    original.extend(good_header.headers.iter().cloned());
                    assert_eq!(others(&headers), others(&original));
                }
            }
        }
        let _ = PayloadHash::parse(&header_text(rng));
    });
}

#[test]
fn the_small_parsers_take_any_text() {
    fuzz("small parsers", 4, |rng, _| {
        let value = if rng.below(2) == 0 { header_text(rng) } else { text(rng) };
        if let Some(condition) = ETagCondition::parse(&value) {
            let _ = condition.matches(&text(rng), rng.below(2) == 0);
        }
        let _ = Timestamp::parse_amz_date(&value);
        let _ = Timestamp::parse_iso8601(&value);
        let _ = Timestamp::parse_http_date(&value);
        for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Crc64Nvme, ChecksumAlgorithm::Sha256, ChecksumAlgorithm::Md5] {
            let _ = algorithm.decode_value(&value);
        }
        let _ = ChecksumAlgorithm::from_header_name(&value);
        let _ = ChecksumAlgorithm::from_xml_element(&value);
        let _ = base64_decode(&value);
        let _ = hex_decode(&value);
        let _ = canonical_uri(&value);
        let _ = canonical_query(&value, |_| false);
        let _ = query_params(&value);
        let _ = percent_decode(&value, true);
        let _ = percent_decode(&value, false);
    });
}

#[test]
fn encodings_come_back_as_they_went() {
    fuzz("encodings", 5, |rng, _| {
        let length = rng.below(64);
        let data = rng.bytes(length);
        assert_eq!(base64_decode(&base64_encode(&data)).as_deref(), Some(data.as_slice()));
        assert_eq!(hex_decode(&hex_encode(&data)).as_deref(), Some(data.as_slice()));
        for slash in [true, false] {
            let encoded = uri_encode(&data, slash);
            assert!(encoded.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.~%".contains(&byte) || (!slash && byte == b'/')), "{encoded}");
            assert_eq!(percent_decode(&encoded, false), data);
        }
    });
}

#[test]
fn a_timestamp_comes_back_in_each_of_its_forms() {
    fuzz("timestamps", 6, |rng, _| {
        // From 1970 to 9999: the range every form can write.
        let time = Timestamp((rng.next() % 253_402_300_800) as i64);
        assert_eq!(Timestamp::parse_amz_date(&time.amz_date()), Some(time));
        assert_eq!(Timestamp::parse_iso8601(&time.iso8601()), Some(time));
        assert_eq!(Timestamp::parse_http_date(&time.http_date()), Some(time));
    });
}
