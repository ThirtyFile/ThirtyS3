//! Signs random requests with `Signer` and with AWS's own `aws-sigv4` crate (a dev-dependency only, never used at run time) and requires the
//! same result: the same `Authorization` header and headers added for a signature in the header, the same query parameters for a presigned URL.

use std::borrow::Cow;
use std::time::{Duration, UNIX_EPOCH};

use aws_credential_types::Credentials as AwsCredentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SessionTokenMode, SignableBody, SignableRequest, SignatureLocation, SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use thirtys3_core::encoding::{query_params, uri_encode};
use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, STREAMING_SIGNED_PAYLOAD, UNSIGNED_PAYLOAD};
use thirtys3_core::{Credentials, Request, Signer, Timestamp, sha256_hex};

/// xorshift64*: a few lines of random numbers that do not change between runs, so a failure can be reproduced from the seed in the message.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
    /// Text from a pool of characters that are awkward to encode.
    fn text(&mut self, max_len: usize, pool: &[&str]) -> String {
        (0..self.below(max_len + 1)).map(|_| *self.pick(pool)).collect()
    }
}

const KEY_CHARS: &[&str] = &[
    "a", "b", "Z", "0", "9", "-", ".", "_", "~", " ", "+", "%", "!", "*", "'", "(", ")", ";", ":", "@", "&", "=", ",", "$", "#", "?", "[", "]", "/", "//", "./",
    "../", "é", "中", "😀", "\t", "\u{7f}",
];
const NAME_CHARS: &[&str] = &["a", "b", "k", "X", "1", "-", "_", ".", " ", "+", "/", "é", "&", "="];
const REGIONS: &[&str] = &["us-east-1", "eu-west-1", "ap-northeast-1", "auto", "us-gov-west-1", "cn-north-1"];
const METHODS: &[&str] = &["GET", "PUT", "POST", "DELETE", "HEAD"];
const UNSIGNED_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "expect",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "x-amzn-trace-id",
];

struct Sample {
    credentials: Credentials,
    region: &'static str,
    time: Timestamp,
    method: &'static str,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    payload: String,
}

fn sample(random: &mut Random) -> Sample {
    let session_token = (random.below(3) == 0).then(|| random.text(40, &["a", "B", "7", "+", "/", "="]));
    let credentials = Credentials {
        access_key_id: format!("AKIA{}", random.text(12, &["A", "Q", "7", "Z"])),
        secret_access_key: random.text(40, &["a", "B", "7", "+", "/", "K"]),
        session_token,
    };
    let key = random.text(30, KEY_CHARS);
    let bucket = random.text(8, &["a", "b", "-", "0"]);
    let query: Vec<String> = (0..random.below(5))
        .map(|_| {
            let name = uri_encode(random.text(8, NAME_CHARS).as_bytes(), true);
            if random.below(4) == 0 { name } else { format!("{name}={}", uri_encode(random.text(12, KEY_CHARS).as_bytes(), true)) }
        })
        .collect();
    let mut headers = vec![("Host".to_owned(), format!("{}.s3.example.com", random.text(6, &["h", "o", "1"])))];
    for _ in 0..random.below(5) {
        let name = random.pick(&[
            "Content-Type",
            "Range",
            "x-amz-meta-a",
            "X-Amz-Meta-B",
            "x-amz-acl",
            "If-Match",
            "Date",
            "User-Agent",
            "Expect",
            "Content-MD5",
            "Cache-Control",
        ]);
        let value = format!("{}{}", random.text(4, &[" ", "  "]), random.text(10, &["v", "a  l", " ", "\"q\"", "é", ",", "/", ";"]));
        headers.push(((*name).to_owned(), value.trim_end().to_owned()));
    }
    let payload = match random.below(4) {
        0 => EMPTY_PAYLOAD_SHA256.to_owned(),
        1 => UNSIGNED_PAYLOAD.to_owned(),
        2 => STREAMING_SIGNED_PAYLOAD.to_owned(),
        _ => sha256_hex(random.text(20, KEY_CHARS).as_bytes()),
    };
    Sample {
        credentials,
        region: random.pick(REGIONS),
        time: Timestamp(946_684_800 + (random.next() % 1_200_000_000) as i64),
        method: random.pick(METHODS),
        path: format!("/{bucket}/{}", uri_encode(key.as_bytes(), false)),
        query: query.join("&"),
        headers,
        payload,
    }
}

fn settings(location: SignatureLocation, expires: Option<Duration>) -> SigningSettings {
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.session_token_mode = SessionTokenMode::Include;
    settings.signature_location = location;
    settings.expires_in = expires;
    settings.excluded_headers = Some(UNSIGNED_HEADERS.iter().map(|name| Cow::Borrowed(*name)).collect());
    settings
}

/// What `aws-sigv4` returns for a request: the headers to add, the query parameters to add, and the signature.
type Signed = (Vec<(String, String)>, Vec<(String, String)>, String);

fn aws_sign(sample: &Sample, location: SignatureLocation, expires: Option<Duration>) -> Signed {
    let identity =
        AwsCredentials::new(&sample.credentials.access_key_id, &sample.credentials.secret_access_key, sample.credentials.session_token.clone(), None, "test").into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(sample.region)
        .name("s3")
        .time(UNIX_EPOCH + Duration::from_secs(sample.time.0 as u64))
        .settings(settings(location, expires))
        .build()
        .unwrap()
        .into();
    let uri = if sample.query.is_empty() { format!("https://example.com{}", sample.path) } else { format!("https://example.com{}?{}", sample.path, sample.query) };
    let body = match sample.payload.as_str() {
        UNSIGNED_PAYLOAD => SignableBody::UnsignedPayload,
        other => SignableBody::Precomputed(other.to_owned()),
    };
    let headers: Vec<(&str, &str)> = sample.headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let signable = SignableRequest::new(sample.method, uri, headers.into_iter(), body).unwrap();
    let (instructions, signature) = sign(signable, &params).unwrap().into_parts();
    let (headers, query) = instructions.into_parts();
    (
        headers.iter().map(|header| (header.name().to_ascii_lowercase(), header.value().to_owned())).collect(),
        query.iter().map(|(name, value)| ((*name).to_owned(), value.to_string())).collect(),
        signature,
    )
}

fn describe(seed: u64, round: usize, sample: &Sample) -> String {
    format!("seed {seed}, round {round}: {} {}?{} headers {:?} payload {}", sample.method, sample.path, sample.query, sample.headers, sample.payload)
}

#[test]
fn signatures_in_the_header_are_those_of_aws_sigv4() {
    for seed in 1..=3_u64 {
        let mut random = Random(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        for round in 0..5000 {
            let sample = sample(&mut random);
            let headers: Vec<(&str, &str)> = sample.headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
            let request = Request { method: sample.method, path: &sample.path, query: &sample.query, headers: &headers };
            let ours = Signer::new(sample.credentials.clone(), sample.region).sign(&request, &sample.payload, sample.time).unwrap();
            let (theirs, _, signature) = aws_sign(&sample, SignatureLocation::Headers, None);
            let context = describe(seed, round, &sample);

            assert_eq!(ours.signature, signature, "signature, {context}");
            let authorization = theirs.iter().find(|(name, _)| name == "authorization").map(|(_, value)| value.as_str()).unwrap();
            // AWS puts a space after the commas between the fields; the pages on S3 show them without. Both are the same header to S3.
            assert_eq!(ours.authorization, authorization.replace(", ", ","), "Authorization, {context}");
            // AWS adds the same headers that we ask the caller to add (it also adds x-amz-content-sha256 only when the checksum kind says so, as here).
            let mut ours_headers: Vec<(String, String)> = ours.headers.clone();
            let mut their_headers: Vec<(String, String)> =
                theirs.iter().map(|(name, value)| (name.clone(), if name == "authorization" { value.replace(", ", ",") } else { value.clone() })).collect();
            ours_headers.sort();
            their_headers.sort();
            assert_eq!(ours_headers, their_headers, "added headers, {context}");
        }
    }
}

#[test]
fn presigned_urls_are_those_of_aws_sigv4() {
    for seed in 1..=3_u64 {
        let mut random = Random(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
        for round in 0..5000 {
            let mut sample = sample(&mut random);
            sample.payload = UNSIGNED_PAYLOAD.to_owned();
            let expires = 1 + random.next() % 604_800;
            let headers: Vec<(&str, &str)> = sample.headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
            let request = Request { method: sample.method, path: &sample.path, query: &sample.query, headers: &headers };
            let ours = Signer::new(sample.credentials.clone(), sample.region).presign(&request, sample.time, expires).unwrap();
            let (_, theirs, signature) = aws_sign(&sample, SignatureLocation::QueryParams, Some(Duration::from_secs(expires)));
            let context = describe(seed, round, &sample);

            let signature_param = format!("X-Amz-Signature={signature}");
            assert!(ours.ends_with(&signature_param), "signature, {context}: {ours}");

            // The parameters added to the query: the same names and values (AWS lists the signature among them, we put it last).
            let given = query_params(&sample.query);
            let mut our_added: Vec<(String, String)> = query_params(&ours)
                .into_iter()
                .filter(|pair| !given.contains(pair) || pair.0.starts_with(b"X-Amz-"))
                .map(|(name, value)| (String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned()))
                .filter(|(name, _)| name.starts_with("X-Amz-"))
                .collect();
            let mut their_added: Vec<(String, String)> = theirs.into_iter().filter(|(name, _)| name.starts_with("X-Amz-")).collect();
            our_added.sort();
            their_added.sort();
            assert_eq!(our_added, their_added, "X-Amz parameters, {context}");
        }
    }
}
