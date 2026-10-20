//! Signature Version 4 for Amazon S3: the canonical request, the string to sign, the signing key, and signing a request or a presigned URL.
//!
//! Follows "Create a signed AWS API request"
//! (<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>) and, for the parts that are specific to S3
//! (the `x-amz-content-sha256` header, `UNSIGNED-PAYLOAD`, presigned URLs, streaming payloads), the S3 pages that AWS has since removed from its
//! documentation and that are kept in the Internet Archive, such as
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html> and
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html>. The examples on those pages are the tests of this module.
//! Nothing cryptographic is written here: the HMAC and the hash come from the `hmac` and `sha2` crates.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::chunk::ChunkChain;
use crate::encoding::{canonical_query, canonical_uri, hex_decode, hex_encode, query_params, uri_encode};
use crate::error::SigError;
use crate::time::Timestamp;

/// The only signing algorithm: Signature Version 4 with HMAC-SHA-256.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The service in a credential scope.
pub const SERVICE: &str = "s3";
/// The value of `x-amz-content-sha256` when the payload is not signed.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// The value of `x-amz-content-sha256` for a body in signed `aws-chunked` chunks.
pub const STREAMING_SIGNED_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// The value of `x-amz-content-sha256` for a body in signed `aws-chunked` chunks followed by signed trailing headers.
pub const STREAMING_SIGNED_PAYLOAD_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// The value of `x-amz-content-sha256` for a body in unsigned `aws-chunked` chunks followed by trailing headers.
pub const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
/// The SHA-256 of nothing, in hex: the payload hash of a request without a body.
pub const EMPTY_PAYLOAD_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// The longest a presigned URL can be valid, in seconds (seven days).
pub const MAX_PRESIGNED_EXPIRES: u64 = 604_800;
/// How far the date of a request may be from the time of the server, in seconds (15 minutes, as S3).
pub const MAX_CLOCK_SKEW: i64 = 900;

type HmacSha256 = Hmac<Sha256>;

/// The SHA-256 of `data` in lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// Whether two byte strings are equal, in a time that depends on their length and not on where they differ. For secrets, such as a session token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// An access key and its secret, with the session token of temporary credentials when there is one. There is no `PartialEq`: comparing secrets is
/// for [`constant_time_eq`].
#[derive(Clone)]
pub struct Credentials {
    /// The access key ID.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
    /// The session token of temporary (STS) credentials.
    pub session_token: Option<String>,
}

impl Credentials {
    /// Long-term credentials, without a session token.
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self { access_key_id: access_key_id.into(), secret_access_key: secret_access_key.into(), session_token: None }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &self.session_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The credential scope, `YYYYMMDD/region/service/aws4_request`, which limits a signature to one day, one region and one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The date as `YYYYMMDD`.
    pub date: String,
    /// The region, such as `us-east-1`.
    pub region: String,
    /// The service, `s3`.
    pub service: String,
}

impl Scope {
    /// The scope of a request made at `time` in `region`.
    pub fn new(time: Timestamp, region: &str) -> Self {
        Self { date: time.date(), region: region.to_owned(), service: SERVICE.to_owned() }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}/aws4_request", self.date, self.region, self.service)
    }
}

/// The key a request is signed with, derived from the secret access key and the scope. It is valid for one scope.
#[derive(Clone)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// `HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(HMAC-SHA256("AWS4" + secret, date), region), service), "aws4_request")`.
    pub fn derive(secret_access_key: &str, scope: &Scope) -> Self {
        let date_key = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), scope.date.as_bytes());
        let region_key = hmac_sha256(&date_key, scope.region.as_bytes());
        let service_key = hmac_sha256(&region_key, scope.service.as_bytes());
        Self(hmac_sha256(&service_key, b"aws4_request"))
    }

    /// The signature of `data` as lower-case hex.
    pub fn sign_hex(&self, data: &[u8]) -> String {
        hex_encode(&hmac_sha256(&self.0, data))
    }

    /// Whether `signature_hex` is the signature of `data`. The comparison takes the same time wherever the two differ.
    pub fn verify_hex(&self, data: &[u8], signature_hex: &str) -> bool {
        let Some(signature) = hex_decode(signature_hex) else { return false };
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts a key of any length");
        mac.update(data);
        mac.verify_slice(&signature).is_ok()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

/// The parts of an HTTP request that a signature covers. Everything is as it is on the wire: the path and the query are still percent-encoded.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The method, such as `GET`.
    pub method: &'a str,
    /// The path, starting with `/`, without the query.
    pub path: &'a str,
    /// The query string, without the `?`.
    pub query: &'a str,
    /// The headers as `(name, value)`; the case of the names does not matter. A header that appears twice is two entries.
    pub headers: &'a [(&'a str, &'a str)],
}

/// The value of a header as it goes into the canonical request: values joined with `,`, each with surrounding spaces removed and
/// runs of spaces made one (only ASCII white space is taken for a space: a no-break space is a character of the value). `None` when the request has no such header.
fn canonical_header_value(headers: &[(&str, &str)], name: &str) -> Option<String> {
    let mut values = headers.iter().filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name)).map(|(_, value)| value).peekable();
    values.peek()?;
    let joined: Vec<String> = values.map(|value| value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")).collect();
    Some(joined.join(","))
}

/// Builds the canonical request:
/// `Method \n CanonicalUri \n CanonicalQueryString \n CanonicalHeaders \n SignedHeaders \n HashedPayload`.
///
/// `signed_headers` are lower-case names in the order they go into the request (sorted, when signing). `skip_signature_param` leaves
/// `X-Amz-Signature` out of the query, as a presigned URL requires.
pub fn canonical_request(request: &Request<'_>, signed_headers: &[String], payload_hash: &str, skip_signature_param: bool) -> Result<String, SigError> {
    let mut out = String::new();
    out.push_str(request.method);
    out.push('\n');
    out.push_str(&canonical_uri(request.path));
    out.push('\n');
    out.push_str(&canonical_query(request.query, |name| skip_signature_param && name.eq_ignore_ascii_case(b"X-Amz-Signature")));
    out.push('\n');
    for name in signed_headers {
        let value = canonical_header_value(request.headers, name).ok_or_else(|| SigError::SignedHeaderMissing(name.clone()))?;
        out.push_str(name);
        out.push(':');
        out.push_str(&value);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&signed_headers.join(";"));
    out.push('\n');
    out.push_str(payload_hash);
    Ok(out)
}

/// Builds the string to sign: `AWS4-HMAC-SHA256 \n Date \n Scope \n Hex(SHA256(CanonicalRequest))`.
pub fn string_to_sign(amz_date: &str, scope: &Scope, canonical_request: &str) -> String {
    format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", sha256_hex(canonical_request.as_bytes()))
}

/// Headers that proxies and load balancers change on the way, which are not signed (the list on the "Create a canonical request" page),
/// together with `authorization`, which is the signature itself, and `expect`.
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

/// The headers `sign` and `presign` add themselves; one the caller passes with the same name is dropped.
const SIGNER_HEADERS: &[&str] = &["x-amz-date", "x-amz-content-sha256", "x-amz-security-token"];

/// The outcome of signing a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// The value of the `Authorization` header.
    pub authorization: String,
    /// The signature in hex. It is the seed signature of an `aws-chunked` body.
    pub signature: String,
    /// The signed header names, sorted.
    pub signed_headers: Vec<String>,
    /// The scope the request was signed for.
    pub scope: Scope,
    /// The `x-amz-date` value.
    pub amz_date: String,
    /// The headers to add to the request: `x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token` when there is a token, and `authorization`.
    pub headers: Vec<(String, String)>,
}

/// Signs requests with one set of credentials for one region.
#[derive(Debug, Clone)]
pub struct Signer {
    credentials: Credentials,
    region: String,
}

impl Signer {
    /// A signer for `region`.
    pub fn new(credentials: Credentials, region: impl Into<String>) -> Self {
        Self { credentials, region: region.into() }
    }

    /// The headers to sign: the caller's, without the ones that proxies change or that this signer sets, lower-cased.
    fn headers_to_sign(request: &Request<'_>) -> Result<Vec<(String, String)>, SigError> {
        let headers: Vec<(String, String)> = request
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
            .filter(|(name, _)| !UNSIGNED_HEADERS.contains(&name.as_str()) && !SIGNER_HEADERS.contains(&name.as_str()))
            .collect();
        if !headers.iter().any(|(name, _)| name == "host") {
            return Err(SigError::MissingHeader("host".to_owned()));
        }
        Ok(headers)
    }

    /// Signs a request that carries its signature in the `Authorization` header.
    ///
    /// `payload_hash` is the SHA-256 of the body in hex (see [`sha256_hex`]), [`UNSIGNED_PAYLOAD`] or one of the streaming values, and becomes the
    /// `x-amz-content-sha256` header. `request.headers` must include `host`; every header in it other than the ones proxies change is signed.
    pub fn sign(&self, request: &Request<'_>, payload_hash: &str, time: Timestamp) -> Result<SignedRequest, SigError> {
        let amz_date = time.amz_date();
        let mut headers = Self::headers_to_sign(request)?;
        headers.push(("x-amz-date".to_owned(), amz_date.clone()));
        headers.push(("x-amz-content-sha256".to_owned(), payload_hash.to_owned()));
        if let Some(token) = &self.credentials.session_token {
            headers.push(("x-amz-security-token".to_owned(), token.clone()));
        }
        let mut signed_headers: Vec<String> = headers.iter().map(|(name, _)| name.clone()).collect();
        signed_headers.sort();
        signed_headers.dedup();

        let pairs: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let to_sign = Request { headers: &pairs, ..*request };
        let canonical = canonical_request(&to_sign, &signed_headers, payload_hash, false)?;
        let scope = Scope::new(time, &self.region);
        let signature = SigningKey::derive(&self.credentials.secret_access_key, &scope).sign_hex(string_to_sign(&amz_date, &scope, &canonical).as_bytes());

        let authorization =
            format!("{ALGORITHM} Credential={}/{scope},SignedHeaders={},Signature={signature}", self.credentials.access_key_id, signed_headers.join(";"));
        let mut added = vec![("x-amz-date".to_owned(), amz_date.clone()), ("x-amz-content-sha256".to_owned(), payload_hash.to_owned())];
        if let Some(token) = &self.credentials.session_token {
            added.push(("x-amz-security-token".to_owned(), token.clone()));
        }
        added.push(("authorization".to_owned(), authorization.clone()));
        Ok(SignedRequest { authorization, signature, signed_headers, scope, amz_date, headers: added })
    }

    /// The chain for signing the chunks of a body sent `aws-chunked`, after signing the request with a streaming payload hash.
    pub fn chunk_chain(&self, signed: &SignedRequest) -> ChunkChain {
        ChunkChain::new(SigningKey::derive(&self.credentials.secret_access_key, &signed.scope), signed.amz_date.clone(), signed.scope.clone(), &signed.signature)
    }

    /// Presigns a request: returns the query string (without `?`) to use in its URL, with the `X-Amz-*` parameters and `X-Amz-Signature`
    /// added to the query already in `request`. The payload is [`UNSIGNED_PAYLOAD`]. `expires_secs` is how long the URL is valid, 1 to 604800.
    /// `request.headers` must include `host`; they are signed, and whoever uses the URL must send the same values.
    pub fn presign(&self, request: &Request<'_>, time: Timestamp, expires_secs: u64) -> Result<String, SigError> {
        if !(1..=MAX_PRESIGNED_EXPIRES).contains(&expires_secs) {
            return Err(SigError::InvalidExpires(expires_secs.to_string()));
        }
        if query_params(request.query).iter().any(|(name, _)| name.to_ascii_lowercase().starts_with(b"x-amz-")) {
            return Err(SigError::MalformedQuery("the query to presign already has X-Amz-* parameters".to_owned()));
        }
        let headers = Self::headers_to_sign(request)?;
        let mut signed_headers: Vec<String> = headers.iter().map(|(name, _)| name.clone()).collect();
        signed_headers.sort();
        signed_headers.dedup();
        let scope = Scope::new(time, &self.region);
        let amz_date = time.amz_date();

        let mut query = request.query.to_owned();
        let mut add = |name: &str, value: &str| {
            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(name);
            query.push('=');
            query.push_str(&uri_encode(value.as_bytes(), true));
        };
        add("X-Amz-Algorithm", ALGORITHM);
        add("X-Amz-Credential", &format!("{}/{scope}", self.credentials.access_key_id));
        add("X-Amz-Date", &amz_date);
        add("X-Amz-Expires", &expires_secs.to_string());
        add("X-Amz-SignedHeaders", &signed_headers.join(";"));
        if let Some(token) = &self.credentials.session_token {
            add("X-Amz-Security-Token", token);
        }

        let pairs: Vec<(&str, &str)> = headers.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
        let to_sign = Request { query: &query, headers: &pairs, ..*request };
        let canonical = canonical_request(&to_sign, &signed_headers, UNSIGNED_PAYLOAD, true)?;
        let signature = SigningKey::derive(&self.credentials.secret_access_key, &scope).sign_hex(string_to_sign(&amz_date, &scope, &canonical).as_bytes());
        Ok(format!("{}&X-Amz-Signature={signature}", canonical_query(&query, |_| false)))
    }
}
