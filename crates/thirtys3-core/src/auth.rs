//! Reading the authentication of an incoming request (the `Authorization` header or the query of a presigned URL) and checking it.
//!
//! Follows the Signature Version 4 pages named in [`crate::sigv4`]: the header format of "Create a signed AWS API request", the query
//! parameters of a presigned URL (`X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`,
//! `X-Amz-Security-Token`; one second to seven days), and a clock skew of 15 minutes.

use crate::chunk::ChunkChain;
use crate::encoding::query_params;
use crate::error::SigError;
use crate::sigv4::{
    ALGORITHM, MAX_CLOCK_SKEW, MAX_PRESIGNED_EXPIRES, Request, SERVICE, STREAMING_SIGNED_PAYLOAD, STREAMING_SIGNED_PAYLOAD_TRAILER,
    STREAMING_UNSIGNED_PAYLOAD_TRAILER, Scope, SigningKey, UNSIGNED_PAYLOAD, canonical_request, string_to_sign,
};
use crate::time::Timestamp;

/// What the `x-amz-content-sha256` header says about the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadHash {
    /// `UNSIGNED-PAYLOAD`: the body is not covered by the signature.
    Unsigned,
    /// The SHA-256 of the body, in lower-case hex. The server has to check the body against it.
    Sha256(String),
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: the body is `aws-chunked`, each chunk signed.
    StreamingSigned,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: `aws-chunked`, each chunk signed, with signed trailing headers.
    StreamingSignedTrailer,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: `aws-chunked` without chunk signatures, with trailing headers.
    StreamingUnsignedTrailer,
}

impl PayloadHash {
    /// Reads the value of `x-amz-content-sha256`. The values for Signature Version 4a (`STREAMING-AWS4-ECDSA-…`) are not supported.
    pub fn parse(value: &str) -> Result<Self, SigError> {
        match value {
            UNSIGNED_PAYLOAD => Ok(Self::Unsigned),
            STREAMING_SIGNED_PAYLOAD => Ok(Self::StreamingSigned),
            STREAMING_SIGNED_PAYLOAD_TRAILER => Ok(Self::StreamingSignedTrailer),
            STREAMING_UNSIGNED_PAYLOAD_TRAILER => Ok(Self::StreamingUnsignedTrailer),
            hash if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) => Ok(Self::Sha256(hash.to_ascii_lowercase())),
            other => Err(SigError::InvalidPayloadHash(other.chars().take(80).collect())),
        }
    }
}

/// Where the signature of a request was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// The `Authorization` header.
    Header,
    /// The query of a presigned URL.
    Query,
}

/// The authentication of a request, read but not yet checked. Look up the secret for [`access_key_id`](Self::access_key_id), then call
/// [`verify`](Self::verify).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuth {
    /// Whether the signature was in the header or in the query.
    pub kind: AuthKind,
    /// The access key ID the request was signed with.
    pub access_key_id: String,
    /// The credential scope, including the region the request was signed for.
    pub scope: Scope,
    /// The signed header names, lower-case, in the order of the signature.
    pub signed_headers: Vec<String>,
    /// The signature, lower-case hex.
    pub signature: String,
    /// The `x-amz-date` or `X-Amz-Date` value as sent.
    pub amz_date: String,
    /// The time in `amz_date`.
    pub time: Timestamp,
    /// `X-Amz-Expires` of a presigned URL, in seconds.
    pub expires_secs: Option<u64>,
    /// The session token of temporary credentials, from `x-amz-security-token` or `X-Amz-Security-Token`.
    pub session_token: Option<String>,
}

/// What a checked signature gives the server to go on with.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Whether the signature was in the header or in the query.
    pub kind: AuthKind,
    /// The access key ID of the request.
    pub access_key_id: String,
    /// The credential scope.
    pub scope: Scope,
    /// The `x-amz-date` or `X-Amz-Date` value as sent.
    pub amz_date: String,
    /// The signature of the request (the seed signature of a chunked body), lower-case hex.
    pub signature: String,
    /// The key the request was signed with.
    pub signing_key: SigningKey,
    /// What the request says about its body. For [`PayloadHash::Sha256`] the server must check the body against the hash.
    pub payload_hash: PayloadHash,
    /// The session token of temporary credentials, which the server has to check itself.
    pub session_token: Option<String>,
}

impl Verified {
    /// The chain for checking the chunk signatures of the body, when the body is signed `aws-chunked`.
    pub fn chunk_chain(&self) -> Option<ChunkChain> {
        match self.payload_hash {
            PayloadHash::StreamingSigned | PayloadHash::StreamingSignedTrailer => {
                Some(ChunkChain::new(self.signing_key.clone(), self.amz_date.clone(), self.scope.clone(), &self.signature))
            }
            _ => None,
        }
    }
}

fn header_value<'a>(request: &Request<'a>, name: &str) -> Option<&'a str> {
    request.headers.iter().find(|(candidate, _)| candidate.eq_ignore_ascii_case(name)).map(|(_, value)| *value)
}

fn parse_scope(credential_scope: &str) -> Result<Scope, SigError> {
    let malformed = |why: &str| SigError::MalformedAuthorization(format!("the credential scope {credential_scope:?} {why}"));
    let parts: Vec<&str> = credential_scope.split('/').collect();
    let [date, region, service, "aws4_request"] = parts[..] else { return Err(malformed("is not date/region/service/aws4_request")) };
    if date.len() != 8 || !date.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed("has a date that is not YYYYMMDD"));
    }
    if region.is_empty() || !region.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
        return Err(malformed("has an invalid region"));
    }
    if service != SERVICE {
        return Err(malformed("is for a service other than s3"));
    }
    Ok(Scope { date: date.to_owned(), region: region.to_owned(), service: service.to_owned() })
}

fn parse_credential(credential: &str, malformed: fn(String) -> SigError) -> Result<(String, Scope), SigError> {
    // The access key ID comes first, then the four parts of the scope. Splitting from the right leaves the key ID whole.
    let mut parts = credential.rsplitn(5, '/');
    let (Some(_), Some(_), Some(_), Some(_), Some(access_key_id)) = (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(malformed(format!("the credential {credential:?} is not access-key/date/region/service/aws4_request")));
    };
    if access_key_id.is_empty() {
        return Err(malformed("the credential has no access key ID".to_owned()));
    }
    let scope = parse_scope(&credential[access_key_id.len() + 1..]).map_err(|error| malformed(error.to_string()))?;
    Ok((access_key_id.to_owned(), scope))
}

fn parse_signed_headers(list: &str, malformed: fn(String) -> SigError) -> Result<Vec<String>, SigError> {
    let names: Vec<String> = list.split(';').map(str::to_ascii_lowercase).collect();
    if names.iter().any(|name| name.is_empty()) {
        return Err(malformed("the signed headers list has an empty name".to_owned()));
    }
    if !names.iter().any(|name| name == "host") {
        return Err(malformed("the host header is not among the signed headers".to_owned()));
    }
    Ok(names)
}

fn parse_signature(signature: &str, malformed: fn(String) -> SigError) -> Result<String, SigError> {
    if signature.len() == 64 && signature.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(signature.to_ascii_lowercase())
    } else {
        Err(malformed("the signature is not 64 hex digits".to_owned()))
    }
}

fn parse_date(amz_date: &str, scope: &Scope) -> Result<Timestamp, SigError> {
    let time = Timestamp::parse_amz_date(amz_date).ok_or_else(|| SigError::InvalidDate(amz_date.chars().take(40).collect()))?;
    if !amz_date.starts_with(&scope.date) {
        return Err(SigError::InvalidDate(format!("{amz_date} is not on the day of the credential scope {}", scope.date)));
    }
    Ok(time)
}

/// The time of a request signed in the header: `x-amz-date`, or when the request has none the `Date` header, which Signature Version 4 allows as
/// the other source of the time. A malformed `x-amz-date` is an error, not a reason to look at `Date`. With `Date` the time in the string to sign is
/// that time as `YYYYMMDDTHHMMSSZ`. Returns that text and the time.
fn header_date(request: &Request<'_>, scope: &Scope) -> Result<(String, Timestamp), SigError> {
    if let Some(amz_date) = header_value(request, "x-amz-date") {
        return Ok((amz_date.to_owned(), parse_date(amz_date, scope)?));
    }
    let date = header_value(request, "date").ok_or_else(|| SigError::MissingHeader("x-amz-date".to_owned()))?;
    let time = Timestamp::parse_http_date(date).ok_or_else(|| SigError::InvalidDate(date.chars().take(40).collect()))?;
    let amz_date = time.amz_date();
    Ok((amz_date.clone(), parse_date(&amz_date, scope)?))
}

fn parse_header_auth(request: &Request<'_>, value: &str) -> Result<ParsedAuth, SigError> {
    let malformed = SigError::MalformedAuthorization;
    let Some(rest) = value.strip_prefix(ALGORITHM).filter(|rest| rest.starts_with(char::is_whitespace)) else {
        return Err(SigError::UnsupportedAlgorithm(value.split_whitespace().next().unwrap_or_default().chars().take(40).collect()));
    };
    let (mut credential, mut signed_headers, mut signature) = (None, None, None);
    for field in rest.split(',') {
        let (name, field_value) = field.trim().split_once('=').ok_or_else(|| malformed(format!("{:?} is not name=value", field.trim())))?;
        let slot = match name {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed_headers,
            "Signature" => &mut signature,
            other => return Err(malformed(format!("unknown field {other:?}"))),
        };
        if slot.replace(field_value).is_some() {
            return Err(malformed(format!("{name} appears twice")));
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) = (credential, signed_headers, signature) else {
        return Err(malformed("Credential, SignedHeaders and Signature are all required".to_owned()));
    };
    let (access_key_id, scope) = parse_credential(credential, malformed)?;
    let (amz_date, time) = header_date(request, &scope)?;
    Ok(ParsedAuth {
        kind: AuthKind::Header,
        access_key_id,
        time,
        scope,
        signed_headers: parse_signed_headers(signed_headers, malformed)?,
        signature: parse_signature(signature, malformed)?,
        amz_date,
        expires_secs: None,
        session_token: header_value(request, "x-amz-security-token").map(str::to_owned),
    })
}

fn parse_query_auth(query: &str) -> Result<ParsedAuth, SigError> {
    let malformed = SigError::MalformedQuery;
    let params: Vec<(String, String)> =
        query_params(query).into_iter().map(|(name, value)| (String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned())).collect();
    let get = |name: &str| -> Result<Option<&str>, SigError> {
        let mut found = params.iter().filter(|(candidate, _)| candidate == name);
        let first = found.next().map(|(_, value)| value.as_str());
        if found.next().is_some() {
            return Err(malformed(format!("{name} appears twice")));
        }
        Ok(first)
    };
    let require = |name: &str| get(name)?.ok_or_else(|| malformed(format!("{name} is missing")));

    let algorithm = require("X-Amz-Algorithm")?;
    if algorithm != ALGORITHM {
        return Err(SigError::UnsupportedAlgorithm(algorithm.chars().take(40).collect()));
    }
    let (access_key_id, scope) = parse_credential(require("X-Amz-Credential")?, malformed)?;
    let amz_date = require("X-Amz-Date")?;
    let expires = require("X-Amz-Expires")?;
    let expires_secs = expires
        .parse::<u64>()
        .ok()
        .filter(|secs| (1..=MAX_PRESIGNED_EXPIRES).contains(secs))
        .ok_or_else(|| SigError::InvalidExpires(expires.chars().take(40).collect()))?;
    Ok(ParsedAuth {
        kind: AuthKind::Query,
        access_key_id,
        time: parse_date(amz_date, &scope)?,
        scope,
        signed_headers: parse_signed_headers(require("X-Amz-SignedHeaders")?, malformed)?,
        signature: parse_signature(require("X-Amz-Signature")?, malformed)?,
        amz_date: amz_date.to_owned(),
        expires_secs: Some(expires_secs),
        session_token: get("X-Amz-Security-Token")?.map(str::to_owned),
    })
}

/// Reads the authentication of a request. `Ok(None)` is an anonymous request: no `Authorization` header and no `X-Amz-Algorithm` in the query.
pub fn parse_request_auth(request: &Request<'_>) -> Result<Option<ParsedAuth>, SigError> {
    let mut headers = request.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let authorization = headers.next().map(|(_, value)| *value);
    if headers.next().is_some() {
        return Err(SigError::MalformedAuthorization("there is more than one Authorization header".to_owned()));
    }
    let in_query = query_params(request.query).iter().any(|(name, _)| name == b"X-Amz-Algorithm");
    match (authorization, in_query) {
        (Some(_), true) => Err(SigError::ConflictingAuthentication),
        (Some(value), false) => parse_header_auth(request, value).map(Some),
        (None, true) => parse_query_auth(request.query).map(Some),
        (None, false) => Ok(None),
    }
}

impl ParsedAuth {
    /// Checks the time of the request against `now`: a header signature is good when the date is within 15 minutes of `now`; a presigned URL
    /// from 15 minutes before its date until its expiry. It does not look at the signature, so a server can refuse a request whose clock is out
    /// of step before it counts as an attempt to guess a key.
    pub fn check_time(&self, now: Timestamp) -> Result<(), SigError> {
        let skewed = SigError::RequestTimeTooSkewed { request_time: self.time, server_time: now };
        match self.expires_secs {
            None if (now.0 - self.time.0).abs() > MAX_CLOCK_SKEW => Err(skewed),
            Some(_) if self.time.0 - now.0 > MAX_CLOCK_SKEW => Err(skewed),
            Some(expires) if now.0 > self.time.0 + expires as i64 => Err(SigError::Expired(Timestamp(self.time.0 + expires as i64))),
            _ => Ok(()),
        }
    }

    /// Checks the time and the signature of `request` against the secret of [`access_key_id`](Self::access_key_id).
    ///
    /// - The time, as [`check_time`](Self::check_time) does.
    /// - A header signature must cover every `x-amz-*` header of the request.
    /// - The signature is compared in constant time.
    ///
    /// The scope's region is not checked here: [`scope`](Self::scope) has it for the server to compare with its own.
    pub fn verify(&self, request: &Request<'_>, secret_access_key: &str, now: Timestamp) -> Result<Verified, SigError> {
        self.check_time(now)?;

        let payload_header = header_value(request, "x-amz-content-sha256");
        let payload_text = match (self.kind, payload_header) {
            (AuthKind::Header, None) => return Err(SigError::MissingHeader("x-amz-content-sha256".to_owned())),
            (AuthKind::Query, None) => UNSIGNED_PAYLOAD,
            (_, Some(value)) => value,
        };
        let payload_hash = PayloadHash::parse(payload_text)?;

        if self.kind == AuthKind::Header {
            let mut unsigned: Vec<String> = request
                .headers
                .iter()
                .map(|(name, _)| name.to_ascii_lowercase())
                .filter(|name| name.starts_with("x-amz-") && !self.signed_headers.contains(name))
                .collect();
            unsigned.sort();
            unsigned.dedup();
            if !unsigned.is_empty() {
                return Err(SigError::HeadersNotSigned(unsigned));
            }
        }

        let canonical = canonical_request(request, &self.signed_headers, payload_text, self.kind == AuthKind::Query)?;
        let signing_key = SigningKey::derive(secret_access_key, &self.scope);
        if !signing_key.verify_hex(string_to_sign(&self.amz_date, &self.scope, &canonical).as_bytes(), &self.signature) {
            return Err(SigError::SignatureDoesNotMatch);
        }
        Ok(Verified {
            kind: self.kind,
            access_key_id: self.access_key_id.clone(),
            scope: self.scope.clone(),
            amz_date: self.amz_date.clone(),
            signature: self.signature.clone(),
            signing_key,
            payload_hash,
            session_token: self.session_token.clone(),
        })
    }
}
