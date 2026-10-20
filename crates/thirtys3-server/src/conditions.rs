//! Conditional requests and byte ranges.
//!
//! Follows "Add preconditions to S3 operations with conditional requests"
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html>) and the `Range`, `If-Match`, `If-None-Match`,
//! `If-Modified-Since` and `If-Unmodified-Since` headers of `GetObject` (<https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html>),
//! with the order of evaluation of RFC 9110, section 13.2.2: `If-Match` before `If-Unmodified-Since`, `If-None-Match` before
//! `If-Modified-Since`, and the second of each pair only when the first is not there.

use std::ops::Range;

use http::HeaderMap;
use thirtys3_core::etag::ETagCondition;
use thirtys3_core::s3_error::code;
use thirtys3_core::{S3Error, Timestamp};

/// What the conditions of a request say about the object they are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Go on.
    Proceed,
    /// The object has not changed from what the client has: answer `304 Not Modified` without a body.
    NotModified,
    /// The object is not what the client expected: `412 PreconditionFailed`.
    PreconditionFailed,
}

/// The conditions in the headers of a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conditions {
    /// `If-Match`: the object has to have one of these ETags.
    pub if_match: Option<ETagCondition>,
    /// `If-None-Match`: the object must not have any of these ETags.
    pub if_none_match: Option<ETagCondition>,
    /// `If-Modified-Since`.
    pub if_modified_since: Option<Timestamp>,
    /// `If-Unmodified-Since`.
    pub if_unmodified_since: Option<Timestamp>,
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// A header with ETags. One that cannot be read matches nothing, so `If-Match` with it fails and `If-None-Match` with it holds.
fn etags(headers: &HeaderMap, name: &str) -> Option<ETagCondition> {
    text(headers, name).map(|value| ETagCondition::parse(value).unwrap_or(ETagCondition::Tags(Vec::new())))
}

impl Conditions {
    /// The conditions of a request: `If-Match` and the others, or for the source of a copy `x-amz-copy-source-if-match` and the others. A date
    /// that cannot be read is left out, as S3 does.
    pub fn from_headers(headers: &HeaderMap, copy_source: bool) -> Self {
        let (matching, none_matching, modified_since, unmodified_since) = if copy_source {
            ("x-amz-copy-source-if-match", "x-amz-copy-source-if-none-match", "x-amz-copy-source-if-modified-since", "x-amz-copy-source-if-unmodified-since")
        } else {
            ("if-match", "if-none-match", "if-modified-since", "if-unmodified-since")
        };
        Self {
            if_match: etags(headers, matching),
            if_none_match: etags(headers, none_matching),
            if_modified_since: text(headers, modified_since).and_then(Timestamp::parse_http_date),
            if_unmodified_since: text(headers, unmodified_since).and_then(Timestamp::parse_http_date),
        }
    }

    /// Whether there is any condition.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Evaluates the conditions of a `GET` or `HEAD` against the object's ETag (in quotes or not) and modification time.
    pub fn evaluate(&self, etag: &str, modified: Timestamp) -> Outcome {
        if let Some(condition) = &self.if_match {
            if !condition.matches(etag, true) {
                return Outcome::PreconditionFailed;
            }
        } else if let Some(date) = self.if_unmodified_since
            && modified.0 > date.0
        {
            return Outcome::PreconditionFailed;
        }
        if let Some(condition) = &self.if_none_match {
            if condition.matches(etag, false) {
                return Outcome::NotModified;
            }
        } else if let Some(date) = self.if_modified_since
            && modified.0 <= date.0
        {
            return Outcome::NotModified;
        }
        Outcome::Proceed
    }

    /// Evaluates the conditions on the source of a copy: those that would be `304` for a `GET` are a failed condition here, as S3 answers.
    pub fn evaluate_copy(&self, etag: &str, modified: Timestamp) -> Result<(), S3Error> {
        match self.evaluate(etag, modified) {
            Outcome::Proceed => Ok(()),
            Outcome::NotModified | Outcome::PreconditionFailed => {
                Err(S3Error::new(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold"))
            }
        }
    }
}

/// The bytes a `Range` header asks for, before the size of the object is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSpec {
    /// `bytes=first-last`, both included.
    Bounded(u64, u64),
    /// `bytes=first-`: to the end.
    From(u64),
    /// `bytes=-length`: the last bytes.
    Suffix(u64),
}

/// Reads a `Range` header. `None` for a value that is not a single `bytes` range: S3 does not do several ranges, and answers a request with a
/// `Range` it cannot read with the whole object.
pub fn parse_range(value: &str) -> Option<RangeSpec> {
    let spec = value.trim().strip_prefix("bytes=")?.trim();
    if spec.contains(',') {
        return None;
    }
    let (first, last) = spec.split_once('-')?;
    let (first, last) = (first.trim(), last.trim());
    let number = |text: &str| (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())).then(|| text.parse::<u64>().ok()).flatten();
    match (first.is_empty(), last.is_empty()) {
        (true, false) => Some(RangeSpec::Suffix(number(last)?)),
        (false, true) => Some(RangeSpec::From(number(first)?)),
        (false, false) => {
            let (first, last) = (number(first)?, number(last)?);
            (first <= last).then_some(RangeSpec::Bounded(first, last))
        }
        (true, true) => None,
    }
}

impl RangeSpec {
    /// The bytes of an object of `size` bytes that this asks for. `416 InvalidRange` if there are none: a start beyond the end, a suffix of 0
    /// bytes, any range of an object with no bytes.
    pub fn resolve(self, size: u64) -> Result<Range<u64>, S3Error> {
        let range = match self {
            Self::Bounded(first, last) if first < size => Some(first..last.saturating_add(1).min(size)),
            Self::From(first) if first < size => Some(first..size),
            Self::Suffix(length) if length > 0 && size > 0 => Some(size.saturating_sub(length)..size),
            _ => None,
        };
        range.ok_or_else(|| S3Error::new(code::INVALID_RANGE, "The requested range is not satisfiable").with_detail("ActualObjectSize", size.to_string()))
    }
}
