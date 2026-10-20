//! Object metadata as headers carry it, and the ranges of a download.

use std::collections::BTreeMap;
use std::ops::Range;

use http::HeaderMap;
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::model::Checksums;
use thirtys3_core::{S3Error, Timestamp};

use crate::error::Error;

/// What is known about an object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectMeta {
    /// The key.
    pub key: String,
    /// The size in bytes.
    pub size: u64,
    /// When the object was last modified.
    pub last_modified: Option<Timestamp>,
    /// The ETag, in double quotes as S3 sends it.
    pub etag: Option<String>,
    /// The content type.
    pub content_type: Option<String>,
    /// The `Content-Disposition`, such as the name a browser offers for the download. Only a `head` or a `get` has it.
    pub content_disposition: Option<String>,
    /// The `Content-Encoding`. Only a `head` or a `get` has it.
    pub content_encoding: Option<String>,
    /// The `Content-Language`. Only a `head` or a `get` has it.
    pub content_language: Option<String>,
    /// The `Cache-Control`. Only a `head` or a `get` has it.
    pub cache_control: Option<String>,
    /// The storage class. `None` is `STANDARD`, which is what S3 leaves out of a `head` and what a listing is made to agree with.
    pub storage_class: Option<String>,
    /// The version, in a bucket with versioning.
    pub version_id: Option<String>,
    /// The user metadata, `x-amz-meta-*` without the prefix and in lower case.
    pub metadata: BTreeMap<String, String>,
    /// The checksums the object has. For an object uploaded in parts the value of a composite checksum ends in `-` and the number of parts.
    pub checksums: Checksums,
}

/// Which bytes of an object to download.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetRange {
    /// From the first number to before the second: `3..7` is four bytes. It must not be empty.
    Bounded(Range<u64>),
    /// From this byte to the end.
    From(u64),
    /// The last this many bytes.
    Suffix(u64),
}

impl GetRange {
    /// The value of the `Range` header.
    pub(crate) fn header(&self) -> Result<String, Error> {
        match self {
            Self::Bounded(range) if range.start < range.end => Ok(format!("bytes={}-{}", range.start, range.end - 1)),
            Self::Bounded(range) => Err(Error::InvalidInput(format!("the range {}..{} has no bytes in it", range.start, range.end))),
            Self::From(start) => Ok(format!("bytes={start}-")),
            Self::Suffix(0) => Err(Error::InvalidInput("a suffix range of 0 bytes has no bytes in it".to_owned())),
            Self::Suffix(length) => Ok(format!("bytes=-{length}")),
        }
    }
}

impl From<Range<u64>> for GetRange {
    fn from(range: Range<u64>) -> Self {
        Self::Bounded(range)
    }
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Reads `bytes first-last/total` into the bytes covered and the size of the object.
pub(crate) fn parse_content_range(value: &str) -> Option<(Range<u64>, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let (first, last): (u64, u64) = (first.trim().parse().ok()?, last.trim().parse().ok()?);
    let total: u64 = total.trim().parse().ok()?;
    (first <= last && last < total).then_some((first..last + 1, total))
}

/// The metadata in the headers of a `HEAD` or `GET` response. For a response to a ranged request (`206`) the size comes from `Content-Range`.
/// Returns the metadata and the bytes the body has.
pub(crate) fn from_headers(key: &str, headers: &HeaderMap, partial: bool) -> Result<(ObjectMeta, Range<u64>), Error> {
    let content_length = text(headers, "content-length").and_then(|length| length.trim().parse::<u64>().ok());
    let (size, covered) = if partial {
        let (covered, total) = text(headers, "content-range")
            .and_then(parse_content_range)
            .ok_or_else(|| Error::Protocol("a partial response without a valid Content-Range".to_owned()))?;
        (total, covered)
    } else {
        let size = content_length.ok_or_else(|| Error::Protocol("a response without Content-Length".to_owned()))?;
        (size, 0..size)
    };
    let mut metadata = BTreeMap::new();
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-amz-meta-") {
            metadata.insert(name.to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned());
        }
    }
    let mut checksums = Checksums::default();
    for algorithm in ChecksumAlgorithm::ALL {
        if let Some(value) = text(headers, algorithm.header_name()) {
            checksums.set(algorithm, value.trim());
        }
    }
    let meta = ObjectMeta {
        key: key.to_owned(),
        size,
        last_modified: text(headers, "last-modified").and_then(Timestamp::parse_http_date),
        etag: text(headers, "etag").map(|etag| etag.trim().to_owned()),
        content_type: text(headers, "content-type").map(str::to_owned),
        content_disposition: text(headers, "content-disposition").map(str::to_owned),
        content_encoding: text(headers, "content-encoding").map(str::to_owned),
        content_language: text(headers, "content-language").map(str::to_owned),
        cache_control: text(headers, "cache-control").map(str::to_owned),
        storage_class: text(headers, "x-amz-storage-class").filter(|class| *class != "STANDARD").map(str::to_owned),
        version_id: text(headers, "x-amz-version-id").map(str::to_owned),
        metadata,
        checksums,
    };
    Ok((meta, covered))
}

/// The error for a response that has no body to say what is wrong: only the status is known.
pub(crate) fn error_for_status(status: u16, context: &str) -> S3Error {
    let (code, message) = match status {
        301 | 307 | 308 => ("PermanentRedirect", "The bucket is at another address (another region or endpoint)"),
        304 => ("NotModified", "The object has not been modified"),
        400 => ("BadRequest", "The service did not accept the request"),
        401 | 403 => ("AccessDenied", "Access denied"),
        404 => ("NotFound", "Not found"),
        405 => ("MethodNotAllowed", "The method is not allowed"),
        409 => ("Conflict", "Conflict"),
        411 => ("MissingContentLength", "The request needs a Content-Length"),
        412 => ("PreconditionFailed", "A condition of the request did not hold"),
        416 => ("InvalidRange", "The requested range is not satisfiable"),
        501 => ("NotImplemented", "The service does not do this"),
        503 => ("ServiceUnavailable", "The service is unavailable"),
        500..=599 => ("InternalError", "The service failed"),
        _ => ("UnexpectedStatus", "The service answered with an unexpected status"),
    };
    let mut error = S3Error::new(code, format!("{message} ({context})"));
    error.status = status;
    error
}
