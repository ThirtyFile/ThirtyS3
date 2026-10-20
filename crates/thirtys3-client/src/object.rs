//! Single objects: `put`, `get`, `head`, `delete` and `delete_many`.

use bytes::Bytes;
use http::{HeaderValue, Method};
use thirtys3_core::S3Error;
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_encode};
use thirtys3_core::etag::md5_digest;
use thirtys3_core::model::{Checksums, DeleteObjectId, DeleteRequest, DeleteResult};
use thirtys3_core::xml::XmlError;

use crate::body::GetBody;
use crate::client::{Client, Spec};
use crate::error::Error;
use crate::meta::{GetRange, ObjectMeta, from_headers};

/// The most keys `DeleteObjects` takes.
const DELETE_BATCH: usize = 1000;
/// The longest answer of `DeleteObjects` that is read: a failure for each of 1000 keys of 1024 bytes, with room to spare.
const DELETE_ANSWER_LIMIT: usize = 4 * 1024 * 1024;

/// What to store with an object, and the conditions for storing it.
#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// The `Content-Type`.
    pub content_type: Option<String>,
    /// The `Cache-Control`.
    pub cache_control: Option<String>,
    /// The `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// The `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// The `Content-Language`.
    pub content_language: Option<String>,
    /// The user metadata as `(name, value)`; each becomes a header `x-amz-meta-{name}`. Names and values have to be plain ASCII text.
    pub metadata: Vec<(String, String)>,
    /// The storage class, such as `STANDARD_IA`.
    pub storage_class: Option<String>,
    /// A checksum of the data to compute and send for the service to verify (and keep). For a multipart upload a checksum of each part.
    pub checksum: Option<ChecksumAlgorithm>,
    /// Store only if there is no object with this key: the call fails with [`ErrorKind::PreconditionFailed`](crate::ErrorKind::PreconditionFailed)
    /// if there is one. (`If-None-Match: *`)
    pub if_none_match: bool,
    /// Store only if the object that is there has this ETag, to replace the version that was read and nothing else. (`If-Match`)
    pub if_match: Option<String>,
}

impl PutOptions {
    /// The headers these options mean. A value that cannot be a header value is an error.
    pub(crate) fn headers(&self) -> Result<Vec<(String, String)>, Error> {
        let mut headers = Vec::new();
        let mut add = |name: &str, value: &Option<String>| -> Result<(), Error> {
            if let Some(value) = value {
                header_value(name, value)?;
                headers.push((name.to_owned(), value.clone()));
            }
            Ok(())
        };
        add("content-type", &self.content_type)?;
        add("cache-control", &self.cache_control)?;
        add("content-disposition", &self.content_disposition)?;
        add("content-encoding", &self.content_encoding)?;
        add("content-language", &self.content_language)?;
        add("x-amz-storage-class", &self.storage_class)?;
        add("if-match", &self.if_match)?;
        if self.if_none_match {
            headers.push(("if-none-match".to_owned(), "*".to_owned()));
        }
        for (name, value) in &self.metadata {
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
                return Err(Error::InvalidInput(format!("{name:?} cannot be the name of user metadata: letters, digits, '-', '_' and '.' only")));
            }
            if !value.is_ascii() {
                return Err(Error::InvalidInput(format!("the user metadata {name:?} has a value that is not ASCII")));
            }
            header_value(name, value)?;
            headers.push((format!("x-amz-meta-{}", name.to_ascii_lowercase()), value.clone()));
        }
        Ok(headers)
    }
}

fn header_value(name: &str, value: &str) -> Result<(), Error> {
    HeaderValue::from_str(value).map(|_| ()).map_err(|_| Error::InvalidInput(format!("the value for {name} cannot be used in a header")))
}

/// What the service says about an object it stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PutResult {
    /// The ETag, in double quotes.
    pub etag: Option<String>,
    /// The version, in a bucket with versioning.
    pub version_id: Option<String>,
    /// The checksums the service reports for the object.
    pub checksums: Checksums,
}

impl PutResult {
    pub(crate) fn from_headers(headers: &http::HeaderMap) -> Self {
        let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).map(|value| value.trim().to_owned());
        let mut checksums = Checksums::default();
        for algorithm in ChecksumAlgorithm::ALL {
            if let Some(value) = text(algorithm.header_name()) {
                checksums.set(algorithm, value);
            }
        }
        Self { etag: text("etag"), version_id: text("x-amz-version-id"), checksums }
    }
}

/// Which part of an object to download, and the conditions.
#[derive(Debug, Clone, Default)]
pub struct GetOptions {
    /// The bytes to get; the whole object if none.
    pub range: Option<GetRange>,
    /// Get only if the ETag is this; otherwise [`ErrorKind::PreconditionFailed`](crate::ErrorKind::PreconditionFailed).
    pub if_match: Option<String>,
    /// Get only if the ETag is not this; otherwise [`ErrorKind::NotModified`](crate::ErrorKind::NotModified).
    pub if_none_match: Option<String>,
}

/// An object being downloaded.
#[derive(Debug)]
pub struct GetResult {
    /// What is known about the object. `meta.size` is the size of the whole object, also when only a range of it is downloaded.
    pub meta: ObjectMeta,
    /// The bytes of the object that the body has.
    pub range: std::ops::Range<u64>,
    /// The bytes.
    pub body: GetBody,
}

impl Client {
    /// Stores an object in one request, which is for objects up to some tens of MiB (use [`put_multipart`](Client::put_multipart) above that).
    /// The data is kept in memory, so a request that fails can be sent again.
    pub async fn put(&self, key: &str, data: Bytes, options: &PutOptions) -> Result<PutResult, Error> {
        let mut spec = Spec::new(Method::PUT, self.object_path(key)?).headers(options.headers()?).body(data.clone());
        if let Some(algorithm) = options.checksum {
            spec = spec.header(algorithm.header_name(), algorithm.checksum_base64(&data));
        }
        let parts = self.execute_ignoring_body(&spec).await?;
        Ok(PutResult::from_headers(&parts.headers))
    }

    /// Downloads an object or a part of it. The bytes arrive as a stream that resumes by itself if the connection breaks (see [`GetBody`]).
    pub async fn get(&self, key: &str, options: &GetOptions) -> Result<GetResult, Error> {
        let path = self.object_path(key)?;
        let mut spec = Spec::new(Method::GET, path.clone());
        if let Some(range) = &options.range {
            spec = spec.header("range", range.header()?);
        }
        if let Some(etag) = &options.if_match {
            spec = spec.header("if-match", etag.clone());
        }
        if let Some(etag) = &options.if_none_match {
            spec = spec.header("if-none-match", etag.clone());
        }
        let (parts, body) = self.execute(&spec).await?.into_parts();
        let partial = parts.status.as_u16() == 206;
        let (meta, covered) = from_headers(key, &parts.headers, partial)?;
        if let (Some(range), false) = (&options.range, partial) {
            // A service that does not do ranges answers 200 with the whole object, which is only right if the range was the whole object.
            let whole = match range {
                GetRange::Bounded(range) => range.start == 0 && range.end >= meta.size,
                GetRange::From(start) => *start == 0,
                GetRange::Suffix(length) => *length >= meta.size,
            };
            if !whole {
                return Err(Error::Protocol("the service did not honour the Range header".to_owned()));
            }
        }
        let body = GetBody::new(self.clone(), key.to_owned(), path, meta.etag.clone(), covered.clone(), body);
        Ok(GetResult { meta, range: covered, body })
    }

    /// What is known about an object, without its data. [`Error::is_not_found`] is true when there is no such object.
    pub async fn head(&self, key: &str) -> Result<ObjectMeta, Error> {
        let spec = Spec::new(Method::HEAD, self.object_path(key)?);
        let (parts, _) = self.execute(&spec).await?.into_parts();
        Ok(from_headers(key, &parts.headers, false)?.0)
    }

    /// Deletes an object. Deleting what is not there is not an error: the object is gone either way.
    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        let spec = Spec::new(Method::DELETE, self.object_path(key)?);
        match self.execute(&spec).await {
            Ok(_) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Deletes objects, up to 1000 in one request when `bulk_delete` is on and one by one when it is off. Returns the keys that could not be
    /// deleted, with the reason. A key that is not there counts as deleted. `Err` is for a failure of the call as a whole.
    pub async fn delete_many(&self, keys: &[String]) -> Result<Vec<(String, Error)>, Error> {
        let mut failed = Vec::new();
        for key in keys {
            self.object_path(key)?;
        }
        if !self.inner.bulk_delete {
            for key in keys {
                if let Err(error) = self.delete(key).await {
                    failed.push((key.clone(), error));
                }
            }
            return Ok(failed);
        }
        for batch in keys.chunks(DELETE_BATCH) {
            let request = DeleteRequest { objects: batch.iter().map(DeleteObjectId::new).collect(), quiet: true };
            let body = Bytes::from(request.to_xml());
            let spec = Spec::new(Method::POST, self.bucket_path())
                .query(&[("delete", "")])
                .header("content-type", "application/xml")
                .header("content-md5", base64_encode(&md5_digest(&body)))
                .body(body);
            let (_, answer) = self.execute_for_body(&spec, DELETE_ANSWER_LIMIT).await?;
            let result = match DeleteResult::from_xml(&answer) {
                Ok(result) => result,
                // S3 can start the answer with 200 and then fail.
                Err(XmlError::WrongRoot { .. }) => return Err(Error::Service(Box::new(error_in_ok_body(&answer)?))),
                Err(error) => return Err(error.into()),
            };
            for failure in result.errors {
                if failure.code == "NoSuchKey" {
                    continue;
                }
                let mut error = S3Error::new(failure.code, failure.message);
                error.resource = Some(failure.key.clone());
                failed.push((failure.key, Error::Service(Box::new(error))));
            }
        }
        Ok(failed)
    }
}

/// The S3 error in the body of an answer that has the status 200. Its status is the one the code has in the table of error codes.
pub(crate) fn error_in_ok_body(body: &[u8]) -> Result<S3Error, Error> {
    let mut error = S3Error::from_xml(body, 200)?;
    error.status = thirtys3_core::s3_error::status_of(&error.code).unwrap_or(500);
    Ok(error)
}
