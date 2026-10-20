//! Multipart uploads: `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload` and `AbortMultipartUpload`, and `put_multipart`, which
//! does all of it for data that comes from a reader.
//!
//! See <https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html>.

use std::time::Instant;

use bytes::{Bytes, BytesMut};
use http::Method;
use thirtys3_core::checksum::{ChecksumAlgorithm, base64_encode};
use thirtys3_core::model::{CompleteMultipartUploadRequest, CompleteMultipartUploadResult, CompletedPart, InitiateMultipartUploadResult};
use thirtys3_core::xml::XmlError;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::task::JoinSet;

use crate::client::{Client, Spec};
use crate::error::Error;
use crate::object::{PutOptions, PutResult, error_in_ok_body};

/// The most parts an upload can have.
pub const MAX_PARTS: u32 = 10_000;
/// The longest answer of the multipart calls that is read.
const ANSWER_LIMIT: usize = 1024 * 1024;

/// A part that was uploaded, to be named when the upload is completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedPart {
    /// The number of the part, 1 to 10,000.
    pub part_number: u32,
    /// The ETag the service gave the part.
    pub etag: String,
    /// The checksum of the part as Base64, when the upload has a checksum algorithm.
    pub checksum: Option<String>,
}

/// A multipart upload that was started. Upload the parts with [`put_part`](Self::put_part), in any order and several at a time, and then
/// [`complete`](Self::complete) it; or [`abort`](Self::abort) it, because parts that are not completed or aborted stay in the bucket and are
/// charged for.
#[derive(Debug, Clone)]
pub struct MultipartUpload {
    client: Client,
    key: String,
    upload_id: String,
    checksum: Option<ChecksumAlgorithm>,
}

impl MultipartUpload {
    /// The ID of the upload.
    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    /// The key of the object being uploaded.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Uploads one part. All the parts but the last have to be at least 5 MiB. The numbers go from 1 to 10,000 and the parts are put together in
    /// the order of their numbers.
    pub async fn put_part(&self, part_number: u32, data: Bytes) -> Result<UploadedPart, Error> {
        if !(1..=MAX_PARTS).contains(&part_number) {
            return Err(Error::InvalidInput(format!("part numbers go from 1 to {MAX_PARTS}, not {part_number}")));
        }
        let number = part_number.to_string();
        let mut spec = Spec::new(Method::PUT, self.client.object_path(&self.key)?)
            .query(&[("partNumber", number.as_str()), ("uploadId", self.upload_id.as_str())])
            .body(data.clone());
        let checksum = self.checksum.map(|algorithm| (algorithm, algorithm.checksum_base64(&data)));
        if let Some((algorithm, value)) = &checksum {
            spec = spec.header(algorithm.header_name(), value.clone());
        }
        let parts = self.client.execute_ignoring_body(&spec).await?;
        let etag =
            parts.headers.get("etag").and_then(|etag| etag.to_str().ok()).ok_or_else(|| Error::Protocol("the answer to UploadPart has no ETag".to_owned()))?;
        Ok(UploadedPart { part_number, etag: etag.trim().to_owned(), checksum: checksum.map(|(_, value)| value) })
    }

    /// Puts the parts together into the object. The parts are named in the order of their numbers.
    ///
    /// The service can answer with the status 200 and then fail; that is an error here too, and one that is tried again when it is the kind that
    /// can pass (`InternalError`, `SlowDown`).
    pub async fn complete(&self, mut parts: Vec<UploadedPart>) -> Result<PutResult, Error> {
        parts.sort_by_key(|part| part.part_number);
        if parts.is_empty() {
            return Err(Error::InvalidInput("an upload needs at least one part".to_owned()));
        }
        let request = CompleteMultipartUploadRequest {
            parts: parts
                .iter()
                .map(|part| {
                    let mut completed = CompletedPart::new(part.part_number, part.etag.clone());
                    if let (Some(algorithm), Some(value)) = (self.checksum, &part.checksum) {
                        completed.checksums.set(algorithm, value.clone());
                    }
                    completed
                })
                .collect(),
        };
        let body = Bytes::from(request.to_xml());
        let spec = Spec::new(Method::POST, self.client.object_path(&self.key)?)
            .query(&[("uploadId", self.upload_id.as_str())])
            .header("content-type", "application/xml")
            .body(body);
        let inner = &self.client.inner;
        let started = Instant::now();
        let mut repeats = 0;
        loop {
            let (headers, answer) = self.client.execute_for_body(&spec, ANSWER_LIMIT).await?;
            match CompleteMultipartUploadResult::from_xml(&answer) {
                Ok(result) => {
                    let mut put = PutResult::from_headers(&headers.headers);
                    put.etag = Some(result.etag);
                    for (algorithm, value) in result.checksums.0 {
                        put.checksums.set(algorithm, value);
                    }
                    return Ok(put);
                }
                Err(XmlError::WrongRoot { .. }) => {
                    let error = Error::Service(Box::new(error_in_ok_body(&answer)?));
                    if !error.is_retryable() || repeats >= inner.max_retries || started.elapsed() >= inner.retry_timeout {
                        return Err(error);
                    }
                    tokio::time::sleep(inner.backoff.delay(repeats)).await;
                    repeats += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Throws away the upload and its parts. An upload that is not there any more counts as aborted.
    pub async fn abort(&self) -> Result<(), Error> {
        let spec = Spec::new(Method::DELETE, self.client.object_path(&self.key)?).query(&[("uploadId", self.upload_id.as_str())]);
        match self.client.execute(&spec).await {
            Ok(_) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Reads until `size` bytes are there or the reader ends.
async fn read_part<R: AsyncRead + Unpin>(reader: &mut R, size: usize) -> std::io::Result<Bytes> {
    let mut buffer = BytesMut::with_capacity(size);
    while buffer.len() < size {
        if reader.read_buf(&mut buffer).await? == 0 {
            break;
        }
    }
    Ok(buffer.freeze())
}

impl Client {
    /// Starts a multipart upload of an object.
    pub async fn create_multipart(&self, key: &str, options: &PutOptions) -> Result<MultipartUpload, Error> {
        if options.if_match.is_some() || options.if_none_match {
            // The conditions belong to the completing of the upload, which does not take them in every service; refusing is better than ignoring.
            return Err(Error::InvalidInput("if_match and if_none_match are for put; a multipart upload does not take them".to_owned()));
        }
        let mut spec = Spec::new(Method::POST, self.object_path(key)?).query(&[("uploads", "")]).headers(options.headers()?);
        if let Some(algorithm) = options.checksum {
            spec = spec.header("x-amz-checksum-algorithm", algorithm.name());
        }
        let (_, body) = self.execute_for_body(&spec, ANSWER_LIMIT).await?;
        let result = InitiateMultipartUploadResult::from_xml(&body)?;
        Ok(MultipartUpload { client: self.clone(), key: key.to_owned(), upload_id: result.upload_id, checksum: options.checksum })
    }

    /// Stores an object from a reader in parts of `part_size`, several at a time, and puts them together at the end. If anything fails the upload
    /// is aborted, so no parts are left in the bucket. At most 10,000 parts, which is 10,000 times `part_size`; a reader with more data than that
    /// fails (`part_size` has to be larger for it).
    ///
    /// Memory use is up to `multipart_concurrency + 1` parts.
    pub async fn put_multipart<R: AsyncRead + Unpin + Send>(&self, key: &str, mut reader: R, options: &PutOptions) -> Result<PutResult, Error> {
        let upload = self.create_multipart(key, options).await?;
        match self.upload_parts(&upload, &mut reader).await {
            Ok(parts) => match upload.complete(parts).await {
                Ok(result) => Ok(result),
                Err(error) => {
                    let _ = upload.abort().await;
                    Err(error)
                }
            },
            Err(error) => {
                let _ = upload.abort().await;
                Err(error)
            }
        }
    }

    async fn upload_parts<R: AsyncRead + Unpin + Send>(&self, upload: &MultipartUpload, reader: &mut R) -> Result<Vec<UploadedPart>, Error> {
        let part_size = self.inner.part_size;
        let mut tasks: JoinSet<Result<UploadedPart, Error>> = JoinSet::new();
        let mut uploaded = Vec::new();
        let mut number = 0_u32;
        let collect = |finished: Result<Result<UploadedPart, Error>, tokio::task::JoinError>, uploaded: &mut Vec<UploadedPart>| -> Result<(), Error> {
            uploaded.push(finished.map_err(|error| Error::Transport(format!("an upload task failed: {error}")))??);
            Ok(())
        };
        loop {
            let data = read_part(reader, part_size).await?;
            // The upload of nothing at all is one empty part; after that an empty read is the end.
            if data.is_empty() && number > 0 {
                break;
            }
            number += 1;
            if number > MAX_PARTS {
                return Err(Error::InvalidInput(format!("more than {MAX_PARTS} parts of {part_size} bytes; use a larger part_size")));
            }
            let last = data.len() < part_size;
            while tasks.len() >= self.inner.multipart_concurrency {
                if let Some(finished) = tasks.join_next().await {
                    collect(finished, &mut uploaded)?;
                }
            }
            let upload = upload.clone();
            tasks.spawn(async move { upload.put_part(number, data).await });
            if last {
                break;
            }
        }
        while let Some(finished) = tasks.join_next().await {
            collect(finished, &mut uploaded)?;
        }
        uploaded.sort_by_key(|part| part.part_number);
        Ok(uploaded)
    }
}

/// The checksum of the data of a part as Base64, for the callers that make parts themselves.
pub fn part_checksum(algorithm: ChecksumAlgorithm, data: &[u8]) -> String {
    let mut hasher = algorithm.hasher();
    hasher.update(data);
    base64_encode(&hasher.finalize())
}
