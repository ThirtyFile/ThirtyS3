//! What a service built on this crate has to provide: the keys, and the operations on its buckets and objects.
//!
//! The protocol is done by the crate: routing, signatures (in the header, in the query and in `aws-chunked` bodies), the XML, the headers, the
//! statuses, conditions and ranges, and the checks on uploaded data. A [`Backend`] works with typed requests and answers and with
//! [`S3Error`]s, and never sees a signature or a line of XML.
//!
//! Every method gets a [`Ctx`] with the access key that was authenticated. Whether that key may do this to this bucket and key is for the backend
//! to decide, on every call. That goes for the source of a copy too, which the service reads with [`Backend::head_object`] before it asks for the
//! copy, so a backend that checks the rights of `head_object` has checked those of the source.
//!
//! # What a backend must be ready for
//!
//! - **A request can be dropped at any `.await`.** When a client goes away, the future that is answering it is dropped, wherever it is. For the
//!   operations that change something and have no body to read (`copy_object`, `delete_object`, `delete_objects` and creating, completing and
//!   aborting an upload) the service avoids that: they run to their end in a task of their own, with the authentication before them
//!   ([`ServerConfig::detach_mutations`](crate::ServerConfig)), and the hooks of the authentication get their calls. Reads and uploads are
//!   dropped with their client, as they should: an upload that stops reading its body gets an error from it. Put the work that must not be cut
//!   in the methods of the first kind, and keep a method that is dropped from leaving something that cannot be told from a finished upload.
//! - **An upload is good only if its body ended with `None`.** The body of [`put_object`](Backend::put_object) and
//!   [`upload_part`](Backend::upload_part) is a stream of `Result`s: when a check fails (a digest, a signature, the length) the stream gives an `Err`
//!   and then ends, so a loop that stops at the first `Err` and treats the stop as the end (`while let Some(Ok(piece)) = body.next().await`) keeps
//!   an upload that was cut short or changed. Read it with `?` on every piece (`TryStreamExt::try_next`), write to a place that is not yet the object,
//!   and make it the object only after the last `None` and with an `Ok`.

use std::ops::Range;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::Stream;
use http::{Extensions, HeaderMap, Method, Uri};
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::etag::ETagCondition;
use thirtys3_core::model::{Checksums, CompletedPart, ObjectEntry, Owner, PartInfo, UploadInfo};
use thirtys3_core::{S3Error, Timestamp};

use crate::body::RequestBody;
use crate::conditions::Conditions;

/// A stream of data of an object.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// The secret of an access key. There is no `PartialEq`: secrets are compared with [`thirtys3_core::constant_time_eq`].
#[derive(Clone)]
pub struct Credential {
    /// The secret access key.
    pub secret_access_key: String,
    /// The session token that has to come with the key (temporary credentials). If there is none, a token in a request is not looked at.
    pub session_token: Option<String>,
}

impl Credential {
    /// A long-term credential.
    pub fn new(secret_access_key: impl Into<String>) -> Self {
        Self { secret_access_key: secret_access_key.into(), session_token: None }
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

/// What the backend is told about a request that is being authenticated. `Debug` leaves out the signature and the token of the request.
#[derive(Clone, Copy)]
pub struct AuthInfo<'a> {
    /// The access key ID the request names. It has not been checked yet.
    pub access_key: &'a str,
    /// The URI of the request.
    pub uri: &'a Uri,
    /// The headers of the request.
    pub headers: &'a HeaderMap,
    /// What the code that mounted the service put in the extensions of the request (the address of the client, for one).
    pub extensions: &'a Extensions,
}

/// How an authentication ended, for the limits on sign-in attempts a backend may keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthOutcome {
    /// The signature is right.
    Verified,
    /// The key is known and the signature is wrong. This is what a guess at a secret looks like.
    BadSignature,
    /// No such access key. This is what a guess at a key looks like.
    UnknownKey,
    /// The backend refused the key (stopped, ended, its bucket gone) by returning an error from [`Backend::secret_key`]: no guess.
    Refused,
    /// Anything else: a request that could not be read, a region that is wrong, an error of the backend. No guess.
    Failed,
}

/// What is known about the request an operation is for. `Debug` leaves out the signature and the token of the request.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    /// The access key that signed the request, whose signature was right.
    pub access_key: &'a str,
    /// The ID of the request, which is also in the answer.
    pub request_id: &'a str,
    /// Whether the signature was in the query (a presigned URL) and not in a header.
    pub presigned: bool,
    /// The region the service answers for.
    pub region: &'a str,
    /// The method of the request.
    pub method: &'a Method,
    /// The URI of the request.
    pub uri: &'a Uri,
    /// The headers of the request.
    pub headers: &'a HeaderMap,
    /// What the code that mounted the service put in the extensions of the request.
    pub extensions: &'a Extensions,
}

/// The headers of a request for `Debug`, without the ones that hold a secret.
struct RedactedHeaders<'a>(&'a HeaderMap);

impl std::fmt::Debug for RedactedHeaders<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (name, value) in self.0 {
            let secret = matches!(name.as_str(), "authorization" | "proxy-authorization" | "cookie" | "x-amz-security-token");
            if secret {
                map.entry(&name.as_str(), &"<redacted>");
            } else {
                map.entry(&name.as_str(), value);
            }
        }
        map.finish()
    }
}

/// The URI of a request for `Debug`: the signature and the token of a presigned URL are left out, because whoever has them can use the URL.
struct RedactedUri<'a>(&'a Uri);

impl std::fmt::Debug for RedactedUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(query) = self.0.query() else { return write!(f, "{}", self.0.path()) };
        let pairs: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((name, _)) if matches!(name, "X-Amz-Signature" | "X-Amz-Security-Token") => format!("{name}=<redacted>"),
                _ => pair.to_owned(),
            })
            .collect();
        write!(f, "{}?{}", self.0.path(), pairs.join("&"))
    }
}

impl std::fmt::Debug for AuthInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInfo")
            .field("access_key", &self.access_key)
            .field("uri", &RedactedUri(self.uri))
            .field("headers", &RedactedHeaders(self.headers))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("access_key", &self.access_key)
            .field("request_id", &self.request_id)
            .field("presigned", &self.presigned)
            .field("region", &self.region)
            .field("method", &self.method)
            .field("uri", &RedactedUri(self.uri))
            .field("headers", &RedactedHeaders(self.headers))
            .finish_non_exhaustive()
    }
}

/// What is known about an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The size in bytes.
    pub size: u64,
    /// The ETag, in double quotes.
    pub etag: String,
    /// When the object was last modified.
    pub last_modified: Timestamp,
    /// The content type; `binary/octet-stream` when none.
    pub content_type: Option<String>,
    /// The user metadata, as `(name, value)` without the `x-amz-meta-` in front of the name.
    pub metadata: Vec<(String, String)>,
    /// The checksums the object has, as Base64.
    pub checksums: Checksums,
    /// The storage class, if the backend has one to tell.
    pub storage_class: Option<String>,
    /// More headers for the answer, such as `content-disposition`. They are added to those of the protocol and can replace them.
    pub headers: HeaderMap,
}

impl ObjectInfo {
    /// An object of this size, with this ETag, modified at this time, with nothing else.
    pub fn new(size: u64, etag: impl Into<String>, last_modified: Timestamp) -> Self {
        Self {
            size,
            etag: etag.into(),
            last_modified,
            content_type: None,
            metadata: Vec::new(),
            checksums: Checksums::default(),
            storage_class: None,
            headers: HeaderMap::new(),
        }
    }
}

/// Where the data of an object comes from.
#[async_trait]
pub trait ObjectSource: Send {
    /// The bytes of `range`, which is inside the object. Called at most once, after the conditions and the range have been checked against the
    /// [`ObjectInfo`] that came with the source, so the data has to be that of the version the info describes.
    async fn open(self: Box<Self>, range: Range<u64>) -> Result<ByteStream, S3Error>;
}

/// An object to download: what is known about it and a way to read it.
pub struct ObjectData {
    /// What is known about the object.
    pub info: ObjectInfo,
    /// The data.
    pub source: Box<dyn ObjectSource>,
}

/// What a write expects to find at the key (`If-None-Match: *`, `If-Match`). The backend has to enforce it when it stores the object, in the
/// same step, so that two writes cannot both succeed: the lock file that is made once, the object that is replaced only if it is still the one
/// that was read. A write that does not hold fails with `PreconditionFailed`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum WriteCondition {
    /// Nothing is expected.
    #[default]
    None,
    /// There must be no object with this key.
    Absent,
    /// The object that is there must have one of these ETags.
    Match(ETagCondition),
}

/// `PutObject`. The other headers a client may set for the object (`Content-Disposition`, `Cache-Control`, `Content-Encoding`, `Content-Language`,
/// `Expires`) are not fields: a backend that keeps them reads them from [`Ctx::headers`] and gives them back in [`ObjectInfo::headers`].
#[derive(Debug)]
pub struct PutObjectRequest {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The data. See [`RequestBody`] for what has to be done with it.
    pub body: RequestBody,
    /// The number of bytes the request says there are.
    pub content_length: Option<u64>,
    /// The content type.
    pub content_type: Option<String>,
    /// The user metadata, as `(name, value)` without the `x-amz-meta-` in front of the name, names in lower case.
    pub metadata: Vec<(String, String)>,
    /// What to expect at the key.
    pub condition: WriteCondition,
}

/// What a store says about the object it has stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutObjectOutput {
    /// The ETag, in double quotes: for an object of one request the MD5 of the data, which the body has worked out.
    pub etag: String,
    /// The version, if the bucket has versions.
    pub version_id: Option<String>,
    /// More headers for the answer.
    pub headers: HeaderMap,
}

/// `CopyObject`, inside one bucket or between buckets the key may reach.
#[derive(Debug, Clone)]
pub struct CopyObjectRequest {
    /// The bucket of the new object.
    pub bucket: String,
    /// The key of the new object.
    pub key: String,
    /// The bucket of the object to copy.
    pub source_bucket: String,
    /// The key of the object to copy.
    pub source_key: String,
    /// `x-amz-metadata-directive: REPLACE`: the new object gets the content type and the metadata below; otherwise those of the source.
    pub replace_metadata: bool,
    /// The content type, with `replace_metadata`.
    pub content_type: Option<String>,
    /// The user metadata, with `replace_metadata`.
    pub metadata: Vec<(String, String)>,
    /// The conditions on the source (`x-amz-copy-source-if-*`). The service has checked them against the source it read with
    /// [`Backend::head_object`]; a backend that copies something that may have changed since can check them again with
    /// [`Conditions::evaluate_copy`](crate::conditions::Conditions::evaluate_copy).
    pub source_conditions: Conditions,
    /// What to expect at the new key.
    pub condition: WriteCondition,
}

/// What `CopyObject` made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyObjectOutput {
    /// The ETag of the new object.
    pub etag: String,
    /// When it was modified.
    pub last_modified: Timestamp,
    /// More headers for the answer.
    pub headers: HeaderMap,
}

/// An object `DeleteObjects` is asked to delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTarget {
    /// The key.
    pub key: String,
    /// The version; a backend without versions answers `NotImplemented` for it.
    pub version_id: Option<String>,
}

/// Where a listing starts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ListStart {
    /// At the first key.
    #[default]
    Beginning,
    /// After this key (`start-after`, or `marker` of version 1).
    After(String),
    /// Where the previous page stopped: the token the backend gave. The service does not look inside it.
    Continuation(String),
}

/// `ListObjects` and `ListObjectsV2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    /// The bucket.
    pub bucket: String,
    /// The keys have to start with this.
    pub prefix: String,
    /// Keys that have this after the prefix are rolled up into common prefixes.
    pub delimiter: Option<String>,
    /// The most entries (objects and common prefixes together) in the page: 1000 at most.
    pub max_keys: u32,
    /// Where to start.
    pub start: ListStart,
}

/// Where a truncated page stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListNext {
    /// The last key or common prefix of the page, which `ListObjects` of version 1 gives as `NextMarker`.
    pub key: String,
    /// The token to continue with, for `ListObjectsV2`: opaque, and checked by the backend when it comes back.
    pub token: String,
}

/// A page of a listing. The keys are as they are, not URL-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListPage {
    /// The objects.
    pub objects: Vec<ObjectEntry>,
    /// The common prefixes.
    pub common_prefixes: Vec<String>,
    /// Whether there is more after this page.
    pub truncated: bool,
    /// Where it stopped, when `truncated`.
    pub next: Option<ListNext>,
}

/// A bucket in the list of buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketInfo {
    /// The name.
    pub name: String,
    /// When it was created.
    pub created: Timestamp,
}

/// `ListBuckets`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListBucketsRequest {
    /// Only the buckets whose names start with this.
    pub prefix: Option<String>,
    /// The most buckets in the answer.
    pub max_buckets: Option<u32>,
    /// The token of the previous answer.
    pub continuation_token: Option<String>,
}

/// The answer to `ListBuckets`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListBucketsOutput {
    /// The buckets the key may see.
    pub buckets: Vec<BucketInfo>,
    /// The owner, if the service tells.
    pub owner: Option<Owner>,
    /// The token for the next page, if the buckets are in pages and there is more.
    pub continuation_token: Option<String>,
}

/// `CreateMultipartUpload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateMultipartUploadRequest {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The content type.
    pub content_type: Option<String>,
    /// The user metadata, names in lower case.
    pub metadata: Vec<(String, String)>,
    /// The checksum algorithm the parts will be sent with.
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
}

/// `UploadPart`.
#[derive(Debug)]
pub struct UploadPartRequest {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The upload.
    pub upload_id: String,
    /// The number of the part, 1 to 10,000 (the service has checked).
    pub part_number: u32,
    /// The data. See [`RequestBody`] for what has to be done with it.
    pub body: RequestBody,
    /// The number of bytes the request says there are.
    pub content_length: Option<u64>,
}

/// What a stored part is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPartOutput {
    /// The ETag of the part, in double quotes: the MD5 of its data.
    pub etag: String,
}

/// `CompleteMultipartUpload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteMultipartUploadRequest {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The upload.
    pub upload_id: String,
    /// The parts, in the order of the request: not empty, at most 10,000. The backend checks that the numbers are ascending (`InvalidPartOrder`),
    /// that the ETags are those of the parts (`InvalidPart`) and that all but the last are 5 MiB (`EntityTooSmall`).
    pub parts: Vec<CompletedPart>,
    /// What to expect at the key.
    pub condition: WriteCondition,
}

/// What a completed upload made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteMultipartUploadOutput {
    /// The ETag of the object: `"` the MD5 of the MD5s of the parts, `-` the number of parts, `"`.
    pub etag: String,
    /// The version, if the bucket has versions.
    pub version_id: Option<String>,
    /// More headers for the answer.
    pub headers: HeaderMap,
}

/// `ListParts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPartsRequest {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The upload.
    pub upload_id: String,
    /// The most parts: 1000 at most.
    pub max_parts: u32,
    /// List the parts after this number.
    pub part_number_marker: u32,
}

/// The answer to `ListParts`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListPartsOutput {
    /// The parts in ascending order of number.
    pub parts: Vec<PartInfo>,
    /// Whether there are more.
    pub truncated: bool,
    /// The number to continue after, when `truncated`.
    pub next_part_number_marker: Option<u32>,
    /// Who started the upload.
    pub initiator: Option<Owner>,
    /// The owner of the object.
    pub owner: Option<Owner>,
    /// The storage class.
    pub storage_class: Option<String>,
}

/// `ListMultipartUploads`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListUploadsRequest {
    /// The bucket.
    pub bucket: String,
    /// Only keys that start with this.
    pub prefix: String,
    /// Keys that have this after the prefix are rolled up into common prefixes.
    pub delimiter: Option<String>,
    /// The most entries: 1000 at most.
    pub max_uploads: u32,
    /// List after this key.
    pub key_marker: String,
    /// With `key_marker`, after this upload.
    pub upload_id_marker: String,
}

/// The answer to `ListMultipartUploads`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListUploadsOutput {
    /// The uploads in the order of their keys and then of their IDs.
    pub uploads: Vec<UploadInfo>,
    /// The common prefixes.
    pub common_prefixes: Vec<String>,
    /// Whether there are more.
    pub truncated: bool,
    /// The key to continue after, when `truncated`.
    pub next_key_marker: Option<String>,
    /// The upload to continue after, when `truncated`.
    pub next_upload_id_marker: Option<String>,
}

/// The operations of a service. Methods that return errors return [`S3Error`]s, which the service sends as they are: use the codes of
/// [`thirtys3_core::s3_error::code`] and say in the message what a person needs to know, nothing about the inside of the service.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    /// The secret of an access key. `Ok(None)` is a key that does not exist; an error is a key that exists and is refused, or a failure of the
    /// backend. The difference matters to [`AuthOutcome`].
    async fn secret_key(&self, access_key: &str) -> Result<Option<Credential>, S3Error>;

    /// Called before the key of a request is looked up, once the request has been read and its time checked. An error is the answer to the
    /// request: this is where a limit on sign-in attempts is applied (`SlowDown`) and an attempt reserved. If it returns `Ok`,
    /// [`after_authentication`](Self::after_authentication) will be called once, unless the request is dropped before the authentication is over (the
    /// client went away).
    async fn before_authentication(&self, _info: &AuthInfo<'_>) -> Result<(), S3Error> {
        Ok(())
    }

    /// Called when the authentication is over, with how it ended, as soon as it is: before any operation, so before the body of an upload has been
    /// read.
    async fn after_authentication(&self, _info: &AuthInfo<'_>, _outcome: AuthOutcome) {}

    /// `ListBuckets`: the buckets the key may see.
    async fn list_buckets(&self, ctx: &Ctx<'_>, request: ListBucketsRequest) -> Result<ListBucketsOutput, S3Error>;

    /// `HeadBucket`, and the check that goes before `GetBucketLocation`: `Ok` if the bucket exists and the key may use it.
    async fn head_bucket(&self, ctx: &Ctx<'_>, bucket: &str) -> Result<(), S3Error>;

    /// `GetObject`: what is known about the object and a way to read it. The service checks the conditions and the range against the info and
    /// then opens the source.
    async fn get_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectData, S3Error>;

    /// `HeadObject`.
    async fn head_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectInfo, S3Error>;

    /// `PutObject`. Read the body to its end, and only keep the object if the end came without an error.
    async fn put_object(&self, ctx: &Ctx<'_>, request: PutObjectRequest) -> Result<PutObjectOutput, S3Error>;

    /// `CopyObject`. The service has already read the source with [`head_object`](Self::head_object), which is where a backend refuses a source its
    /// key may not read, and has checked the conditions on the source against what that said (`source_conditions` is passed on for a backend that
    /// wants to check them again, against the data it is about to copy).
    async fn copy_object(&self, ctx: &Ctx<'_>, request: CopyObjectRequest) -> Result<CopyObjectOutput, S3Error>;

    /// `DeleteObject`. An object that is not there is deleted: `Ok`.
    async fn delete_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<(), S3Error>;

    /// `DeleteObjects`: one result for each target, in the same order. The default deletes them one by one with
    /// [`delete_object`](Self::delete_object) (`NotImplemented` for a version); override it to check the access once.
    async fn delete_objects(&self, ctx: &Ctx<'_>, bucket: &str, targets: &[DeleteTarget]) -> Result<Vec<Result<(), S3Error>>, S3Error> {
        let mut results = Vec::with_capacity(targets.len());
        for target in targets {
            results.push(if target.version_id.is_some() {
                Err(S3Error::new("NotImplemented", "Versions are not supported"))
            } else {
                self.delete_object(ctx, bucket, &target.key).await
            });
        }
        Ok(results)
    }

    /// `ListObjects` and `ListObjectsV2`.
    async fn list_objects(&self, ctx: &Ctx<'_>, request: ListRequest) -> Result<ListPage, S3Error>;

    /// `CreateMultipartUpload`: the ID of the new upload.
    async fn create_multipart_upload(&self, ctx: &Ctx<'_>, request: CreateMultipartUploadRequest) -> Result<String, S3Error>;

    /// `UploadPart`. Read the body to its end, and only keep the part if the end came without an error.
    async fn upload_part(&self, ctx: &Ctx<'_>, request: UploadPartRequest) -> Result<UploadPartOutput, S3Error>;

    /// `CompleteMultipartUpload`.
    async fn complete_multipart_upload(&self, ctx: &Ctx<'_>, request: CompleteMultipartUploadRequest) -> Result<CompleteMultipartUploadOutput, S3Error>;

    /// `AbortMultipartUpload`.
    async fn abort_multipart_upload(&self, ctx: &Ctx<'_>, bucket: &str, key: &str, upload_id: &str) -> Result<(), S3Error>;

    /// `ListParts`.
    async fn list_parts(&self, ctx: &Ctx<'_>, request: ListPartsRequest) -> Result<ListPartsOutput, S3Error>;

    /// `ListMultipartUploads`.
    async fn list_multipart_uploads(&self, ctx: &Ctx<'_>, request: ListUploadsRequest) -> Result<ListUploadsOutput, S3Error>;
}
