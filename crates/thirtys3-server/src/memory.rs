//! A backend that keeps its buckets in memory: for tests, for examples, and as the shortest complete example of a [`Backend`].
//!
//! It is not meant to hold data you care about. It keeps every object whole in memory, checks the access of a key only by whether it may write,
//! and has no limits on the number of objects.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use thirtys3_core::etag::{etag_from_md5, md5_digest, multipart_etag, unquote};
use thirtys3_core::model::{ObjectEntry, PartInfo, UploadInfo};
use thirtys3_core::s3_error::code;
use thirtys3_core::{S3Error, Timestamp};

use crate::backend::*;

#[derive(Clone)]
struct Stored {
    data: Bytes,
    info: ObjectInfo,
}

struct Upload {
    bucket: String,
    key: String,
    content_type: Option<String>,
    metadata: Vec<(String, String)>,
    parts: BTreeMap<u32, (Bytes, String, Timestamp)>,
    initiated: Timestamp,
}

#[derive(Default)]
struct State {
    buckets: BTreeMap<String, Timestamp>,
    objects: BTreeMap<(String, String), Stored>,
    uploads: BTreeMap<String, Upload>,
    next_upload: u64,
}

struct User {
    credential: Credential,
    writable: bool,
}

/// What happened to the authentications, for tests.
pub type AuthLog = Arc<Mutex<Vec<(String, AuthOutcome)>>>;

/// A backend in memory. Make one with [`MemoryBackend::new`], add buckets and keys, and give it to an [`S3Service`](crate::S3Service).
#[derive(Clone)]
pub struct MemoryBackend {
    state: Arc<Mutex<State>>,
    users: Arc<Mutex<HashMap<String, Arc<User>>>>,
    auth_log: AuthLog,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    /// A backend with no buckets and no keys.
    pub fn new() -> Self {
        Self { state: Arc::default(), users: Arc::default(), auth_log: Arc::default() }
    }

    /// Adds a bucket.
    #[must_use]
    pub fn with_bucket(self, name: &str) -> Self {
        self.state.lock().unwrap().buckets.insert(name.to_owned(), Timestamp::now());
        self
    }

    /// Adds an access key that may read and write every bucket.
    #[must_use]
    pub fn with_key(self, access_key: &str, secret: &str) -> Self {
        self.users.lock().unwrap().insert(access_key.to_owned(), Arc::new(User { credential: Credential::new(secret), writable: true }));
        self
    }

    /// Adds an access key that may only read.
    #[must_use]
    pub fn with_read_only_key(self, access_key: &str, secret: &str) -> Self {
        self.users.lock().unwrap().insert(access_key.to_owned(), Arc::new(User { credential: Credential::new(secret), writable: false }));
        self
    }

    /// Takes a key away, as a service does when a key is revoked.
    pub fn revoke_key(&self, access_key: &str) {
        self.users.lock().unwrap().remove(access_key);
    }

    /// Puts an object in without going through the protocol.
    pub fn insert(&self, bucket: &str, key: &str, data: &[u8]) {
        let data = Bytes::copy_from_slice(data);
        let info = ObjectInfo::new(data.len() as u64, etag_from_md5(&md5_digest(&data)), Timestamp::now());
        self.state.lock().unwrap().objects.insert((bucket.to_owned(), key.to_owned()), Stored { data, info });
    }

    /// The data of an object.
    pub fn object(&self, bucket: &str, key: &str) -> Option<Bytes> {
        self.state.lock().unwrap().objects.get(&(bucket.to_owned(), key.to_owned())).map(|stored| stored.data.clone())
    }

    /// What is known about an object.
    pub fn info(&self, bucket: &str, key: &str) -> Option<ObjectInfo> {
        self.state.lock().unwrap().objects.get(&(bucket.to_owned(), key.to_owned())).map(|stored| stored.info.clone())
    }

    /// The keys of a bucket.
    pub fn keys(&self, bucket: &str) -> Vec<String> {
        self.state.lock().unwrap().objects.keys().filter(|(name, _)| name == bucket).map(|(_, key)| key.clone()).collect()
    }

    /// The number of multipart uploads that have not been completed or aborted.
    pub fn open_uploads(&self) -> usize {
        self.state.lock().unwrap().uploads.len()
    }

    /// How the authentications ended: the access key and the outcome, in order.
    pub fn auth_log(&self) -> Vec<(String, AuthOutcome)> {
        self.auth_log.lock().unwrap().clone()
    }

    fn user(&self, ctx: &Ctx<'_>) -> Result<Arc<User>, S3Error> {
        self.users.lock().unwrap().get(ctx.access_key).cloned().ok_or_else(|| S3Error::new(code::ACCESS_DENIED, "Access Denied"))
    }

    fn read(&self, ctx: &Ctx<'_>, bucket: &str) -> Result<(), S3Error> {
        self.user(ctx)?;
        if self.state.lock().unwrap().buckets.contains_key(bucket) { Ok(()) } else { Err(no_such_bucket(bucket)) }
    }

    fn write(&self, ctx: &Ctx<'_>, bucket: &str) -> Result<(), S3Error> {
        if !self.user(ctx)?.writable {
            return Err(S3Error::new(code::ACCESS_DENIED, "This access key is read-only"));
        }
        self.read(ctx, bucket)
    }
}

fn no_such_bucket(bucket: &str) -> S3Error {
    S3Error::new(code::NO_SUCH_BUCKET, "The specified bucket does not exist").with_detail("BucketName", bucket.to_owned())
}

fn no_such_key(key: &str) -> S3Error {
    S3Error::new(code::NO_SUCH_KEY, "The specified key does not exist.").with_detail("Key", key.to_owned())
}

fn no_such_upload() -> S3Error {
    S3Error::new(code::NO_SUCH_UPLOAD, "The specified upload does not exist. The upload ID may be invalid, or the upload may have been aborted or completed.")
}

fn check(existing: Option<&Stored>, condition: &WriteCondition) -> Result<(), S3Error> {
    let failed = match condition {
        WriteCondition::None => false,
        WriteCondition::Absent => existing.is_some(),
        WriteCondition::Match(wanted) => !existing.is_some_and(|stored| wanted.matches(&stored.info.etag, true)),
    };
    if failed { Err(S3Error::new(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold")) } else { Ok(()) }
}

struct Slice(Bytes);

#[async_trait]
impl ObjectSource for Slice {
    async fn open(self: Box<Self>, range: Range<u64>) -> Result<ByteStream, S3Error> {
        let data = self.0.slice(range.start as usize..range.end as usize);
        // In pieces, as a file would come; they share the memory of the object and copy nothing.
        let pieces: Vec<Result<Bytes, std::io::Error>> = (0..data.len()).step_by(64 * 1024).map(|at| Ok(data.slice(at..(at + 64 * 1024).min(data.len())))).collect();
        Ok(futures_util::stream::iter(pieces).boxed())
    }
}

/// The group a key belongs to under a delimiter: the key up to the first delimiter after the prefix, the delimiter included.
fn group_of(key: &str, prefix: &str, delimiter: Option<&str>) -> Option<String> {
    let delimiter = delimiter?;
    key[prefix.len()..].find(delimiter).map(|at| key[..prefix.len() + at + delimiter.len()].to_owned())
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn secret_key(&self, access_key: &str) -> Result<Option<Credential>, S3Error> {
        Ok(self.users.lock().unwrap().get(access_key).map(|user| user.credential.clone()))
    }

    async fn after_authentication(&self, info: &AuthInfo<'_>, outcome: AuthOutcome) {
        let mut log = self.auth_log.lock().unwrap();
        // The newest 10,000: a record for tests, not a log that can fill the memory.
        if log.len() >= 10_000 {
            log.remove(0);
        }
        log.push((info.access_key.to_owned(), outcome));
    }

    async fn list_buckets(&self, ctx: &Ctx<'_>, request: ListBucketsRequest) -> Result<ListBucketsOutput, S3Error> {
        self.user(ctx)?;
        let state = self.state.lock().unwrap();
        let buckets = state
            .buckets
            .iter()
            .filter(|(name, _)| request.prefix.as_deref().is_none_or(|prefix| name.starts_with(prefix)))
            .take(request.max_buckets.unwrap_or(u32::MAX) as usize)
            .map(|(name, created)| BucketInfo { name: name.clone(), created: *created })
            .collect();
        Ok(ListBucketsOutput { buckets, ..ListBucketsOutput::default() })
    }

    async fn head_bucket(&self, ctx: &Ctx<'_>, bucket: &str) -> Result<(), S3Error> {
        self.read(ctx, bucket)
    }

    async fn get_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectData, S3Error> {
        self.read(ctx, bucket)?;
        let stored = self.state.lock().unwrap().objects.get(&(bucket.to_owned(), key.to_owned())).cloned().ok_or_else(|| no_such_key(key))?;
        Ok(ObjectData { info: stored.info, source: Box::new(Slice(stored.data)) })
    }

    async fn head_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectInfo, S3Error> {
        self.read(ctx, bucket)?;
        self.info(bucket, key).ok_or_else(|| no_such_key(key))
    }

    async fn put_object(&self, ctx: &Ctx<'_>, mut request: PutObjectRequest) -> Result<PutObjectOutput, S3Error> {
        self.write(ctx, &request.bucket)?;
        let mut data = BytesMut::new();
        while let Some(piece) = request.body.next().await {
            data.extend_from_slice(&piece?);
        }
        // The end came without an error: the data is what the request said it was.
        let digests = request.body.digests().ok_or_else(|| S3Error::new(code::INTERNAL_ERROR, "the body was not checked"))?;
        let etag = digests.etag();
        let mut info = ObjectInfo::new(digests.size, etag.clone(), Timestamp::now());
        info.content_type = request.content_type;
        info.metadata = request.metadata;
        for (algorithm, digest) in &digests.checksums {
            info.checksums.set(*algorithm, thirtys3_core::checksum::base64_encode(digest));
        }
        let mut state = self.state.lock().unwrap();
        let slot = (request.bucket, request.key);
        check(state.objects.get(&slot), &request.condition)?;
        state.objects.insert(slot, Stored { data: data.freeze(), info });
        Ok(PutObjectOutput { etag, version_id: None, headers: http::HeaderMap::new() })
    }

    async fn copy_object(&self, ctx: &Ctx<'_>, request: CopyObjectRequest) -> Result<CopyObjectOutput, S3Error> {
        self.write(ctx, &request.bucket)?;
        self.read(ctx, &request.source_bucket)?;
        let mut state = self.state.lock().unwrap();
        let source = state.objects.get(&(request.source_bucket.clone(), request.source_key.clone())).cloned().ok_or_else(|| no_such_key(&request.source_key))?;
        request.source_conditions.evaluate_copy(&source.info.etag, source.info.last_modified)?;
        let slot = (request.bucket, request.key);
        check(state.objects.get(&slot), &request.condition)?;
        let mut stored = Stored { data: source.data, info: ObjectInfo { last_modified: Timestamp::now(), ..source.info } };
        if request.replace_metadata {
            stored.info.content_type = request.content_type;
            stored.info.metadata = request.metadata;
        }
        let output = CopyObjectOutput { etag: stored.info.etag.clone(), last_modified: stored.info.last_modified, headers: http::HeaderMap::new() };
        state.objects.insert(slot, stored);
        Ok(output)
    }

    async fn delete_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<(), S3Error> {
        self.write(ctx, bucket)?;
        self.state.lock().unwrap().objects.remove(&(bucket.to_owned(), key.to_owned()));
        Ok(())
    }

    async fn list_objects(&self, ctx: &Ctx<'_>, request: ListRequest) -> Result<ListPage, S3Error> {
        self.read(ctx, &request.bucket)?;
        let after = match &request.start {
            ListStart::Beginning => String::new(),
            ListStart::After(key) => key.clone(),
            ListStart::Continuation(token) => token
                .strip_prefix("after:")
                .map(str::to_owned)
                .ok_or_else(|| S3Error::new(code::INVALID_ARGUMENT, "Invalid continuation token").with_detail("ArgumentName", "continuation-token"))?,
        };
        let delimiter = request.delimiter.as_deref();
        let state = self.state.lock().unwrap();
        let mut page = ListPage::default();
        let mut last = String::new();
        if request.max_keys == 0 {
            return Ok(page);
        }
        for ((bucket, key), stored) in &state.objects {
            if *bucket != request.bucket || !key.starts_with(&request.prefix) || key.as_str() <= after.as_str() {
                continue;
            }
            let group = group_of(key, &request.prefix, delimiter);
            if let Some(group) = &group
                && (page.common_prefixes.last() == Some(group) || group.as_str() <= after.as_str())
            {
                continue;
            }
            if page.objects.len() + page.common_prefixes.len() >= request.max_keys as usize {
                page.truncated = true;
                break;
            }
            match group {
                Some(group) => {
                    last = group.clone();
                    page.common_prefixes.push(group);
                }
                None => {
                    last = key.clone();
                    let mut entry = ObjectEntry::new(key.clone(), stored.info.last_modified, stored.info.etag.clone(), stored.info.size);
                    entry.checksum_algorithms = stored.info.checksums.0.iter().map(|(algorithm, _)| algorithm.name().to_owned()).collect();
                    page.objects.push(entry);
                }
            }
        }
        if page.truncated {
            page.next = Some(ListNext { token: format!("after:{last}"), key: last });
        }
        Ok(page)
    }

    async fn create_multipart_upload(&self, ctx: &Ctx<'_>, request: CreateMultipartUploadRequest) -> Result<String, S3Error> {
        self.write(ctx, &request.bucket)?;
        let mut state = self.state.lock().unwrap();
        state.next_upload += 1;
        let id = format!("{:08x}-{:016x}", state.next_upload, Timestamp::now().0);
        state.uploads.insert(
            id.clone(),
            Upload {
                bucket: request.bucket,
                key: request.key,
                content_type: request.content_type,
                metadata: request.metadata,
                parts: BTreeMap::new(),
                initiated: Timestamp::now(),
            },
        );
        Ok(id)
    }

    async fn upload_part(&self, ctx: &Ctx<'_>, mut request: UploadPartRequest) -> Result<UploadPartOutput, S3Error> {
        self.write(ctx, &request.bucket)?;
        let mut data = BytesMut::new();
        while let Some(piece) = request.body.next().await {
            data.extend_from_slice(&piece?);
        }
        let digests = request.body.digests().ok_or_else(|| S3Error::new(code::INTERNAL_ERROR, "the body was not checked"))?;
        let etag = digests.etag();
        let mut state = self.state.lock().unwrap();
        let upload =
            state.uploads.get_mut(&request.upload_id).filter(|upload| upload.bucket == request.bucket && upload.key == request.key).ok_or_else(no_such_upload)?;
        upload.parts.insert(request.part_number, (data.freeze(), etag.clone(), Timestamp::now()));
        Ok(UploadPartOutput { etag })
    }

    async fn complete_multipart_upload(&self, ctx: &Ctx<'_>, request: CompleteMultipartUploadRequest) -> Result<CompleteMultipartUploadOutput, S3Error> {
        self.write(ctx, &request.bucket)?;
        let mut state = self.state.lock().unwrap();
        let upload =
            state.uploads.get(&request.upload_id).filter(|upload| upload.bucket == request.bucket && upload.key == request.key).ok_or_else(no_such_upload)?;
        if request.parts.is_empty() || request.parts.len() > 10_000 {
            return Err(S3Error::new(code::INVALID_PART, "You must specify at least one part"));
        }
        // The order of the list first, then that the parts are there with those ETags, then their sizes.
        if request.parts.windows(2).any(|pair| pair[1].part_number <= pair[0].part_number) {
            return Err(S3Error::new(
                code::INVALID_PART_ORDER,
                "The list of parts was not in ascending order. The parts list must be specified in order by part number.",
            ));
        }
        let mut data = BytesMut::new();
        let mut md5s = Vec::new();
        for part in &request.parts {
            let (bytes, etag, _) = upload.parts.get(&part.part_number).ok_or_else(|| S3Error::new(code::INVALID_PART, "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag."))?;
            if part.etag.as_deref().map(unquote) != Some(unquote(etag)) {
                return Err(S3Error::new(
                    code::INVALID_PART,
                    "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
                ));
            }
            md5s.push(md5_digest(bytes));
            data.extend_from_slice(bytes);
        }
        let last = request.parts.len() - 1;
        if request.parts[..last].iter().any(|part| upload.parts[&part.part_number].0.len() < 5 * 1024 * 1024) {
            return Err(S3Error::new(code::ENTITY_TOO_SMALL, "Your proposed upload is smaller than the minimum allowed object size."));
        }
        let slot = (request.bucket.clone(), request.key.clone());
        check(state.objects.get(&slot), &request.condition)?;
        let upload = state.uploads.remove(&request.upload_id).expect("checked above");
        let etag = multipart_etag(&md5s);
        let mut info = ObjectInfo::new(data.len() as u64, etag.clone(), Timestamp::now());
        info.content_type = upload.content_type;
        info.metadata = upload.metadata;
        state.objects.insert(slot, Stored { data: data.freeze(), info });
        Ok(CompleteMultipartUploadOutput { etag, version_id: None, headers: http::HeaderMap::new() })
    }

    async fn abort_multipart_upload(&self, ctx: &Ctx<'_>, bucket: &str, key: &str, upload_id: &str) -> Result<(), S3Error> {
        self.write(ctx, bucket)?;
        let mut state = self.state.lock().unwrap();
        match state.uploads.get(upload_id) {
            Some(upload) if upload.bucket == bucket && upload.key == key => {
                state.uploads.remove(upload_id);
                Ok(())
            }
            _ => Err(no_such_upload()),
        }
    }

    async fn list_parts(&self, ctx: &Ctx<'_>, request: ListPartsRequest) -> Result<ListPartsOutput, S3Error> {
        self.read(ctx, &request.bucket)?;
        let state = self.state.lock().unwrap();
        let upload =
            state.uploads.get(&request.upload_id).filter(|upload| upload.bucket == request.bucket && upload.key == request.key).ok_or_else(no_such_upload)?;
        let mut parts: Vec<PartInfo> = upload
            .parts
            .range(request.part_number_marker.saturating_add(1)..)
            .take(request.max_parts as usize + 1)
            .map(|(number, (data, etag, modified))| PartInfo {
                part_number: *number,
                last_modified: *modified,
                etag: etag.clone(),
                size: data.len() as u64,
                checksums: Default::default(),
            })
            .collect();
        // No parts asked for is no parts, and not a listing that is cut off with nowhere to go on from.
        let truncated = request.max_parts > 0 && parts.len() > request.max_parts as usize;
        parts.truncate(request.max_parts as usize);
        let next = parts.last().map(|part| part.part_number).filter(|_| truncated);
        Ok(ListPartsOutput { parts, truncated, next_part_number_marker: next, storage_class: Some("STANDARD".to_owned()), ..ListPartsOutput::default() })
    }

    async fn list_multipart_uploads(&self, ctx: &Ctx<'_>, request: ListUploadsRequest) -> Result<ListUploadsOutput, S3Error> {
        self.read(ctx, &request.bucket)?;
        let state = self.state.lock().unwrap();
        let mut candidates: Vec<(&String, &Upload)> =
            state.uploads.iter().filter(|(_, upload)| upload.bucket == request.bucket && upload.key.starts_with(&request.prefix)).collect();
        candidates.sort_by(|a, b| (&a.1.key, a.0).cmp(&(&b.1.key, b.0)));
        let delimiter = request.delimiter.as_deref();
        let mut output = ListUploadsOutput::default();
        let mut last = (String::new(), String::new());
        for (id, upload) in candidates {
            // After the key marker; and when there is an upload ID marker as well, an upload of the key of the marker is after it if its ID is.
            let before_marker = if request.upload_id_marker.is_empty() {
                upload.key.as_str() <= request.key_marker.as_str()
            } else {
                (upload.key.as_str(), id.as_str()) <= (request.key_marker.as_str(), request.upload_id_marker.as_str())
            };
            if before_marker && !request.key_marker.is_empty() {
                continue;
            }
            let group = group_of(&upload.key, &request.prefix, delimiter);
            if let Some(group) = &group
                && (output.common_prefixes.last() == Some(group) || group.as_str() <= request.key_marker.as_str())
            {
                continue;
            }
            if output.uploads.len() + output.common_prefixes.len() >= request.max_uploads as usize {
                output.truncated = true;
                break;
            }
            match group {
                Some(group) => {
                    last = (group.clone(), String::new());
                    output.common_prefixes.push(group);
                }
                None => {
                    last = (upload.key.clone(), id.clone());
                    output.uploads.push(UploadInfo {
                        key: upload.key.clone(),
                        upload_id: id.clone(),
                        initiator: None,
                        owner: None,
                        storage_class: Some("STANDARD".to_owned()),
                        initiated: upload.initiated,
                        checksum_algorithm: None,
                        checksum_type: None,
                    });
                }
            }
        }
        if output.truncated {
            output.next_key_marker = Some(last.0);
            output.next_upload_id_marker = Some(last.1);
        }
        Ok(output)
    }
}
