//! A backend that keeps a record of what the service did to it, and can be made to behave badly.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use thirtys3_core::S3Error;
use thirtys3_server::memory::MemoryBackend;
use thirtys3_server::*;

use super::backend;

/// The memory backend, with a record of the calls that matter and switches for bad behaviour.
#[derive(Clone)]
pub struct Watched {
    pub inner: MemoryBackend,
    pub events: Arc<Mutex<Vec<String>>>,
    /// `before_authentication` answers `SlowDown`.
    pub limit_attempts: Arc<AtomicBool>,
    /// Access keys whose `secret_key` is an error: known and refused.
    pub refused: Arc<Mutex<HashSet<String>>>,
    /// `put_object` answers without reading the body.
    pub ignore_bodies: Arc<AtomicBool>,
    /// Keys that cannot be deleted.
    pub undeletable: Arc<Mutex<HashSet<String>>>,
    /// A session token that has to come with the access key.
    pub token: Arc<Mutex<Option<String>>>,
    /// `complete_multipart_upload` fails with `InternalError`.
    pub fail_complete: Arc<AtomicBool>,
    /// `delete_objects` leaves the last result out.
    pub short_delete_results: Arc<AtomicBool>,
    /// Buckets whose objects the access keys may not read.
    pub unreadable: Arc<Mutex<HashSet<String>>>,
    /// `copy_object` is given no conditions on the source, as a backend that leaves them to the service.
    pub forget_source_conditions: Arc<AtomicBool>,
    /// How long the operations that change something take, so that a test can drop the request in the middle of one.
    pub op_delay: Arc<Mutex<Duration>>,
    /// How long `secret_key` takes.
    pub auth_delay: Arc<Mutex<Duration>>,
    /// `delete_object` panics.
    pub panic_on_delete: Arc<AtomicBool>,
}

impl Watched {
    pub fn new() -> Self {
        Self {
            inner: backend(),
            events: Arc::default(),
            limit_attempts: Arc::default(),
            refused: Arc::default(),
            ignore_bodies: Arc::default(),
            undeletable: Arc::default(),
            fail_complete: Arc::default(),
            short_delete_results: Arc::default(),
            unreadable: Arc::default(),
            forget_source_conditions: Arc::default(),
            op_delay: Arc::default(),
            auth_delay: Arc::default(),
            panic_on_delete: Arc::default(),
            token: Arc::default(),
        }
    }

    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn note(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }

    /// An operation that changes something takes its time, and says when it began and when it was done.
    async fn slow<T>(&self, name: &str, work: impl std::future::Future<Output = T>) -> T {
        self.note(format!("{name} started"));
        let delay = *self.op_delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        let result = work.await;
        self.note(format!("{name} finished"));
        result
    }
}

#[async_trait]
impl Backend for Watched {
    async fn secret_key(&self, access_key: &str) -> Result<Option<Credential>, S3Error> {
        let delay = *self.auth_delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        if self.refused.lock().unwrap().contains(access_key) {
            return Err(S3Error::new("AccessDenied", "This access key is stopped"));
        }
        let mut credential = self.inner.secret_key(access_key).await?;
        if let (Some(credential), Some(token)) = (&mut credential, self.token.lock().unwrap().clone()) {
            credential.session_token = Some(token);
        }
        Ok(credential)
    }

    async fn before_authentication(&self, info: &AuthInfo<'_>) -> Result<(), S3Error> {
        self.note(format!("before:{}", info.access_key));
        if self.limit_attempts.load(Ordering::Relaxed) { Err(S3Error::new("SlowDown", "Too many failed sign-ins")) } else { Ok(()) }
    }

    async fn after_authentication(&self, info: &AuthInfo<'_>, outcome: AuthOutcome) {
        self.note(format!("after:{}:{outcome:?}", info.access_key));
        self.inner.after_authentication(info, outcome).await;
    }

    async fn list_buckets(&self, ctx: &Ctx<'_>, request: ListBucketsRequest) -> Result<ListBucketsOutput, S3Error> {
        self.note(format!("list_buckets:{:?}", request.max_buckets));
        self.inner.list_buckets(ctx, request).await
    }

    async fn head_bucket(&self, ctx: &Ctx<'_>, bucket: &str) -> Result<(), S3Error> {
        self.inner.head_bucket(ctx, bucket).await
    }

    async fn get_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectData, S3Error> {
        if self.unreadable.lock().unwrap().contains(bucket) {
            return Err(S3Error::new("AccessDenied", "Access Denied"));
        }
        self.inner.get_object(ctx, bucket, key).await
    }

    async fn head_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<ObjectInfo, S3Error> {
        self.note(format!("head:{bucket}/{key}"));
        if self.unreadable.lock().unwrap().contains(bucket) {
            return Err(S3Error::new("AccessDenied", "Access Denied"));
        }
        self.inner.head_object(ctx, bucket, key).await
    }

    async fn put_object(&self, ctx: &Ctx<'_>, request: PutObjectRequest) -> Result<PutObjectOutput, S3Error> {
        self.note(format!("put:{}", request.key));
        if self.ignore_bodies.load(Ordering::Relaxed) {
            // Answers at once, as a backend that forgot to read the body would.
            return Ok(PutObjectOutput { etag: "\"d41d8cd98f00b204e9800998ecf8427e\"".to_owned(), version_id: None, headers: http::HeaderMap::new() });
        }
        let result = self.inner.put_object(ctx, request).await;
        self.note(format!("put finished:{}", if result.is_ok() { "ok" } else { "error" }));
        result
    }

    async fn copy_object(&self, ctx: &Ctx<'_>, mut request: CopyObjectRequest) -> Result<CopyObjectOutput, S3Error> {
        self.note(format!("copy:{}/{}", request.source_bucket, request.source_key));
        if self.forget_source_conditions.load(Ordering::Relaxed) {
            request.source_conditions = Default::default();
        }
        self.slow("copy", self.inner.copy_object(ctx, request)).await
    }

    async fn delete_object(&self, ctx: &Ctx<'_>, bucket: &str, key: &str) -> Result<(), S3Error> {
        assert!(!self.panic_on_delete.load(Ordering::Relaxed), "a backend that panics");
        if self.undeletable.lock().unwrap().contains(key) {
            return Err(S3Error::new("AccessDenied", "Access Denied"));
        }
        self.slow("delete", self.inner.delete_object(ctx, bucket, key)).await
    }

    async fn delete_objects(&self, ctx: &Ctx<'_>, bucket: &str, targets: &[DeleteTarget]) -> Result<Vec<Result<(), S3Error>>, S3Error> {
        let mut results = Vec::new();
        for target in targets {
            results.push(if target.version_id.is_some() {
                Err(S3Error::new("NotImplemented", "Versions are not supported"))
            } else {
                self.delete_object(ctx, bucket, &target.key).await
            });
        }
        if self.short_delete_results.load(Ordering::Relaxed) {
            results.pop();
        }
        Ok(results)
    }

    async fn list_objects(&self, ctx: &Ctx<'_>, request: ListRequest) -> Result<ListPage, S3Error> {
        self.inner.list_objects(ctx, request).await
    }

    async fn create_multipart_upload(&self, ctx: &Ctx<'_>, request: CreateMultipartUploadRequest) -> Result<String, S3Error> {
        self.slow("create", self.inner.create_multipart_upload(ctx, request)).await
    }

    async fn upload_part(&self, ctx: &Ctx<'_>, request: UploadPartRequest) -> Result<UploadPartOutput, S3Error> {
        self.inner.upload_part(ctx, request).await
    }

    async fn complete_multipart_upload(&self, ctx: &Ctx<'_>, request: CompleteMultipartUploadRequest) -> Result<CompleteMultipartUploadOutput, S3Error> {
        self.note("complete");
        if self.fail_complete.load(Ordering::Relaxed) {
            return Err(S3Error::new("InternalError", "We encountered an internal error. Please try again."));
        }
        self.slow("complete", self.inner.complete_multipart_upload(ctx, request)).await
    }

    async fn abort_multipart_upload(&self, ctx: &Ctx<'_>, bucket: &str, key: &str, upload_id: &str) -> Result<(), S3Error> {
        self.slow("abort", self.inner.abort_multipart_upload(ctx, bucket, key, upload_id)).await
    }

    async fn list_parts(&self, ctx: &Ctx<'_>, request: ListPartsRequest) -> Result<ListPartsOutput, S3Error> {
        self.inner.list_parts(ctx, request).await
    }

    async fn list_multipart_uploads(&self, ctx: &Ctx<'_>, request: ListUploadsRequest) -> Result<ListUploadsOutput, S3Error> {
        self.inner.list_multipart_uploads(ctx, request).await
    }
}
