//! The protocol layer of an S3 server: it checks who sent a request and what the request carries, works out which operation it is, calls a
//! [`Backend`] for the storage, and writes the answer in S3's format. It takes and returns [`http`] types, so it runs under any server that does
//! (hyper, axum, a `tower` stack) and keeps no connections of its own. Built on [`thirtys3_core`].
//!
//! # What it does
//!
//! - **Authentication** comes before anything else, the routing included: Signature Version 4 in the `Authorization` header (or the `Date` header
//!   instead of `x-amz-date`), in the query of a presigned URL, and over an `aws-chunked` body with a signature for every chunk and for the
//!   trailing headers. A clock that is out of step is refused before an attempt is counted, so the hooks [`Backend::before_authentication`] and
//!   [`Backend::after_authentication`] can limit attempts to guess a key.
//! - **The body of an upload** is checked while it streams to the backend: `Content-Length` or the decoded length of a chunked body, `Content-MD5`,
//!   `x-amz-content-sha256`, the checksums in the headers and in the trailer, the size limit, and the chunk signatures. Data reaches the backend as
//!   it arrives, and an upload is good only if the stream ended with `None`: a backend must not keep what a stream that ended with an error gave it.
//! - **The operations** are `ListBuckets`, `HeadBucket`, `ListObjects` and `ListObjectsV2`, `GetObject`, `HeadObject`, `PutObject`, `CopyObject`,
//!   `DeleteObject`, `DeleteObjects`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListParts` and
//!   `ListMultipartUploads`. Conditions (`If-Match` and the others), ranges and the `response-*` overrides are handled here, so a backend only
//!   gives the data. What it does not do (versioning, ACLs, encryption, tags, object lock, the rest of S3) is answered with `NotImplemented`.
//! - **Limits** are in [`ServerConfig`]: the size of an object, of a chunk and of a document, how long a listing's prefix may be, and how long the
//!   service waits for the next piece of a body. The head of a request and the idle time of a connection are for the code that serves connections.
//!
//! # Using it
//!
//! ```no_run
//! use std::convert::Infallible;
//!
//! use hyper::server::conn::http1;
//! use hyper::service::service_fn;
//! use hyper_util::rt::TokioIo;
//! use thirtys3_server::memory::MemoryBackend;
//! use thirtys3_server::{S3Service, ServerConfig};
//!
//! # async fn example() -> std::io::Result<()> {
//! let backend = MemoryBackend::new().with_bucket("demo").with_key("ACCESS_KEY", "SECRET_KEY");
//! let service = S3Service::new(backend, ServerConfig::default());
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:9000").await?;
//! loop {
//!     let (stream, _) = listener.accept().await?;
//!     let service = service.clone();
//!     tokio::spawn(async move {
//!         let hyper_service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
//!             let service = service.clone();
//!             async move { Ok::<_, Infallible>(service.handle(request).await) }
//!         });
//!         let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), hyper_service).await;
//!     });
//! }
//! # }
//! ```
//!
//! For a real service, implement [`Backend`] over your storage: `secret_key` finds the secret of an access key, and the other methods are the
//! operations. [`memory::MemoryBackend`] is a complete example of one.

// `S3Error` is the error type of every operation of a backend and carries what a response needs, so it is not small.
#![allow(clippy::result_large_err)]

pub mod backend;
pub mod body;
pub mod chunked;
pub mod conditions;
pub mod config;
pub mod memory;
mod ops;
pub mod route;
mod service;

pub use backend::*;
pub use body::{BodyPlan, Digests, RequestBody};
pub use config::ServerConfig;
pub use service::{ResponseBody, S3Service};
