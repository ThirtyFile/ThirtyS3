//! A small S3 client for the calls a file service needs: storing objects (in one request or in parts), downloading them (whole or a range,
//! resuming by itself when the connection breaks), looking at them, deleting them and listing them. Built on [`thirtys3_core`], with
//! [`hyper`] and [`rustls`].
//!
//! ```no_run
//! use bytes::Bytes;
//! use thirtys3_client::{Client, ClientConfig, Credentials, GetOptions, PutOptions};
//!
//! # async fn example() -> Result<(), thirtys3_client::Error> {
//! let config = ClientConfig::new("my-bucket", Credentials::new("ACCESS_KEY", "SECRET_KEY")).endpoint("https://s3.example.com").region("us-east-1");
//! let client = Client::new(config)?;
//! client.put("hello.txt", Bytes::from_static(b"hello"), &PutOptions::default()).await?;
//! let object = client.get("hello.txt", &GetOptions::default()).await?;
//! assert_eq!(object.body.bytes().await?, "hello");
//! # Ok(())
//! # }
//! ```
//!
//! Requests are signed with Signature Version 4 and sent over TLS (plain `http://` only when the settings allow it). What fails in a way that can
//! pass is repeated with a growing wait. Timeouts only watch for a connection that goes quiet, never the total time of a transfer.

mod body;
mod client;
mod config;
mod error;
mod list;
mod meta;
mod multipart;
mod object;
mod retry;
mod transport;

pub use body::GetBody;
pub use client::Client;
pub use config::{Addressing, ClientConfig};
pub use error::{Error, ErrorKind};
pub use list::{ListOptions, ListPage};
pub use meta::{GetRange, ObjectMeta};
pub use multipart::{MAX_PARTS, MultipartUpload, UploadedPart, part_checksum};
pub use object::{GetOptions, GetResult, PutOptions, PutResult};
pub use thirtys3_core::checksum::ChecksumAlgorithm;
pub use thirtys3_core::{Credentials, S3Error};
