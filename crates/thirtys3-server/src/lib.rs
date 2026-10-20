//! A small S3 server protocol layer: authentication and routing for the operations a file service offers. Built on [`thirtys3_core`].

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
