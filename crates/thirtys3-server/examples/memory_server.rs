//! An S3 server in memory, to try clients against.
//!
//! ```text
//! cargo run -p thirtys3-server --example memory_server
//! AWS_ACCESS_KEY_ID=AKIAEXAMPLE AWS_SECRET_ACCESS_KEY=example-secret aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://demo
//! ```
//!
//! The address is the first argument or `THIRTYS3_ADDR`; the key pair is `THIRTYS3_ACCESS_KEY` and `THIRTYS3_SECRET_KEY`. Everything is lost when
//! the server stops.

use std::convert::Infallible;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use thirtys3_server::memory::MemoryBackend;
use thirtys3_server::{S3Service, ServerConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let address = std::env::args().nth(1).or_else(|| std::env::var("THIRTYS3_ADDR").ok()).unwrap_or_else(|| "127.0.0.1:9000".to_owned());
    let access = std::env::var("THIRTYS3_ACCESS_KEY").unwrap_or_else(|_| "AKIAEXAMPLE".to_owned());
    let secret = std::env::var("THIRTYS3_SECRET_KEY").unwrap_or_else(|_| "example-secret".to_owned());
    let backend = MemoryBackend::new().with_bucket("demo").with_key(&access, &secret);
    let service = S3Service::new(backend, ServerConfig::default());

    let listener = TcpListener::bind(&address).await?;
    println!("listening on http://{}, access key {access}, bucket demo", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        let service = service.clone();
        tokio::spawn(async move {
            let hyper_service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                let service = service.clone();
                async move { Ok::<_, Infallible>(service.handle(request).await) }
            });
            let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), hyper_service).await;
        });
    }
}
