# ThirtyS3

**A small, honest S3 library for Rust: a client and a server that speak the same protocol, written from AWS's own documentation.**

Most S3 libraries try to cover the whole of AWS. ThirtyS3 does the opposite. It covers the part of S3 that a file service really uses (upload,
download, list, copy, delete, multipart) and tries to get every detail of that part right: signatures, `aws-chunked` uploads, checksums, error
responses, retries, and what happens when a connection breaks halfway through.

It has three crates that work together or on their own:

| Crate | What it is for |
| --- | --- |
| `thirtys3-client` | Talk to AWS S3, MinIO, RustFS and friends. Retries, resumable downloads, multipart uploads. |
| `thirtys3-server` | Be an S3 endpoint in front of your own storage. Implement one trait and the usual tools just work. |
| `thirtys3-core` | The shared parts: Signature Version 4, S3 XML, error responses, ETags, checksums. |

> **Status:** version 0.1.0, on [crates.io](https://crates.io/crates/thirtys3-client). The tests are thorough, but it has not seen production traffic yet. Please try
> it, and tell us what breaks.

```sh
cargo add thirtys3-client   # to talk to an S3 service
cargo add thirtys3-server   # to be one
```

## Why another S3 library?

- **Small on purpose.** About 8,000 lines of Rust, no unsafe code, and no hand-written cryptography (HMAC and hashes come from RustCrypto).
- **One protocol implementation for both sides.** The client and the server share the same signing and parsing code, so they are tested against each
  other, as well as against the AWS CLI and a real S3-compatible service.
- **Careful with uploads.** The server checks the signature of every chunk and every checksum while the data streams in, and never lets a backend
  mistake a cut-off or tampered upload for a finished one.
- **Careful with hostile input.** Every reader of untrusted bytes (XML, headers, chunk framing, paths) has limits and is tested with random input.

## Try it in two minutes

Start a server that keeps everything in memory:

```sh
cargo run -p thirtys3-server --example memory_server
```

Then use it with the tools you already have:

```sh
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE AWS_SECRET_ACCESS_KEY=example-secret AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://127.0.0.1:9000 s3 cp ./photo.jpg s3://demo/photo.jpg
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://demo
```

## Using the client

```rust
use bytes::Bytes;
use thirtys3_client::{Client, ClientConfig, Credentials, GetOptions, PutOptions};

async fn example() -> Result<(), thirtys3_client::Error> {
    let config = ClientConfig::new("my-bucket", Credentials::new("ACCESS_KEY", "SECRET_KEY"))
        .endpoint("https://s3.example.com")
        .region("us-east-1");
    let client = Client::new(config)?;

    client.put("hello.txt", Bytes::from_static(b"hello"), &PutOptions::default()).await?;
    let object = client.get("hello.txt", &GetOptions::default()).await?;
    assert_eq!(object.body.bytes().await?, "hello");
    Ok(())
}
```

Big files go through `put_multipart`, listings come back as streams, and a download that loses its connection picks up where it stopped (and
notices if the object changed in the meantime).

## Using the server

Give `S3Service` a `Backend` (your storage) and a `ServerConfig`, then hand it `http` requests. It works with hyper, axum or anything that speaks the
`http` crate's types. The complete example is in [`crates/thirtys3-server/examples/memory_server.rs`](crates/thirtys3-server/examples/memory_server.rs),
and `MemoryBackend` shows how a backend looks.

The server takes care of authentication, the body checks, routing, conditions, ranges and S3-style errors. Your backend only stores and returns data.

## What is and is not covered

ThirtyS3 handles uploads, downloads, listings, copies, deletes and multipart uploads, with Signature Version 4 in headers or in presigned URLs. It does
not do IAM, bucket policies, ACLs, versioning, server-side encryption or the many bucket-level settings, and the server answers those with
`NotImplemented`. The full list, the limits you can set and how everything is tested are on the `compatibility` page of the `thirtys3-core` documentation.

## Contributing

Bug reports, questions and patches are welcome. A good bug report has the request that went wrong. A good patch comes with a test that fails
without it. Before you send one:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Set `THIRTYS3_FUZZ_ITERATIONS=100000` to run the random-input tests for longer. Please write issues, comments and commit messages in English.

## Licence

[Apache-2.0](LICENSE)
