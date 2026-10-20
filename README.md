# ThirtyS3

A small S3 protocol library for Rust, client and server, written against AWS's official documentation. It covers the part of S3 that a file
service needs, not the whole API.

- `thirtys3-core`: Signature Version 4 (signing, verifying, presigned URLs, `aws-chunked`), S3 XML, error responses, ETags and checksums
- `thirtys3-client`: a client for objects, listings and multipart uploads
- `thirtys3-server`: the protocol layer of a server, which takes `http` requests and returns `http` responses
- Not supported, and answered with `NotImplemented`: IAM and bucket policies, versioning, server-side encryption, Signature Version 2

The library is under development and has no release yet.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Licence

[Apache-2.0](LICENSE)
