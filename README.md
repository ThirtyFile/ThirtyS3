# ThirtyS3

A small S3 protocol library for Rust, client and server, written against AWS's official documentation. It covers the part of S3 that a file
service needs, not the whole API.

- `thirtys3-core`: Signature Version 4 (signing, verifying, presigned URLs, `aws-chunked`), S3 XML, error responses, ETags and checksums
- `thirtys3-client`: a client for objects, listings and multipart uploads, with retries, path-style and virtual-hosted addressing, and downloads that
  carry on from where they broke off
- `thirtys3-server`: the protocol layer of a server, which takes `http` requests and returns `http` responses
- Not supported, and answered with `NotImplemented`: IAM and bucket policies, versioning, server-side encryption, Signature Version 2

The library is under development and has no release yet.

## Tested against

- The AWS documentation's own examples and AWS's signing test suite, and 30,000 random requests signed by `aws-sigv4` as well
- An in-memory S3 service that checks every signature, with faults on demand (errors, dropped connections, downloads cut off, a clock that is off)
- [RustFS](https://github.com/rustfs/rustfs) in a container (`.github/workflows/services.yml`). MinIO no longer publishes container images.

To run the tests of the client against a service of your own, set `THIRTYS3_TEST_ENDPOINT`, `THIRTYS3_TEST_BUCKET`, `THIRTYS3_TEST_ACCESS_KEY` and
`THIRTYS3_TEST_SECRET_KEY` (and `THIRTYS3_TEST_REGION`) and run `cargo test -p thirtys3-client --test service`. Use a bucket for tests.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Licence

[Apache-2.0](LICENSE)
