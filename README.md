# ThirtyS3

A small S3 protocol library for Rust, client and server, written against AWS's official documentation. It covers the part of S3 that a file
service needs, not the whole API.

- `thirtys3-core`: Signature Version 4 (signing, verifying, presigned URLs, `aws-chunked`), S3 XML, error responses, ETags and checksums
- `thirtys3-client`: a client for objects, listings and multipart uploads, with retries, path-style and virtual-hosted addressing, and downloads that
  carry on from where they broke off
- `thirtys3-server`: the protocol layer of a server, which takes `http` requests and returns `http` responses. It checks signatures (header,
  presigned URL and `aws-chunked` with its chunk signatures and trailing checksums), routes the 17 operations of a file service to a `Backend` trait you
  implement, and answers with S3's errors. `MemoryBackend` is an in-memory implementation; `cargo run -p thirtys3-server --example memory_server` starts one

Cryptography is not written here: HMAC and the hashes come from the RustCrypto crates (`hmac`, `sha1`, `sha2`, `md-5`) and the CRCs from `crc-fast`.
The code is `#![forbid(unsafe_code)]`.

## What is covered

| Area | Client | Server |
| --- | --- | --- |
| Signature Version 4: header, `Date` header instead of `x-amz-date`, presigned URL | yes | yes |
| `aws-chunked` bodies: signed chunks, signed trailer, unsigned trailer | no (bodies are sent whole, signed with their SHA-256 or `UNSIGNED-PAYLOAD` over TLS) | yes |
| Operations | `PutObject`, `GetObject` (ranges, resume), `HeadObject`, `DeleteObject`, `DeleteObjects`, `ListObjectsV2`, multipart upload (create, parts, complete, abort) | the same 17 with `ListObjects` v1, `CopyObject`, `ListBuckets`, `HeadBucket`, `ListParts`, `ListMultipartUploads` |
| Checksums: CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5, XXHASH64, XXHASH3, XXHASH128; composite and full-object | yes | yes |
| Conditions: `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, copy-source conditions, `If-None-Match: *` on put | `If-Match` and `If-None-Match` on put, `If-Match` on get and when a download resumes | all of them |
| Retries, clock-skew correction, `200` with an `<Error>` body | yes | the server can answer a failed `CompleteMultipartUpload` that way (`ServerConfig::complete_failures_in_ok_response`) |
| Path-style and virtual-hosted addressing | yes | yes (`ServerConfig::virtual_host_suffixes`) |

Not supported, and answered with `NotImplemented` by the server: IAM and bucket policies, ACLs, versioning, server-side encryption, object lock, tags,
website redirects, `SelectObjectContent`, bucket configuration of any kind, Signature Version 2 and Signature Version 4a. The server never serves a
request without a valid signature.

## Limits and what a deployment has to add

The service layer is a function from an `http` request to an `http` response; connections belong to whoever mounts it.

- Set in `ServerConfig`: the biggest object (5 GiB by default), the biggest `aws-chunked` chunk (8 MiB), the biggest XML document (1 MiB), the longest
  prefix and delimiter of a listing, and how long to wait for the next piece of a body (30 seconds). The XML reader limits depth (16) and elements.
  Key names are limited to 1,024 bytes and user metadata to 2 KiB, as in S3.
- Not set here: the time a client may take to send the head of a request, the idle time of a connection, the number of connections and the size of a
  head. With hyper that is `header_read_timeout` and the limits of its connection builder.
- Every attempt to guess a key can be counted with `Backend::before_authentication` and `Backend::after_authentication`.
- The client reads at most 256 KiB of an error and limits the size of every document it reads. Its timeouts watch for silence, never for the total time
  of a transfer.

## Tested against

- The AWS documentation's own examples and AWS's signing test suite, and 30,000 random requests signed by `aws-sigv4` as well
- An in-memory S3 service that checks every signature, with faults on demand (errors, dropped connections, downloads cut off, a clock that is off)
- The AWS CLI v2 against the server: `cp`, `sync`, `mv`, `rm`, `ls`, multipart uploads of large files, `presign` and the `s3api` calls (the tests are
  skipped where `aws` is not installed)
- [RustFS](https://github.com/rustfs/rustfs) in a container (`.github/workflows/services.yml`). MinIO no longer publishes container images.
- Random input: XML documents, `Authorization` headers, `aws-chunked` framing, ranges, conditions, paths and whole requests of every operation, and a
  client against services that answer with garbage (`tests/fuzz.rs` of the core and server crates, `tests/hostile.rs` of the client). They run a few
  thousand inputs in a normal `cargo test`; for more, set `THIRTYS3_FUZZ_ITERATIONS` (and `THIRTYS3_FUZZ_SEED`).
- Mutation checks: the source was changed on purpose in more than sixty places that matter (a condition left out, a limit raised, a check skipped), and
  a test fails for every one of them.

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
