# What ThirtyS3 supports, and what it checks

This page is the long version of the README: exactly which parts of S3 are covered, which limits you can set, and how the code is tested.

## Supported

| Area | Client | Server |
| --- | --- | --- |
| Signature Version 4: header, `Date` header instead of `x-amz-date`, presigned URL | yes | yes |
| `aws-chunked` bodies: signed chunks, signed trailer, unsigned trailer | no (bodies are sent whole, signed with their SHA-256, or `UNSIGNED-PAYLOAD` over TLS) | yes |
| Operations | `PutObject`, `GetObject` (ranges, resume), `HeadObject`, `DeleteObject`, `DeleteObjects`, `ListObjectsV2`, multipart upload (create, parts, complete, abort) | the same, plus `ListObjects` v1, `CopyObject`, `ListBuckets`, `HeadBucket`, `ListParts`, `ListMultipartUploads` (17 in all) |
| Checksums: CRC32, CRC32C, CRC64NVME, SHA-1, SHA-256, SHA-512, MD5, XXHASH64, XXHASH3, XXHASH128, composite and full-object | yes | yes |
| Conditions: `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, copy-source conditions | `If-Match` and `If-None-Match` on put, `If-Match` on get and when a download resumes | all of them |
| Retries, clock-skew correction, a `200` with an `<Error>` body | yes | can answer a failed `CompleteMultipartUpload` that way (`ServerConfig::complete_failures_in_ok_response`) |
| Path-style and virtual-hosted addressing | yes | yes (`ServerConfig::virtual_host_suffixes`) |

### Not supported

The server answers these with `NotImplemented`: IAM and bucket policies, ACLs, versioning, server-side encryption, object lock, tags, website
redirects, `SelectObjectContent`, bucket configuration of any kind, Signature Version 2 and Signature Version 4a. A request without a valid signature
is never served.

## Limits, and what a deployment has to add

The server is a function from an `http` request to an `http` response. Connections belong to whoever mounts it.

Set in `ServerConfig`:

- the biggest object (5 GiB by default), the biggest `aws-chunked` chunk (8 MiB) and the biggest XML document (1 MiB);
- the longest prefix and delimiter of a listing;
- how long to wait for the next piece of a body (30 seconds). It is an idle time, so a slow upload that keeps sending is not cut off.

Fixed, as in S3: keys up to 1,024 bytes, user metadata up to 2 KiB, 1,000 keys per `DeleteObjects`, 10,000 parts per upload. The XML reader limits
depth (16 levels) and the number of elements.

Not set here, so set it where you serve connections: how long a client may take to send the head of a request, the idle time of a connection, the
number of connections, and the size of a head. With hyper that is `header_read_timeout` and the limits of its connection builder.

Attempts to guess a key can be counted with `Backend::before_authentication` and `Backend::after_authentication`.

The client reads at most 256 KiB of an error and limits the size of every document it reads. Its timeouts watch for silence, never for the total time
of a transfer.

## Known limits of this version

These are things the library does not do yet, or does on purpose, that a deployment should know about.

- **Client TLS** uses the certificate store of the operating system and cannot be given another root certificate. A store with a private CA has to
  have the CA installed on the machine.
- **Client hashing** runs on the thread that polls the request: the SHA-256 of a part of 8 MiB is a few milliseconds, which is fine for a handful of
  concurrent uploads and not for hundreds.
- **Server body timeout** is a time of silence, not a minimum rate (see above). Bound the rate or the total time where connections are served.
- **A backend must be ready to be dropped.** When a client goes away, the future that is answering it is dropped at whatever `.await` it is on, in
  the middle of a copy or of the completing of an upload as well. The documentation of the `Backend` trait says what that means for an upload's body.
- **The path of a request** is decoded once, after the bucket and the key are told apart, and signed as it was sent. A reverse proxy that rewrites
  `%2F` or `//` before the service sees them changes what was signed.

## How it is tested

- The examples in the AWS documentation and AWS's own signing test suite, and 30,000 random requests signed by `aws-sigv4` as well.
- An in-memory S3 service that checks every signature, with faults on demand (errors, dropped connections, downloads cut off, a clock that is off).
- The AWS CLI v2 against the server: `cp`, `sync`, `mv`, `rm`, `ls`, multipart uploads of large files, `presign` and the `s3api` calls. The tests are
  skipped where `aws` is not installed.
- [RustFS](https://github.com/rustfs/rustfs) in a container (`.github/workflows/services.yml`). MinIO no longer publishes container images.
- Random input: XML documents, `Authorization` headers, `aws-chunked` framing, ranges, conditions, paths and whole requests of every operation, and a
  client against services that answer with garbage (`tests/fuzz.rs` in the core and server crates, `tests/hostile.rs` in the client). A normal
  `cargo test` runs a few thousand inputs. For more, set `THIRTYS3_FUZZ_ITERATIONS` and `THIRTYS3_FUZZ_SEED`.
- Mutation checks: the source was changed on purpose in more than sixty places that matter (a condition left out, a limit raised, a check skipped)
  and a test fails for every one of them.

To run the client's tests against a service of your own, set `THIRTYS3_TEST_ENDPOINT`, `THIRTYS3_TEST_BUCKET`, `THIRTYS3_TEST_ACCESS_KEY` and
`THIRTYS3_TEST_SECRET_KEY` (and `THIRTYS3_TEST_REGION`), then run `cargo test -p thirtys3-client --test service`. Use a bucket made for tests.
