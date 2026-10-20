# Changelog

## 0.1.0

The first version. Nothing is published yet.

- `thirtys3-core`: Signature Version 4 (signing, verifying, presigned URLs, the `Date` header, `aws-chunked` chunk and trailer signatures), the S3 XML
  documents of the operations of a file service, error responses and their table of codes, ETags, and ten checksum algorithms.
- `thirtys3-client`: put, get (ranges, resuming downloads), head, delete, delete many, list, and multipart uploads, with retries, clock-skew
  correction, path-style and virtual-hosted addressing.
- `thirtys3-server`: authentication, `aws-chunked` verification, routing and S3 error responses for 17 operations over a `Backend` trait, with an
  in-memory backend and an example server. Limits on sizes and a timeout for a body that stops coming.
- A review before the first release changed these, each with a test that failed before:
  - A presigned URL now has to sign every `x-amz-*` header it is used with. Before, whoever held a presigned `PUT` could add `x-amz-copy-source`
    (and the like) and turn it into a copy.
  - `CopyObject` reads its source with the rights of the key before it copies, and checks the conditions on the source itself.
  - Header checks that could not read a header (`If-None-Match`, `Content-MD5`) used to skip it; they are errors now.
  - The token of temporary credentials is compared in constant time and after the signature.
  - A body that is longer than its declared length is stopped when it goes over; data after the end of an `aws-chunked` body is an error;
    a chunked body without `x-amz-decoded-content-length` is a 411.
  - Requests without a `Host` header (HTTP/2), hosts with a trailing dot, bucket names such as `..` and keys with NUL are handled.
  - `If-Range`, `Range` units in any case, `Content-Range: bytes */N` on a 416, and no whole-object checksums on a range.
  - The client's timeout is for silence also while a request is being uploaded; a lost answer to a conditional `put` or to the completing of an
    upload no longer reads as a failure; the body of an answer that breaks off is retried; `put_multipart` aborts its upload when it is dropped;
    a download that goes on is not cut off by `retry_timeout`; `delete` no longer takes any 404 for a deleted key.
  - `Debug` of errors, `Ctx` and `AuthInfo` leaves out signatures and tokens; secrets have no `PartialEq`; public enums that will grow are
    `#[non_exhaustive]`.
- Tests: the AWS documentation's examples and signing test suite, cross-checks with `aws-sigv4`, the AWS CLI v2, RustFS, random input for every
  reader of what a stranger sends, and mutation checks.
