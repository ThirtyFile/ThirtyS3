# Changelog

## 0.1.0

The first version. Nothing is published yet.

- `thirtys3-core`: Signature Version 4 (signing, verifying, presigned URLs, the `Date` header, `aws-chunked` chunk and trailer signatures), the S3 XML
  documents of the operations of a file service, error responses and their table of codes, ETags, and ten checksum algorithms.
- `thirtys3-client`: put, get (ranges, resuming downloads), head, delete, delete many, list, and multipart uploads, with retries, clock-skew
  correction, path-style and virtual-hosted addressing.
- `thirtys3-server`: authentication, `aws-chunked` verification, routing and S3 error responses for 17 operations over a `Backend` trait, with an
  in-memory backend and an example server. Limits on sizes and a timeout for a body that stops coming.
- Tests: the AWS documentation's examples and signing test suite, cross-checks with `aws-sigv4`, the AWS CLI v2, RustFS, random input for every
  reader of what a stranger sends, and mutation checks.
