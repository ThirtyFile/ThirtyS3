# AWS SigV4 signing test suite (v4)

A copy of the `v4` cases of the AWS signing test suite, taken from the `aws-sigv4` crate 1.6.0 (`aws-signing-test-suite/`), which took it from
the CRT test suite at <https://github.com/awslabs/aws-c-auth/tree/v0.9.0/tests/aws-signing-test-suite>. It is licensed under the Apache License 2.0
(see `LICENSE`). Only the Signature Version 4 cases are kept; the Signature Version 4a cases are not used.

`tests/suite.rs` runs it. S3 differs from the suite's `service` in one way that matters: it does not normalise the path (`.`, `..` and `//` are
part of an object key). The cases that expect a normalised path are therefore compared with their `-unnormalized` twins instead.
