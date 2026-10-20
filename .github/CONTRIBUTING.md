# Contributing to ThirtyS3

Thank you for helping.

## Problems and ideas

[Open an issue](https://github.com/ThirtyFile/ThirtyS3/issues/new/choose) and pick the form that fits: a problem, an idea, the documentation, or an improvement to the code. Look through the [existing issues](https://github.com/ThirtyFile/ThirtyS3/issues) first.

Security problems are reported privately: see the [security policy](SECURITY.md).

## Changing the code

1. For anything larger than a small fix, agree on the idea in an issue first.
2. Create a branch from `main`: `feat/…`, `fix/…`, `docs/…` or `chore/…`.
3. Every fix comes with a test that fails without it. Format the code and run the checks:
   ```bash
   cargo fmt
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --locked
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
   ```
   Set `THIRTYS3_FUZZ_ITERATIONS=100000` to run the random-input tests for longer. Some tests use the AWS CLI when it is installed; the others do not need it. Pull requests run the same on Linux and Windows, the build of the fuzz crate, `cargo package` and `cargo deny`. The fuzz targets run weekly (**Actions > Fuzz > Run workflow** runs them now), `main` is scanned with CodeQL after merges and every week, and the client is tried against a real service (RustFS) in the **Services** workflow.
4. Open a pull request with a title that says what changes, one label (`enhancement`, `bug`, `performance`, `documentation`, `dependencies` or `maintenance`), and `Closes #123` in the description. Pull requests are squash-merged.

Code, comments and documentation are written in English. A change in what the library supports or checks is written in the `compatibility` page of the `thirtys3-core` documentation (`crates/thirtys3-core/src/compatibility.rs`). The documentation of a module names the pages of the AWS documentation it follows; some of those pages are gone from the current documentation, and the module then says which archived version it uses.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](../LICENSE), and you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).
