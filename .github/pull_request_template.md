## What changes

<!-- One or two sentences: what is different for the people who use the library. Closes #123 -->

## How it was tested

<!-- The test that fails without the change, and what you tried against a real client or service -->

## Checklist

- [ ] The title says what changes, in plain words (it becomes the line in the release notes)
- [ ] One label: `enhancement`, `bug`, `performance`, `documentation`, `dependencies` or `maintenance`
- [ ] The code is formatted (`cargo fmt`), and `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` pass
- [ ] A fix has a test that fails without it
- [ ] The `compatibility` page (`crates/thirtys3-core/src/compatibility.rs`), the README and the documentation are updated if behaviour changes
