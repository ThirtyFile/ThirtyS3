//! The AWS CLI against the server, which speaks the `aws-chunked` framing with trailing checksums that the SDKs of today use. The tests are skipped when
//! `aws` is not on the path.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use support::{ACCESS_KEY, BUCKET, REGION, SECRET_KEY, Server, start};
use thirtys3_core::checksum::ChecksumAlgorithm;

fn aws_exists() -> bool {
    Command::new("aws").arg("--version").output().map(|output| output.status.success()).unwrap_or(false)
}

struct Cli<'a> {
    server: &'a Server,
    home: PathBuf,
}

impl<'a> Cli<'a> {
    fn new(server: &'a Server, name: &str) -> Self {
        let home = std::env::temp_dir().join(format!("thirtys3-awscli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        Self { server, home }
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let output = Command::new("aws")
            .arg("--endpoint-url")
            .arg(self.server.endpoint())
            .args(args)
            .env("AWS_ACCESS_KEY_ID", ACCESS_KEY)
            .env("AWS_SECRET_ACCESS_KEY", SECRET_KEY)
            .env("AWS_DEFAULT_REGION", REGION)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_CONFIG_FILE", self.home.join("config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", self.home.join("credentials"))
            .env("AWS_PAGER", "")
            .output()
            .expect("aws runs");
        (output.status.success(), String::from_utf8_lossy(&output.stdout).into_owned(), String::from_utf8_lossy(&output.stderr).into_owned())
    }

    fn ok(&self, args: &[&str]) -> String {
        let (success, out, err) = self.run(args);
        assert!(success, "aws {args:?} failed:\n{out}\n{err}");
        out
    }

    fn file(&self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.home.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Cli<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i * 7 + i / 31) as u8).collect()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn copy_list_head_and_remove() {
    if !aws_exists() {
        return;
    }
    let server = start().await;
    let cli = Cli::new(&server, "basic");
    let content = data(1_500_000);
    let source = cli.file("source.bin", &content);
    cli.ok(&["s3", "cp", text(&source), &format!("s3://{BUCKET}/dir/one.bin")]);
    assert_eq!(server.service.backend().object(BUCKET, "dir/one.bin").unwrap(), content);
    // The CLI sends a checksum in the trailer; the server keeps it.
    let kept = server.service.backend().info(BUCKET, "dir/one.bin").unwrap();
    assert!(!kept.checksums.is_empty(), "{kept:?}");
    for algorithm in [ChecksumAlgorithm::Crc32, ChecksumAlgorithm::Crc32c, ChecksumAlgorithm::Crc64Nvme, ChecksumAlgorithm::Sha256] {
        if let Some(value) = kept.checksums.get(algorithm) {
            assert_eq!(value, algorithm.checksum_base64(&content), "{algorithm:?}");
        }
    }

    let two = cli.file("two.txt", b"two");
    cli.ok(&["s3", "cp", text(&two), &format!("s3://{BUCKET}/dir/two.txt")]);
    let listing = cli.ok(&["s3", "ls", &format!("s3://{BUCKET}/dir/")]);
    assert!(listing.contains("one.bin"), "{listing}");
    let listing = cli.ok(&["s3", "ls", &format!("s3://{BUCKET}/"), "--recursive", "--summarize"]);
    assert!(listing.contains("Total Objects: 2"), "{listing}");

    let head = cli.ok(&["s3api", "head-object", "--bucket", BUCKET, "--key", "dir/one.bin"]);
    assert!(head.contains("\"ContentLength\": 1500000"), "{head}");

    let back = cli.home.join("back.bin");
    cli.ok(&["s3", "cp", &format!("s3://{BUCKET}/dir/one.bin"), text(&back)]);
    assert_eq!(std::fs::read(&back).unwrap(), content);

    cli.ok(&["s3", "mv", &format!("s3://{BUCKET}/dir/one.bin"), &format!("s3://{BUCKET}/moved/one.bin")]);
    assert_eq!(server.service.backend().keys(BUCKET), ["dir/two.txt", "moved/one.bin"]);
    cli.ok(&["s3", "rm", &format!("s3://{BUCKET}/"), "--recursive"]);
    assert!(server.service.backend().keys(BUCKET).is_empty());
    // A key that is not there is an error with the code of S3.
    let (success, _, err) = cli.run(&["s3api", "head-object", "--bucket", BUCKET, "--key", "gone"]);
    assert!(!success && err.contains("404"), "{err}");
    let sink = cli.home.join("sink");
    let (success, _, err) = cli.run(&["s3api", "get-object", "--bucket", BUCKET, "--key", "gone", text(&sink)]);
    assert!(!success && err.contains("NoSuchKey"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_file_goes_in_parts_and_a_directory_is_synced() {
    if !aws_exists() {
        return;
    }
    let server = start().await;
    let cli = Cli::new(&server, "large");
    // More than the threshold of the CLI for a multipart upload (8 MiB), so it sends parts of 8 MiB, each in `aws-chunked` with a trailer.
    let content = data(20 * 1024 * 1024 + 123);
    let source = cli.file("large.bin", &content);
    cli.ok(&["s3", "cp", text(&source), &format!("s3://{BUCKET}/large.bin")]);
    assert_eq!(server.service.backend().object(BUCKET, "large.bin").unwrap(), content);
    assert_eq!(server.service.backend().open_uploads(), 0);
    let head = cli.ok(&["s3api", "head-object", "--bucket", BUCKET, "--key", "large.bin"]);
    assert!(head.contains("-3"), "the ETag of three parts: {head}");
    let back = cli.home.join("large.back");
    cli.ok(&["s3", "cp", &format!("s3://{BUCKET}/large.bin"), text(&back)]);
    assert_eq!(std::fs::read(&back).unwrap(), content);

    let tree = cli.home.join("tree");
    std::fs::create_dir_all(tree.join("sub dir")).unwrap();
    std::fs::write(tree.join("a.txt"), b"a").unwrap();
    std::fs::write(tree.join("sub dir").join("b c+d.txt"), b"bcd").unwrap();
    std::fs::write(tree.join("sub dir").join("\u{fc}.txt"), b"u").unwrap();
    // The CLI uploads what is newer than the object; times in S3 are whole seconds, so the files are made older than the second of the upload.
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
    for path in [tree.join("a.txt"), tree.join("sub dir").join("b c+d.txt"), tree.join("sub dir").join("\u{fc}.txt")] {
        std::fs::File::options().write(true).open(path).unwrap().set_modified(past).unwrap();
    }
    cli.ok(&["s3", "sync", text(&tree), &format!("s3://{BUCKET}/tree")]);
    assert_eq!(server.service.backend().keys(BUCKET), ["large.bin", "tree/a.txt", "tree/sub dir/b c+d.txt", "tree/sub dir/\u{fc}.txt"]);
    let out = cli.home.join("out");
    cli.ok(&["s3", "sync", &format!("s3://{BUCKET}/tree"), text(&out)]);
    assert_eq!(std::fs::read(out.join("sub dir").join("b c+d.txt")).unwrap(), b"bcd");
    // A second sync has nothing to do.
    let again = cli.ok(&["s3", "sync", text(&tree), &format!("s3://{BUCKET}/tree")]);
    assert!(again.trim().is_empty(), "{again}");
}

#[tokio::test(flavor = "multi_thread")]
async fn api_calls_copy_delete_many_and_presign() {
    if !aws_exists() {
        return;
    }
    let server = start().await;
    let cli = Cli::new(&server, "api");
    server.service.backend().insert(BUCKET, "a/1", b"one");
    server.service.backend().insert(BUCKET, "a/2", b"two");
    server.service.backend().insert(BUCKET, "b/3", b"three");

    let listing = cli.ok(&["s3api", "list-objects-v2", "--bucket", BUCKET, "--delimiter", "/", "--output", "json"]);
    assert!(listing.contains("\"Prefix\": \"a/\"") && listing.contains("\"Prefix\": \"b/\""), "{listing}");
    let paged = cli.ok(&["s3api", "list-objects-v2", "--bucket", BUCKET, "--max-items", "1", "--page-size", "1", "--output", "json"]);
    assert!(paged.contains("NextToken"), "{paged}");
    let v1 = cli.ok(&["s3api", "list-objects", "--bucket", BUCKET, "--prefix", "a/"]);
    assert!(v1.contains("a/1") && v1.contains("a/2") && !v1.contains("b/3"), "{v1}");

    cli.ok(&["s3api", "copy-object", "--bucket", BUCKET, "--key", "copy", "--copy-source", &format!("{BUCKET}/a/1")]);
    assert_eq!(server.service.backend().object(BUCKET, "copy").unwrap(), "one");

    let delete = cli.file("delete.json", br#"{"Objects":[{"Key":"a/1"},{"Key":"a/2"},{"Key":"never-there"}],"Quiet":false}"#);
    let out = cli.ok(&["s3api", "delete-objects", "--bucket", BUCKET, "--delete", &format!("file://{}", text(&delete))]);
    assert!(out.contains("never-there"), "a key that is not there is deleted too: {out}");
    assert_eq!(server.service.backend().keys(BUCKET), ["b/3", "copy"]);

    let url = cli.ok(&["s3", "presign", &format!("s3://{BUCKET}/b/3"), "--expires-in", "300"]).trim().to_owned();
    let target = url.strip_prefix(&server.endpoint()).unwrap_or_else(|| panic!("{url}"));
    let got = support::send_raw(&server, http::Method::GET, target, &[], bytes::Bytes::new()).await;
    assert_eq!((got.status, got.body.as_ref()), (http::StatusCode::OK, b"three".as_slice()));

    let buckets = cli.ok(&["s3api", "list-buckets"]);
    assert!(buckets.contains(BUCKET), "{buckets}");
    let (success, _, err) = cli.run(&["s3api", "list-objects-v2", "--bucket", "no-such-bucket"]);
    assert!(!success && err.contains("NoSuchBucket"), "{err}");
}
