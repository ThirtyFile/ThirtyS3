//! Things a review of the server found. Each test failed before the change that fixed it.

mod support;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use support::{BUCKET, Watched, req, signed_headers, start, start_with, tag};
use thirtys3_core::Timestamp;
use thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
use thirtys3_server::{S3Service, ServerConfig};

// ---- a presigned URL signs what it lets through ----

#[tokio::test]
async fn a_presigned_upload_cannot_be_turned_into_a_copy_by_whoever_holds_it() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "victim", b"not for the holder of the link");
    let now = Timestamp::now();
    let url = support::presign(&server, "PUT", "/bucket/dest", 300, now);
    let sent = [("content-length", "0".to_owned()), ("x-amz-copy-source", "bucket/victim".to_owned())];
    let answer = support::send_raw(&server, Method::PUT, &url, &sent, Bytes::new()).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.text());
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AccessDenied"));
    assert!(server.service.backend().object(BUCKET, "dest").is_none(), "nothing was copied");
    // The same link, as it was signed, works.
    let answer = support::send_raw(&server, Method::PUT, &url, &[("content-length", "3".to_owned())], Bytes::from_static(b"abc")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
}

// ---- who may be copied from ----

#[tokio::test]
async fn a_copy_reads_its_source_with_the_rights_of_the_key_and_checks_the_conditions_on_it() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    backend.inner.insert(BUCKET, "mine", b"mine");
    backend.inner.insert("other", "secret", b"somebody else's");
    backend.unreadable.lock().unwrap().insert("other".to_owned());

    // The key may write to `bucket` and may not read `other`: the copy is refused before anything is copied.
    let answer = support::send(&server, Method::PUT, "/bucket/stolen", &[("x-amz-copy-source", "other/secret")], b"").await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{}", answer.text());
    assert!(backend.inner.object(BUCKET, "stolen").is_none());
    assert!(backend.events().iter().all(|event| !event.starts_with("copy:")), "the backend was not asked to copy: {:?}", backend.events());

    // A copy that is allowed reads the source first.
    let answer = support::send(&server, Method::PUT, "/bucket/copy", &[("x-amz-copy-source", "bucket/mine")], b"").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    let events = backend.events();
    let head = events.iter().position(|event| event == "head:bucket/mine").expect("the source was read");
    let copy = events.iter().position(|event| event == "copy:bucket/mine").expect("and then copied");
    assert!(head < copy);

    // The conditions on the source are the service's to check, whatever the backend does with them.
    backend.forget_source_conditions.store(true, std::sync::atomic::Ordering::Relaxed);
    let answer =
        support::send(&server, Method::PUT, "/bucket/copy2", &[("x-amz-copy-source", "bucket/mine"), ("x-amz-copy-source-if-match", "\"nope\"")], b"").await;
    assert_eq!(answer.status, StatusCode::PRECONDITION_FAILED, "{}", answer.text());
    assert!(backend.inner.object(BUCKET, "copy2").is_none());
}

// ---- the host of a request ----

/// A request for the service to answer in the process, signed for `host`; with no `Host` header, as HTTP/2 has none, when `with_host` is false.
fn request(method: &str, host: &str, target: &str, extra: &[(&str, &str)], with_host: bool, odd: &[(&str, &[u8])]) -> http::Request<Full<Bytes>> {
    let (headers, _) = signed_headers(host, method, target, extra, Some(0), EMPTY_PAYLOAD_SHA256, &support::signer());
    let mut builder = http::Request::builder().method(method).uri(if with_host { target.to_owned() } else { format!("http://{host}{target}") });
    for (name, value) in headers {
        if name != "host" || with_host {
            builder = builder.header(name, value);
        }
    }
    for (name, value) in odd {
        builder = builder.header(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_bytes(value).unwrap());
    }
    builder.body(Full::new(Bytes::new())).unwrap()
}

async fn answer_of(service: &S3Service<Watched>, request: http::Request<Full<Bytes>>) -> (StatusCode, String) {
    let response = service.handle(request).await;
    let status = response.status();
    (status, String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes()).into_owned())
}

fn service(config: ServerConfig) -> (S3Service<Watched>, Watched) {
    let backend = Watched::new();
    (S3Service::new(backend.clone(), config), backend)
}

#[tokio::test]
async fn a_request_with_its_host_in_the_uri_and_not_in_a_header_is_authenticated() {
    let (service, backend) = service(support::config());
    backend.inner.insert(BUCKET, "k", b"hello");
    let (status, body) = answer_of(&service, request("GET", "localhost:9000", "/bucket/k", &[], false, &[])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, "hello");
}

#[tokio::test]
async fn a_host_with_the_dot_of_the_root_is_the_same_host() {
    let config = ServerConfig { virtual_host_suffixes: vec!["s3.example.com".to_owned()], ..support::config() };
    let (service, backend) = service(config);
    backend.inner.insert(BUCKET, "photo.jpg", b"picture");
    for host in ["bucket.s3.example.com", "bucket.s3.example.com.", "Bucket.S3.Example.Com.:9000"] {
        let (status, body) = answer_of(&service, request("GET", host, "/photo.jpg", &[], true, &[])).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "picture"), "{host}");
    }
}

// ---- the name of the bucket and of the key ----

#[tokio::test]
async fn names_that_reach_outside_the_buckets_are_refused() {
    let server = start().await;
    // `..` is not a bucket, and neither is a name made with an encoded slash: the slash that ends the bucket is the one that was sent.
    for (target, code) in [
        ("/../k", "InvalidBucketName"),
        ("/./k", "InvalidBucketName"),
        ("/%2E%2E/k", "InvalidBucketName"),
        ("/bucket%2Fx/k", "NoSuchBucket"),
        ("/bucket/a%00b", "InvalidURI"),
        ("/bu%00cket/k", "InvalidBucketName"),
    ] {
        let answer = support::send(&server, Method::GET, target, &[], b"").await;
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some(code), "{target}: {}", answer.text());
    }
    // A key can have an encoded slash in it, which is a slash of the key.
    server.service.backend().insert(BUCKET, "a/b", b"x");
    assert_eq!(support::send(&server, Method::GET, "/bucket/a%2Fb", &[], b"").await.status, StatusCode::OK);
}

// ---- headers that cannot be read are not headers that are not there ----

#[tokio::test]
async fn a_condition_or_a_digest_that_cannot_be_read_is_an_error_and_not_a_write_without_it() {
    let (service, backend) = service(support::config());
    backend.inner.insert(BUCKET, "k", b"original");
    for (name, value) in [("if-none-match", b"*\xff".as_slice()), ("if-match", b"\xff"), ("content-md5", b"\xff")] {
        let mut put = request("PUT", "localhost", "/bucket/k", &[], true, &[(name, value)]);
        let (parts, _) = put.into_parts();
        put = http::Request::from_parts(parts, Full::new(Bytes::from_static(b"replaced")));
        let (status, body) = answer_of(&service, put).await;
        // The length of the body is signed as 0 in this helper, so only the status and the code matter here.
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert_eq!(tag(&body, "Code").as_deref(), Some("InvalidArgument"), "{name}: {body}");
    }
    assert_eq!(backend.inner.object(BUCKET, "k").unwrap(), "original");
}

// ---- the token of temporary credentials ----

#[tokio::test]
async fn a_wrong_token_is_not_told_apart_from_a_wrong_signature_by_someone_without_the_secret() {
    let backend = Watched::new();
    *backend.token.lock().unwrap() = Some("the-token".to_owned());
    let server = start_with(backend.clone(), support::config()).await;
    let signer_with_token = |secret: &str, token: &str| {
        thirtys3_core::Signer::new(
            thirtys3_core::Credentials { session_token: Some(token.to_owned()), ..thirtys3_core::Credentials::new(support::ACCESS_KEY, secret) },
            support::REGION,
        )
    };
    let get = |signer: thirtys3_core::Signer| {
        let server = &server;
        async move { support::send_signed(server, &signer, Timestamp::now(), Method::GET, "/bucket", &[], b"", EMPTY_PAYLOAD_SHA256).await }
    };
    // Someone who knows the access key and not the secret, with a wrong token: this is a guess at the secret, and is counted as one.
    let answer = get(signer_with_token("not-the-secret", "guess")).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"), "{}", answer.text());
    assert!(backend.events().iter().any(|event| event == "after:AKIATESTKEY:BadSignature"), "{:?}", backend.events());
    // The right secret and a wrong token is a mistake of whoever has the secret.
    let answer = get(signer_with_token(support::SECRET_KEY, "guess")).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidToken"), "{}", answer.text());
    let answer = get(signer_with_token(support::SECRET_KEY, "the-token")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
}

// ---- the length of a chunked body ----

#[tokio::test]
async fn a_chunked_body_without_its_decoded_length_is_a_411() {
    let server = start().await;
    let body = b"0\r\n\r\n";
    let (headers, _) = signed_headers(
        &server.host(),
        "PUT",
        "/bucket/k",
        &[("content-encoding", "aws-chunked")],
        Some(body.len()),
        thirtys3_core::sigv4::STREAMING_UNSIGNED_PAYLOAD_TRAILER,
        &support::signer(),
    );
    let sent: Vec<(&str, String)> = headers.iter().filter(|(name, _)| name != "host").map(|(name, value)| (name.as_str(), value.clone())).collect();
    let answer = support::send_raw(&server, Method::PUT, "/bucket/k", &sent, Bytes::from_static(body)).await;
    assert_eq!(answer.status, StatusCode::LENGTH_REQUIRED, "{}", answer.text());
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("MissingContentLength"));
}

// ---- ending an upload ----

#[tokio::test]
async fn the_list_of_parts_of_a_complete_is_checked_before_the_backend_sees_it() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    let created = req(Method::POST, "/bucket/k?uploads").send(&server).await;
    let id = tag(&created.text(), "UploadId").unwrap();
    let target = format!("/bucket/k?uploadId={id}");
    let part = |number: u32| format!("<Part><PartNumber>{number}</PartNumber><ETag>\"a\"</ETag></Part>");
    let ten_thousand_and_one: String = (1..=10_001).map(part).collect();
    for (name, parts, code) in [
        ("none", String::new(), "MalformedXML"),
        ("too many", ten_thousand_and_one, "MalformedXML"),
        ("number zero", part(0), "InvalidArgument"),
        ("number 10001", part(10_001), "InvalidArgument"),
        ("not ascending", format!("{}{}", part(2), part(1)), "InvalidPartOrder"),
        ("twice", format!("{}{}", part(1), part(1)), "InvalidPartOrder"),
    ] {
        let body = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
        let answer = req(Method::POST, &target).body(body).send(&server).await;
        assert_eq!(tag(&answer.text(), "Code").as_deref(), Some(code), "{name}: {}", &answer.text()[..answer.text().len().min(300)]);
    }
    assert!(!backend.events().iter().any(|event| event == "complete"), "the backend was asked to complete a list that makes no sense");
}

#[tokio::test]
async fn listing_buckets_has_the_limits_of_a_listing() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    let answer = support::send(&server, Method::GET, "/?max-buckets=99999999", &[], b"").await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert!(backend.events().iter().any(|event| event == "list_buckets:Some(10000)"), "{:?}", backend.events());
    let long = "x".repeat(2000);
    let answer = support::send(&server, Method::GET, &format!("/?prefix={long}"), &[], b"").await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", answer.text());
}

// ---- ranges ----

async fn get(server: &support::Server, headers: &[(&str, &str)]) -> support::Answer {
    let mut request = req(Method::GET, "/bucket/k");
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.send(server).await
}

#[tokio::test]
async fn ranges_follow_rfc_9110() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "k", b"0123456789");
    let info = server.service.backend().info(BUCKET, "k").unwrap();
    // The unit of a range is not case sensitive.
    let answer = get(&server, &[("range", "Bytes=2-4")]).await;
    assert_eq!((answer.status, answer.body.as_ref()), (StatusCode::PARTIAL_CONTENT, b"234".as_slice()));
    // `If-Range` with the ETag of the object gives the range, and with another one the whole object.
    let answer = get(&server, &[("range", "bytes=2-4"), ("if-range", &info.etag)]).await;
    assert_eq!(answer.status, StatusCode::PARTIAL_CONTENT);
    let answer = get(&server, &[("range", "bytes=2-4"), ("if-range", "\"another\"")]).await;
    assert_eq!((answer.status, answer.body.as_ref()), (StatusCode::OK, b"0123456789".as_slice()));
    let weak = format!("W/{}", info.etag);
    let answer = get(&server, &[("range", "bytes=2-4"), ("if-range", &weak)]).await;
    assert_eq!(answer.status, StatusCode::OK, "a weak ETag is never enough for a range");
    // With a date, it has to be the date of the last modification.
    let answer = get(&server, &[("range", "bytes=2-4"), ("if-range", &info.last_modified.http_date())]).await;
    assert_eq!(answer.status, StatusCode::PARTIAL_CONTENT);
    let earlier = Timestamp(info.last_modified.0 - 1).http_date();
    let answer = get(&server, &[("range", "bytes=2-4"), ("if-range", &earlier)]).await;
    assert_eq!(answer.status, StatusCode::OK);
    // A range outside the object says how long the object is.
    let answer = get(&server, &[("range", "bytes=50-60")]).await;
    assert_eq!(answer.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(answer.header("content-range"), Some("bytes */10"));
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidRange"));
}

#[tokio::test]
async fn the_checksums_of_a_whole_object_are_not_sent_with_a_part_of_it() {
    let server = start().await;
    let put = req(Method::PUT, "/bucket/k")
        .header("x-amz-checksum-crc32", &thirtys3_core::checksum::ChecksumAlgorithm::Crc32.checksum_base64(b"0123456789"))
        .body("0123456789")
        .send(&server)
        .await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.text());
    let whole = req(Method::GET, "/bucket/k").send(&server).await;
    assert!(whole.header("x-amz-checksum-crc32").is_some());
    let part = req(Method::GET, "/bucket/k").header("range", "bytes=0-3").send(&server).await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.header("x-amz-checksum-crc32"), None);
}

// ---- what is printed ----

#[test]
fn what_is_printed_of_a_request_leaves_out_its_signature_and_token() {
    use thirtys3_server::{AuthInfo, Ctx};
    let mut headers = http::HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKIA/x, Signature=SECRET-SIGNATURE"));
    headers.insert("x-amz-security-token", HeaderValue::from_static("SECRET-TOKEN"));
    headers.insert("host", HeaderValue::from_static("localhost"));
    let uri: http::Uri = "/bucket/k?X-Amz-Signature=SECRET-SIGNATURE&X-Amz-Security-Token=SECRET-TOKEN&partNumber=1".parse().unwrap();
    let extensions = http::Extensions::new();
    let info = AuthInfo { access_key: "AKIA", uri: &uri, headers: &headers, extensions: &extensions };
    let ctx =
        Ctx { access_key: "AKIA", request_id: "id", presigned: true, region: "r", method: &Method::GET, uri: &uri, headers: &headers, extensions: &extensions };
    for printed in [format!("{info:?} {info:#?}"), format!("{ctx:?} {ctx:#?}")] {
        assert!(!printed.contains("SECRET"), "{printed}");
        assert!(printed.contains("AKIA") && printed.contains("localhost") && printed.contains("partNumber=1"), "{printed}");
    }
}

// ---- the memory backend, which is what people copy ----

#[tokio::test]
async fn uploads_are_listed_after_the_key_marker_and_parts_can_be_asked_for_none_at_a_time() {
    let server = start().await;
    let mut ids = Vec::new();
    for key in ["a", "a", "b"] {
        let created = req(Method::POST, &format!("/bucket/{key}?uploads")).send(&server).await;
        ids.push((key, tag(&created.text(), "UploadId").unwrap()));
    }
    let keys = |text: &str| thirtys3_server_keys(text);
    // After a key marker alone: the uploads of keys after it, and none of the key itself.
    let answer = req(Method::GET, "/bucket?uploads&key-marker=a").send(&server).await;
    assert_eq!(keys(&answer.text()), ["b"], "{}", answer.text());
    // With an upload ID marker too: the uploads of that key whose ID is after the marker, and the keys after it.
    let first = ids[0].1.clone().min(ids[1].1.clone());
    let answer = req(Method::GET, &format!("/bucket?uploads&key-marker=a&upload-id-marker={first}")).send(&server).await;
    assert_eq!(keys(&answer.text()), ["a", "b"], "{}", answer.text());

    // No parts asked for are no parts, and the listing is not cut off, also when the upload has parts.
    let part = req(Method::PUT, &format!("/bucket/a?partNumber=1&uploadId={}", ids[0].1)).body("some data").send(&server).await;
    assert_eq!(part.status, StatusCode::OK, "{}", part.text());
    let answer = req(Method::GET, &format!("/bucket/a?uploadId={}&max-parts=0", ids[0].1)).send(&server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(tag(&answer.text(), "IsTruncated").as_deref(), Some("false"), "{}", answer.text());
}

fn thirtys3_server_keys(xml: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find("<Upload>") {
        let upload = &rest[at..];
        let key = upload.split("<Key>").nth(1).and_then(|text| text.split("</Key>").next()).unwrap_or_default();
        keys.push(key.to_owned());
        rest = &upload["<Upload>".len()..];
    }
    keys
}

// ---- an operation that changes something is done to its end ----

/// A request with a body, signed, for the service to answer in the process.
fn request_with(method: &str, target: &str, extra: &[(&str, &str)], body: &[u8]) -> http::Request<Full<Bytes>> {
    let (headers, _) = signed_headers("localhost", method, target, extra, Some(body.len()), &thirtys3_core::sha256_hex(body), &support::signer());
    let mut builder = http::Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Full::new(Bytes::copy_from_slice(body))).unwrap()
}

async fn wait_for(backend: &Watched, event: &str) {
    for _ in 0..300 {
        if backend.events().iter().any(|candidate| candidate == event) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("{event:?} did not happen: {:?}", backend.events());
}

/// Answers `request`, drops the future that answers it once `begun` has happened, and returns.
async fn drop_in_the_middle(service: &S3Service<Watched>, backend: &Watched, request: http::Request<Full<Bytes>>, begun: &str) {
    let answering = tokio::spawn({
        let service = service.clone();
        async move { service.handle(request).await }
    });
    wait_for(backend, begun).await;
    answering.abort();
    let _ = answering.await;
}

fn slow_service(config: ServerConfig) -> (S3Service<Watched>, Watched) {
    let (service, backend) = service(config);
    *backend.op_delay.lock().unwrap() = std::time::Duration::from_millis(250);
    (service, backend)
}

#[tokio::test]
async fn a_client_that_goes_away_does_not_leave_a_copy_or_a_delete_half_done() {
    let (service, backend) = slow_service(support::config());
    backend.inner.insert(BUCKET, "source", b"data");
    backend.inner.insert(BUCKET, "doomed", b"data");
    backend.inner.insert(BUCKET, "doomed too", b"data");

    drop_in_the_middle(&service, &backend, request_with("PUT", "/bucket/copy", &[("x-amz-copy-source", "bucket/source")], b""), "copy started").await;
    wait_for(&backend, "copy finished").await;
    assert_eq!(backend.inner.object(BUCKET, "copy").unwrap(), "data");

    backend.events.lock().unwrap().clear();
    drop_in_the_middle(&service, &backend, request_with("DELETE", "/bucket/doomed", &[], b""), "delete started").await;
    wait_for(&backend, "delete finished").await;
    assert!(backend.inner.object(BUCKET, "doomed").is_none());

    backend.events.lock().unwrap().clear();
    let body = b"<Delete><Object><Key>doomed too</Key></Object></Delete>";
    drop_in_the_middle(&service, &backend, request_with("POST", "/bucket?delete", &[], body), "delete started").await;
    for _ in 0..300 {
        if backend.inner.object(BUCKET, "doomed too").is_none() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the delete of several objects was left half done");
}

#[tokio::test]
async fn a_client_that_goes_away_does_not_leave_an_upload_half_put_together() {
    let (service, backend) = service(support::config());
    let created = service.handle(request_with("POST", "/bucket/big?uploads", &[], b"")).await;
    let id = tag(&String::from_utf8_lossy(&created.into_body().collect().await.unwrap().to_bytes()), "UploadId").unwrap();
    let part = service.handle(request_with("PUT", &format!("/bucket/big?partNumber=1&uploadId={id}"), &[], b"the one part")).await;
    let etag = part.headers().get("etag").unwrap().to_str().unwrap().to_owned();
    *backend.op_delay.lock().unwrap() = std::time::Duration::from_millis(250);

    let complete = format!("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>");
    drop_in_the_middle(&service, &backend, request_with("POST", &format!("/bucket/big?uploadId={id}"), &[], complete.as_bytes()), "complete started").await;
    wait_for(&backend, "complete finished").await;
    assert_eq!(backend.inner.object(BUCKET, "big").unwrap(), "the one part");
    assert_eq!(backend.inner.open_uploads(), 0);
}

#[tokio::test]
async fn the_authentication_of_such_an_operation_ends_too_and_the_hook_gets_its_call() {
    let (service, backend) = service(support::config());
    backend.inner.insert(BUCKET, "k", b"x");
    *backend.auth_delay.lock().unwrap() = std::time::Duration::from_millis(250);
    let answering = tokio::spawn({
        let service = service.clone();
        async move { service.handle(request_with("DELETE", "/bucket/k", &[], b"")).await }
    });
    wait_for(&backend, "before:AKIATESTKEY").await;
    answering.abort();
    let _ = answering.await;
    wait_for(&backend, "after:AKIATESTKEY:Verified").await;
    wait_for(&backend, "delete finished").await;
    assert!(backend.inner.object(BUCKET, "k").is_none());
}

#[tokio::test]
async fn with_the_setting_off_the_operation_goes_with_its_client() {
    let (service, backend) = slow_service(ServerConfig { detach_mutations: false, ..support::config() });
    backend.inner.insert(BUCKET, "k", b"x");
    drop_in_the_middle(&service, &backend, request_with("DELETE", "/bucket/k", &[], b""), "delete started").await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!backend.events().iter().any(|event| event == "delete finished"), "{:?}", backend.events());
    assert!(backend.inner.object(BUCKET, "k").is_some());
}

#[tokio::test]
async fn a_backend_that_panics_in_such_an_operation_is_an_internal_error_and_not_a_dead_connection() {
    let (service, backend) = service(support::config());
    backend.inner.insert(BUCKET, "k", b"x");
    backend.panic_on_delete.store(true, std::sync::atomic::Ordering::Relaxed);
    let (status, body) = answer_of(&service, request_with("DELETE", "/bucket/k", &[], b"")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(tag(&body, "Code").as_deref(), Some("InternalError"));
    // And the service goes on.
    backend.panic_on_delete.store(false, std::sync::atomic::Ordering::Relaxed);
    let (status, _) = answer_of(&service, request_with("DELETE", "/bucket/k", &[], b"")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
