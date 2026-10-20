//! The protocol as the server speaks it, with raw requests: the errors, the authentication, the routing, and what is refused.

mod support;

use http::{Method, StatusCode};
use support::{BUCKET, Watched, req, start, start_with, tag};
use thirtys3_core::{Credentials, Signer, Timestamp};

#[tokio::test]
async fn every_answer_has_a_request_id_and_the_headers_s3_has() {
    let server = start().await;
    let first = req(Method::GET, "/").send(&server).await;
    let second = req(Method::GET, "/").send(&server).await;
    assert_eq!(first.status, StatusCode::OK);
    let id = first.header("x-amz-request-id").unwrap();
    assert_eq!(id.len(), 16);
    assert!(id.bytes().all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)), "{id}");
    assert_ne!(Some(id), second.header("x-amz-request-id"));
    assert_eq!(first.header("x-amz-id-2"), Some(id));
    assert_eq!(first.header("server"), Some("thirtys3"));
    assert!(first.header("date").unwrap().ends_with(" GMT"));
    assert_eq!(first.header("content-type"), Some("application/xml"));
}

#[tokio::test]
async fn an_error_is_the_document_of_the_documentation() {
    let server = start().await;
    let answer = req(Method::GET, "/bucket/no-such-key").send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.header("content-type"), Some("application/xml"));
    let xml = answer.text();
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>"), "{xml}");
    assert_eq!(tag(&xml, "Code").as_deref(), Some("NoSuchKey"));
    assert_eq!(tag(&xml, "Key").as_deref(), Some("no-such-key"));
    assert_eq!(tag(&xml, "Resource").as_deref(), Some("/bucket/no-such-key"));
    assert_eq!(tag(&xml, "RequestId").as_deref(), answer.header("x-amz-request-id"));
    assert_eq!(tag(&xml, "HostId").as_deref(), answer.header("x-amz-id-2"));
    assert!(tag(&xml, "Message").is_some());
}

#[tokio::test]
async fn an_error_to_a_head_has_a_status_and_no_body() {
    let server = start().await;
    let answer = req(Method::HEAD, "/bucket/no-such-key").send(&server).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert!(answer.body.is_empty());
    assert!(answer.header("x-amz-request-id").is_some());
    assert_eq!(req(Method::HEAD, "/no-such-bucket").send(&server).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_request_without_a_signature_is_refused_and_so_is_anything_else_that_is_not_sigv4() {
    let server = start().await;
    for (name, answer) in [
        ("no signature", req(Method::GET, "/bucket/k").unsigned().send(&server).await),
        ("list buckets", req(Method::GET, "/").unsigned().send(&server).await),
        (
            "signature version 2",
            req(Method::GET, "/bucket/k")
                .unsigned()
                .header("authorization", "AWS AKIATESTKEY:frJIUN8DYpKDtOLCwo//yllqDzg=")
                .header("date", "Tue, 27 Mar 2007 19:36:42 +0000")
                .send(&server)
                .await,
        ),
    ] {
        assert!(answer.status == StatusCode::FORBIDDEN || answer.status == StatusCode::BAD_REQUEST, "{name}: {:?}", answer.status);
        assert!(answer.text().contains("<Error>"), "{name}");
    }
    assert_eq!(tag(&req(Method::GET, "/bucket/k").unsigned().send(&server).await.text(), "Code").as_deref(), Some("AccessDenied"));
    assert_eq!(
        tag(&req(Method::GET, "/bucket/k").unsigned().header("authorization", "AWS AKIATESTKEY:x").send(&server).await.text(), "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn a_wrong_signature_and_an_unknown_key_are_told_apart() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    let wrong = req(Method::GET, "/bucket/k").signer(Signer::new(Credentials::new(support::ACCESS_KEY, "not the secret"), support::REGION)).send(&server).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    assert_eq!(tag(&wrong.text(), "Code").as_deref(), Some("SignatureDoesNotMatch"));
    assert_eq!(tag(&wrong.text(), "AWSAccessKeyId").as_deref(), Some(support::ACCESS_KEY));
    let unknown = req(Method::GET, "/bucket/k").signer(Signer::new(Credentials::new("AKIAUNKNOWN", "x"), support::REGION)).send(&server).await;
    assert_eq!(tag(&unknown.text(), "Code").as_deref(), Some("InvalidAccessKeyId"));
    assert_eq!(unknown.status, StatusCode::FORBIDDEN);
    let fine = req(Method::GET, "/bucket/k").send(&server).await;
    assert_eq!(fine.status, StatusCode::NOT_FOUND, "signed right, and then there is no such key");
    assert_eq!(
        backend.events(),
        [
            "before:AKIATESTKEY",
            "after:AKIATESTKEY:BadSignature",
            "before:AKIAUNKNOWN",
            "after:AKIAUNKNOWN:UnknownKey",
            "before:AKIATESTKEY",
            "after:AKIATESTKEY:Verified",
        ]
    );
}

#[tokio::test]
async fn a_key_the_backend_refuses_is_no_guess() {
    let backend = Watched::new();
    backend.refused.lock().unwrap().insert(support::ACCESS_KEY.to_owned());
    let server = start_with(backend.clone(), support::config()).await;
    let answer = req(Method::GET, "/bucket/k").send(&server).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AccessDenied"));
    assert_eq!(backend.events(), ["before:AKIATESTKEY", "after:AKIATESTKEY:Refused"]);
}

#[tokio::test]
async fn a_clock_that_is_out_of_step_is_refused_before_anything_is_counted() {
    let backend = Watched::new();
    let server = start_with(backend.clone(), support::config()).await;
    // Margins of ten seconds on both sides of the 900 of the limit: the time of the request is made first and the server looks at it later, perhaps seconds
    // later on a slow machine, and a second that goes by in between moves a request that is on the line to the other side of it
    for offset in [-3600, 3600, -910, 910] {
        let answer = req(Method::GET, "/bucket/k").at(Timestamp(Timestamp::now().0 + offset)).send(&server).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{offset}");
        let xml = answer.text();
        assert_eq!(tag(&xml, "Code").as_deref(), Some("RequestTimeTooSkewed"), "{offset}");
        assert_eq!(tag(&xml, "MaxAllowedSkewMilliseconds").as_deref(), Some("900000"));
        assert!(tag(&xml, "ServerTime").is_some() && tag(&xml, "RequestTime").is_some());
    }
    assert!(backend.events().is_empty(), "no attempt was begun: {:?}", backend.events());
    for offset in [-890, 890] {
        assert_eq!(req(Method::GET, "/bucket/k").at(Timestamp(Timestamp::now().0 + offset)).send(&server).await.status, StatusCode::NOT_FOUND, "{offset}");
    }
}

#[tokio::test]
async fn a_region_that_is_not_the_servers_is_refused_with_the_right_one() {
    let server = start().await;
    let other = Signer::new(Credentials::new(support::ACCESS_KEY, support::SECRET_KEY), "eu-west-1");
    let answer = req(Method::GET, "/bucket/k").signer(other).send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AuthorizationHeaderMalformed"));
    assert_eq!(tag(&answer.text(), "Region").as_deref(), Some(support::REGION));
    // Unless the service does not care.
    let lenient = start_with(support::backend(), thirtys3_server::ServerConfig { enforce_region: false, ..support::config() }).await;
    let other = Signer::new(Credentials::new(support::ACCESS_KEY, support::SECRET_KEY), "eu-west-1");
    assert_eq!(req(Method::GET, "/bucket/k").signer(other).send(&lenient).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_attempt_limit_of_the_backend_is_the_answer() {
    let backend = Watched::new();
    backend.limit_attempts.store(true, std::sync::atomic::Ordering::Relaxed);
    let server = start_with(backend.clone(), support::config()).await;
    let answer = req(Method::GET, "/bucket/k").send(&server).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("SlowDown"));
    assert_eq!(backend.events(), ["before:AKIATESTKEY"], "after_authentication is not called when before_authentication refused");
}

#[tokio::test]
async fn a_session_token_that_has_to_come_with_the_key() {
    let backend = Watched::new();
    *backend.token.lock().unwrap() = Some("TOKEN".to_owned());
    let server = start_with(backend.clone(), support::config()).await;
    let without = req(Method::GET, "/bucket/k").send(&server).await;
    assert_eq!(tag(&without.text(), "Code").as_deref(), Some("InvalidToken"));
    let with = Signer::new(Credentials { session_token: Some("TOKEN".into()), ..Credentials::new(support::ACCESS_KEY, support::SECRET_KEY) }, support::REGION);
    assert_eq!(req(Method::GET, "/bucket/k").signer(with).send(&server).await.status, StatusCode::NOT_FOUND);
    let wrong = Signer::new(Credentials { session_token: Some("OTHER".into()), ..Credentials::new(support::ACCESS_KEY, support::SECRET_KEY) }, support::REGION);
    assert_eq!(tag(&req(Method::GET, "/bucket/k").signer(wrong).send(&server).await.text(), "Code").as_deref(), Some("InvalidToken"));
    assert_eq!(backend.events().iter().filter(|event| event.ends_with(":Failed")).count(), 2);
}

#[tokio::test]
async fn headers_that_were_not_signed_are_refused() {
    let server = start().await;
    let answer = req(Method::PUT, "/bucket/k").body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK);
    // x-amz-meta-sneaky is sent but was not part of what was signed.
    let (path, query) = ("/bucket/k2", "");
    let host = server.host();
    let headers = [("host", host.as_str()), ("content-length", "1")];
    let request = thirtys3_core::Request { method: "PUT", path, query, headers: &headers };
    let signed = support::signer().sign(&request, &thirtys3_core::sha256_hex(b"x"), Timestamp::now()).unwrap();
    let mut sent: Vec<(&str, String)> = vec![("content-length", "1".to_owned()), ("x-amz-meta-sneaky", "1".to_owned())];
    sent.extend(signed.headers.iter().map(|(name, value)| (name.as_str(), value.clone())));
    let answer = support::send_raw(&server, Method::PUT, "/bucket/k2", &sent, "x".into()).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AccessDenied"));
    assert!(tag(&answer.text(), "HeadersNotSigned").unwrap().contains("x-amz-meta-sneaky"));
}

#[tokio::test]
async fn the_date_header_is_the_time_of_a_request_that_has_no_x_amz_date() {
    use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, Scope, SigningKey, canonical_request, string_to_sign};
    let server = start().await;
    let now = Timestamp::now();
    let date = now.http_date();
    let host = server.host();
    let headers = [("host", host.as_str()), ("date", date.as_str()), ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)];
    let names: Vec<String> = ["date", "host", "x-amz-content-sha256"].iter().map(|name| (*name).to_owned()).collect();
    let request = thirtys3_core::Request { method: "GET", path: "/bucket", query: "list-type=2", headers: &headers };
    let canonical = canonical_request(&request, &names, EMPTY_PAYLOAD_SHA256, false).unwrap();
    let scope = Scope::new(now, support::REGION);
    let signature = SigningKey::derive(support::SECRET_KEY, &scope).sign_hex(string_to_sign(&now.amz_date(), &scope, &canonical).as_bytes());
    let authorization = format!("AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders=date;host;x-amz-content-sha256,Signature={signature}", support::ACCESS_KEY);
    let sent = [("date", date.clone()), ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256.to_owned()), ("authorization", authorization.clone())];
    let answer = support::send_raw(&server, Method::GET, "/bucket?list-type=2", &sent, bytes::Bytes::new()).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    // An hour ago is too far.
    let old = Timestamp(now.0 - 3600);
    let stale = [("date", old.http_date()), ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256.to_owned()), ("authorization", authorization)];
    let answer = support::send_raw(&server, Method::GET, "/bucket?list-type=2", &stale, bytes::Bytes::new()).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
}

// ---- routing ----

#[tokio::test]
async fn operations_that_are_not_done_are_not_implemented_and_are_not_mistaken_for_others() {
    let server = start().await;
    server.service.backend().insert(BUCKET, "k", b"data");
    for (method, target) in [
        (Method::GET, "/bucket?acl"),
        (Method::GET, "/bucket?versioning"),
        (Method::GET, "/bucket?versions"),
        (Method::GET, "/bucket?tagging"),
        (Method::GET, "/bucket?policy"),
        (Method::GET, "/bucket?cors"),
        (Method::GET, "/bucket?lifecycle"),
        (Method::GET, "/bucket?encryption"),
        (Method::GET, "/bucket?object-lock"),
        (Method::PUT, "/bucket?acl"),
        (Method::PUT, "/bucket"),
        (Method::DELETE, "/bucket"),
        (Method::POST, "/bucket"),
        (Method::GET, "/bucket/k?acl"),
        (Method::GET, "/bucket/k?tagging"),
        (Method::GET, "/bucket/k?attributes"),
        (Method::GET, "/bucket/k?torrent"),
        (Method::GET, "/bucket/k?versionId=abc"),
        (Method::HEAD, "/bucket/k?versionId=abc"),
        (Method::DELETE, "/bucket/k?versionId=abc"),
        (Method::PUT, "/bucket/k?acl"),
        (Method::PUT, "/bucket/k?tagging"),
        (Method::POST, "/bucket/k?restore"),
        (Method::POST, "/bucket/k?select&select-type=2"),
        (Method::POST, "/bucket/k"),
        (Method::GET, "/bucket/k?partNumber=1"),
        (Method::GET, "/?analytics"),
    ] {
        let answer = req(method.clone(), target).send(&server).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "{method} {target}: {}", answer.text());
        if method != Method::HEAD {
            assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("NotImplemented"), "{method} {target}");
        }
    }
    assert_eq!(server.service.backend().object(BUCKET, "k").unwrap(), "data", "nothing was changed by the refusals");
    assert!(server.service.backend().keys("other").is_empty());
}

#[tokio::test]
async fn unsupported_operations_are_only_known_to_those_who_signed() {
    let server = start().await;
    let answer = req(Method::GET, "/bucket?acl").unsigned().send(&server).await;
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("AccessDenied"), "the routing does not show before the signature is right");
}

#[tokio::test]
async fn methods_that_mean_nothing_are_not_allowed() {
    let server = start().await;
    for (method, target) in [
        (Method::PATCH, "/bucket/k"),
        (Method::OPTIONS, "/bucket/k"),
        (Method::PUT, "/"),
        (Method::DELETE, "/"),
        (Method::POST, "/"),
        (Method::PATCH, "/bucket"),
        (Method::TRACE, "/bucket/k"),
    ] {
        let answer = req(method.clone(), target).send(&server).await;
        assert!(answer.status == StatusCode::METHOD_NOT_ALLOWED || answer.status == StatusCode::NOT_IMPLEMENTED, "{method} {target}: {:?}", answer.status);
    }
    assert_eq!(req(Method::PATCH, "/bucket/k").send(&server).await.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn keys_and_list_types_that_cannot_be_used() {
    let server = start().await;
    let long = format!("/bucket/{}", "k".repeat(1025));
    let answer = req(Method::PUT, &long).body("x").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("KeyTooLongError"));
    assert_eq!(req(Method::PUT, &format!("/bucket/{}", "k".repeat(1024))).body("x").send(&server).await.status, StatusCode::OK);
    let answer = req(Method::GET, "/bucket?list-type=3").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidArgument"));
    let answer = req(Method::GET, "/bucket/%FF%FE").send(&server).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "a key that is not UTF-8");
    assert_eq!(tag(&answer.text(), "Code").as_deref(), Some("InvalidURI"));
}

#[tokio::test]
async fn headers_that_ask_for_what_is_not_kept_are_refused_before_anything_is_stored() {
    let server = start().await;
    for (name, value) in [
        ("x-amz-acl", "private"),
        ("x-amz-acl", "public-read"),
        ("x-amz-grant-read", "id=1"),
        ("x-amz-server-side-encryption", "AES256"),
        ("x-amz-server-side-encryption-customer-key", "x"),
        ("x-amz-tagging", "a=b"),
        ("x-amz-object-lock-mode", "GOVERNANCE"),
        ("x-amz-website-redirect-location", "/x"),
    ] {
        let answer = req(Method::PUT, "/bucket/k").header(name, value).body("x").send(&server).await;
        assert_eq!(answer.status, StatusCode::NOT_IMPLEMENTED, "{name}");
    }
    assert!(server.service.backend().keys(BUCKET).is_empty());
    // With the setting off they are accepted and ignored.
    let lenient = start_with(support::backend(), thirtys3_server::ServerConfig { reject_unsupported_headers: false, ..support::config() }).await;
    assert_eq!(req(Method::PUT, "/bucket/k").header("x-amz-acl", "private").body("x").send(&lenient).await.status, StatusCode::OK);
}

#[tokio::test]
async fn buckets_and_their_location() {
    let server = start().await;
    let list = req(Method::GET, "/").send(&server).await;
    assert_eq!(list.status, StatusCode::OK);
    let names = support::tags(&list.text(), "Name");
    assert_eq!(names, ["bucket", "other"]);
    assert!(list.text().contains("<CreationDate>") && list.text().contains("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""));
    let prefixed = req(Method::GET, "/?prefix=oth").send(&server).await;
    assert_eq!(support::tags(&prefixed.text(), "Name"), ["other"]);

    let head = req(Method::HEAD, "/bucket").send(&server).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.header("x-amz-bucket-region"), Some(support::REGION));
    assert!(head.body.is_empty());
    let location = req(Method::GET, "/bucket?location").send(&server).await;
    assert!(location.text().contains(&format!(">{}</LocationConstraint>", support::REGION)), "{}", location.text());
    let default = start_with(support::backend(), thirtys3_server::ServerConfig { region: "us-east-1".to_owned(), ..support::config() }).await;
    let signer = Signer::new(Credentials::new(support::ACCESS_KEY, support::SECRET_KEY), "us-east-1");
    let answer = req(Method::GET, "/bucket?location").signer(signer).send(&default).await;
    assert!(answer.text().contains("<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"), "{}", answer.text());
}

#[tokio::test]
async fn the_bucket_may_be_in_the_host_name() {
    let config = thirtys3_server::ServerConfig { virtual_host_suffixes: vec!["s3.example.com".to_owned()], ..support::config() };
    let server = start_with(support::backend(), config).await;
    server.service.backend().insert(BUCKET, "dir/k", b"virtual");
    let answer = req(Method::GET, "/dir/k").host("bucket.s3.example.com").send(&server).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(answer.body, "virtual");
    let list = req(Method::GET, "/?list-type=2&prefix=dir/").host("BUCKET.S3.EXAMPLE.COM:8080").send(&server).await;
    assert_eq!(support::tags(&list.text(), "Key"), ["dir/k"]);
    // A host that is not under the suffix has the bucket in the path.
    let path_style = req(Method::GET, "/bucket/dir/k").send(&server).await;
    assert_eq!(path_style.body, "virtual");
    // The root of a host with a bucket is that bucket, not the list of buckets.
    let root = req(Method::GET, "/").host("bucket.s3.example.com").send(&server).await;
    assert!(root.text().contains("<ListBucketResult"), "{}", root.text());
}
