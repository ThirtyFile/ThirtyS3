//! Deleting several objects: `DeleteObjects` in batches of 1000, or one at a time for services that do not have it.

mod support;

use http::Method;
use support::{Fault, TestServer, client, config};
use thirtys3_client::{Client, Error, ErrorKind};

fn keys(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("k{i:05}")).collect()
}

fn filled(server: &TestServer, keys: &[String]) {
    for key in keys {
        server.put_object(key, b"x");
    }
}

#[tokio::test]
async fn several_keys_in_one_request() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names = keys(5);
    filled(&server, &names);
    server.put_object("kept", b"x");
    let failed = client.delete_many(&names).await.unwrap();
    assert!(failed.is_empty());
    assert_eq!(server.keys(), ["kept"]);
    let posts = server.requests_matching(Method::POST, "/bucket");
    assert_eq!(posts.len(), 1);
    assert!(posts[0].query.starts_with("delete"));
    assert!(posts[0].authenticated, "signed, with the Content-MD5 the service requires and checks");
    assert!(posts[0].header("content-md5").is_some());
    assert_eq!(posts[0].header("content-type"), Some("application/xml"));
}

#[tokio::test]
async fn more_than_a_thousand_keys_go_in_batches_of_a_thousand() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names = keys(2500);
    filled(&server, &names);
    assert!(client.delete_many(&names).await.unwrap().is_empty());
    assert!(server.keys().is_empty());
    assert_eq!(server.requests_matching(Method::POST, "/bucket").len(), 3);
}

#[tokio::test]
async fn keys_that_are_not_there_count_as_deleted() {
    let server = TestServer::start().await;
    let client = client(&server);
    assert!(client.delete_many(&["nothing".to_owned(), "nothing/either".to_owned()]).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_keys_that_could_not_be_deleted_come_back_with_the_reason() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names = vec!["a".to_owned(), "undeletable-b".to_owned(), "c".to_owned()];
    filled(&server, &names);
    let failed = client.delete_many(&names).await.unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, "undeletable-b");
    assert_eq!(failed[0].1.kind(), ErrorKind::PermissionDenied);
    assert_eq!(server.keys(), ["undeletable-b"]);
}

#[tokio::test]
async fn keys_with_awkward_characters() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names: Vec<String> = ["a b", "中文", "a&b<c>", "per%cent", "a/../b", "emoji 😀"].iter().map(|key| (*key).to_owned()).collect();
    filled(&server, &names);
    assert!(client.delete_many(&names).await.unwrap().is_empty());
    assert!(server.keys().is_empty());
}

#[tokio::test]
async fn without_bulk_delete_each_key_is_deleted_by_itself() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.bulk_delete = false;
    let client = Client::new(config).unwrap();
    let names = keys(4);
    filled(&server, &names);
    assert!(client.delete_many(&names).await.unwrap().is_empty());
    assert!(server.keys().is_empty());
    assert_eq!(server.requests_matching(Method::DELETE, "/bucket").len(), 4);
    assert!(server.requests_matching(Method::POST, "/bucket").is_empty());
}

#[tokio::test]
async fn without_bulk_delete_a_failure_is_reported_for_its_key_and_the_others_go_on() {
    let server = TestServer::start().await;
    let mut config = config(&server);
    config.bulk_delete = false;
    let client = Client::new(config).unwrap();
    let names = keys(3);
    filled(&server, &names);
    server.fault(Some(Method::DELETE), Some("k00001"), None, 100, Fault::Status(403, "AccessDenied"));
    let failed = client.delete_many(&names).await.unwrap();
    assert_eq!(failed.iter().map(|(key, _)| key.as_str()).collect::<Vec<_>>(), ["k00001"]);
    assert_eq!(server.keys(), ["k00001"]);
}

#[tokio::test]
async fn nothing_to_delete_sends_nothing() {
    let server = TestServer::start().await;
    let client = client(&server);
    assert!(client.delete_many(&[]).await.unwrap().is_empty());
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_key_that_cannot_be_used_stops_everything_before_anything_is_deleted() {
    let server = TestServer::start().await;
    let client = client(&server);
    filled(&server, &keys(2));
    let error = client.delete_many(&["k00000".to_owned(), String::new()]).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(server.keys().len(), 2);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_busy_service_is_waited_for() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names = keys(3);
    filled(&server, &names);
    server.fault(Some(Method::POST), None, Some("delete"), 2, Fault::Status(503, "SlowDown"));
    assert!(client.delete_many(&names).await.unwrap().is_empty());
    assert_eq!(server.requests_matching(Method::POST, "/bucket").len(), 3);
}

#[tokio::test]
async fn an_answer_that_is_200_and_then_an_error_is_an_error() {
    let server = TestServer::start().await;
    let client = client(&server);
    let names = keys(2);
    filled(&server, &names);
    server.fault(Some(Method::POST), None, Some("delete"), 100, Fault::OkWithError("AccessDenied"));
    let error = client.delete_many(&names).await.unwrap_err();
    assert!(matches!(&error, Error::Service(s3) if s3.code == "AccessDenied"), "{error:?}");
}
