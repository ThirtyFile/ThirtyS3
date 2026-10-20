//! Listing: pages, continuation, prefixes, folders, and keys that need the URL encoding.

mod support;

use bytes::Bytes;
use futures_util::StreamExt;
use http::Method;
use support::{TestServer, client};
use thirtys3_client::{ErrorKind, ListOptions, PutOptions};

fn server_with(keys: &[&str]) -> TestServer {
    let server = futures_executor_free_block(TestServer::start());
    for key in keys {
        server.put_object(key, key.as_bytes());
    }
    server
}

/// The tests are `async`, but building the fixture before them is simpler without one more layer.
fn futures_executor_free_block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

async fn keys(client: &thirtys3_client::Client, prefix: &str, options: &ListOptions) -> Vec<String> {
    client.list(prefix, options).map(|object| object.unwrap().key).collect().await
}

#[tokio::test(flavor = "multi_thread")]
async fn everything_under_a_prefix_in_key_order() {
    let server = server_with(&["a/1", "a/2", "b/1", "a/3", "ab", "c"]);
    let client = client(&server);
    assert_eq!(keys(&client, "a/", &ListOptions::default()).await, ["a/1", "a/2", "a/3"]);
    assert_eq!(keys(&client, "a", &ListOptions::default()).await, ["a/1", "a/2", "a/3", "ab"], "a prefix is a prefix of the key, not of a folder");
    assert_eq!(keys(&client, "", &ListOptions::default()).await, ["a/1", "a/2", "a/3", "ab", "b/1", "c"]);
    assert!(keys(&client, "zzz", &ListOptions::default()).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_entries_have_what_a_listing_has() {
    let server = server_with(&["file.txt"]);
    let client = client(&server);
    let listed = client.list("", &ListOptions::default()).next().await.unwrap().unwrap();
    assert_eq!((listed.key.as_str(), listed.size), ("file.txt", 8));
    assert_eq!(listed.etag, server.object("file.txt").map(|object| object.etag));
    assert!(listed.last_modified.is_some());
    assert_eq!(listed.storage_class.as_deref(), Some("STANDARD"));
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_are_followed_with_the_continuation_token() {
    let names: Vec<String> = (0..10).map(|i| format!("k{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let server = server_with(&refs);
    let client = client(&server);
    let options = ListOptions { page_size: Some(3), ..ListOptions::default() };
    assert_eq!(keys(&client, "", &options).await, names);
    let requests = server.requests_matching(Method::GET, "/bucket");
    assert_eq!(requests.len(), 4, "3 + 3 + 3 + 1");
    assert!(!requests[0].query.contains("continuation-token"));
    assert!(requests[1..].iter().all(|request| request.query.contains("continuation-token=")));
    assert!(
        requests.iter().all(|request| request.query.contains("max-keys=3") && request.query.contains("list-type=2") && request.query.contains("encoding-type=url"))
    );
    assert!(requests.iter().all(|request| request.authenticated));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listing_asks_for_pages_only_as_they_are_read() {
    let names: Vec<String> = (0..10).map(|i| format!("k{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let server = server_with(&refs);
    let client = client(&server);
    let options = ListOptions { page_size: Some(2), ..ListOptions::default() };
    let first: Vec<_> = client.list("", &options).take(2).collect().await;
    assert_eq!(first.len(), 2);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_one_by_one() {
    let server = server_with(&["a", "b", "c", "d", "e"]);
    let client = client(&server);
    let options = ListOptions { page_size: Some(2), ..ListOptions::default() };
    let (first, token) = client.list_page("", &options, None).await.unwrap();
    assert_eq!(first.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    let (second, token) = client.list_page("", &options, token.as_deref()).await.unwrap();
    assert_eq!(second.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["c", "d"]);
    let (last, token) = client.list_page("", &options, token.as_deref()).await.unwrap();
    assert_eq!(last.objects.len(), 1);
    assert_eq!(token, None);
    let pages: Vec<_> = client.list_pages("", &options).collect().await;
    assert_eq!(pages.iter().map(|page| page.as_ref().unwrap().objects.len()).collect::<Vec<_>>(), [2, 2, 1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_after() {
    let server = server_with(&["a", "b", "c", "d"]);
    let client = client(&server);
    let options = ListOptions { start_after: Some("b".into()), ..ListOptions::default() };
    assert_eq!(keys(&client, "", &options).await, ["c", "d"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_with_a_delimiter() {
    let server = server_with(&["photos/2020/a.jpg", "photos/2020/b.jpg", "photos/2021/c.jpg", "photos/readme.txt", "other.txt"]);
    let client = client(&server);
    let listed = client.list_with_delimiter("photos/", "/").await.unwrap();
    assert_eq!(listed.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["photos/readme.txt"]);
    assert_eq!(listed.common_prefixes, ["photos/2020/", "photos/2021/"]);
    let top = client.list_with_delimiter("", "/").await.unwrap();
    assert_eq!(top.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["other.txt"]);
    assert_eq!(top.common_prefixes, ["photos/"]);
    let nothing = client.list_with_delimiter("nope/", "/").await.unwrap();
    assert!(nothing.objects.is_empty() && nothing.common_prefixes.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_across_pages() {
    let mut names = Vec::new();
    for folder in 0..5 {
        for file in 0..3 {
            names.push(format!("f{folder}/file{file}"));
        }
    }
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let server = server_with(&refs);
    let client = client(&server);
    let options = ListOptions { delimiter: Some("/".into()), page_size: Some(2), ..ListOptions::default() };
    let pages: Vec<_> = client.list_pages("", &options).collect().await;
    let prefixes: Vec<String> = pages.into_iter().flat_map(|page| page.unwrap().common_prefixes).collect();
    assert_eq!(prefixes, ["f0/", "f1/", "f2/", "f3/", "f4/"], "each folder once, though they came in several pages");
}

#[tokio::test(flavor = "multi_thread")]
async fn awkward_keys_and_prefixes_are_listed_through_the_url_encoding() {
    let awkward = ["日本語/ファイル.txt", "with space/ and + plus", "per%cent/%41", "control\u{1}char", "amp&lt;/<tag>", "line\nbreak/x"];
    let server = server_with(&awkward);
    let client = client(&server);
    let mut expected: Vec<&str> = awkward.to_vec();
    expected.sort();
    let listed = keys(&client, "", &ListOptions::default()).await;
    assert_eq!(listed, expected);
    // A prefix with the same characters, and folders made of them.
    assert_eq!(keys(&client, "with space/", &ListOptions::default()).await, ["with space/ and + plus"]);
    assert_eq!(keys(&client, "per%cent/", &ListOptions::default()).await, ["per%cent/%41"]);
    let folders = client.list_with_delimiter("", "/").await.unwrap();
    assert!(folders.common_prefixes.contains(&"日本語/".to_owned()) && folders.common_prefixes.contains(&"per%cent/".to_owned()), "{:?}", folders.common_prefixes);
    assert!(folders.objects.iter().any(|o| o.key == "control\u{1}char"));
    assert!(server.requests().iter().all(|request| request.authenticated));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_bucket_lists_nothing_and_a_missing_one_is_not_found() {
    let server = server_with(&[]);
    let client = client(&server);
    assert!(keys(&client, "", &ListOptions::default()).await.is_empty());
    let mut config = support::config(&server);
    config.bucket = "missing".into();
    let other = thirtys3_client::Client::new(config).unwrap();
    let error = other.list("", &ListOptions::default()).next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(other.list("", &ListOptions::default()).next().await.is_some(), "the error is an item of the stream; the stream ends after it");
}

#[tokio::test(flavor = "multi_thread")]
async fn what_was_put_is_listed() {
    let server = server_with(&[]);
    let client = client(&server);
    for key in ["x/1", "x/2"] {
        client.put(key, Bytes::from_static(b"v"), &PutOptions::default()).await.unwrap();
    }
    assert_eq!(keys(&client, "x/", &ListOptions::default()).await, ["x/1", "x/2"]);
}
