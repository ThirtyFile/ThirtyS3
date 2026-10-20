//! Virtual-hosted style over a real connection: the bucket in the host name (`bucket.localhost`, which names the local machine).
//!
//! These tests are skipped where `*.localhost` does not resolve.

mod support;

use bytes::Bytes;
use support::{TestServer, config};
use thirtys3_client::{Addressing, Client, GetOptions, ListOptions, PutOptions};

async fn client_for(server: &TestServer) -> Option<Client> {
    if tokio::net::lookup_host((format!("{}.localhost", support::BUCKET), server.port())).await.is_err() {
        eprintln!("skipped: bucket.localhost does not resolve here");
        return None;
    }
    let mut config = config(server);
    config.endpoint = Some(format!("http://localhost:{}", server.port()));
    config.addressing = Addressing::VirtualHosted;
    Some(Client::new(config).unwrap())
}

#[tokio::test]
async fn the_bucket_is_in_the_host_and_the_key_is_the_whole_path() {
    let server = TestServer::start().await;
    let Some(client) = client_for(&server).await else { return };
    client.put("dir/a b.txt", Bytes::from_static(b"hello"), &PutOptions::default()).await.unwrap();
    let put = &server.requests()[0];
    assert_eq!(put.header("host"), Some(format!("bucket.localhost:{}", server.port()).as_str()));
    assert_eq!(put.path, "/dir/a%20b.txt");
    assert!(put.authenticated, "the signature covers that host");

    let object = client.get("dir/a b.txt", &GetOptions::default()).await.unwrap();
    assert_eq!(object.body.bytes().await.unwrap(), "hello");
    assert_eq!(client.head("dir/a b.txt").await.unwrap().size, 5);
    client.delete("dir/a b.txt").await.unwrap();
    assert!(server.requests().iter().all(|request| request.authenticated));
}

#[tokio::test]
async fn listing_asks_the_root_of_the_host() {
    let server = TestServer::start().await;
    let Some(client) = client_for(&server).await else { return };
    server.put_object("x/1", b"1");
    let page = client.list_with_delimiter("", "/").await.unwrap();
    assert_eq!(page.common_prefixes, ["x/"]);
    let list = server.requests().into_iter().find(|request| request.query.contains("list-type=2")).unwrap();
    assert_eq!(list.path, "/");
    assert!(list.authenticated);
    use futures_util::StreamExt;
    let options = ListOptions::default();
    let mut keys = client.list("", &options);
    assert_eq!(keys.next().await.unwrap().unwrap().key, "x/1");
}
