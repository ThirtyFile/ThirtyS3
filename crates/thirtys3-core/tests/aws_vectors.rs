//! The worked examples from AWS's Signature Version 4 documentation for S3, which AWS says can be used as a test suite for an implementation.
//!
//! The pages are no longer in the current documentation; these are the versions in the Internet Archive:
//! - `sig-v4-header-based-auth.html` (GET Object, PUT Object, GET Bucket Lifecycle, GET Bucket List Objects), snapshot of 2025-01
//! - `sigv4-query-string-auth.html` (the presigned GET), snapshot of 2025-01-04
//! - `sigv4-streaming.html` (the chunked PUT), snapshot of 2024-12-18
//! - `sigv4-streaming-trailers.html` (the chunked PUT with a trailing checksum), snapshot of 2025
//!
//! All of them use the example credentials from the documentation, the time 20130524T000000Z and the region us-east-1.

use thirtys3_core::sigv4::{EMPTY_PAYLOAD_SHA256, STREAMING_SIGNED_PAYLOAD, STREAMING_SIGNED_PAYLOAD_TRAILER, canonical_request, string_to_sign};
use thirtys3_core::{Credentials, Request, Scope, Signer, Timestamp, sha256_hex};

const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TIME: Timestamp = Timestamp(1_369_353_600); // 20130524T000000Z

fn signer() -> Signer {
    Signer::new(Credentials::new(ACCESS_KEY, SECRET_KEY), "us-east-1")
}

/// Signs, and checks the canonical request, the string to sign and the signature against the documentation.
fn check(request: &Request<'_>, payload_hash: &str, canonical: &str, string_to_sign_hash: &str, signature: &str, signed_headers: &str) {
    let signed = signer().sign(request, payload_hash, TIME).unwrap();
    assert_eq!(signed.signature, signature);
    assert_eq!(
        signed.authorization,
        format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/20130524/us-east-1/s3/aws4_request,SignedHeaders={signed_headers},Signature={signature}")
    );
    // The documented canonical request, built from the headers the documentation lists (the ones the signer adds included).
    let mut headers: Vec<(&str, &str)> = request.headers.to_vec();
    headers.extend(signed.headers.iter().filter(|(name, _)| name != "authorization").map(|(name, value)| (name.as_str(), value.as_str())));
    let full = Request { headers: &headers, ..*request };
    let names: Vec<String> = signed_headers.split(';').map(str::to_owned).collect();
    let built = canonical_request(&full, &names, payload_hash, false).unwrap();
    assert_eq!(built, canonical);
    assert_eq!(sha256_hex(built.as_bytes()), string_to_sign_hash);
    assert_eq!(
        string_to_sign("20130524T000000Z", &Scope::new(TIME, "us-east-1"), &built),
        format!("AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n{string_to_sign_hash}")
    );
}

#[test]
fn get_object_with_a_range() {
    let request = Request { method: "GET", path: "/test.txt", query: "", headers: &[("Host", "examplebucket.s3.amazonaws.com"), ("Range", "bytes=0-9")] };
    check(
        &request,
        EMPTY_PAYLOAD_SHA256,
        "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972",
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        "host;range;x-amz-content-sha256;x-amz-date",
    );
}

#[test]
fn put_object_with_a_dollar_sign_in_the_key() {
    let body_hash = sha256_hex(b"Welcome to Amazon S3.");
    assert_eq!(body_hash, "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072");
    let request = Request {
        method: "PUT",
        path: "/test$file.text",
        query: "",
        headers: &[("Host", "examplebucket.s3.amazonaws.com"), ("Date", "Fri, 24 May 2013 00:00:00 GMT"), ("x-amz-storage-class", "REDUCED_REDUNDANCY")],
    };
    check(
        &request,
        &body_hash,
        "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\nx-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\ndate;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
        "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d",
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
        "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
    );
}

#[test]
fn get_bucket_lifecycle() {
    let request = Request { method: "GET", path: "/", query: "lifecycle", headers: &[("Host", "examplebucket.s3.amazonaws.com")] };
    check(
        &request,
        EMPTY_PAYLOAD_SHA256,
        "GET\n/\nlifecycle=\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca",
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
        "host;x-amz-content-sha256;x-amz-date",
    );
}

#[test]
fn get_bucket_list_objects() {
    let request = Request { method: "GET", path: "/", query: "max-keys=2&prefix=J", headers: &[("Host", "examplebucket.s3.amazonaws.com")] };
    check(
        &request,
        EMPTY_PAYLOAD_SHA256,
        "GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7",
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        "host;x-amz-content-sha256;x-amz-date",
    );
}

#[test]
fn presigned_get() {
    let request = Request { method: "GET", path: "/test.txt", query: "", headers: &[("Host", "examplebucket.s3.amazonaws.com")] };
    let query = signer().presign(&request, TIME, 86400).unwrap();
    assert_eq!(
        query,
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
}

const CHUNK_1_HASH: &str = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
const CHUNK_2_HASH: &str = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a";

#[test]
fn the_chunk_hashes_of_the_documentation_are_those_of_a_repeated_a() {
    assert_eq!(sha256_hex(&vec![b'a'; 65536]), CHUNK_1_HASH);
    assert_eq!(sha256_hex(&vec![b'a'; 1024]), CHUNK_2_HASH);
}

#[test]
fn chunked_put() {
    let request = Request {
        method: "PUT",
        path: "/examplebucket/chunkObject.txt",
        query: "",
        headers: &[
            ("Host", "s3.amazonaws.com"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "66560"),
            ("Content-Length", "66824"),
        ],
    };
    let signed = signer().sign(&request, STREAMING_SIGNED_PAYLOAD, TIME).unwrap();
    assert_eq!(signed.signature, "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9");
    assert_eq!(
        signed.authorization,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
    );

    let mut chain = signer().chunk_chain(&signed);
    assert_eq!(chain.sign_chunk(CHUNK_1_HASH), "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648");
    assert_eq!(chain.sign_chunk(CHUNK_2_HASH), "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497");
    assert_eq!(chain.sign_chunk(EMPTY_PAYLOAD_SHA256), "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");
}

#[test]
fn chunked_put_with_a_trailing_checksum() {
    // The documentation's canonical request has x-amz-trailer and no content-length, whereas the Authorization header printed below it lists
    // content-length and no x-amz-trailer. The seed signature is the one of the canonical request, so the canonical request is what is tested.
    let request = Request {
        method: "PUT",
        path: "/examplebucket/chunkObject.txt",
        query: "",
        headers: &[
            ("Host", "s3.amazonaws.com"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "66560"),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
        ],
    };
    let signed = signer().sign(&request, STREAMING_SIGNED_PAYLOAD_TRAILER, TIME).unwrap();
    assert_eq!(
        signed.signed_headers.join(";"),
        "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer"
    );
    assert_eq!(signed.signature, "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e");

    let mut chain = signer().chunk_chain(&signed);
    assert_eq!(chain.sign_chunk(CHUNK_1_HASH), "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2");
    assert_eq!(chain.sign_chunk(CHUNK_2_HASH), "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7");
    assert_eq!(chain.sign_chunk(EMPTY_PAYLOAD_SHA256), "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992");
    let trailer_hash = sha256_hex(b"x-amz-checksum-crc32c:sOO8/Q==\n");
    assert_eq!(trailer_hash, "1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774");
    assert_eq!(chain.sign_trailer(&trailer_hash), "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435");
}
