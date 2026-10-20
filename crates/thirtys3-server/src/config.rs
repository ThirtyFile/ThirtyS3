//! The settings of the service.

/// The settings of an [`S3Service`](crate::S3Service). [`ServerConfig::default`] has the values S3 itself uses for the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// The region the service answers for. A request has to be signed for this region (the credential scope), and `HeadBucket` and
    /// `GetBucketLocation` tell it. Default `us-east-1`.
    pub region: String,
    /// Whether a request signed for another region is refused (`AuthorizationHeaderMalformed`, which names the right one). Default on.
    pub enforce_region: bool,
    /// Domain names under which the bucket is the first label of the host name (`bucket.s3.example.com`, for `s3.example.com`). A request to a host
    /// that is not under one of them has the bucket in the path (path-style). Default none: path-style only.
    pub virtual_host_suffixes: Vec<String>,
    /// The longest XML body of a request that is read (`DeleteObjects`, `CompleteMultipartUpload`), in bytes. Default 1 MiB.
    pub max_xml_bytes: usize,
    /// The largest chunk of an `aws-chunked` body, in bytes. Default 8 MiB.
    pub max_chunk_size: u64,
    /// The largest object or part, in bytes. Default 5 GiB, the most one request can store.
    pub max_object_size: u64,
    /// The longest prefix, marker or key in a listing, in bytes. Default 1024.
    pub max_listing_key_length: usize,
    /// The longest delimiter, in bytes. Default 64.
    pub max_delimiter_length: usize,
    /// Refuse with `NotImplemented` the requests that ask for what the service does not keep: ACLs, server-side encryption, object lock, tags and
    /// website redirects. Default on. With it off they are accepted and ignored.
    pub reject_unsupported_headers: bool,
    /// Answer `CompleteMultipartUpload` that fails on the side of the backend (a 5xx error) with status 200 and an `Error` document in the body, as
    /// S3 does when it fails after it has begun to answer. Clients that know S3 treat such an answer as a failure to retry; others see a success
    /// that is not one. Default off.
    pub complete_failures_in_ok_response: bool,
    /// How long the service waits for the next piece of the body of an upload (or of a document) before it gives up with `RequestTimeout`. This
    /// guards against a client that opens a request and then sends nothing; the time to read the head of a request and the idle time of a
    /// connection are for the code that serves the connections. Default 30 seconds; `None` waits for ever.
    ///
    /// This is a time of silence, not a rate: a client that sends a byte every 29 seconds keeps its request, so a deployment that has to bound the
    /// time of a request (or its rate) does it where it serves connections, or in a layer around the service. The timeout needs a Tokio runtime,
    /// and the service does as a whole (it has no other use of Tokio than this timer, and `None` removes even that).
    pub body_idle_timeout: Option<std::time::Duration>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_owned(),
            enforce_region: true,
            virtual_host_suffixes: Vec::new(),
            max_xml_bytes: 1024 * 1024,
            max_chunk_size: 8 * 1024 * 1024,
            max_object_size: 5 * 1024 * 1024 * 1024,
            max_listing_key_length: 1024,
            max_delimiter_length: 64,
            reject_unsupported_headers: true,
            complete_failures_in_ok_response: false,
            body_idle_timeout: Some(std::time::Duration::from_secs(30)),
        }
    }
}
