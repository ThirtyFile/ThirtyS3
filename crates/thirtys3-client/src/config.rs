//! The settings of a client, and how they decide the address of a request.
//!
//! Path-style and virtual-hosted style are described on
//! <https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html>: `https://s3.region.amazonaws.com/bucket/key` and
//! `https://bucket.s3.region.amazonaws.com/key`.

use std::time::Duration;

use http::Uri;
use thirtys3_core::Credentials;
use thirtys3_core::encoding::uri_encode;

use crate::error::Error;

/// Where the bucket is in the address of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Addressing {
    /// Virtual-hosted style (the bucket is in the host name) for the endpoint of AWS, and path-style for an endpoint that was given, because
    /// services such as MinIO and most S3-compatible gateways are reached that way. Either way a bucket with a `.` in its name and an
    /// endpoint that is an IP address use path-style, because there is no certificate or name for them in the host.
    #[default]
    Auto,
    /// The bucket is the first part of the path: `https://host/bucket/key`.
    PathStyle,
    /// The bucket is in the host name: `https://bucket.host/key`. Still path-style for a bucket with a `.` in its name (the wildcard
    /// certificate of AWS covers one level of names only) and for an endpoint that is an IP address.
    VirtualHosted,
}

/// The settings of a [`Client`](crate::Client). Use [`ClientConfig::new`] and change what differs from the defaults.
#[derive(Clone)]
pub struct ClientConfig {
    /// The address of the service, such as `https://s3.example.com` or `http://127.0.0.1:9000`. `None` is AWS: `https://s3.{region}.amazonaws.com`.
    pub endpoint: Option<String>,
    /// The region used in signing. Empty is `us-east-1`. Some services want `auto` or any fixed name.
    pub region: String,
    /// The name of the bucket.
    pub bucket: String,
    /// The keys.
    pub credentials: Credentials,
    /// Path-style or virtual-hosted style.
    pub addressing: Addressing,
    /// Whether an `http://` endpoint is allowed. Off by default, so keys are never sent in the clear by mistake.
    pub allow_http: bool,
    /// How long to wait for a connection. Default 10 seconds.
    pub connect_timeout: Duration,
    /// How long a connection may be silent: waiting for the answer to start, and between the pieces of a download. The total time of a transfer
    /// is not limited, so large files and slow connections are not interrupted. Default 30 seconds.
    pub read_timeout: Duration,
    /// How many times a request is repeated after it failed in a way that can pass (the connection, a time-out, 500, 502, 503, 504, `SlowDown`).
    /// For a download that broke off, how many breaks in a row without receiving anything are tried again. Default 3.
    pub max_retries: u32,
    /// How long, from the start of a request or of a download, retries and resuming go on. Default 3 minutes.
    pub retry_timeout: Duration,
    /// The wait before the first repeat. It doubles each time, with random variation. Default 100 milliseconds.
    pub backoff_initial: Duration,
    /// The longest wait between repeats. Default 15 seconds.
    pub backoff_max: Duration,
    /// The size of the parts of a multipart upload in bytes: at least 5 MiB, at most 5 GiB. At most 10,000 parts, so this limits the size of an
    /// object uploaded from a stream to 10,000 times this. Default 8 MiB.
    pub part_size: usize,
    /// How many parts of a multipart upload are sent at once. Default 4.
    pub multipart_concurrency: usize,
    /// Whether `delete_many` uses `DeleteObjects`. Turn it off for services that do not have it: each key is deleted by itself. Default on.
    pub bulk_delete: bool,
    /// Added to the `User-Agent` header. Default none.
    pub user_agent: Option<String>,
}

impl ClientConfig {
    /// Settings for a bucket with these keys, for AWS in `us-east-1`.
    pub fn new(bucket: impl Into<String>, credentials: Credentials) -> Self {
        Self {
            endpoint: None,
            region: String::new(),
            bucket: bucket.into(),
            credentials,
            addressing: Addressing::Auto,
            allow_http: false,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_timeout: Duration::from_secs(180),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_secs(15),
            part_size: 8 * 1024 * 1024,
            multipart_concurrency: 4,
            bulk_delete: true,
            user_agent: None,
        }
    }

    /// Sets the endpoint.
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the region.
    #[must_use]
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// The address of the bucket, worked out from the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) https: bool,
    /// `host` or `host:port` as it goes into the `Host` header (the port only when it is not the default of the scheme).
    pub(crate) authority: String,
    /// The path before the key, without a trailing slash: `` for virtual-hosted style, `/bucket` for path-style, with the path of the endpoint in front.
    pub(crate) base_path: String,
}

fn is_ip_literal(host: &str) -> bool {
    host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}

impl Target {
    pub(crate) fn resolve(config: &ClientConfig) -> Result<Self, Error> {
        let bucket = config.bucket.trim();
        if bucket.is_empty() || bucket.contains(['/', '?', '#', ' ']) {
            return Err(Error::Config(format!("{:?} is not a bucket name", config.bucket)));
        }
        let region = if config.region.trim().is_empty() { "us-east-1" } else { config.region.trim() };
        let custom = config.endpoint.as_deref().map(str::trim).filter(|endpoint| !endpoint.is_empty());
        let default_endpoint = format!("https://s3.{region}.amazonaws.com");
        let uri: Uri =
            custom.unwrap_or(&default_endpoint).trim_end_matches('/').parse().map_err(|error| Error::Config(format!("the endpoint is not a URL: {error}")))?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") if config.allow_http => false,
            Some("http") => return Err(Error::Config("the endpoint is http:// and allow_http is off; the keys would be sent without encryption".to_owned())),
            _ => return Err(Error::Config("the endpoint has to start with https:// (or http://, with allow_http)".to_owned())),
        };
        if uri.query().is_some() {
            return Err(Error::Config("the endpoint has a query".to_owned()));
        }
        let host = uri.host().filter(|host| !host.is_empty()).ok_or_else(|| Error::Config("the endpoint has no host".to_owned()))?;
        let default_port = if https { 443 } else { 80 };
        let port = uri.port_u16().filter(|port| *port != default_port);
        let base = uri.path().trim_end_matches('/');

        let path_style = match config.addressing {
            Addressing::PathStyle => true,
            Addressing::VirtualHosted => false,
            Addressing::Auto => custom.is_some(),
        } || bucket.contains('.')
            || is_ip_literal(host);
        let with_port = |host: &str| match port {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        Ok(if path_style {
            Self { https, authority: with_port(host), base_path: format!("{base}/{}", uri_encode(bucket.as_bytes(), true)) }
        } else {
            // An endpoint that already has the bucket in front of it is used as it is.
            let host = if host.starts_with(&format!("{bucket}.")) { host.to_owned() } else { format!("{bucket}.{host}") };
            Self { https, authority: with_port(&host), base_path: base.to_owned() }
        })
    }

    /// The path of an object on the wire: the base path and the key, encoded.
    pub(crate) fn object_path(&self, key: &str) -> String {
        format!("{}/{}", self.base_path, uri_encode(key.as_bytes(), false))
    }

    /// The path of the bucket itself: `/` for virtual-hosted style and `/bucket` for path-style, as the AWS CLI sends it.
    pub(crate) fn bucket_path(&self) -> String {
        if self.base_path.is_empty() { "/".to_owned() } else { self.base_path.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bucket: &str) -> ClientConfig {
        ClientConfig::new(bucket, Credentials::new("a", "b"))
    }

    fn target(config: &ClientConfig) -> (bool, String, String) {
        let target = Target::resolve(config).unwrap();
        (target.https, target.authority, target.base_path)
    }

    #[test]
    fn aws_is_virtual_hosted_by_default() {
        assert_eq!(target(&config("files")), (true, "files.s3.us-east-1.amazonaws.com".into(), String::new()));
        assert_eq!(target(&config("files").region("eu-west-1")), (true, "files.s3.eu-west-1.amazonaws.com".into(), String::new()));
        assert_eq!(target(&config("files").region("  ")), (true, "files.s3.us-east-1.amazonaws.com".into(), String::new()));
    }

    #[test]
    fn a_bucket_with_a_dot_is_path_style_because_the_certificate_covers_one_level() {
        assert_eq!(target(&config("my.bucket")), (true, "s3.us-east-1.amazonaws.com".into(), "/my.bucket".into()));
        let mut forced = config("my.bucket");
        forced.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&forced), (true, "s3.us-east-1.amazonaws.com".into(), "/my.bucket".into()));
    }

    #[test]
    fn an_endpoint_that_was_given_is_path_style_unless_virtual_hosted_is_asked_for() {
        assert_eq!(target(&config("files").endpoint("https://s3.example.com")), (true, "s3.example.com".into(), "/files".into()));
        let mut virtual_hosted = config("files").endpoint("https://acct.r2.cloudflarestorage.com");
        virtual_hosted.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&virtual_hosted), (true, "files.acct.r2.cloudflarestorage.com".into(), String::new()));
        let mut path_style = config("files");
        path_style.addressing = Addressing::PathStyle;
        assert_eq!(target(&path_style), (true, "s3.us-east-1.amazonaws.com".into(), "/files".into()));
    }

    #[test]
    fn an_endpoint_that_already_has_the_bucket_in_front_is_used_as_it_is() {
        let mut config = config("files").endpoint("https://files.s3.example.com");
        config.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&config), (true, "files.s3.example.com".into(), String::new()));
        // A host that only starts with the same letters is not that.
        let mut other = self::config("files").endpoint("https://filesystem.example.com");
        other.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&other).1, "files.filesystem.example.com");
    }

    #[test]
    fn an_ip_address_cannot_have_a_bucket_in_front_so_it_is_path_style() {
        let mut config = config("files").endpoint("http://127.0.0.1:9000");
        config.allow_http = true;
        config.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&config), (false, "127.0.0.1:9000".into(), "/files".into()));
        let mut v6 = self::config("files").endpoint("http://[::1]:9000");
        v6.allow_http = true;
        v6.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&v6), (false, "[::1]:9000".into(), "/files".into()));
    }

    #[test]
    fn the_port_is_in_the_host_only_when_it_is_not_the_default_of_the_scheme() {
        assert_eq!(target(&config("b").endpoint("https://host:443")).1, "host");
        assert_eq!(target(&config("b").endpoint("https://host:8443")).1, "host:8443");
        let mut http = config("b").endpoint("http://host:80");
        http.allow_http = true;
        assert_eq!(target(&http).1, "host");
        http.endpoint = Some("http://host:9000".into());
        assert_eq!(target(&http).1, "host:9000");
    }

    #[test]
    fn a_path_in_the_endpoint_is_kept_in_front() {
        assert_eq!(target(&config("b").endpoint("https://gw.example.com/s3/")), (true, "gw.example.com".into(), "/s3/b".into()));
        let mut virtual_hosted = config("b").endpoint("https://gw.example.com/s3");
        virtual_hosted.addressing = Addressing::VirtualHosted;
        assert_eq!(target(&virtual_hosted), (true, "b.gw.example.com".into(), "/s3".into()));
    }

    #[test]
    fn paths_of_objects_and_of_the_bucket() {
        let path_style = Target::resolve(&config("files").endpoint("https://s3.example.com")).unwrap();
        assert_eq!(path_style.object_path("a b/ü/x+y"), "/files/a%20b/%C3%BC/x%2By");
        assert_eq!(path_style.object_path("//a/../b"), "/files///a/../b");
        assert_eq!(path_style.bucket_path(), "/files");
        let virtual_hosted = Target::resolve(&config("files")).unwrap();
        assert_eq!(virtual_hosted.object_path("a b"), "/a%20b");
        assert_eq!(virtual_hosted.bucket_path(), "/");
    }

    #[test]
    fn an_http_endpoint_needs_allow_http() {
        let error = Target::resolve(&config("b").endpoint("http://nas.local:9000")).unwrap_err();
        assert!(matches!(error, Error::Config(message) if message.contains("allow_http")));
        let mut allowed = config("b").endpoint("http://nas.local:9000");
        allowed.allow_http = true;
        assert!(Target::resolve(&allowed).is_ok());
    }

    #[test]
    fn settings_that_cannot_work_are_refused() {
        for endpoint in ["s3.example.com", "ftp://example.com", "https://", "https://example.com?x=1", "https:///path", "not a url"] {
            assert!(matches!(Target::resolve(&config("b").endpoint(endpoint)), Err(Error::Config(_))), "{endpoint:?}");
        }
        for bucket in ["", "  ", "a/b", "a b", "a?b", "a#b"] {
            assert!(matches!(Target::resolve(&config(bucket)), Err(Error::Config(_))), "{bucket:?}");
        }
    }

    #[test]
    fn an_empty_endpoint_is_aws() {
        assert_eq!(target(&config("b").endpoint("  ")).1, "b.s3.us-east-1.amazonaws.com");
        assert_eq!(target(&config("b").endpoint("https://s3.example.com/")).1, "s3.example.com");
    }

    #[test]
    fn secrets_are_not_printed_with_the_settings() {
        let printed = format!("{:?}", ClientConfig::new("b", Credentials::new("AKIA", "super-secret")));
        assert!(printed.contains("AKIA") && !printed.contains("super-secret"), "{printed}");
    }
}
