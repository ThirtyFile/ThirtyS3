//! Which operation a request is for.
//!
//! The operations are told apart by the method, by whether there is a bucket and a key, and by the query parameters that name a subresource
//! (`?uploads`, `?uploadId=…`, `?delete`, `?location`). A request that names a subresource of S3 that this service does not have is never mistaken
//! for a plain `GET` or `PUT`: `GET /bucket?acl` is an unsupported operation, not a listing.
//!
//! The paths of the API: <https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations_Amazon_Simple_Storage_Service.html>; the two styles of
//! address: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html>.

use http::Method;
use http::request::Parts;
use thirtys3_core::S3Error;
use thirtys3_core::encoding::{percent_decode, query_params};
use thirtys3_core::s3_error::code;

use crate::config::ServerConfig;

/// An operation the service does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `GET /`
    ListBuckets,
    /// `HEAD /bucket`
    HeadBucket,
    /// `GET /bucket?location`
    GetBucketLocation,
    /// `GET /bucket` (version 1) and `GET /bucket?list-type=2`
    ListObjects {
        /// Whether it is `ListObjectsV2`.
        v2: bool,
    },
    /// `GET /bucket?uploads`
    ListMultipartUploads,
    /// `POST /bucket?delete`
    DeleteObjects,
    /// `GET /bucket/key`
    GetObject,
    /// `HEAD /bucket/key`
    HeadObject,
    /// `PUT /bucket/key`
    PutObject,
    /// `PUT /bucket/key` with `x-amz-copy-source`
    CopyObject,
    /// `DELETE /bucket/key`
    DeleteObject,
    /// `POST /bucket/key?uploads`
    CreateMultipartUpload,
    /// `PUT /bucket/key?partNumber=…&uploadId=…`
    UploadPart,
    /// `POST /bucket/key?uploadId=…`
    CompleteMultipartUpload,
    /// `DELETE /bucket/key?uploadId=…`
    AbortMultipartUpload,
    /// `GET /bucket/key?uploadId=…`
    ListParts,
}

/// Where a request is going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// What to do.
    pub op: Op,
    /// The bucket, decoded.
    pub bucket: Option<String>,
    /// The key, decoded.
    pub key: Option<String>,
    /// The query parameters, decoded.
    pub query: Vec<(String, String)>,
}

impl Route {
    /// The value of a query parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(candidate, _)| candidate == name).map(|(_, value)| value.as_str())
    }

    /// Whether a query parameter is there, with or without a value.
    pub fn has(&self, name: &str) -> bool {
        self.query.iter().any(|(candidate, _)| candidate == name)
    }
}

/// The subresources of buckets and objects that are operations of S3 other than the ones this service does. A request that has one of them is
/// answered with `NotImplemented`.
const OTHER_SUBRESOURCES: &[&str] = &[
    "abac",
    "accelerate",
    "acl",
    "analytics",
    "attributes",
    "cors",
    "encryption",
    "intelligent-tiering",
    "inventory",
    "legal-hold",
    "lifecycle",
    "logging",
    "metadataConfiguration",
    "metadataTable",
    "metrics",
    "notification",
    "object-lock",
    "ownershipControls",
    "policy",
    "policyStatus",
    "publicAccessBlock",
    "renameObject",
    "replication",
    "requestPayment",
    "restore",
    "retention",
    "select",
    "session",
    "tagging",
    "torrent",
    "versioning",
    "versions",
    "website",
];

fn not_implemented(what: &str) -> S3Error {
    S3Error::new(code::NOT_IMPLEMENTED, format!("A header or parameter you provided implies functionality that is not implemented: {what}"))
}

fn first_unsupported(route_query: &[(String, String)], extra: &[&str]) -> Option<String> {
    route_query.iter().map(|(name, _)| name.as_str()).find(|name| OTHER_SUBRESOURCES.contains(name) || extra.contains(name)).map(str::to_owned)
}

/// Decodes a path or key as text.
fn text(bytes: Vec<u8>, what: &str) -> Result<String, S3Error> {
    String::from_utf8(bytes).map_err(|_| S3Error::new("InvalidURI", format!("Couldn't parse the specified URI: the {what} is not valid UTF-8")))
}

/// Works out the operation of a request.
pub fn route(parts: &Parts, config: &ServerConfig) -> Result<Route, S3Error> {
    let query: Vec<(String, String)> = query_params(parts.uri.query().unwrap_or_default())
        .into_iter()
        .map(|(name, value)| (String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned()))
        .collect();

    // The bucket from the host name, when the host is under one of the domains that are served in virtual-hosted style.
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|host| host.to_str().ok())
        .map(|host| host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(name, _)| name));
    let hosted_bucket = host.and_then(|host| {
        let host = host.to_ascii_lowercase();
        config
            .virtual_host_suffixes
            .iter()
            .find_map(|suffix| host.strip_suffix(&format!(".{}", suffix.to_ascii_lowercase())).filter(|bucket| !bucket.is_empty()).map(str::to_owned))
    });

    let path = text(percent_decode(parts.uri.path(), false), "path")?;
    let rest = path.strip_prefix('/').unwrap_or(&path);
    let (bucket, key) = match hosted_bucket {
        Some(bucket) => (Some(bucket), (!rest.is_empty()).then(|| rest.to_owned())),
        None if rest.is_empty() => (None, None),
        None => match rest.split_once('/') {
            Some((bucket, key)) => (Some(bucket.to_owned()), (!key.is_empty()).then(|| key.to_owned())),
            None => (Some(rest.to_owned()), None),
        },
    };
    if bucket.as_deref() == Some("") {
        return Err(S3Error::new(code::INVALID_BUCKET_NAME, "The specified bucket is not valid."));
    }
    if let Some(key) = &key
        && key.len() > 1024
    {
        return Err(S3Error::new(code::KEY_TOO_LONG, "Your key is too long").with_detail("MaxSizeAllowed", "1024").with_detail("Size", key.len().to_string()));
    }

    let mut route = Route { op: Op::ListBuckets, bucket, key, query };
    route.op = operation(&parts.method, &route, parts)?;
    Ok(route)
}

fn operation(method: &Method, route: &Route, parts: &Parts) -> Result<Op, S3Error> {
    let get = *method == Method::GET;
    let head = *method == Method::HEAD;
    let put = *method == Method::PUT;
    let post = *method == Method::POST;
    let delete = *method == Method::DELETE;
    let wrong_method =
        || S3Error::new(code::METHOD_NOT_ALLOWED, "The specified method is not allowed against this resource.").with_detail("Method", method.as_str().to_owned());

    match (&route.bucket, &route.key) {
        (None, _) => {
            if let Some(name) = first_unsupported(&route.query, &[]) {
                return Err(not_implemented(&name));
            }
            if get { Ok(Op::ListBuckets) } else { Err(wrong_method()) }
        }
        (Some(_), None) => {
            if get && route.has("location") {
                return Ok(Op::GetBucketLocation);
            }
            if get && route.has("uploads") {
                return Ok(Op::ListMultipartUploads);
            }
            if post && route.has("delete") {
                return Ok(Op::DeleteObjects);
            }
            if let Some(name) = first_unsupported(&route.query, &[]) {
                return Err(not_implemented(&name));
            }
            if get {
                return match route.param("list-type") {
                    None => Ok(Op::ListObjects { v2: false }),
                    Some("2") => Ok(Op::ListObjects { v2: true }),
                    Some(other) => Err(S3Error::new(code::INVALID_ARGUMENT, "Invalid list-type: only 2 is known")
                        .with_detail("ArgumentName", "list-type")
                        .with_detail("ArgumentValue", other.to_owned())),
                };
            }
            if head {
                return Ok(Op::HeadBucket);
            }
            // Making and removing buckets: the buckets are the service's own.
            if put || delete {
                return Err(not_implemented("creating and deleting buckets"));
            }
            if post {
                return Err(not_implemented("POST to a bucket"));
            }
            Err(wrong_method())
        }
        (Some(_), Some(_)) => {
            let upload = route.param("uploadId").is_some();
            if let Some(name) = first_unsupported(&route.query, &["versionId"]) {
                return Err(not_implemented(&name));
            }
            if get && route.has("partNumber") && !upload {
                return Err(not_implemented("partNumber"));
            }
            if get && upload {
                return Ok(Op::ListParts);
            }
            if get {
                return Ok(Op::GetObject);
            }
            if head {
                return if route.has("partNumber") { Err(not_implemented("partNumber")) } else { Ok(Op::HeadObject) };
            }
            if put && upload && route.has("partNumber") {
                return if parts.headers.contains_key("x-amz-copy-source") { Err(not_implemented("UploadPartCopy")) } else { Ok(Op::UploadPart) };
            }
            if put && (upload || route.has("partNumber")) {
                return Err(S3Error::new(code::INVALID_ARGUMENT, "A part is uploaded with both partNumber and uploadId"));
            }
            if put {
                return Ok(if parts.headers.contains_key("x-amz-copy-source") { Op::CopyObject } else { Op::PutObject });
            }
            if delete {
                return Ok(if upload { Op::AbortMultipartUpload } else { Op::DeleteObject });
            }
            if post && route.has("uploads") {
                return Ok(Op::CreateMultipartUpload);
            }
            if post && upload {
                return Ok(Op::CompleteMultipartUpload);
            }
            if post {
                return Err(not_implemented("POST to an object"));
            }
            Err(wrong_method())
        }
    }
}

/// Request headers that ask for what the service does not keep.
pub fn unsupported_header(parts: &Parts) -> Option<String> {
    parts
        .headers
        .keys()
        .map(http::HeaderName::as_str)
        .find(|name| {
            name.starts_with("x-amz-grant-")
                || name.starts_with("x-amz-server-side-encryption")
                || name.starts_with("x-amz-object-lock")
                || matches!(*name, "x-amz-acl" | "x-amz-tagging" | "x-amz-tagging-directive" | "x-amz-website-redirect-location")
        })
        .map(str::to_owned)
}

/// The error for a request with such a header.
pub fn unsupported_header_error(name: &str) -> S3Error {
    not_implemented(name)
}
