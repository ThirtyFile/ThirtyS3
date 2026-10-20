//! The XML documents of the operations a file service offers: what a server writes and a client reads (the results), and what a client writes
//! and a server reads (the requests with a body).
//!
//! Each type follows the page of its operation in the S3 API reference, `https://docs.aws.amazon.com/AmazonS3/latest/API/API_<Operation>.html`
//! (`ListBuckets`, `GetBucketLocation`, `ListObjects`, `ListObjectsV2`, `CopyObject`, `DeleteObjects`, `CreateMultipartUpload`,
//! `CompleteMultipartUpload`, `ListParts`, `ListMultipartUploads`), for the elements and their names, and its examples for the form S3 writes:
//! the namespace on the document element, `…T…:…:….000Z` timestamps, ETags in double quotes. A type that is read keeps what it needs; elements it
//! does not know are ignored.
//!
//! In the listings, `encoding-type=url` is `url_encoded`: when a document is written the keys, prefixes, delimiter and markers are encoded, and
//! when it is read they are decoded, so the values in the types are always the real ones. The documentation does not say which characters S3
//! encodes; every byte except ASCII letters and digits is, which any client decodes and which ThirtyFile's tests expect.

use std::str::FromStr;

use crate::checksum::ChecksumAlgorithm;
use crate::encoding::percent_decode;
use crate::time::Timestamp;
use crate::xml::{self, Element, Limits, XmlError, XmlWriter};

fn parse_root(xml: &[u8], name: &'static str) -> Result<Element, XmlError> {
    xml::parse_root(xml, name, &Limits::default())
}

/// The limits for the document of `DeleteObjects`: 1,000 objects of up to six elements each, three levels deep. A larger document is refused before
/// a tree is built for it.
const DELETE_LIMITS: Limits = Limits { max_bytes: 4 * 1024 * 1024, max_depth: 4, max_elements: 10_000 };

fn parse_bool(text: &str) -> Option<bool> {
    match text {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_number<T: FromStr>(text: &str) -> Option<T> {
    text.parse().ok()
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Every byte except ASCII letters and digits as `%XX`.
fn url_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn url_decode(text: &str) -> String {
    String::from_utf8_lossy(&percent_decode(text, true)).into_owned()
}

/// Encodes `text` if the document is URL-encoded.
fn encoded(url: bool, text: &str) -> String {
    if url { url_encode(text) } else { text.to_owned() }
}

fn decoded(url: bool, text: String) -> String {
    if url { url_decode(&text) } else { text }
}

fn required_time(element: &Element, name: &'static str) -> Result<Timestamp, XmlError> {
    let text = element.required_text(name)?;
    Timestamp::parse_iso8601(text.trim()).ok_or_else(|| XmlError::invalid(name, text))
}

fn optional_time(element: &Element, name: &str) -> Result<Option<Timestamp>, XmlError> {
    element.parsed_child(name, Timestamp::parse_iso8601)
}

fn optional_text(element: &Element, name: &str) -> Option<String> {
    element.child_text(name).map(str::to_owned)
}

/// The text of a child with the white space around it taken off, for values that are never meant to have any (an ETag, an upload ID, a version).
fn optional_trimmed(element: &Element, name: &str) -> Option<String> {
    element.child_text(name).map(|text| text.trim().to_owned())
}

fn required_number<T: FromStr>(element: &Element, name: &'static str) -> Result<T, XmlError> {
    let text = element.required_text(name)?;
    parse_number(text.trim()).ok_or_else(|| XmlError::invalid(name, text))
}

/// The owner of a bucket or an object, or the initiator of a multipart upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The canonical user ID.
    pub id: String,
    /// The display name.
    pub display_name: Option<String>,
}

impl Owner {
    fn write(&self, writer: &mut XmlWriter, element: &str) {
        writer.start(element).leaf_opt("DisplayName", self.display_name.as_deref()).leaf("ID", &self.id).end();
    }

    fn read(element: &Element) -> Result<Self, XmlError> {
        Ok(Self { id: element.required_text("ID")?.to_owned(), display_name: optional_text(element, "DisplayName") })
    }

    fn read_child(parent: &Element, name: &str) -> Result<Option<Self>, XmlError> {
        parent.child(name).map(Self::read).transpose()
    }
}

/// The checksums of an object, a part or a result: the `Checksum*` elements that are there, as Base64.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checksums(pub Vec<(ChecksumAlgorithm, String)>);

impl Checksums {
    /// The Base64 value for an algorithm.
    pub fn get(&self, algorithm: ChecksumAlgorithm) -> Option<&str> {
        self.0.iter().find(|(candidate, _)| *candidate == algorithm).map(|(_, value)| value.as_str())
    }

    /// Sets the value for an algorithm, replacing one that was there.
    pub fn set(&mut self, algorithm: ChecksumAlgorithm, value: impl Into<String>) {
        self.0.retain(|(candidate, _)| *candidate != algorithm);
        self.0.push((algorithm, value.into()));
    }

    /// Whether there are no checksums.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn write(&self, writer: &mut XmlWriter) {
        for algorithm in ChecksumAlgorithm::ALL {
            if let Some(value) = self.get(algorithm) {
                writer.leaf(algorithm.xml_element(), value);
            }
        }
    }

    fn read(element: &Element) -> Self {
        let mut checksums = Self::default();
        for child in &element.children {
            if let Some(algorithm) = ChecksumAlgorithm::from_xml_element(&child.name) {
                checksums.set(algorithm, child.text.trim());
            }
        }
        checksums
    }
}

// ---- ListBuckets, GetBucketLocation ----

/// A bucket in the result of `ListBuckets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// The name.
    pub name: String,
    /// When the bucket was created.
    pub creation_date: Timestamp,
    /// The region of the bucket.
    pub region: Option<String>,
}

/// The result of `ListBuckets`: `ListAllMyBucketsResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListAllMyBucketsResult {
    /// The owner of the buckets.
    pub owner: Option<Owner>,
    /// The buckets.
    pub buckets: Vec<Bucket>,
    /// The token for the next page, when the buckets are paginated and there is more.
    pub continuation_token: Option<String>,
    /// The prefix that was asked for, if one was.
    pub prefix: Option<String>,
}

impl ListAllMyBucketsResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("ListAllMyBucketsResult", true);
        if let Some(owner) = &self.owner {
            owner.write(&mut writer, "Owner");
        }
        writer.start("Buckets");
        for bucket in &self.buckets {
            writer
                .start("Bucket")
                .leaf("Name", &bucket.name)
                .leaf("CreationDate", &bucket.creation_date.iso8601())
                .leaf_opt("BucketRegion", bucket.region.as_deref())
                .end();
        }
        writer.end().leaf_opt("ContinuationToken", self.continuation_token.as_deref()).leaf_opt("Prefix", self.prefix.as_deref());
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "ListAllMyBucketsResult")?;
        let mut buckets = Vec::new();
        if let Some(list) = root.child("Buckets") {
            for bucket in list.children_named("Bucket") {
                buckets.push(Bucket {
                    name: bucket.required_text("Name")?.to_owned(),
                    creation_date: required_time(bucket, "CreationDate")?,
                    region: optional_text(bucket, "BucketRegion"),
                });
            }
        }
        Ok(Self {
            owner: Owner::read_child(&root, "Owner")?,
            buckets,
            continuation_token: optional_text(&root, "ContinuationToken"),
            prefix: optional_text(&root, "Prefix").map(|p| p.trim().to_owned()),
        })
    }
}

/// The result of `GetBucketLocation`: `LocationConstraint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationConstraint(
    /// The region, or `None` for `us-east-1`, which S3 answers with an empty element.
    pub Option<String>,
);

impl LocationConstraint {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("LocationConstraint", true);
        if let Some(region) = &self.0 {
            writer.text(region);
        }
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "LocationConstraint")?;
        let region = root.text.trim();
        Ok(Self((!region.is_empty()).then(|| region.to_owned())))
    }

    /// The region the constraint means: `us-east-1` for none, `eu-west-1` for `EU` (as the documentation says), the value itself otherwise.
    pub fn region(&self) -> &str {
        match self.0.as_deref() {
            None | Some("") => "us-east-1",
            Some("EU") => "eu-west-1",
            Some(other) => other,
        }
    }
}

// ---- ListObjects, ListObjectsV2 ----

/// An object in a listing: `Contents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEntry {
    /// The key.
    pub key: String,
    /// When the object was last modified.
    pub last_modified: Timestamp,
    /// The ETag, in double quotes.
    pub etag: String,
    /// The size in bytes.
    pub size: u64,
    /// The storage class, `STANDARD` for S3.
    pub storage_class: String,
    /// The owner, listed when the request asks for it.
    pub owner: Option<Owner>,
    /// The checksum algorithms the object has.
    pub checksum_algorithms: Vec<String>,
    /// The checksum type, `FULL_OBJECT` or `COMPOSITE`.
    pub checksum_type: Option<String>,
}

impl ObjectEntry {
    /// An entry with the storage class `STANDARD` and nothing optional.
    pub fn new(key: impl Into<String>, last_modified: Timestamp, etag: impl Into<String>, size: u64) -> Self {
        Self {
            key: key.into(),
            last_modified,
            etag: etag.into(),
            size,
            storage_class: "STANDARD".to_owned(),
            owner: None,
            checksum_algorithms: Vec::new(),
            checksum_type: None,
        }
    }

    fn write(&self, writer: &mut XmlWriter, url: bool) {
        writer.start("Contents").leaf("Key", &encoded(url, &self.key)).leaf("LastModified", &self.last_modified.iso8601()).leaf("ETag", &self.etag);
        for algorithm in &self.checksum_algorithms {
            writer.leaf("ChecksumAlgorithm", algorithm);
        }
        writer.leaf_opt("ChecksumType", self.checksum_type.as_deref()).leaf("Size", &self.size.to_string()).leaf("StorageClass", &self.storage_class);
        if let Some(owner) = &self.owner {
            owner.write(writer, "Owner");
        }
        writer.end();
    }

    fn read(element: &Element, url: bool) -> Result<Self, XmlError> {
        Ok(Self {
            key: decoded(url, element.required_text("Key")?.to_owned()),
            last_modified: required_time(element, "LastModified")?,
            etag: element.child_text("ETag").unwrap_or_default().to_owned(),
            size: required_number(element, "Size")?,
            storage_class: element.child_text("StorageClass").unwrap_or("STANDARD").to_owned(),
            owner: Owner::read_child(element, "Owner")?,
            checksum_algorithms: element.children_named("ChecksumAlgorithm").map(|e| e.text.trim().to_owned()).collect(),
            checksum_type: optional_text(element, "ChecksumType"),
        })
    }
}

fn write_common_prefixes(writer: &mut XmlWriter, prefixes: &[String], url: bool) {
    for prefix in prefixes {
        writer.start("CommonPrefixes").leaf("Prefix", &encoded(url, prefix)).end();
    }
}

fn read_common_prefixes(root: &Element, url: bool) -> Result<Vec<String>, XmlError> {
    root.children_named("CommonPrefixes").map(|group| Ok(decoded(url, group.required_text("Prefix")?.to_owned()))).collect()
}

fn read_url_encoding(root: &Element) -> Result<bool, XmlError> {
    match root.child_text("EncodingType").map(str::trim) {
        None | Some("") => Ok(false),
        Some("url") => Ok(true),
        Some(other) => Err(XmlError::invalid("EncodingType", other)),
    }
}

/// The result of `ListObjectsV2`: `ListBucketResult` with `KeyCount` and continuation tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObjectsV2Result {
    /// The bucket.
    pub name: String,
    /// The prefix of the request, empty for none.
    pub prefix: String,
    /// The delimiter of the request.
    pub delimiter: Option<String>,
    /// The `max-keys` of the request (or 1000).
    pub max_keys: u32,
    /// The number of keys and common prefixes in this page.
    pub key_count: u32,
    /// Whether there is more.
    pub is_truncated: bool,
    /// The `continuation-token` of the request.
    pub continuation_token: Option<String>,
    /// The token for the next page, when `is_truncated`.
    pub next_continuation_token: Option<String>,
    /// The `start-after` of the request.
    pub start_after: Option<String>,
    /// The objects.
    pub contents: Vec<ObjectEntry>,
    /// The common prefixes the delimiter rolled keys up into.
    pub common_prefixes: Vec<String>,
    /// Whether keys are URL-encoded in the document (`encoding-type=url`).
    pub url_encoded: bool,
}

impl ListObjectsV2Result {
    /// The document.
    pub fn to_xml(&self) -> String {
        let url = self.url_encoded;
        let mut writer = XmlWriter::new("ListBucketResult", true);
        writer.leaf("Name", &self.name).leaf("Prefix", &encoded(url, &self.prefix));
        writer.leaf_opt("Delimiter", self.delimiter.as_deref().map(|d| encoded(url, d)).as_deref());
        writer.leaf("MaxKeys", &self.max_keys.to_string());
        if url {
            writer.leaf("EncodingType", "url");
        }
        writer.leaf("KeyCount", &self.key_count.to_string()).leaf("IsTruncated", bool_text(self.is_truncated));
        writer.leaf_opt("ContinuationToken", self.continuation_token.as_deref()).leaf_opt("NextContinuationToken", self.next_continuation_token.as_deref());
        writer.leaf_opt("StartAfter", self.start_after.as_deref().map(|s| encoded(url, s)).as_deref());
        for entry in &self.contents {
            entry.write(&mut writer, url);
        }
        write_common_prefixes(&mut writer, &self.common_prefixes, url);
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "ListBucketResult")?;
        let url = read_url_encoding(&root)?;
        let contents = root.children_named("Contents").map(|e| ObjectEntry::read(e, url)).collect::<Result<Vec<_>, _>>()?;
        let common_prefixes = read_common_prefixes(&root, url)?;
        Ok(Self {
            name: root.required_text("Name")?.to_owned(),
            prefix: decoded(url, root.child_text("Prefix").unwrap_or_default().to_owned()),
            delimiter: optional_text(&root, "Delimiter").map(|d| decoded(url, d)),
            max_keys: root.parsed_child("MaxKeys", parse_number)?.unwrap_or(1000),
            key_count: root.parsed_child("KeyCount", parse_number)?.unwrap_or((contents.len() + common_prefixes.len()) as u32),
            is_truncated: root.parsed_child("IsTruncated", parse_bool)?.unwrap_or(false),
            continuation_token: optional_text(&root, "ContinuationToken"),
            next_continuation_token: optional_text(&root, "NextContinuationToken"),
            start_after: optional_text(&root, "StartAfter").map(|s| decoded(url, s)),
            contents,
            common_prefixes,
            url_encoded: url,
        })
    }
}

/// The result of `ListObjects` (version 1): `ListBucketResult` with `Marker` and `NextMarker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObjectsV1Result {
    /// The bucket.
    pub name: String,
    /// The prefix of the request, empty for none.
    pub prefix: String,
    /// The `marker` of the request, empty for none.
    pub marker: String,
    /// The marker for the next page; S3 only sends it when there is a delimiter and the list is truncated.
    pub next_marker: Option<String>,
    /// The delimiter of the request.
    pub delimiter: Option<String>,
    /// The `max-keys` of the request (or 1000).
    pub max_keys: u32,
    /// Whether there is more.
    pub is_truncated: bool,
    /// The objects.
    pub contents: Vec<ObjectEntry>,
    /// The common prefixes the delimiter rolled keys up into.
    pub common_prefixes: Vec<String>,
    /// Whether keys are URL-encoded in the document (`encoding-type=url`).
    pub url_encoded: bool,
}

impl ListObjectsV1Result {
    /// The document.
    pub fn to_xml(&self) -> String {
        let url = self.url_encoded;
        let mut writer = XmlWriter::new("ListBucketResult", true);
        writer.leaf("Name", &self.name).leaf("Prefix", &encoded(url, &self.prefix)).leaf("Marker", &encoded(url, &self.marker));
        writer.leaf_opt("NextMarker", self.next_marker.as_deref().map(|m| encoded(url, m)).as_deref());
        writer.leaf_opt("Delimiter", self.delimiter.as_deref().map(|d| encoded(url, d)).as_deref());
        writer.leaf("MaxKeys", &self.max_keys.to_string());
        if url {
            writer.leaf("EncodingType", "url");
        }
        writer.leaf("IsTruncated", bool_text(self.is_truncated));
        for entry in &self.contents {
            entry.write(&mut writer, url);
        }
        write_common_prefixes(&mut writer, &self.common_prefixes, url);
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "ListBucketResult")?;
        let url = read_url_encoding(&root)?;
        Ok(Self {
            name: root.required_text("Name")?.to_owned(),
            prefix: decoded(url, root.child_text("Prefix").unwrap_or_default().to_owned()),
            marker: decoded(url, root.child_text("Marker").unwrap_or_default().to_owned()),
            next_marker: optional_text(&root, "NextMarker").map(|m| decoded(url, m)),
            delimiter: optional_text(&root, "Delimiter").map(|d| decoded(url, d)),
            max_keys: root.parsed_child("MaxKeys", parse_number)?.unwrap_or(1000),
            is_truncated: root.parsed_child("IsTruncated", parse_bool)?.unwrap_or(false),
            contents: root.children_named("Contents").map(|e| ObjectEntry::read(e, url)).collect::<Result<_, _>>()?,
            common_prefixes: read_common_prefixes(&root, url)?,
            url_encoded: url,
        })
    }
}

// ---- CopyObject ----

/// The result of `CopyObject`: `CopyObjectResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyObjectResult {
    /// The ETag of the new object, in double quotes.
    pub etag: String,
    /// When the new object was last modified.
    pub last_modified: Timestamp,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub checksum_type: Option<String>,
    /// The checksums of the new object.
    pub checksums: Checksums,
}

impl CopyObjectResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("CopyObjectResult", true);
        writer.leaf("ETag", &self.etag).leaf("LastModified", &self.last_modified.iso8601()).leaf_opt("ChecksumType", self.checksum_type.as_deref());
        self.checksums.write(&mut writer);
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "CopyObjectResult")?;
        Ok(Self {
            etag: root.required_text("ETag")?.to_owned(),
            last_modified: required_time(&root, "LastModified")?,
            checksum_type: optional_text(&root, "ChecksumType"),
            checksums: Checksums::read(&root),
        })
    }
}

// ---- DeleteObjects ----

/// An object to delete in the request of `DeleteObjects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteObjectId {
    /// The key.
    pub key: String,
    /// The version, which a bucket without versioning does not have.
    pub version_id: Option<String>,
    /// Delete only if the ETag is this.
    pub etag: Option<String>,
    /// Delete only if the last modification time is this.
    pub last_modified_time: Option<Timestamp>,
    /// Delete only if the size is this.
    pub size: Option<u64>,
}

impl DeleteObjectId {
    /// An object to delete by key.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into(), version_id: None, etag: None, last_modified_time: None, size: None }
    }
}

/// The request of `DeleteObjects`: `Delete`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeleteRequest {
    /// The objects.
    pub objects: Vec<DeleteObjectId>,
    /// Whether to answer only with the failures.
    pub quiet: bool,
}

impl DeleteRequest {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("Delete", true);
        for object in &self.objects {
            writer.start("Object").leaf("Key", &object.key).leaf_opt("VersionId", object.version_id.as_deref()).leaf_opt("ETag", object.etag.as_deref());
            if let Some(time) = object.last_modified_time {
                writer.leaf("LastModifiedTime", &time.iso8601());
            }
            if let Some(size) = object.size {
                writer.leaf("Size", &size.to_string());
            }
            writer.end();
        }
        if self.quiet {
            writer.leaf("Quiet", "true");
        }
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = xml::parse_root(xml, "Delete", &DELETE_LIMITS)?;
        let objects = root
            .children_named("Object")
            .map(|object| {
                Ok(DeleteObjectId {
                    key: object.required_text("Key")?.to_owned(),
                    version_id: optional_trimmed(object, "VersionId"),
                    etag: optional_trimmed(object, "ETag"),
                    last_modified_time: optional_time(object, "LastModifiedTime")?,
                    size: object.parsed_child("Size", parse_number)?,
                })
            })
            .collect::<Result<_, XmlError>>()?;
        Ok(Self { objects, quiet: root.parsed_child("Quiet", parse_bool)?.unwrap_or(false) })
    }
}

/// An object `DeleteObjects` deleted: `Deleted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    /// The key.
    pub key: String,
    /// The version.
    pub version_id: Option<String>,
    /// Whether the deletion made a delete marker.
    pub delete_marker: Option<bool>,
    /// The version of the delete marker.
    pub delete_marker_version_id: Option<String>,
}

impl Deleted {
    /// A deleted key.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into(), version_id: None, delete_marker: None, delete_marker_version_id: None }
    }
}

/// An object `DeleteObjects` could not delete: `Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteFailure {
    /// The key.
    pub key: String,
    /// The version.
    pub version_id: Option<String>,
    /// The error code, such as `AccessDenied`.
    pub code: String,
    /// The message.
    pub message: String,
}

/// The result of `DeleteObjects`: `DeleteResult`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeleteResult {
    /// The objects that were deleted (S3 leaves them out of a quiet request's result).
    pub deleted: Vec<Deleted>,
    /// The objects that could not be deleted.
    pub errors: Vec<DeleteFailure>,
}

impl DeleteResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("DeleteResult", true);
        for deleted in &self.deleted {
            writer.start("Deleted").leaf("Key", &deleted.key).leaf_opt("VersionId", deleted.version_id.as_deref());
            if let Some(marker) = deleted.delete_marker {
                writer.leaf("DeleteMarker", bool_text(marker));
            }
            writer.leaf_opt("DeleteMarkerVersionId", deleted.delete_marker_version_id.as_deref()).end();
        }
        for failure in &self.errors {
            writer
                .start("Error")
                .leaf("Key", &failure.key)
                .leaf_opt("VersionId", failure.version_id.as_deref())
                .leaf("Code", &failure.code)
                .leaf("Message", &failure.message)
                .end();
        }
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "DeleteResult")?;
        let deleted = root
            .children_named("Deleted")
            .map(|e| {
                Ok(Deleted {
                    key: e.required_text("Key")?.to_owned(),
                    version_id: optional_text(e, "VersionId"),
                    delete_marker: e.parsed_child("DeleteMarker", parse_bool)?,
                    delete_marker_version_id: optional_text(e, "DeleteMarkerVersionId"),
                })
            })
            .collect::<Result<_, XmlError>>()?;
        let errors = root
            .children_named("Error")
            .map(|e| {
                Ok(DeleteFailure {
                    key: e.child_text("Key").unwrap_or_default().to_owned(),
                    version_id: optional_text(e, "VersionId"),
                    code: e.required_text("Code")?.to_owned(),
                    message: e.child_text("Message").unwrap_or_default().to_owned(),
                })
            })
            .collect::<Result<_, XmlError>>()?;
        Ok(Self { deleted, errors })
    }
}

// ---- Multipart uploads ----

/// The result of `CreateMultipartUpload`: `InitiateMultipartUploadResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateMultipartUploadResult {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The ID of the upload, which every later call needs.
    pub upload_id: String,
}

impl InitiateMultipartUploadResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("InitiateMultipartUploadResult", true);
        writer.leaf("Bucket", &self.bucket).leaf("Key", &self.key).leaf("UploadId", &self.upload_id);
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "InitiateMultipartUploadResult")?;
        Ok(Self {
            bucket: root.required_text("Bucket")?.to_owned(),
            key: root.required_text("Key")?.to_owned(),
            upload_id: root.required_text("UploadId")?.trim().to_owned(),
        })
    }
}

/// A part in the request of `CompleteMultipartUpload`: `Part`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedPart {
    /// The number of the part, 1 to 10,000.
    pub part_number: u32,
    /// The ETag S3 gave when the part was uploaded.
    pub etag: Option<String>,
    /// The checksums of the part.
    pub checksums: Checksums,
}

impl CompletedPart {
    /// A part with an ETag and no checksums.
    pub fn new(part_number: u32, etag: impl Into<String>) -> Self {
        Self { part_number, etag: Some(etag.into()), checksums: Checksums::default() }
    }
}

/// The request of `CompleteMultipartUpload`: `CompleteMultipartUpload`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompleteMultipartUploadRequest {
    /// The parts, which have to be in ascending order of number.
    pub parts: Vec<CompletedPart>,
}

impl CompleteMultipartUploadRequest {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("CompleteMultipartUpload", true);
        for part in &self.parts {
            writer.start("Part");
            part.checksums.write(&mut writer);
            writer.leaf_opt("ETag", part.etag.as_deref()).leaf("PartNumber", &part.part_number.to_string()).end();
        }
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "CompleteMultipartUpload")?;
        let parts = root
            .children_named("Part")
            .map(|part| {
                Ok(CompletedPart { part_number: required_number(part, "PartNumber")?, etag: optional_trimmed(part, "ETag"), checksums: Checksums::read(part) })
            })
            .collect::<Result<_, XmlError>>()?;
        Ok(Self { parts })
    }
}

/// The result of `CompleteMultipartUpload`: `CompleteMultipartUploadResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteMultipartUploadResult {
    /// The URL of the object.
    pub location: String,
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The ETag of the object (`"…-N"` with `N` parts), in double quotes.
    pub etag: String,
    /// The checksums of the object.
    pub checksums: Checksums,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub checksum_type: Option<String>,
}

impl CompleteMultipartUploadResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("CompleteMultipartUploadResult", true);
        writer.leaf("Location", &self.location).leaf("Bucket", &self.bucket).leaf("Key", &self.key).leaf("ETag", &self.etag);
        self.checksums.write(&mut writer);
        writer.leaf_opt("ChecksumType", self.checksum_type.as_deref());
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "CompleteMultipartUploadResult")?;
        Ok(Self {
            location: root.child_text("Location").unwrap_or_default().to_owned(),
            bucket: root.required_text("Bucket")?.to_owned(),
            key: root.required_text("Key")?.to_owned(),
            etag: root.required_text("ETag")?.to_owned(),
            checksums: Checksums::read(&root),
            checksum_type: optional_text(&root, "ChecksumType"),
        })
    }
}

/// A part in the result of `ListParts`: `Part`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartInfo {
    /// The number of the part.
    pub part_number: u32,
    /// When the part was uploaded.
    pub last_modified: Timestamp,
    /// The ETag of the part, in double quotes.
    pub etag: String,
    /// The size of the part in bytes.
    pub size: u64,
    /// The checksums of the part.
    pub checksums: Checksums,
}

/// The result of `ListParts`: `ListPartsResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPartsResult {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// The ID of the upload.
    pub upload_id: String,
    /// The `part-number-marker` of the request.
    pub part_number_marker: Option<u32>,
    /// The marker for the next page, when `is_truncated`.
    pub next_part_number_marker: Option<u32>,
    /// The `max-parts` of the request (or 1000).
    pub max_parts: u32,
    /// Whether there is more.
    pub is_truncated: bool,
    /// The parts, in ascending order of number.
    pub parts: Vec<PartInfo>,
    /// Who started the upload.
    pub initiator: Option<Owner>,
    /// The owner of the object.
    pub owner: Option<Owner>,
    /// The storage class.
    pub storage_class: Option<String>,
    /// The checksum algorithm of the upload.
    pub checksum_algorithm: Option<String>,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub checksum_type: Option<String>,
}

impl ListPartsResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("ListPartsResult", true);
        writer.leaf("Bucket", &self.bucket).leaf("Key", &self.key).leaf("UploadId", &self.upload_id);
        writer.leaf_opt("PartNumberMarker", self.part_number_marker.map(|n| n.to_string()).as_deref());
        writer.leaf_opt("NextPartNumberMarker", self.next_part_number_marker.map(|n| n.to_string()).as_deref());
        writer.leaf("MaxParts", &self.max_parts.to_string()).leaf("IsTruncated", bool_text(self.is_truncated));
        for part in &self.parts {
            writer
                .start("Part")
                .leaf("PartNumber", &part.part_number.to_string())
                .leaf("LastModified", &part.last_modified.iso8601())
                .leaf("ETag", &part.etag)
                .leaf("Size", &part.size.to_string());
            part.checksums.write(&mut writer);
            writer.end();
        }
        if let Some(initiator) = &self.initiator {
            initiator.write(&mut writer, "Initiator");
        }
        if let Some(owner) = &self.owner {
            owner.write(&mut writer, "Owner");
        }
        writer
            .leaf_opt("StorageClass", self.storage_class.as_deref())
            .leaf_opt("ChecksumAlgorithm", self.checksum_algorithm.as_deref())
            .leaf_opt("ChecksumType", self.checksum_type.as_deref());
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "ListPartsResult")?;
        let parts = root
            .children_named("Part")
            .map(|part| {
                Ok(PartInfo {
                    part_number: required_number(part, "PartNumber")?,
                    last_modified: required_time(part, "LastModified")?,
                    etag: part.child_text("ETag").unwrap_or_default().to_owned(),
                    size: required_number(part, "Size")?,
                    checksums: Checksums::read(part),
                })
            })
            .collect::<Result<_, XmlError>>()?;
        Ok(Self {
            bucket: root.required_text("Bucket")?.to_owned(),
            key: root.required_text("Key")?.to_owned(),
            upload_id: root.required_text("UploadId")?.to_owned(),
            part_number_marker: root.parsed_child("PartNumberMarker", parse_number)?,
            next_part_number_marker: root.parsed_child("NextPartNumberMarker", parse_number)?,
            max_parts: root.parsed_child("MaxParts", parse_number)?.unwrap_or(1000),
            is_truncated: root.parsed_child("IsTruncated", parse_bool)?.unwrap_or(false),
            parts,
            initiator: Owner::read_child(&root, "Initiator")?,
            owner: Owner::read_child(&root, "Owner")?,
            storage_class: optional_text(&root, "StorageClass"),
            checksum_algorithm: optional_text(&root, "ChecksumAlgorithm"),
            checksum_type: optional_text(&root, "ChecksumType"),
        })
    }
}

/// An upload in progress in the result of `ListMultipartUploads`: `Upload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadInfo {
    /// The key.
    pub key: String,
    /// The ID of the upload.
    pub upload_id: String,
    /// Who started it.
    pub initiator: Option<Owner>,
    /// The owner of the object.
    pub owner: Option<Owner>,
    /// The storage class.
    pub storage_class: Option<String>,
    /// When it was started.
    pub initiated: Timestamp,
    /// The checksum algorithm of the upload.
    pub checksum_algorithm: Option<String>,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub checksum_type: Option<String>,
}

/// The result of `ListMultipartUploads`: `ListMultipartUploadsResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListMultipartUploadsResult {
    /// The bucket.
    pub bucket: String,
    /// The `key-marker` of the request.
    pub key_marker: Option<String>,
    /// The `upload-id-marker` of the request.
    pub upload_id_marker: Option<String>,
    /// The key marker for the next page, when `is_truncated`.
    pub next_key_marker: Option<String>,
    /// The upload ID marker for the next page, when `is_truncated`.
    pub next_upload_id_marker: Option<String>,
    /// The prefix of the request.
    pub prefix: Option<String>,
    /// The delimiter of the request.
    pub delimiter: Option<String>,
    /// The `max-uploads` of the request (or 1000).
    pub max_uploads: u32,
    /// Whether there is more.
    pub is_truncated: bool,
    /// The uploads.
    pub uploads: Vec<UploadInfo>,
    /// The common prefixes the delimiter rolled keys up into.
    pub common_prefixes: Vec<String>,
    /// Whether keys are URL-encoded in the document (`encoding-type=url`).
    pub url_encoded: bool,
}

impl ListMultipartUploadsResult {
    /// The document.
    pub fn to_xml(&self) -> String {
        let url = self.url_encoded;
        let enc = |value: &Option<String>| value.as_deref().map(|v| encoded(url, v));
        let mut writer = XmlWriter::new("ListMultipartUploadsResult", true);
        writer.leaf("Bucket", &self.bucket).leaf_opt("KeyMarker", enc(&self.key_marker).as_deref()).leaf_opt("UploadIdMarker", self.upload_id_marker.as_deref());
        writer.leaf_opt("NextKeyMarker", enc(&self.next_key_marker).as_deref()).leaf_opt("NextUploadIdMarker", self.next_upload_id_marker.as_deref());
        writer.leaf_opt("Prefix", enc(&self.prefix).as_deref()).leaf_opt("Delimiter", enc(&self.delimiter).as_deref());
        writer.leaf("MaxUploads", &self.max_uploads.to_string());
        if url {
            writer.leaf("EncodingType", "url");
        }
        writer.leaf("IsTruncated", bool_text(self.is_truncated));
        for upload in &self.uploads {
            writer.start("Upload").leaf("Key", &encoded(url, &upload.key)).leaf("UploadId", &upload.upload_id);
            if let Some(initiator) = &upload.initiator {
                initiator.write(&mut writer, "Initiator");
            }
            if let Some(owner) = &upload.owner {
                owner.write(&mut writer, "Owner");
            }
            writer.leaf_opt("StorageClass", upload.storage_class.as_deref()).leaf("Initiated", &upload.initiated.iso8601());
            writer.leaf_opt("ChecksumAlgorithm", upload.checksum_algorithm.as_deref()).leaf_opt("ChecksumType", upload.checksum_type.as_deref()).end();
        }
        write_common_prefixes(&mut writer, &self.common_prefixes, url);
        writer.finish()
    }

    /// Reads the document.
    pub fn from_xml(xml: &[u8]) -> Result<Self, XmlError> {
        let root = parse_root(xml, "ListMultipartUploadsResult")?;
        let url = read_url_encoding(&root)?;
        let dec = |name: &str| optional_text(&root, name).map(|v| decoded(url, v));
        let uploads = root
            .children_named("Upload")
            .map(|upload| {
                Ok(UploadInfo {
                    key: decoded(url, upload.required_text("Key")?.to_owned()),
                    upload_id: upload.required_text("UploadId")?.to_owned(),
                    initiator: Owner::read_child(upload, "Initiator")?,
                    owner: Owner::read_child(upload, "Owner")?,
                    storage_class: optional_text(upload, "StorageClass"),
                    initiated: required_time(upload, "Initiated")?,
                    checksum_algorithm: optional_text(upload, "ChecksumAlgorithm"),
                    checksum_type: optional_text(upload, "ChecksumType"),
                })
            })
            .collect::<Result<_, XmlError>>()?;
        Ok(Self {
            bucket: root.required_text("Bucket")?.to_owned(),
            key_marker: dec("KeyMarker"),
            upload_id_marker: optional_text(&root, "UploadIdMarker"),
            next_key_marker: dec("NextKeyMarker"),
            next_upload_id_marker: optional_text(&root, "NextUploadIdMarker"),
            prefix: dec("Prefix"),
            delimiter: dec("Delimiter"),
            max_uploads: root.parsed_child("MaxUploads", parse_number)?.unwrap_or(1000),
            is_truncated: root.parsed_child("IsTruncated", parse_bool)?.unwrap_or(false),
            uploads,
            common_prefixes: read_common_prefixes(&root, url)?,
            url_encoded: url,
        })
    }
}
