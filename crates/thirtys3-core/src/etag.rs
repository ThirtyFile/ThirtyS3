//! ETags of objects, and the `If-Match` and `If-None-Match` headers that compare them.
//!
//! Follows "Checking object integrity" (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html>): the ETag
//! of an object uploaded in one request is the MD5 of its content in hex; for an object uploaded in parts, S3 "concatenates the bytes for the MD5
//! digests together and then calculates the MD5 digest of these concatenated values", and "adds a dash with the total number of parts to the
//! end". And "Add preconditions to S3 operations with conditional requests"
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html>) for the headers.

use md5::{Digest, Md5};

use crate::encoding::hex_encode;

/// The MD5 of `data`.
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// The ETag of an object uploaded in one request, from the MD5 of its content: the hex in double quotes, as S3 sends it.
pub fn etag_from_md5(md5: &[u8]) -> String {
    format!("\"{}\"", hex_encode(md5))
}

/// The ETag of an object uploaded in parts, from the MD5 of each part in order: the hex of the MD5 of the digests one after the other, a dash and
/// the number of parts, in double quotes.
pub fn multipart_etag(part_md5s: &[impl AsRef<[u8]>]) -> String {
    let mut hasher = Md5::new();
    for md5 in part_md5s {
        hasher.update(md5.as_ref());
    }
    format!("\"{}-{}\"", hex_encode(&hasher.finalize()), part_md5s.len())
}

/// An ETag without the double quotes (and without a weak-validator `W/` in front of them).
pub fn unquote(etag: &str) -> &str {
    let etag = etag.trim();
    let etag = etag.strip_prefix("W/").unwrap_or(etag);
    etag.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(etag)
}

/// One entity tag in a header: `"abc"` or `W/"abc"`. A tag without quotes is taken as it is, because some clients send them that way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTag {
    /// Whether the tag had `W/` in front.
    pub weak: bool,
    /// The tag inside the quotes.
    pub value: String,
}

/// The value of an `If-Match` or `If-None-Match` header: `*` or a list of entity tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETagCondition {
    /// `*`: any current version.
    Any,
    /// A list of tags.
    Tags(Vec<EntityTag>),
}

impl ETagCondition {
    /// Reads the header value. `None` for an empty value or a quote that is not closed.
    pub fn parse(header: &str) -> Option<Self> {
        let header = header.trim();
        if header == "*" {
            return Some(Self::Any);
        }
        let mut tags = Vec::new();
        let mut rest = header;
        while !rest.is_empty() {
            rest = rest.trim_start_matches([' ', '\t', ',']);
            if rest.is_empty() {
                break;
            }
            let (weak, after) = match rest.strip_prefix("W/") {
                Some(after) => (true, after),
                None => (false, rest),
            };
            if let Some(quoted) = after.strip_prefix('"') {
                let end = quoted.find('"')?;
                tags.push(EntityTag { weak, value: quoted[..end].to_owned() });
                rest = &quoted[end + 1..];
            } else {
                let end = after.find(',').unwrap_or(after.len());
                let value = after[..end].trim();
                if !value.is_empty() {
                    tags.push(EntityTag { weak, value: value.to_owned() });
                }
                rest = &after[end..];
            }
        }
        (!tags.is_empty()).then_some(Self::Tags(tags))
    }

    /// Whether `etag` (with or without quotes) is the one the header names. `strong` is the strong comparison `If-Match` uses, which never
    /// matches a weak tag; otherwise the weak comparison that `If-None-Match` uses, which ignores the `W/`.
    pub fn matches(&self, etag: &str, strong: bool) -> bool {
        match self {
            Self::Any => true,
            Self::Tags(tags) => {
                let current = unquote(etag);
                tags.iter().any(|tag| tag.value == current && !(strong && tag.weak))
            }
        }
    }
}
