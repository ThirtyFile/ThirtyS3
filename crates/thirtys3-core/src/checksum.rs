//! The checksum algorithms of S3, computed as data streams by, and the Base64 form they travel in.
//!
//! Follows "Checking object integrity for data uploads in Amazon S3"
//! (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html>) and the `Checksum` data type
//! (<https://docs.aws.amazon.com/AmazonS3/latest/API/API_Checksum.html>): the ten algorithms, the `x-amz-checksum-*` headers and `Checksum*`
//! elements, values as Base64 of the digest, and the two kinds of checksum of a multipart upload (composite, and full object for the CRCs).
//!
//! The documentation does not give the byte order of the CRCs and the xxHash algorithms; they are written big-endian, as the AWS SDKs and the
//! sample in the documentation do (`sOO8/Q==` is the CRC32C `0xB0E3BCFD` of the object in the trailing-checksum example). XXHASH64 has seed 0.
//! Nothing cryptographic is written here: the hashes come from `sha1`, `sha2` and `md-5`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use crc_fast::CrcAlgorithm;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use xxhash_rust::xxh3::Xxh3;
use xxhash_rust::xxh64::Xxh64;

/// A checksum algorithm S3 knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChecksumAlgorithm {
    /// CRC-32 (`CRC32`), 4 bytes.
    Crc32,
    /// CRC-32C (`CRC32C`), 4 bytes.
    Crc32c,
    /// CRC-64/NVME (`CRC64NVME`), 8 bytes.
    Crc64Nvme,
    /// SHA-1 (`SHA1`), 20 bytes.
    Sha1,
    /// SHA-256 (`SHA256`), 32 bytes.
    Sha256,
    /// SHA-512 (`SHA512`), 64 bytes.
    Sha512,
    /// MD5 (`MD5`), 16 bytes.
    Md5,
    /// XXH64 (`XXHASH64`), 8 bytes.
    Xxhash64,
    /// XXH3 with 64 bits (`XXHASH3`), 8 bytes.
    Xxhash3,
    /// XXH3 with 128 bits (`XXHASH128`), 16 bytes.
    Xxhash128,
}

impl ChecksumAlgorithm {
    /// Every algorithm, in the order the documentation lists the `Checksum*` elements.
    pub const ALL: [Self; 10] =
        [Self::Crc32, Self::Crc32c, Self::Crc64Nvme, Self::Md5, Self::Sha1, Self::Sha256, Self::Sha512, Self::Xxhash128, Self::Xxhash3, Self::Xxhash64];

    /// The name in `x-amz-checksum-algorithm` and `ChecksumAlgorithm`, such as `CRC32C`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Md5 => "MD5",
            Self::Xxhash64 => "XXHASH64",
            Self::Xxhash3 => "XXHASH3",
            Self::Xxhash128 => "XXHASH128",
        }
    }

    /// The header that carries the checksum of a request or an object, such as `x-amz-checksum-crc32c`.
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Sha512 => "x-amz-checksum-sha512",
            Self::Md5 => "x-amz-checksum-md5",
            Self::Xxhash64 => "x-amz-checksum-xxhash64",
            Self::Xxhash3 => "x-amz-checksum-xxhash3",
            Self::Xxhash128 => "x-amz-checksum-xxhash128",
        }
    }

    /// The XML element that carries the checksum in a result, such as `ChecksumCRC32C`.
    pub const fn xml_element(self) -> &'static str {
        match self {
            Self::Crc32 => "ChecksumCRC32",
            Self::Crc32c => "ChecksumCRC32C",
            Self::Crc64Nvme => "ChecksumCRC64NVME",
            Self::Sha1 => "ChecksumSHA1",
            Self::Sha256 => "ChecksumSHA256",
            Self::Sha512 => "ChecksumSHA512",
            Self::Md5 => "ChecksumMD5",
            Self::Xxhash64 => "ChecksumXXHASH64",
            Self::Xxhash3 => "ChecksumXXHASH3",
            Self::Xxhash128 => "ChecksumXXHASH128",
        }
    }

    /// The algorithm with this name (`CRC32`, …), whatever the case.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|algorithm| algorithm.name().eq_ignore_ascii_case(name))
    }

    /// The algorithm whose checksum is carried by this header, whatever the case.
    pub fn from_header_name(header: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|algorithm| algorithm.header_name().eq_ignore_ascii_case(header))
    }

    /// The algorithm whose checksum is carried by this XML element.
    pub fn from_xml_element(element: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|algorithm| algorithm.xml_element() == element)
    }

    /// The length of the digest in bytes.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme | Self::Xxhash64 | Self::Xxhash3 => 8,
            Self::Md5 | Self::Xxhash128 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Whether a multipart upload can have a full-object checksum with this algorithm: only the CRCs can, because the checksum of the whole
    /// object can be worked out from the checksums of the parts (see [`combine_crc`]).
    pub const fn supports_full_object(self) -> bool {
        matches!(self, Self::Crc32 | Self::Crc32c | Self::Crc64Nvme)
    }

    /// A hasher for this algorithm.
    pub fn hasher(self) -> Hasher {
        Hasher(match self {
            Self::Crc32 => State::Crc(crc_fast::Digest::new(CrcAlgorithm::Crc32IsoHdlc), self),
            Self::Crc32c => State::Crc(crc_fast::Digest::new(CrcAlgorithm::Crc32Iscsi), self),
            Self::Crc64Nvme => State::Crc(crc_fast::Digest::new(CrcAlgorithm::Crc64Nvme), self),
            Self::Sha1 => State::Sha1(Sha1::new()),
            Self::Sha256 => State::Sha256(Sha256::new()),
            Self::Sha512 => State::Sha512(Box::new(Sha512::new())),
            Self::Md5 => State::Md5(Md5::new()),
            Self::Xxhash64 => State::Xxhash64(Box::new(Xxh64::new(0))),
            Self::Xxhash3 => State::Xxhash3(Box::new(Xxh3::new()), false),
            Self::Xxhash128 => State::Xxhash3(Box::new(Xxh3::new()), true),
        })
    }

    /// The checksum of `data` as Base64.
    pub fn checksum_base64(self, data: &[u8]) -> String {
        let mut hasher = self.hasher();
        hasher.update(data);
        hasher.finalize_base64()
    }

    /// Reads a checksum value as it appears in a header or an element: Base64 of exactly [`digest_len`](Self::digest_len) bytes.
    pub fn decode_value(self, value: &str) -> Option<Vec<u8>> {
        let digest = STANDARD.decode(value.trim()).ok()?;
        (digest.len() == self.digest_len()).then_some(digest)
    }
}

enum State {
    Crc(crc_fast::Digest, ChecksumAlgorithm),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Box<Sha512>),
    Md5(Md5),
    Xxhash64(Box<Xxh64>),
    /// `true` for the 128-bit form.
    Xxhash3(Box<Xxh3>, bool),
}

/// A checksum being computed as data goes by. Feed it with [`update`](Self::update) and read it with [`finalize`](Self::finalize).
pub struct Hasher(State);

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hasher").field(&self.algorithm()).finish()
    }
}

impl Hasher {
    /// The algorithm of this hasher.
    pub fn algorithm(&self) -> ChecksumAlgorithm {
        match &self.0 {
            State::Crc(_, algorithm) => *algorithm,
            State::Sha1(_) => ChecksumAlgorithm::Sha1,
            State::Sha256(_) => ChecksumAlgorithm::Sha256,
            State::Sha512(_) => ChecksumAlgorithm::Sha512,
            State::Md5(_) => ChecksumAlgorithm::Md5,
            State::Xxhash64(_) => ChecksumAlgorithm::Xxhash64,
            State::Xxhash3(_, false) => ChecksumAlgorithm::Xxhash3,
            State::Xxhash3(_, true) => ChecksumAlgorithm::Xxhash128,
        }
    }

    /// Adds data.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            State::Crc(digest, _) => digest.update(data),
            State::Sha1(hasher) => hasher.update(data),
            State::Sha256(hasher) => hasher.update(data),
            State::Sha512(hasher) => hasher.update(data),
            State::Md5(hasher) => hasher.update(data),
            State::Xxhash64(hasher) => hasher.update(data),
            State::Xxhash3(hasher, _) => hasher.update(data),
        }
    }

    /// The digest of the data so far: big-endian for the CRCs and xxHash, as the hash defines it for the others.
    pub fn finalize(&self) -> Vec<u8> {
        match &self.0 {
            State::Crc(digest, algorithm) => {
                let value = digest.finalize();
                match algorithm.digest_len() {
                    4 => (value as u32).to_be_bytes().to_vec(),
                    _ => value.to_be_bytes().to_vec(),
                }
            }
            State::Sha1(hasher) => hasher.clone().finalize().to_vec(),
            State::Sha256(hasher) => hasher.clone().finalize().to_vec(),
            State::Sha512(hasher) => hasher.clone().finalize().to_vec(),
            State::Md5(hasher) => hasher.clone().finalize().to_vec(),
            State::Xxhash64(hasher) => hasher.digest().to_be_bytes().to_vec(),
            State::Xxhash3(hasher, false) => hasher.digest().to_be_bytes().to_vec(),
            State::Xxhash3(hasher, true) => hasher.digest128().to_be_bytes().to_vec(),
        }
    }

    /// The digest as Base64, the form of `x-amz-checksum-*` headers and `Checksum*` elements.
    pub fn finalize_base64(&self) -> String {
        STANDARD.encode(self.finalize())
    }
}

/// Several checksums computed in one pass over the data.
#[derive(Debug, Default)]
pub struct Hashers(Vec<Hasher>);

impl Hashers {
    /// Hashers for these algorithms (one each, even if one is named twice).
    pub fn new(algorithms: impl IntoIterator<Item = ChecksumAlgorithm>) -> Self {
        let mut chosen: Vec<ChecksumAlgorithm> = algorithms.into_iter().collect();
        chosen.sort();
        chosen.dedup();
        Self(chosen.into_iter().map(ChecksumAlgorithm::hasher).collect())
    }

    /// Adds data to every hasher.
    pub fn update(&mut self, data: &[u8]) {
        for hasher in &mut self.0 {
            hasher.update(data);
        }
    }

    /// The Base64 checksum of each algorithm, sorted by algorithm.
    pub fn finalize_base64(&self) -> Vec<(ChecksumAlgorithm, String)> {
        self.0.iter().map(|hasher| (hasher.algorithm(), hasher.finalize_base64())).collect()
    }
}

/// Base64 (standard alphabet, with padding) of bytes.
pub fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// The digest of a composite checksum of a multipart upload: the checksum of the part digests put one after the other. The documentation says
/// that a composite checksum "is calculated based on the individual checksums of each part" and shows it computed this way (its Java example
/// feeds each part's SHA-256 into one more SHA-256).
pub fn composite_digest(algorithm: ChecksumAlgorithm, part_digests: &[Vec<u8>]) -> Vec<u8> {
    let mut hasher = algorithm.hasher();
    for digest in part_digests {
        hasher.update(digest);
    }
    hasher.finalize()
}

/// The value S3 puts in the `x-amz-checksum-*` header of an object uploaded in parts with composite checksums: the Base64 of the
/// [`composite_digest`], then `-` and the number of parts. The documentation only says this for the ETag (see [`crate::etag::multipart_etag`]);
/// for checksums it is what S3 does.
pub fn composite_checksum_value(algorithm: ChecksumAlgorithm, part_digests: &[Vec<u8>]) -> String {
    format!("{}-{}", base64_encode(&composite_digest(algorithm, part_digests)), part_digests.len())
}

/// The full-object CRC of an object from the CRCs and the sizes of its parts, in order. `None` for an algorithm that is not a CRC or when a
/// digest does not have the length of the algorithm. S3 does this to check the full-object checksum of a multipart upload against the parts
/// without reading them again.
pub fn combine_crc(algorithm: ChecksumAlgorithm, parts: &[(Vec<u8>, u64)]) -> Option<Vec<u8>> {
    let crc_algorithm = match algorithm {
        ChecksumAlgorithm::Crc32 => CrcAlgorithm::Crc32IsoHdlc,
        ChecksumAlgorithm::Crc32c => CrcAlgorithm::Crc32Iscsi,
        ChecksumAlgorithm::Crc64Nvme => CrcAlgorithm::Crc64Nvme,
        _ => return None,
    };
    let value =
        |digest: &[u8]| -> Option<u64> { (digest.len() == algorithm.digest_len()).then(|| digest.iter().fold(0_u64, |value, byte| value << 8 | u64::from(*byte))) };
    let (first, rest) = parts.split_first()?;
    let mut combined = value(&first.0)?;
    for (digest, length) in rest {
        combined = crc_fast::checksum_combine(crc_algorithm, combined, value(digest)?, *length);
    }
    Some(if algorithm.digest_len() == 4 { (combined as u32).to_be_bytes().to_vec() } else { combined.to_be_bytes().to_vec() })
}
