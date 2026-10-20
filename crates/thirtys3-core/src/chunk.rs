//! The signatures of an `aws-chunked` body: each chunk is signed with the signature of the one before it, starting from the seed signature of the
//! request, so the chunks cannot be reordered or cut short.
//!
//! Follows "Signature Calculations for the Authorization Header: Transferring Payload in Multiple Chunks" and the page on trailing headers,
//! which AWS has removed from its documentation and which are kept in the Internet Archive:
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html> and
//! <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html>.

use crate::error::SigError;
use crate::sigv4::{ALGORITHM, EMPTY_PAYLOAD_SHA256, Scope, SigningKey};

/// The chain of chunk signatures of one request. The sender calls [`sign_chunk`](Self::sign_chunk) for each chunk; the receiver calls
/// [`verify_chunk`](Self::verify_chunk), which moves the chain on only when the signature is right.
#[derive(Debug, Clone)]
pub struct ChunkChain {
    key: SigningKey,
    amz_date: String,
    scope: Scope,
    previous: String,
    /// Whether the chunk with no data has been verified: nothing follows it but the trailing headers.
    finished: bool,
}

impl ChunkChain {
    /// Starts the chain at the seed signature, which is the signature of the request itself.
    pub fn new(key: SigningKey, amz_date: String, scope: Scope, seed_signature: &str) -> Self {
        Self { key, amz_date, scope, previous: seed_signature.to_ascii_lowercase(), finished: false }
    }

    fn chunk_string_to_sign(&self, chunk_sha256_hex: &str) -> String {
        format!("{ALGORITHM}-PAYLOAD\n{}\n{}\n{}\n{EMPTY_PAYLOAD_SHA256}\n{chunk_sha256_hex}", self.amz_date, self.scope, self.previous)
    }

    fn trailer_string_to_sign(&self, trailer_sha256_hex: &str) -> String {
        format!("{ALGORITHM}-TRAILER\n{}\n{}\n{}\n{trailer_sha256_hex}", self.amz_date, self.scope, self.previous)
    }

    /// Signs the next chunk, whose data has the SHA-256 `chunk_sha256_hex`, and moves the chain on. The last chunk, the one with no data,
    /// is signed with the SHA-256 of nothing ([`EMPTY_PAYLOAD_SHA256`]).
    pub fn sign_chunk(&mut self, chunk_sha256_hex: &str) -> String {
        let signature = self.key.sign_hex(self.chunk_string_to_sign(chunk_sha256_hex).as_bytes());
        self.previous = signature.clone();
        signature
    }

    /// Checks the signature a sender gave to the next chunk. On success the chain moves on; on failure it stays where it was. The chunk with no
    /// data ([`EMPTY_PAYLOAD_SHA256`]) ends the chain: no chunk can follow it, and [`is_finished`](Self::is_finished) says it has been seen.
    pub fn verify_chunk(&mut self, chunk_sha256_hex: &str, claimed_signature: &str) -> Result<(), SigError> {
        if self.finished || !self.key.verify_hex(self.chunk_string_to_sign(chunk_sha256_hex).as_bytes(), claimed_signature) {
            return Err(SigError::SignatureDoesNotMatch);
        }
        self.previous = claimed_signature.to_ascii_lowercase();
        self.finished = chunk_sha256_hex == EMPTY_PAYLOAD_SHA256;
        Ok(())
    }

    /// Whether the chunk with no data has been verified. A body that stops before it was cut short, whatever the chunks before the cut were.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Signs the trailing headers, which come after the chunk with no data. `trailer_sha256_hex` is the SHA-256 of the headers as
    /// `name:value\n` lines, such as `x-amz-checksum-crc32c:sOO8/Q==\n`.
    pub fn sign_trailer(&self, trailer_sha256_hex: &str) -> String {
        self.key.sign_hex(self.trailer_string_to_sign(trailer_sha256_hex).as_bytes())
    }

    /// Checks the `x-amz-trailer-signature` of the trailing headers. They come after the chunk with no data, so this fails until that chunk has been
    /// verified.
    pub fn verify_trailer(&self, trailer_sha256_hex: &str, claimed_signature: &str) -> Result<(), SigError> {
        if self.finished && self.key.verify_hex(self.trailer_string_to_sign(trailer_sha256_hex).as_bytes(), claimed_signature) {
            Ok(())
        } else {
            Err(SigError::SignatureDoesNotMatch)
        }
    }
}
