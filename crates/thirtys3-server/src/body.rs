//! The body of a request, with everything that can be checked about it checked on the way through.
//!
//! The bytes are handed on as they arrive, not held back until they have been checked, so a body of any size passes with the memory of one
//! piece. What follows from that is the one rule a backend has to keep: **an upload is complete and right only when the stream has ended with
//! `None`.** Until then the chunk signatures, the signature of the trailing headers, the hash of the payload, `Content-MD5`, the checksums, the
//! length and the size limit have been checked only for what came so far; the stream ends with an error as soon as one of them is wrong, at the
//! latest in place of the end. A backend therefore reads the stream to the end before it keeps anything, and drops what it has when the
//! stream gives an error or is dropped.

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use thirtys3_core::checksum::{ChecksumAlgorithm, Hasher, base64_encode};
use thirtys3_core::encoding::hex_encode;
use thirtys3_core::s3_error::code;
use thirtys3_core::{ChunkChain, S3Error};

use crate::chunked::{Decoder, Event};

/// The error type of the bodies the service accepts.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body as the service receives it.
pub type IncomingBody = UnsyncBoxBody<Bytes, BoxError>;

/// What was worked out about the data of a body that came through completely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// The number of bytes of data.
    pub size: u64,
    /// The MD5, which is the ETag of an object uploaded in one request.
    pub md5: [u8; 16],
    /// The SHA-256, when the request had a payload hash to check it against.
    pub sha256: Option<[u8; 32]>,
    /// The checksums the request named, as the raw digests.
    pub checksums: Vec<(ChecksumAlgorithm, Vec<u8>)>,
}

impl Digests {
    /// The ETag of an object with this data: the MD5 in hex, in double quotes.
    pub fn etag(&self) -> String {
        thirtys3_core::etag::etag_from_md5(&self.md5)
    }
}

/// How the data of a body comes.
#[derive(Debug)]
#[non_exhaustive]
pub enum Framing {
    /// As it is.
    Plain,
    /// In `aws-chunked` chunks; `signed` checks the signature of each chunk with the chain, `trailers` says the body ends with trailing headers.
    Chunked {
        /// The chain of chunk signatures, for a signed body.
        signed: Option<ChunkChain>,
        /// Whether the body ends with trailing headers.
        trailers: bool,
    },
}

/// What to check about a body.
#[derive(Debug)]
pub struct BodyPlan {
    /// How the data comes.
    pub framing: Framing,
    /// The number of bytes of data the request declares: `Content-Length`, or `x-amz-decoded-content-length` for a chunked body.
    pub length: Option<u64>,
    /// The SHA-256 of the data in hex, when the request says what it is (`x-amz-content-sha256`).
    pub payload_sha256: Option<String>,
    /// The `Content-MD5`, decoded.
    pub content_md5: Option<Vec<u8>>,
    /// The checksums the headers give, as the digests they decode to.
    pub checksums: Vec<(ChecksumAlgorithm, Vec<u8>)>,
    /// The checksums the request says will come in the trailing headers.
    pub trailer_checksums: Vec<ChecksumAlgorithm>,
    /// The most bytes of data accepted.
    pub max_size: u64,
    /// The largest chunk accepted.
    pub max_chunk: u64,
    /// How long to wait for the next piece of the body; `None` waits for ever.
    pub idle_timeout: Option<std::time::Duration>,
}

fn malformed_trailer(message: &str) -> S3Error {
    S3Error::new(code::MALFORMED_TRAILER, message)
}

struct State {
    inner: IncomingBody,
    inner_done: bool,
    decoder: Option<Decoder>,
    chain: Option<ChunkChain>,
    plan_length: Option<u64>,
    max_size: u64,
    idle_timeout: Option<std::time::Duration>,
    payload_sha256: Option<String>,
    content_md5: Option<Vec<u8>>,
    header_checksums: Vec<(ChecksumAlgorithm, Vec<u8>)>,
    trailer_checksums: Vec<ChecksumAlgorithm>,
    md5: Hasher,
    sha256: Option<Hasher>,
    checksum_hashers: Vec<Hasher>,
    /// The hash of the data of the chunk being read, for a signed body, and the signature it has to match.
    chunk: Option<(Hasher, String)>,
    size: u64,
    /// Everything the framing of the body said has come and was checked; what is left is for the connection's body to end.
    ended: bool,
    /// The digests, worked out when the framing ended and published when the whole body has ended, with nothing after the end.
    pending: Option<Digests>,
    finished: bool,
    failed: bool,
    digests: Arc<OnceLock<Digests>>,
}

impl State {
    fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        if let Some(sha) = &mut self.sha256 {
            sha.update(data);
        }
        for hasher in &mut self.checksum_hashers {
            hasher.update(data);
        }
        if let Some((hasher, _)) = &mut self.chunk {
            hasher.update(data);
        }
    }

    fn count(&mut self, length: usize) -> Result<(), S3Error> {
        self.size += length as u64;
        // More than was said it would be is known at once: a body does not run on to the size limit for the length to be found wrong at its end.
        if let Some(declared) = self.plan_length
            && self.size > declared
        {
            return Err(S3Error::new(code::INCOMPLETE_BODY, "You provided more bytes than the length specified in the request.")
                .with_detail("NumberBytesExpected", declared.to_string())
                .with_detail("NumberBytesProvided", self.size.to_string()));
        }
        if self.size > self.max_size {
            return Err(S3Error::new(code::ENTITY_TOO_LARGE, "Your proposed upload exceeds the maximum allowed size")
                .with_detail("MaxSizeAllowed", self.max_size.to_string()));
        }
        Ok(())
    }

    /// Checks what can only be checked at the end, and works out the digests.
    fn finish(&mut self, trailer: Option<Vec<(String, String)>>) -> Result<Digests, S3Error> {
        if let Some(declared) = self.plan_length
            && declared != self.size
        {
            return Err(S3Error::new(code::INCOMPLETE_BODY, "You did not provide the number of bytes specified by the Content-Length HTTP header.")
                .with_detail("NumberBytesExpected", declared.to_string())
                .with_detail("NumberBytesProvided", self.size.to_string()));
        }
        let md5 = self.md5.finalize();
        if let Some(wanted) = &self.content_md5
            && *wanted != md5
        {
            return Err(S3Error::new(code::BAD_DIGEST, "The Content-MD5 you specified did not match what we received.")
                .with_detail("ExpectedDigest", base64_encode(wanted))
                .with_detail("CalculatedDigest", base64_encode(&md5)));
        }
        let sha256 = self.sha256.as_ref().map(Hasher::finalize);
        if let (Some(wanted), Some(actual)) = (&self.payload_sha256, &sha256)
            && !wanted.eq_ignore_ascii_case(&hex_encode(actual))
        {
            return Err(S3Error::new(code::X_AMZ_CONTENT_SHA256_MISMATCH, "The provided 'x-amz-content-sha256' header does not match what was computed.")
                .with_detail("ClientComputedContentSHA256", wanted.clone())
                .with_detail("S3ComputedContentSHA256", hex_encode(actual)));
        }
        let computed: Vec<(ChecksumAlgorithm, Vec<u8>)> = self.checksum_hashers.iter().map(|hasher| (hasher.algorithm(), hasher.finalize())).collect();
        for (algorithm, wanted) in &self.header_checksums {
            if computed.iter().find(|(candidate, _)| candidate == algorithm).is_some_and(|(_, actual)| actual != wanted) {
                return Err(bad_checksum(*algorithm, wanted, &computed));
            }
        }
        let mut seen = Vec::new();
        for (name, value) in trailer.unwrap_or_default() {
            let Some(algorithm) = ChecksumAlgorithm::from_header_name(&name) else { continue };
            if !self.trailer_checksums.contains(&algorithm) {
                return Err(malformed_trailer("a checksum in the trailing headers that the request did not announce in x-amz-trailer"));
            }
            let wanted = algorithm.decode_value(&value).ok_or_else(|| malformed_trailer("a checksum in the trailing headers is not valid"))?;
            if computed.iter().find(|(candidate, _)| *candidate == algorithm).is_some_and(|(_, actual)| *actual != wanted) {
                return Err(bad_checksum(algorithm, &wanted, &computed));
            }
            seen.push(algorithm);
        }
        if let Some(missing) = self.trailer_checksums.iter().find(|algorithm| !seen.contains(algorithm)) {
            return Err(malformed_trailer(&format!("{} was announced in x-amz-trailer and did not come", missing.header_name())));
        }
        Ok(Digests {
            size: self.size,
            md5: md5.try_into().expect("MD5 is 16 bytes"),
            sha256: sha256.map(|digest| digest.try_into().expect("SHA-256 is 32 bytes")),
            checksums: computed,
        })
    }

    /// The next piece, `None` at the end.
    async fn next(&mut self) -> Result<Option<Bytes>, S3Error> {
        loop {
            if self.finished {
                return Ok(None);
            }
            if self.ended {
                // The framing is over. Nothing may follow it, in what has been read or in what is still to come, and only when the body has ended
                // without anything after the end is it good.
                if let Some(decoder) = &self.decoder {
                    decoder.finish().map_err(|error| decode_error(&error))?;
                }
                if self.inner_done {
                    if let Some(digests) = self.pending.take() {
                        let _ = self.digests.set(digests);
                    }
                    self.finished = true;
                    continue;
                }
            }
            if let Some(decoder) = &mut self.decoder {
                match decoder.next_event().map_err(|error| decode_error(&error))? {
                    Some(Event::Chunk { size, signature }) => {
                        if let Some(chain) = &mut self.chain {
                            let signature = signature.unwrap_or_default();
                            if size == 0 {
                                // Nothing follows the last chunk but its signature to check.
                                let empty = thirtys3_core::sigv4::EMPTY_PAYLOAD_SHA256;
                                chain.verify_chunk(empty, &signature).map_err(chunk_signature_error)?;
                            } else {
                                self.chunk = Some((ChecksumAlgorithm::Sha256.hasher(), signature));
                            }
                        }
                        continue;
                    }
                    Some(Event::Data(data)) => {
                        self.count(data.len())?;
                        self.update(&data);
                        return Ok(Some(data));
                    }
                    Some(Event::ChunkEnd) => {
                        if let (Some(chain), Some((hasher, signature))) = (&mut self.chain, self.chunk.take()) {
                            chain.verify_chunk(&hex_encode(&hasher.finalize()), &signature).map_err(chunk_signature_error)?;
                        }
                        continue;
                    }
                    Some(Event::Trailer { headers, signature }) => {
                        if let Some(chain) = &self.chain {
                            let mut text = String::new();
                            for (name, value) in &headers {
                                text.push_str(name);
                                text.push(':');
                                text.push_str(value);
                                text.push('\n');
                            }
                            let hash = thirtys3_core::sha256_hex(text.as_bytes());
                            chain
                                .verify_trailer(&hash, &signature.ok_or_else(|| malformed_trailer("the trailing headers have no x-amz-trailer-signature"))?)
                                .map_err(chunk_signature_error)?;
                        }
                        self.pending = Some(self.finish(Some(headers))?);
                        self.ended = true;
                        continue;
                    }
                    Some(Event::End) => {
                        self.pending = Some(self.finish(None)?);
                        self.ended = true;
                        continue;
                    }
                    None => {}
                }
            }
            if self.inner_done {
                match &self.decoder {
                    Some(decoder) => decoder.finish().map_err(|error| decode_error(&error))?,
                    None => {
                        self.pending = Some(self.finish(None)?);
                        self.ended = true;
                        continue;
                    }
                }
                // The decoder is done, so the end of the framing was seen and `ended` is set: the next turn publishes the digests.
                debug_assert!(self.ended);
                continue;
            }
            let frame = match self.idle_timeout {
                None => self.inner.frame().await,
                Some(wait) => tokio::time::timeout(wait, self.inner.frame()).await.map_err(|_| {
                    S3Error::new(code::REQUEST_TIMEOUT, "Your socket connection to the server was not read from or written to within the timeout period.")
                })?,
            };
            match frame {
                None => self.inner_done = true,
                Some(Err(error)) => return Err(S3Error::new(code::INCOMPLETE_BODY, format!("The request body could not be read: {error}"))),
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else { continue };
                    match &mut self.decoder {
                        Some(decoder) => decoder.push(&data),
                        None => {
                            if !data.is_empty() {
                                self.count(data.len())?;
                                self.update(&data);
                                return Ok(Some(data));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn bad_checksum(algorithm: ChecksumAlgorithm, wanted: &[u8], computed: &[(ChecksumAlgorithm, Vec<u8>)]) -> S3Error {
    let actual = computed.iter().find(|(candidate, _)| *candidate == algorithm).map(|(_, digest)| base64_encode(digest)).unwrap_or_default();
    S3Error::new(code::BAD_DIGEST, format!("The {} you specified did not match the calculated checksum.", algorithm.name()))
        .with_detail("ExpectedDigest", base64_encode(wanted))
        .with_detail("CalculatedDigest", actual)
}

fn decode_error(error: &crate::chunked::DecodeError) -> S3Error {
    if error.truncated {
        S3Error::new(code::INCOMPLETE_BODY, error.message.clone())
    } else {
        S3Error::new(code::INVALID_REQUEST, format!("The aws-chunked body is not well formed: {}", error.message))
    }
}

fn chunk_signature_error(_: thirtys3_core::SigError) -> S3Error {
    S3Error::new(code::SIGNATURE_DOES_NOT_MATCH, "The chunk signature we calculated does not match the signature you provided.")
}

/// The body of a request, read with its checks. It is a [`Stream`] of pieces of data. Read the module documentation for the rule about when an
/// upload may be kept.
pub struct RequestBody {
    pieces: Pin<Box<dyn Stream<Item = Result<Bytes, S3Error>> + Send>>,
    digests: Arc<OnceLock<Digests>>,
}

impl std::fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestBody").field("digests", &self.digests.get()).finish_non_exhaustive()
    }
}

impl RequestBody {
    /// A body read from `inner` and checked as `plan` says.
    pub fn new(inner: IncomingBody, plan: BodyPlan) -> Self {
        let digests = Arc::new(OnceLock::new());
        let (decoder, chain) = match plan.framing {
            Framing::Plain => (None, None),
            Framing::Chunked { signed, trailers } => (Some(Decoder::new(signed.is_some(), trailers, plan.max_chunk)), signed),
        };
        let mut algorithms: Vec<ChecksumAlgorithm> = plan.checksums.iter().map(|(algorithm, _)| *algorithm).chain(plan.trailer_checksums.iter().copied()).collect();
        algorithms.sort();
        algorithms.dedup();
        let state = State {
            inner,
            inner_done: false,
            decoder,
            chain,
            plan_length: plan.length,
            max_size: plan.max_size,
            idle_timeout: plan.idle_timeout,
            md5: ChecksumAlgorithm::Md5.hasher(),
            sha256: plan.payload_sha256.is_some().then(|| ChecksumAlgorithm::Sha256.hasher()),
            payload_sha256: plan.payload_sha256,
            content_md5: plan.content_md5,
            header_checksums: plan.checksums,
            trailer_checksums: plan.trailer_checksums,
            checksum_hashers: algorithms.into_iter().map(ChecksumAlgorithm::hasher).collect(),
            chunk: None,
            size: 0,
            ended: false,
            pending: None,
            finished: false,
            failed: false,
            digests: digests.clone(),
        };
        let pieces = futures_util::stream::unfold(state, |mut state| async move {
            if state.failed {
                return None;
            }
            match state.next().await {
                Ok(Some(data)) => Some((Ok(data), state)),
                Ok(None) => None,
                Err(error) => {
                    state.failed = true;
                    Some((Err(error), state))
                }
            }
        });
        Self { pieces: Box::pin(pieces), digests }
    }

    /// A body that is these bytes, for tests and for the operations that have none.
    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        let data: Bytes = data.into();
        let body = http_body_util::Full::new(data.clone()).map_err(|never| match never {}).boxed_unsync();
        Self::new(
            body,
            BodyPlan {
                framing: Framing::Plain,
                length: Some(data.len() as u64),
                payload_sha256: None,
                content_md5: None,
                checksums: Vec::new(),
                trailer_checksums: Vec::new(),
                max_size: u64::MAX,
                max_chunk: 8 * 1024 * 1024,
                idle_timeout: None,
            },
        )
    }

    /// A handle to the digests that stays valid when the body has been moved on, for the code that has to check afterwards that the whole body
    /// was read. It has the digests once the stream has ended with `None`.
    pub fn handle(&self) -> Arc<OnceLock<Digests>> {
        self.digests.clone()
    }

    /// What was worked out about the data, once the stream has ended with `None`. Before that, and after an error, there is nothing.
    pub fn digests(&self) -> Option<&Digests> {
        self.digests.get()
    }

    /// Reads all of it into memory. For small bodies and tests. The result is what [`digests`](Self::digests) was checked against.
    pub async fn collect(mut self) -> Result<(Bytes, Digests), S3Error> {
        use futures_util::StreamExt;
        let mut data = bytes::BytesMut::new();
        while let Some(piece) = self.next().await {
            data.extend_from_slice(&piece?);
        }
        let digests = self.digests().cloned().ok_or_else(|| S3Error::new(code::INTERNAL_ERROR, "the body ended without being checked"))?;
        Ok((data.freeze(), digests))
    }
}

impl Stream for RequestBody {
    type Item = Result<Bytes, S3Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.pieces.as_mut().poll_next(context)
    }
}
