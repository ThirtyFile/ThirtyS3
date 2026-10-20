//! Decoding of `aws-chunked` bodies, the framing that streaming uploads use.
//!
//! Follows "Signature Calculations for the Authorization Header: Transferring Payload in Multiple Chunks" and the page on trailing headers, which
//! AWS has removed from its documentation and which are kept in the Internet Archive
//! (<https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html>, `…/sigv4-streaming-trailers.html`). A body is a series of chunks,
//! each `hex-size[;chunk-signature=hex]\r\n data \r\n`, ended by a chunk of size 0, which is followed by trailing headers (`name:value\r\n`
//! lines and an empty line) when the request said it has them, or by an empty line when not.
//!
//! The decoder does no I/O: bytes go in with [`Decoder::push`] and [`Event`]s come out of [`Decoder::next_event`]. It checks the framing only; the
//! signatures are checked by the caller, with [`thirtys3_core::ChunkChain`].

use bytes::{Bytes, BytesMut};

/// The longest line of framing: a chunk header (a size and a signature) or a trailing header.
const MAX_LINE: usize = 4096;
/// The most trailing headers.
const MAX_TRAILERS: usize = 32;

/// What is wrong with a body: it is not `aws-chunked`, or it ends too soon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// What is wrong.
    pub message: String,
    /// Whether the body ended before it was complete (as opposed to being wrong in what it did say).
    pub truncated: bool,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DecodeError {}

fn wrong(message: impl Into<String>) -> DecodeError {
    DecodeError { message: message.into(), truncated: false }
}

/// A piece of a decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A chunk begins. `size` bytes of data follow in [`Event::Data`] events; the chunk of size 0 ends the data. `signature` is the
    /// `chunk-signature` of a signed body.
    Chunk {
        /// The number of bytes of data in the chunk.
        size: u64,
        /// The signature in the header of the chunk, lower-case hex.
        signature: Option<String>,
    },
    /// Data of the current chunk.
    Data(Bytes),
    /// The data of the current chunk is complete (and its line ending read).
    ChunkEnd,
    /// The trailing headers, after the chunk of size 0. `signature` is the value of `x-amz-trailer-signature`, which is not among `headers`.
    Trailer {
        /// The names (lower-case) and values.
        headers: Vec<(String, String)>,
        /// The `x-amz-trailer-signature`.
        signature: Option<String>,
    },
    /// The body is complete.
    End,
}

#[derive(Debug)]
enum State {
    Header,
    Data {
        remaining: u64,
    },
    DataEnd,
    /// After the chunk of size 0 of a body without trailing headers: the empty line.
    LastLine,
    Trailers {
        lines: Vec<(String, String)>,
        signature: Option<String>,
        bytes: usize,
    },
    Done,
}

/// Decodes the framing of an `aws-chunked` body.
#[derive(Debug)]
pub struct Decoder {
    signed: bool,
    trailers: bool,
    max_chunk: u64,
    buffer: BytesMut,
    state: State,
}

impl Decoder {
    /// A decoder. `signed` is for a body whose chunks have signatures; `trailers` for one that ends with trailing headers; `max_chunk` is the
    /// largest chunk accepted, in bytes.
    pub fn new(signed: bool, trailers: bool, max_chunk: u64) -> Self {
        Self { signed, trailers, max_chunk, buffer: BytesMut::new(), state: State::Header }
    }

    /// Adds bytes of the body.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Whether the end of the body has been reached.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Bytes pushed that are not decoded yet.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// To be called when no more bytes will come: an error if the body is not complete.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if !self.is_done() {
            return Err(DecodeError { message: "the body ends before the last chunk".to_owned(), truncated: true });
        }
        if !self.buffer.is_empty() {
            return Err(wrong("there is data after the end of the body"));
        }
        Ok(())
    }

    /// The line at the start of the buffer, without its `\r\n`, if it is all there.
    fn line(&mut self) -> Result<Option<BytesMut>, DecodeError> {
        match self.buffer.windows(2).position(|pair| pair == b"\r\n") {
            Some(at) if at > MAX_LINE => Err(wrong("a line of the framing is too long")),
            Some(at) => {
                let line = self.buffer.split_to(at);
                let _ = self.buffer.split_to(2);
                Ok(Some(line))
            }
            None if self.buffer.len() > MAX_LINE => Err(wrong("a line of the framing is too long")),
            None => Ok(None),
        }
    }

    /// The next piece of the body, or `None` when more bytes are needed (or the body is done).
    pub fn next_event(&mut self) -> Result<Option<Event>, DecodeError> {
        loop {
            match &mut self.state {
                State::Done => return Ok(None),
                State::Header => {
                    let Some(line) = self.line()? else { return Ok(None) };
                    let (size, signature) = self.parse_header(&line)?;
                    self.state = match (size, self.trailers) {
                        (0, true) => State::Trailers { lines: Vec::new(), signature: None, bytes: 0 },
                        (0, false) => State::LastLine,
                        (size, _) => State::Data { remaining: size },
                    };
                    return Ok(Some(Event::Chunk { size, signature }));
                }
                State::Data { remaining } => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    let take = (*remaining).min(self.buffer.len() as u64) as usize;
                    let data = self.buffer.split_to(take).freeze();
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.state = State::DataEnd;
                    }
                    return Ok(Some(Event::Data(data)));
                }
                State::DataEnd => {
                    if self.buffer.len() < 2 {
                        return Ok(None);
                    }
                    if &self.buffer[..2] != b"\r\n" {
                        return Err(wrong("a chunk is not followed by a line ending"));
                    }
                    let _ = self.buffer.split_to(2);
                    self.state = State::Header;
                    return Ok(Some(Event::ChunkEnd));
                }
                State::LastLine => {
                    if self.buffer.len() < 2 {
                        return Ok(None);
                    }
                    if &self.buffer[..2] != b"\r\n" {
                        return Err(wrong("the last chunk is not followed by a line ending"));
                    }
                    let _ = self.buffer.split_to(2);
                    self.state = State::Done;
                    return Ok(Some(Event::End));
                }
                State::Trailers { .. } => {
                    let Some(line) = self.line()? else { return Ok(None) };
                    let State::Trailers { lines, signature, bytes } = &mut self.state else { unreachable!() };
                    if line.is_empty() {
                        let event = Event::Trailer { headers: std::mem::take(lines), signature: signature.take() };
                        self.state = State::Done;
                        return Ok(Some(event));
                    }
                    *bytes += line.len();
                    if lines.len() >= MAX_TRAILERS || *bytes > 8 * MAX_LINE {
                        return Err(wrong("too many trailing headers"));
                    }
                    let text = std::str::from_utf8(&line).map_err(|_| wrong("a trailing header is not text"))?;
                    let (name, value) = text.split_once(':').ok_or_else(|| wrong("a trailing header has no colon"))?;
                    let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_owned());
                    if name.is_empty() {
                        return Err(wrong("a trailing header has no name"));
                    }
                    if name == "x-amz-trailer-signature" {
                        if signature.replace(value.to_ascii_lowercase()).is_some() {
                            return Err(wrong("two trailer signatures"));
                        }
                    } else {
                        lines.push((name, value));
                    }
                }
            }
        }
    }

    /// Reads `size[;chunk-signature=hex]`.
    fn parse_header(&self, line: &[u8]) -> Result<(u64, Option<String>), DecodeError> {
        let text = std::str::from_utf8(line).map_err(|_| wrong("a chunk header is not text"))?;
        let (size_text, extension) = match text.split_once(';') {
            Some((size, extension)) => (size, Some(extension)),
            None => (text, None),
        };
        if size_text.is_empty() || size_text.len() > 16 || !size_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(wrong("a chunk header does not start with a size in hex"));
        }
        let size = u64::from_str_radix(size_text, 16).map_err(|_| wrong("a chunk size is not a number"))?;
        if size > self.max_chunk {
            return Err(wrong(format!("a chunk of {size} bytes is larger than the {} bytes allowed", self.max_chunk)));
        }
        let signature = if self.signed {
            let signature = extension.and_then(|extension| extension.strip_prefix("chunk-signature=")).ok_or_else(|| wrong("a chunk has no chunk-signature"))?;
            if signature.len() != 64 || !signature.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(wrong("a chunk-signature is not 64 hex digits"));
            }
            Some(signature.to_ascii_lowercase())
        } else {
            // The chunks of an unsigned body have no signature; anything after the size is ignored.
            None
        };
        Ok((size, signature))
    }
}
