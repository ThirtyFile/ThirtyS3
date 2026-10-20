//! The body of a download, which carries on from where it broke off when the connection drops.

use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use http::Method;
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::client::{Client, Spec};
use crate::error::{Error, ErrorKind};
use crate::meta::parse_content_range;
use crate::transport::body_error;

type Pieces = Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>;

/// The bytes of an object as they arrive. It is a [`Stream`] of pieces.
///
/// When the connection breaks or goes silent for longer than the read timeout, the rest is asked for with a `Range` request and `If-Match` the
/// ETag of the object (when it has one), and the stream goes on as if nothing had happened: up to `max_retries` breaks in a row in which nothing
/// was received, and until `retry_timeout` after the start of the download. If the object was replaced meanwhile the stream ends with
/// [`Error::ObjectChanged`], so that a download never mixes two versions.
pub struct GetBody {
    pieces: Pieces,
    length: u64,
}

impl std::fmt::Debug for GetBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetBody").field("length", &self.length).finish_non_exhaustive()
    }
}

impl GetBody {
    /// The number of bytes the body has in all.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Whether the body has no bytes.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Reads all of it into memory.
    pub async fn bytes(mut self) -> Result<Bytes, Error> {
        use futures_util::StreamExt;
        let mut data = BytesMut::with_capacity(self.length.min(64 * 1024 * 1024) as usize);
        while let Some(piece) = self.next().await {
            data.extend_from_slice(&piece?);
        }
        Ok(data.freeze())
    }
}

impl Stream for GetBody {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.pieces.as_mut().poll_next(context)
    }
}

struct State {
    client: Client,
    key: String,
    path: String,
    etag: Option<String>,
    /// The next byte to receive, as a position in the object.
    next: u64,
    /// Where the body ends, as a position in the object.
    end: u64,
    body: Option<Incoming>,
    started: Instant,
    /// Breaks in a row without receiving anything.
    failures: u32,
    done: bool,
}

impl State {
    /// Asks for the rest of the object and takes the new response as the body.
    async fn resume(&mut self) -> Result<(), Error> {
        let mut spec = Spec::new(Method::GET, self.path.clone()).header("range", format!("bytes={}-{}", self.next, self.end - 1));
        if let Some(etag) = &self.etag {
            spec = spec.header("if-match", etag.clone());
        }
        let response = match self.client.execute(&spec).await {
            Ok(response) => response,
            Err(error) if error.kind() == ErrorKind::PreconditionFailed => return Err(Error::ObjectChanged),
            Err(error) => return Err(error),
        };
        let (parts, body) = response.into_parts();
        let covered = parts.headers.get("content-range").and_then(|value| value.to_str().ok()).and_then(parse_content_range).map(|(range, _)| range);
        if parts.status.as_u16() != 206 || covered.as_ref().map(|range| range.start) != Some(self.next) {
            return Err(Error::Protocol(format!("asked for the rest of {:?} from byte {} and did not get exactly that", self.key, self.next)));
        }
        self.body = Some(body);
        Ok(())
    }

    /// The next piece, or `None` at the end.
    async fn step(mut self) -> Option<(Result<Bytes, Error>, Self)> {
        loop {
            if self.done || self.next >= self.end {
                return None;
            }
            if self.body.is_none()
                && let Err(error) = self.resume().await
            {
                self.done = true;
                return Some((Err(error), self));
            }
            let mut body = self.body.take()?;
            let read_timeout = self.client.inner.transport.read_timeout;
            let failure = match tokio::time::timeout(read_timeout, body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    self.body = Some(body);
                    let Ok(data) = frame.into_data() else { continue };
                    if data.is_empty() {
                        continue;
                    }
                    // A server that sends more than it said is not believed.
                    let data = data.slice(..data.len().min((self.end - self.next) as usize));
                    self.next += data.len() as u64;
                    self.failures = 0;
                    return Some((Ok(data), self));
                }
                Ok(Some(Err(error))) => body_error(&error),
                Ok(None) => Error::Transport(format!("the download ended {} bytes early", self.end - self.next)),
                Err(_) => Error::Timeout("the download stopped coming".to_owned()),
            };
            self.failures += 1;
            let inner = &self.client.inner;
            if self.failures > inner.max_retries || self.started.elapsed() >= inner.retry_timeout {
                self.done = true;
                return Some((Err(failure), self));
            }
            let wait = inner.backoff.delay(self.failures - 1);
            tracing::debug!("the download of {:?} broke off ({failure}); asking for the rest in {wait:?}", self.key);
            tokio::time::sleep(wait).await;
        }
    }
}

impl GetBody {
    /// The body of a response to a request for `covered` bytes of the object at `path`, whose ETag is `etag`.
    pub(crate) fn new(client: Client, key: String, path: String, etag: Option<String>, covered: Range<u64>, first: Incoming) -> Self {
        let state = State { client, key, path, etag, next: covered.start, end: covered.end, body: Some(first), started: Instant::now(), failures: 0, done: false };
        Self { pieces: Box::pin(futures_util::stream::unfold(state, State::step)), length: covered.end - covered.start }
    }
}
