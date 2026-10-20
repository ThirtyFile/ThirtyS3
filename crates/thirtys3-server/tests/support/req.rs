//! Raw requests that can be made to do odd things: another host, another time, another signer, no length, no signature.

use bytes::Bytes;
use http::Method;
use thirtys3_core::{Request as SigRequest, Signer, Timestamp, sha256_hex};

use super::{Answer, Server, send_raw, signer};

/// A request to build, sign and send.
pub struct Req<'a> {
    pub method: Method,
    pub target: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body: Bytes,
    pub host: Option<String>,
    pub time: Timestamp,
    pub signer: Signer,
    pub payload_hash: Option<String>,
    pub signed: bool,
    pub content_length: bool,
}

impl<'a> Req<'a> {
    pub fn new(method: Method, target: &'a str) -> Self {
        Self {
            method,
            target,
            headers: Vec::new(),
            body: Bytes::new(),
            host: None,
            time: Timestamp::now(),
            signer: signer(),
            payload_hash: None,
            signed: true,
            content_length: true,
        }
    }

    pub fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_owned());
        self
    }

    pub fn at(mut self, time: Timestamp) -> Self {
        self.time = time;
        self
    }

    pub fn signer(mut self, signer: Signer) -> Self {
        self.signer = signer;
        self
    }

    pub fn payload_hash(mut self, hash: &str) -> Self {
        self.payload_hash = Some(hash.to_owned());
        self
    }

    pub fn unsigned(mut self) -> Self {
        self.signed = false;
        self
    }

    pub fn no_content_length(mut self) -> Self {
        self.content_length = false;
        self
    }

    pub async fn send<B>(self, server: &Server<B>) -> Answer {
        let (path, query) = self.target.split_once('?').unwrap_or((self.target, ""));
        let host = self.host.clone().unwrap_or_else(|| server.host());
        let length = self.body.len().to_string();
        let mut headers: Vec<(&str, &str)> = vec![("host", &host)];
        headers.extend(self.headers.iter().copied());
        if self.content_length && (!self.body.is_empty() || self.method == Method::PUT || self.method == Method::POST) {
            headers.push(("content-length", &length));
        }
        let mut sent: Vec<(String, String)> =
            headers.iter().filter(|(name, _)| *name != "host").map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
        if self.signed {
            let hash = self.payload_hash.clone().unwrap_or_else(|| sha256_hex(&self.body));
            let request = SigRequest { method: self.method.as_str(), path, query, headers: &headers };
            let signed = self.signer.sign(&request, &hash, self.time).unwrap();
            sent.extend(signed.headers.iter().cloned());
        }
        if self.host.is_some() {
            sent.push(("host".to_owned(), host.clone()));
        }
        let sent: Vec<(&str, String)> = sent.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
        send_raw(server, self.method, self.target, &sent, self.body).await
    }
}

pub fn req(method: Method, target: &str) -> Req<'_> {
    Req::new(method, target)
}

/// The text between two tags of an XML answer.
pub fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].to_owned())
}

/// The text of every element with this name.
pub fn tags(xml: &str, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&format!("<{name}>")) {
        let from = start + name.len() + 2;
        let Some(end) = rest[from..].find(&format!("</{name}>")) else { break };
        found.push(rest[from..from + end].to_owned());
        rest = &rest[from + end..];
    }
    found
}

/// The headers of a signed request, to send by hand: `host` first, the headers given, the `content-length`, and what the signature adds.
pub fn signed_headers(
    host: &str,
    method: &str,
    target: &str,
    extra: &[(&str, &str)],
    content_length: Option<usize>,
    payload_hash: &str,
    signer: &Signer,
) -> (Vec<(String, String)>, thirtys3_core::SignedRequest) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let length = content_length.map(|length| length.to_string());
    let mut headers: Vec<(&str, &str)> = vec![("host", host)];
    headers.extend(extra.iter().copied());
    if let Some(length) = &length {
        headers.push(("content-length", length));
    }
    let request = SigRequest { method, path, query, headers: &headers };
    let signed = signer.sign(&request, payload_hash, Timestamp::now()).unwrap();
    let mut all: Vec<(String, String)> = headers.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
    all.extend(signed.headers.iter().cloned());
    (all, signed)
}

/// An HTTP/1.1 request head as bytes.
pub fn request_head(method: &str, target: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}
