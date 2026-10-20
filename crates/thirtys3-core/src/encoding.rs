//! URI encoding as Signature Version 4 defines it, and the canonical forms of a path and a query string.
//!
//! Follows "Create a signed AWS API request" (`UriEncode()`, `CanonicalUri`, `CanonicalQueryString`) at
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>.
//! Amazon S3 differs from other services in one way that matters here: the path is encoded once (not twice) and is never normalised
//! (`.`, `..` and `//` are kept), because an object key may contain them.

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Whether `byte` is one of the unreserved characters, `A-Z a-z 0-9 - . _ ~`, which `UriEncode()` leaves as they are.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// `UriEncode()`: encodes every byte except the unreserved characters, as `%XX` with upper-case hex digits (a space becomes `%20`, never `+`).
/// The forward slash is encoded only when `encode_slash` is true: it stays as it is in an object key and in a path, and is encoded everywhere else.
pub fn uri_encode(input: &[u8], encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        if is_unreserved(byte) || (byte == b'/' && !encode_slash) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 15) as usize] as char);
        }
    }
    out
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes `%XX` sequences (and, when `plus_as_space` is true, `+` as a space). A `%` that is not followed by two hex digits is kept as it is.
/// The result is bytes, because a decoded path or query may not be valid UTF-8.
pub fn percent_decode(input: &str, plus_as_space: bool) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.len() - i >= 3 => match (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// `CanonicalUri`: the path as it was sent on the wire, decoded and encoded again the way `UriEncode()` does (slashes kept). An empty path is `/`.
/// Taking the wire form makes a client that encodes `!` or `*` differently from AWS sign the same string as AWS.
pub fn canonical_uri(wire_path: &str) -> String {
    if wire_path.is_empty() {
        return "/".to_owned();
    }
    uri_encode(&percent_decode(wire_path, false), false)
}

/// The decoded `(name, value)` pairs of a query string, in the order they appear. A parameter without `=` has an empty value; `+` is a space.
pub fn query_params(wire_query: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    wire_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name, true), percent_decode(value, true))
        })
        .collect()
}

/// `CanonicalQueryString`: each name and value decoded and encoded again, sorted by name and then by value. `skip` is given each decoded name
/// and returns true for the parameters to leave out (`X-Amz-Signature` in a presigned URL). A parameter without `=` has an empty value (`?acl` is `acl=`).
/// A `+` in a query is a space (and `%2B` is a plus), as S3 reads it.
pub fn canonical_query(wire_query: &str, skip: impl Fn(&[u8]) -> bool) -> String {
    let mut pairs: Vec<(String, String)> = wire_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = percent_decode(name, true);
            if skip(&name) {
                return None;
            }
            Some((uri_encode(&name, true), uri_encode(&percent_decode(value, true), true)))
        })
        .collect();
    pairs.sort();
    let mut out = String::new();
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// Lower-case hex of `bytes`.
pub fn hex_encode(bytes: &[u8]) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LOWER[(byte >> 4) as usize] as char);
        out.push(LOWER[(byte & 15) as usize] as char);
    }
    out
}

/// Decodes hex (either case). `None` when the length is odd or a character is not a hex digit.
pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes.chunks_exact(2).map(|pair| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?)).collect()
}
