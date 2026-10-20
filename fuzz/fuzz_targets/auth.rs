#![no_main]

use libfuzzer_sys::fuzz_target;
use thirtys3_core::{PayloadHash, Request, Timestamp, parse_request_auth};

// The lines of the input are the `Authorization` header, the query, `x-amz-date` and `x-amz-content-sha256` of a request.
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.split('\n');
    let (authorization, query, date, hash) = (lines.next().unwrap_or(""), lines.next().unwrap_or(""), lines.next().unwrap_or(""), lines.next().unwrap_or(""));
    let headers = [("host", "s3.example.com"), ("authorization", authorization), ("x-amz-date", date), ("x-amz-content-sha256", hash)];
    let request = Request { method: "GET", path: "/bucket/key", query, headers: &headers };
    if let Ok(Some(parsed)) = parse_request_auth(&request) {
        let _ = parsed.check_time(Timestamp(1_700_000_000));
        let _ = parsed.verify(&request, "secret", Timestamp(1_700_000_000));
    }
    let _ = PayloadHash::parse(hash);
});
