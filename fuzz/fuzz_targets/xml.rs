#![no_main]

use libfuzzer_sys::fuzz_target;
use thirtys3_core::S3Error;
use thirtys3_core::model::*;
use thirtys3_core::xml::{self, Limits};

// Every reader of a document gets the same bytes: none of them may panic, hang or build a tree larger than its limits.
fuzz_target!(|data: &[u8]| {
    let _ = ListAllMyBucketsResult::from_xml(data);
    let _ = LocationConstraint::from_xml(data);
    let _ = ListObjectsV2Result::from_xml(data);
    let _ = ListObjectsV1Result::from_xml(data);
    let _ = CopyObjectResult::from_xml(data);
    let _ = DeleteRequest::from_xml(data);
    let _ = DeleteResult::from_xml(data);
    let _ = InitiateMultipartUploadResult::from_xml(data);
    let _ = CompleteMultipartUploadRequest::from_xml(data);
    let _ = CompleteMultipartUploadResult::from_xml(data);
    let _ = ListPartsResult::from_xml(data);
    let _ = ListMultipartUploadsResult::from_xml(data);
    let _ = S3Error::from_xml(data, 400);
    let _ = xml::parse(data, &Limits { max_bytes: 4096, max_depth: 4, max_elements: 64 });
});
