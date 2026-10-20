//! The documents of the operations: the examples from AWS's documentation must be read, and what is written must be read back.
//!
//! The fixtures are the example responses and requests on the pages `API_<Operation>.html` of the S3 API reference.

use thirtys3_core::Timestamp;
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::model::*;
use thirtys3_core::xml::XmlError;

const T: Timestamp = Timestamp(1_255_369_830); // 2009-10-12T17:50:30Z

// ---- the documentation's examples ----

#[test]
fn list_buckets_example() {
    let xml = r#"<ListAllMyBucketsResult>
 <Buckets>
  <Bucket>
   <CreationDate>2019-12-11T23:32:47+00:00</CreationDate>
   <Name>amzn-s3-demo-bucket</Name>
  </Bucket>
  <Bucket>
   <CreationDate>2019-11-10T23:32:13+00:00</CreationDate>
   <Name>amzn-s3-demo-bucket1</Name>
  </Bucket>
 </Buckets>
 <Owner>
  <ID>AIDACKCEVSQ6C2EXAMPLE</ID>
 </Owner>
</ListAllMyBucketsResult>"#;
    let result = ListAllMyBucketsResult::from_xml(xml.as_bytes()).unwrap();
    assert_eq!(result.buckets.len(), 2);
    assert_eq!(result.buckets[0].name, "amzn-s3-demo-bucket");
    assert_eq!(result.buckets[0].creation_date, Timestamp::parse_amz_date("20191211T233247Z").unwrap());
    assert_eq!(result.owner, Some(Owner { id: "AIDACKCEVSQ6C2EXAMPLE".into(), display_name: None }));
    assert_eq!(result.continuation_token, None);
}

#[test]
fn paginated_list_buckets_example() {
    let xml = r#"<ListAllMyBucketsResult>
 <Buckets><Bucket><CreationDate>2024-11-14T23:32:47+00:00</CreationDate><Name>amzn-s3-demo-bucket</Name><BucketRegion>us-east-2</BucketRegion></Bucket></Buckets>
 <Owner><ID>AIDACKCEVSQ6C2EXAMPLE</ID></Owner>
 <Prefix>
  amzn-s3-demo-bucket
 </Prefix>
 <ContinuationToken>eyJOZXh0VG9rZW4iOiBudWxsLCAiYm90b190cnVuY2F0ZV9hbW91bnQiEXAMPLE=</ContinuationToken>
</ListAllMyBucketsResult>"#;
    let result = ListAllMyBucketsResult::from_xml(xml.as_bytes()).unwrap();
    assert_eq!(result.buckets[0].region.as_deref(), Some("us-east-2"));
    assert_eq!(result.prefix.as_deref(), Some("amzn-s3-demo-bucket"));
    assert_eq!(result.continuation_token.as_deref(), Some("eyJOZXh0VG9rZW4iOiBudWxsLCAiYm90b190cnVuY2F0ZV9hbW91bnQiEXAMPLE="));
}

#[test]
fn get_bucket_location_example() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-west-2</LocationConstraint>";
    let constraint = LocationConstraint::from_xml(xml.as_bytes()).unwrap();
    assert_eq!(constraint.region(), "us-west-2");
}

#[test]
fn the_location_of_us_east_1_is_empty_and_eu_is_eu_west_1() {
    let empty = LocationConstraint::from_xml(b"<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>").unwrap();
    assert_eq!(empty, LocationConstraint(None));
    assert_eq!(empty.region(), "us-east-1");
    assert_eq!(LocationConstraint(Some("EU".into())).region(), "eu-west-1");
    assert_eq!(
        LocationConstraint(None).to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></LocationConstraint>"
    );
    assert_eq!(
        LocationConstraint(Some("us-west-2".into())).to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-west-2</LocationConstraint>"
    );
}

#[test]
fn list_objects_v2_example() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Name>quotes</Name>
 <Prefix>E</Prefix>
 <StartAfter>ExampleGuide.pdf</StartAfter>
 <KeyCount>1</KeyCount>
 <MaxKeys>3</MaxKeys>
 <IsTruncated>false</IsTruncated>
 <Contents>
  <Key>ExampleObject.txt</Key>
  <LastModified>2013-09-17T18:07:53.000Z</LastModified>
  <ETag>"599bab3ed2c697f1d26842727561fd94"</ETag>
  <Size>857</Size>
  <StorageClass>REDUCED_REDUNDANCY</StorageClass>
 </Contents>
</ListBucketResult>"#;
    let result = ListObjectsV2Result::from_xml(xml.as_bytes()).unwrap();
    assert_eq!((result.name.as_str(), result.prefix.as_str(), result.start_after.as_deref()), ("quotes", "E", Some("ExampleGuide.pdf")));
    assert_eq!((result.key_count, result.max_keys, result.is_truncated), (1, 3, false));
    let object = &result.contents[0];
    assert_eq!(object.key, "ExampleObject.txt");
    assert_eq!(object.etag, "\"599bab3ed2c697f1d26842727561fd94\"");
    assert_eq!((object.size, object.storage_class.as_str()), (857, "REDUCED_REDUNDANCY"));
    assert_eq!(object.last_modified, Timestamp::parse_amz_date("20130917T180753Z").unwrap());
}

#[test]
fn delete_objects_examples() {
    let request = "<Delete>\n<Object>\n<Key>sample1.txt</Key>\n</Object>\n<Object>\n<Key>sample2.txt</Key>\n</Object>\n</Delete>";
    let parsed = DeleteRequest::from_xml(request.as_bytes()).unwrap();
    assert_eq!(parsed.objects.iter().map(|o| o.key.as_str()).collect::<Vec<_>>(), ["sample1.txt", "sample2.txt"]);
    assert!(!parsed.quiet);

    let response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n<Deleted>\n <Key>sample1.txt</Key>\n</Deleted>\n<Error>\n<Key>sample2.txt</Key>\n<Code>AccessDenied</Code>\n<Message>Access Denied</Message>\n</Error>\n</DeleteResult>";
    let result = DeleteResult::from_xml(response.as_bytes()).unwrap();
    assert_eq!(result.deleted, [Deleted::new("sample1.txt")]);
    assert_eq!(result.errors, [DeleteFailure { key: "sample2.txt".into(), version_id: None, code: "AccessDenied".into(), message: "Access Denied".into() }]);

    let versioned = "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n <Deleted>\n <Key>SampleDocument.txt</Key>\n <DeleteMarker>true</DeleteMarker> \n <DeleteMarkerVersionId>NeQt5xeFTfgPJD8B4CGWnkSLtluMr11s</DeleteMarkerVersionId>\n </Deleted>\n</DeleteResult>";
    let result = DeleteResult::from_xml(versioned.as_bytes()).unwrap();
    assert_eq!(result.deleted[0].delete_marker, Some(true));
    assert_eq!(result.deleted[0].delete_marker_version_id.as_deref(), Some("NeQt5xeFTfgPJD8B4CGWnkSLtluMr11s"));
}

#[test]
fn complete_multipart_upload_examples() {
    let request = r#"<CompleteMultipartUpload>
 <Part><PartNumber>1</PartNumber><ETag>"a54357aff0632cce46d942af68356b38"</ETag></Part>
 <Part><PartNumber>2</PartNumber><ETag>"0c78aef83f66abc1fa1e8477f296d394"</ETag></Part>
 <Part><PartNumber>3</PartNumber><ETag>"acbd18db4cc2f85cedef654fccc4a4d8"</ETag></Part>
</CompleteMultipartUpload>"#;
    let parsed = CompleteMultipartUploadRequest::from_xml(request.as_bytes()).unwrap();
    assert_eq!(parsed.parts.iter().map(|p| p.part_number).collect::<Vec<_>>(), [1, 2, 3]);
    assert_eq!(parsed.parts[0].etag.as_deref(), Some("\"a54357aff0632cce46d942af68356b38\""));

    let response = r#"<?xml version="1.0" encoding="UTF-8"?>
 <CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Location>http://amzn-s3-demo-bucket.s3.<Region>.amazonaws.com/Example-Object</Location>
 <Bucket>amzn-s3-demo-bucket</Bucket>
 <Key>Example-Object</Key>
 <ETag>"3858f62230ac3c915f300c664312c11f-9"</ETag>
 </CompleteMultipartUploadResult>"#;
    // The documentation writes <Region> inside the URL: it is a placeholder, and not well-formed XML.
    assert!(CompleteMultipartUploadResult::from_xml(response.as_bytes()).is_err());
    let response = response.replace("<Region>", "us-east-1");
    let result = CompleteMultipartUploadResult::from_xml(response.as_bytes()).unwrap();
    assert_eq!((result.bucket.as_str(), result.key.as_str()), ("amzn-s3-demo-bucket", "Example-Object"));
    assert_eq!(result.etag, "\"3858f62230ac3c915f300c664312c11f-9\"");
}

#[test]
fn list_parts_example() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Bucket>example-bucket</Bucket>
 <Key>example-object</Key>
 <UploadId>XXBsb2FkIElEIGZvciBlbHZpbmcncyVcdS1tb3ZpZS5tMnRzEEEwbG9hZA</UploadId>
 <Initiator><ID>arn:aws:iam::111122223333:user/some-user-11116a31-17b5-4fb7-9df5-b288870f11xx</ID></Initiator>
 <Owner><ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID></Owner>
 <StorageClass>STANDARD</StorageClass>
 <PartNumberMarker>1</PartNumberMarker>
 <NextPartNumberMarker>3</NextPartNumberMarker>
 <MaxParts>2</MaxParts>
 <IsTruncated>true</IsTruncated>
 <Part><PartNumber>2</PartNumber><LastModified>2010-11-10T20:48:34.000Z</LastModified><ETag>"7778aef83f66abc1fa1e8477f296d394"</ETag><Size>10485760</Size></Part>
 <Part><PartNumber>3</PartNumber><LastModified>2010-11-10T20:48:33.000Z</LastModified><ETag>"aaaa18db4cc2f85cedef654fccc4a4x8"</ETag><Size>10485760</Size></Part>
</ListPartsResult>"#;
    let result = ListPartsResult::from_xml(xml.as_bytes()).unwrap();
    assert_eq!((result.part_number_marker, result.next_part_number_marker, result.max_parts, result.is_truncated), (Some(1), Some(3), 2, true));
    assert_eq!(result.parts.iter().map(|p| (p.part_number, p.size)).collect::<Vec<_>>(), [(2, 10_485_760), (3, 10_485_760)]);
    assert_eq!(result.storage_class.as_deref(), Some("STANDARD"));
    assert_eq!(result.initiator.unwrap().id, "arn:aws:iam::111122223333:user/some-user-11116a31-17b5-4fb7-9df5-b288870f11xx");
}

#[test]
fn list_multipart_uploads_example() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Bucket>bucket</Bucket>
 <KeyMarker></KeyMarker>
 <UploadIdMarker></UploadIdMarker>
 <NextKeyMarker>my-movie.m2ts</NextKeyMarker>
 <NextUploadIdMarker>YW55IGlkZWEgd2h5IGVsdmluZydzIHVwbG9hZCBmYWlsZWQ</NextUploadIdMarker>
 <MaxUploads>3</MaxUploads>
 <IsTruncated>true</IsTruncated>
 <Upload><Key>my-divisor</Key><UploadId>XMgbGlrZSBlbHZpbmcncyBub3QgaGF2aW5nIG11Y2ggbHVjaw</UploadId>
  <Initiator><ID>arn:aws:iam::111122223333:user/user1</ID></Initiator><Owner><ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID></Owner>
  <StorageClass>STANDARD</StorageClass><Initiated>2010-11-10T20:48:33.000Z</Initiated></Upload>
 <Upload><Key>my-movie.m2ts</Key><UploadId>VXBsb2FkIElEIGZvciBlbHZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA</UploadId>
  <Initiator><ID>b1d16700c70b0b05597d7acd6a3f92be</ID></Initiator><Owner><ID>b1d16700c70b0b05597d7acd6a3f92be</ID></Owner>
  <StorageClass>STANDARD</StorageClass><Initiated>2010-11-10T20:48:33.000Z</Initiated></Upload>
</ListMultipartUploadsResult>"#;
    let result = ListMultipartUploadsResult::from_xml(xml.as_bytes()).unwrap();
    assert_eq!((result.next_key_marker.as_deref(), result.max_uploads, result.is_truncated), (Some("my-movie.m2ts"), 3, true));
    assert_eq!(result.key_marker.as_deref(), Some(""));
    assert_eq!(result.uploads.iter().map(|u| u.key.as_str()).collect::<Vec<_>>(), ["my-divisor", "my-movie.m2ts"]);
    assert_eq!(result.uploads[1].initiated, Timestamp::parse_amz_date("20101110T204833Z").unwrap());
}

// ---- what is written ----

fn entry(key: &str) -> ObjectEntry {
    ObjectEntry::new(key, T, "\"d41d8cd98f00b204e9800998ecf8427e\"", 5)
}

#[test]
fn the_list_objects_v2_document_is_in_the_form_s3_writes() {
    let result = ListObjectsV2Result {
        name: "bucket".into(),
        prefix: "p/".into(),
        delimiter: Some("/".into()),
        max_keys: 1000,
        key_count: 2,
        is_truncated: true,
        continuation_token: None,
        next_continuation_token: Some("token".into()),
        start_after: None,
        contents: vec![entry("p/a.txt")],
        common_prefixes: vec!["p/sub/".into()],
        url_encoded: false,
    };
    assert_eq!(
        result.to_xml(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>bucket</Name><Prefix>p/</Prefix><Delimiter>/</Delimiter><MaxKeys>1000</MaxKeys><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated><NextContinuationToken>token</NextContinuationToken><Contents><Key>p/a.txt</Key><LastModified>2009-10-12T17:50:30.000Z</LastModified><ETag>\"d41d8cd98f00b204e9800998ecf8427e\"</ETag><Size>5</Size><StorageClass>STANDARD</StorageClass></Contents><CommonPrefixes><Prefix>p/sub/</Prefix></CommonPrefixes></ListBucketResult>"
    );
}

#[test]
fn url_encoding_encodes_everything_but_ascii_letters_and_digits_and_is_undone_on_reading() {
    let prefix = "中文 # %/";
    let result = ListObjectsV2Result {
        name: "b".into(),
        prefix: prefix.into(),
        delimiter: Some("/".into()),
        max_keys: 1000,
        key_count: 1,
        is_truncated: false,
        continuation_token: Some("a+b/c=".into()),
        next_continuation_token: None,
        start_after: Some(prefix.into()),
        contents: vec![entry("中文 # %/a.txt")],
        common_prefixes: vec![prefix.into()],
        url_encoded: true,
    };
    let xml = result.to_xml();
    let encoded = "%E4%B8%AD%E6%96%87%20%23%20%25%2F";
    assert!(xml.contains(&format!("<Prefix>{encoded}</Prefix>")), "{xml}");
    assert!(xml.contains("<Delimiter>%2F</Delimiter>"), "{xml}");
    assert!(xml.contains(&format!("<StartAfter>{encoded}</StartAfter>")), "{xml}");
    assert!(xml.contains(&format!("<Key>{encoded}a%2Etxt</Key>")), "{xml}");
    assert!(xml.contains("<EncodingType>url</EncodingType>"), "{xml}");
    assert!(xml.contains("<ContinuationToken>a+b/c=</ContinuationToken>"), "the tokens are not encoded: {xml}");
    assert_eq!(ListObjectsV2Result::from_xml(xml.as_bytes()).unwrap(), result);
}

#[test]
fn without_url_encoding_a_percent_sign_is_a_percent_sign() {
    let result = ListObjectsV1Result {
        name: "b".into(),
        prefix: "100%".into(),
        marker: String::new(),
        next_marker: None,
        delimiter: None,
        max_keys: 1000,
        is_truncated: false,
        contents: vec![entry("100%25.txt")],
        common_prefixes: vec![],
        url_encoded: false,
    };
    let xml = result.to_xml();
    assert!(xml.contains("<Prefix>100%</Prefix>") && xml.contains("<Key>100%25.txt</Key>") && xml.contains("<Marker></Marker>"), "{xml}");
    assert!(!xml.contains("EncodingType"), "{xml}");
    assert_eq!(ListObjectsV1Result::from_xml(xml.as_bytes()).unwrap(), result);
}

#[test]
fn a_listing_with_an_unknown_encoding_type_is_refused() {
    let xml = "<ListBucketResult><Name>b</Name><EncodingType>base64</EncodingType></ListBucketResult>";
    assert!(matches!(ListObjectsV2Result::from_xml(xml.as_bytes()).unwrap_err(), XmlError::Invalid { name, .. } if name == "EncodingType"));
}

#[test]
fn every_document_reads_back_what_was_written() {
    let mut checksums = Checksums::default();
    checksums.set(ChecksumAlgorithm::Crc32c, "sOO8/Q==");
    checksums.set(ChecksumAlgorithm::Sha256, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
    let owner = Owner { id: "id".into(), display_name: Some("Name & <Co>".into()) };

    let buckets = ListAllMyBucketsResult {
        owner: Some(owner.clone()),
        buckets: vec![Bucket { name: "a".into(), creation_date: T, region: Some("eu-west-1".into()) }, Bucket { name: "b".into(), creation_date: T, region: None }],
        continuation_token: Some("tok".into()),
        prefix: Some("pre".into()),
    };
    assert_eq!(ListAllMyBucketsResult::from_xml(buckets.to_xml().as_bytes()).unwrap(), buckets);

    let mut full_entry = entry("k & <v>");
    full_entry.owner = Some(owner.clone());
    full_entry.checksum_algorithms = vec!["CRC32C".into(), "SHA256".into()];
    full_entry.checksum_type = Some("FULL_OBJECT".into());
    let v2 = ListObjectsV2Result {
        name: "b".into(),
        prefix: String::new(),
        delimiter: None,
        max_keys: 50,
        key_count: 1,
        is_truncated: false,
        continuation_token: Some("c".into()),
        next_continuation_token: None,
        start_after: Some("s".into()),
        contents: vec![full_entry.clone()],
        common_prefixes: vec![],
        url_encoded: false,
    };
    assert_eq!(ListObjectsV2Result::from_xml(v2.to_xml().as_bytes()).unwrap(), v2);
    let v1 = ListObjectsV1Result {
        name: "b".into(),
        prefix: "p".into(),
        marker: "m".into(),
        next_marker: Some("n".into()),
        delimiter: Some("/".into()),
        max_keys: 5,
        is_truncated: true,
        contents: vec![full_entry],
        common_prefixes: vec!["p/".into(), "q/".into()],
        url_encoded: false,
    };
    assert_eq!(ListObjectsV1Result::from_xml(v1.to_xml().as_bytes()).unwrap(), v1);

    let copy = CopyObjectResult { etag: "\"e\"".into(), last_modified: T, checksum_type: Some("COMPOSITE".into()), checksums: checksums.clone() };
    assert_eq!(CopyObjectResult::from_xml(copy.to_xml().as_bytes()).unwrap(), copy);

    let delete = DeleteRequest {
        objects: vec![
            DeleteObjectId::new("a"),
            DeleteObjectId { key: "b & c".into(), version_id: Some("v".into()), etag: Some("\"e\"".into()), last_modified_time: Some(T), size: Some(7) },
        ],
        quiet: true,
    };
    assert_eq!(DeleteRequest::from_xml(delete.to_xml().as_bytes()).unwrap(), delete);
    let deleted = DeleteResult {
        deleted: vec![
            Deleted::new("a"),
            Deleted { key: "b".into(), version_id: Some("v".into()), delete_marker: Some(false), delete_marker_version_id: Some("m".into()) },
        ],
        errors: vec![DeleteFailure { key: "c".into(), version_id: None, code: "AccessDenied".into(), message: "Access Denied".into() }],
    };
    assert_eq!(DeleteResult::from_xml(deleted.to_xml().as_bytes()).unwrap(), deleted);

    let initiated = InitiateMultipartUploadResult { bucket: "b".into(), key: "k/ü".into(), upload_id: "u".into() };
    assert_eq!(InitiateMultipartUploadResult::from_xml(initiated.to_xml().as_bytes()).unwrap(), initiated);

    let complete =
        CompleteMultipartUploadRequest { parts: vec![CompletedPart::new(1, "\"a\""), CompletedPart { part_number: 2, etag: None, checksums: checksums.clone() }] };
    assert_eq!(CompleteMultipartUploadRequest::from_xml(complete.to_xml().as_bytes()).unwrap(), complete);
    let completed = CompleteMultipartUploadResult {
        location: "http://h/b/k".into(),
        bucket: "b".into(),
        key: "k".into(),
        etag: "\"x-2\"".into(),
        checksums: checksums.clone(),
        checksum_type: Some("COMPOSITE".into()),
    };
    assert_eq!(CompleteMultipartUploadResult::from_xml(completed.to_xml().as_bytes()).unwrap(), completed);

    let parts = ListPartsResult {
        bucket: "b".into(),
        key: "k".into(),
        upload_id: "u".into(),
        part_number_marker: Some(0),
        next_part_number_marker: Some(2),
        max_parts: 2,
        is_truncated: true,
        parts: vec![PartInfo { part_number: 1, last_modified: T, etag: "\"p\"".into(), size: 5, checksums: checksums.clone() }],
        initiator: Some(owner.clone()),
        owner: Some(owner.clone()),
        storage_class: Some("STANDARD".into()),
        checksum_algorithm: Some("CRC32C".into()),
        checksum_type: Some("COMPOSITE".into()),
    };
    assert_eq!(ListPartsResult::from_xml(parts.to_xml().as_bytes()).unwrap(), parts);

    let uploads = ListMultipartUploadsResult {
        bucket: "b".into(),
        key_marker: Some("km".into()),
        upload_id_marker: Some("um".into()),
        next_key_marker: Some("nk".into()),
        next_upload_id_marker: Some("nu".into()),
        prefix: Some("p".into()),
        delimiter: Some("/".into()),
        max_uploads: 10,
        is_truncated: true,
        uploads: vec![UploadInfo {
            key: "k 1".into(),
            upload_id: "u".into(),
            initiator: Some(owner.clone()),
            owner: Some(owner),
            storage_class: Some("STANDARD".into()),
            initiated: T,
            checksum_algorithm: None,
            checksum_type: None,
        }],
        common_prefixes: vec!["p/".into()],
        url_encoded: true,
    };
    assert_eq!(ListMultipartUploadsResult::from_xml(uploads.to_xml().as_bytes()).unwrap(), uploads);
}

#[test]
fn checksums_are_written_in_the_order_of_the_documentation_and_unknown_elements_are_ignored() {
    let mut checksums = Checksums::default();
    checksums.set(ChecksumAlgorithm::Sha256, "b");
    checksums.set(ChecksumAlgorithm::Crc32, "a");
    checksums.set(ChecksumAlgorithm::Sha256, "c");
    let xml = CopyObjectResult { etag: "\"e\"".into(), last_modified: T, checksum_type: None, checksums }.to_xml();
    assert!(xml.contains("<ChecksumCRC32>a</ChecksumCRC32><ChecksumSHA256>c</ChecksumSHA256>"), "{xml}");
    let read = CopyObjectResult::from_xml(b"<CopyObjectResult><ETag>\"e\"</ETag><LastModified>2009-10-12T17:50:30.000Z</LastModified><Something>x</Something><ChecksumSHA1> abc= </ChecksumSHA1></CopyObjectResult>").unwrap();
    assert_eq!(read.checksums.get(ChecksumAlgorithm::Sha1), Some("abc="));
    assert_eq!(read.checksums.get(ChecksumAlgorithm::Crc32), None);
}

#[test]
fn a_required_element_that_is_missing_or_a_value_that_is_wrong_is_refused() {
    assert!(matches!(
        InitiateMultipartUploadResult::from_xml(b"<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key></InitiateMultipartUploadResult>").unwrap_err(),
        XmlError::Missing { name: "UploadId", .. }
    ));
    assert!(matches!(DeleteRequest::from_xml(b"<Delete><Object><VersionId>v</VersionId></Object></Delete>").unwrap_err(), XmlError::Missing { name: "Key", .. }));
    assert!(matches!(
        CompleteMultipartUploadRequest::from_xml(b"<CompleteMultipartUpload><Part><ETag>e</ETag></Part></CompleteMultipartUpload>").unwrap_err(),
        XmlError::Missing { name: "PartNumber", .. }
    ));
    assert!(matches!(
        CompleteMultipartUploadRequest::from_xml(b"<CompleteMultipartUpload><Part><PartNumber>one</PartNumber></Part></CompleteMultipartUpload>").unwrap_err(),
        XmlError::Invalid { .. }
    ));
    assert!(matches!(
        CompleteMultipartUploadRequest::from_xml(b"<CompleteMultipartUpload><Part><PartNumber>-1</PartNumber></Part></CompleteMultipartUpload>").unwrap_err(),
        XmlError::Invalid { .. }
    ));
    assert!(matches!(DeleteRequest::from_xml(b"<Delete><Quiet>yes</Quiet></Delete>").unwrap_err(), XmlError::Invalid { .. }));
    assert!(matches!(ListPartsResult::from_xml(b"<ListPartsResult><Bucket>b</Bucket><Key>k</Key><UploadId>u</UploadId><Part><PartNumber>1</PartNumber><LastModified>yesterday</LastModified><Size>1</Size></Part></ListPartsResult>").unwrap_err(), XmlError::Invalid { .. }));
    assert!(matches!(DeleteRequest::from_xml(b"<Other/>").unwrap_err(), XmlError::WrongRoot { .. }));
}

#[test]
fn empty_requests_are_valid_documents_with_nothing_in_them() {
    assert_eq!(DeleteRequest::from_xml(b"<Delete/>").unwrap(), DeleteRequest::default());
    assert_eq!(CompleteMultipartUploadRequest::from_xml(b"<CompleteMultipartUpload></CompleteMultipartUpload>").unwrap(), CompleteMultipartUploadRequest::default());
}

#[test]
fn hostile_requests_are_refused_before_they_cost_anything() {
    let bomb = "<?xml version=\"1.0\"?><!DOCTYPE d [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><Delete><Object><Key>&b;</Key></Object></Delete>";
    assert_eq!(DeleteRequest::from_xml(bomb.as_bytes()).unwrap_err(), XmlError::DocType);
    let deep = format!("<Delete>{}</Delete>", "<Object>".repeat(1000));
    assert!(matches!(DeleteRequest::from_xml(deep.as_bytes()).unwrap_err(), XmlError::TooDeep(_)));
    let wide = format!("<Delete>{}</Delete>", "<Object><Key>k</Key></Object>".repeat(400_000));
    assert!(DeleteRequest::from_xml(wide.as_bytes()).is_err());
}
