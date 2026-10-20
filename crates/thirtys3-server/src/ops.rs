//! The operations: what each one reads from the request, what it asks of the backend and how it answers.

use bytes::Bytes;
use futures_util::StreamExt;
use http::request::Parts;
use http::{HeaderMap, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use thirtys3_core::S3Error;
use thirtys3_core::checksum::ChecksumAlgorithm;
use thirtys3_core::etag::ETagCondition;
use thirtys3_core::model as xml;
use thirtys3_core::s3_error::code;

use crate::backend::*;
use crate::body::{Framing, IncomingBody, RequestBody};
use crate::conditions::{Conditions, Outcome, parse_range};
use crate::route::{Op, Route};
use crate::service::{Authenticated, ResponseBody, S3Service, empty_response, full, header_text, set_header, xml_response};

/// The user metadata of S3 is limited to 2 KiB in all, names and values together.
const MAX_METADATA_BYTES: usize = 2048;

fn invalid_argument(name: &str, value: &str, message: &str) -> S3Error {
    S3Error::new(code::INVALID_ARGUMENT, message)
        .with_detail("ArgumentName", name.to_owned())
        .with_detail("ArgumentValue", value.chars().take(256).collect::<String>())
}

/// A number in the query: the default when it is not there, an error when it is not a whole number from 0 up.
fn count(route: &Route, name: &str, default: u32) -> Result<u32, S3Error> {
    match route.param(name) {
        None | Some("") => Ok(default),
        Some(text) => match text.parse::<i64>() {
            Ok(number) if number >= 0 => Ok(number.min(i64::from(u32::MAX)) as u32),
            Ok(_) => Err(invalid_argument(name, text, &format!("Argument {name} must be an integer between 0 and 2147483647"))),
            Err(_) => Err(invalid_argument(name, text, &format!("Provided {name} not an integer or within integer range"))),
        },
    }
}

/// `encoding-type`: only `url`.
fn url_encoding(route: &Route) -> Result<bool, S3Error> {
    match route.param("encoding-type") {
        None | Some("") => Ok(false),
        Some("url") => Ok(true),
        Some(other) => Err(invalid_argument("encoding-type", other, "Invalid Encoding Method specified in Request")),
    }
}

fn check_length(name: &str, value: &str, longest: usize) -> Result<(), S3Error> {
    if value.len() > longest { Err(invalid_argument(name, "(too long)", &format!("{name} is longer than {longest} bytes"))) } else { Ok(()) }
}

/// The user metadata in the headers: `x-amz-meta-name: value`.
fn user_metadata(headers: &HeaderMap) -> Result<Vec<(String, String)>, S3Error> {
    let mut metadata = Vec::new();
    let mut bytes = 0;
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-amz-meta-") {
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            bytes += name.len() + value.len();
            metadata.push((name.to_owned(), value));
        }
    }
    if bytes > MAX_METADATA_BYTES {
        return Err(S3Error::new(code::METADATA_TOO_LARGE, "Your metadata headers exceed the maximum allowed metadata size.")
            .with_detail("MaxSizeAllowed", MAX_METADATA_BYTES.to_string()));
    }
    Ok(metadata)
}

/// `If-None-Match: *` and `If-Match` on a write.
fn write_condition(headers: &HeaderMap) -> Result<WriteCondition, S3Error> {
    if let Some(none) = header_text(headers, "if-none-match") {
        return if none.trim() == "*" { Ok(WriteCondition::Absent) } else { Err(S3Error::new(code::NOT_IMPLEMENTED, "If-None-Match takes only *")) };
    }
    Ok(match header_text(headers, "if-match") {
        Some(wanted) => WriteCondition::Match(ETagCondition::parse(wanted).unwrap_or(ETagCondition::Tags(Vec::new()))),
        None => WriteCondition::None,
    })
}

fn precondition_failed() -> S3Error {
    S3Error::new(code::PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold")
}

/// The headers of an answer about an object. The overrides in the query (`response-content-type` and the others) come last.
fn object_headers(info: &ObjectInfo, route: &Route) -> HeaderMap {
    let mut headers = HeaderMap::new();
    set_header(&mut headers, "content-type", info.content_type.as_deref().unwrap_or("binary/octet-stream"));
    set_header(&mut headers, "etag", &info.etag);
    set_header(&mut headers, "last-modified", &info.last_modified.http_date());
    set_header(&mut headers, "accept-ranges", "bytes");
    for (name, value) in &info.metadata {
        set_header(&mut headers, &format!("x-amz-meta-{name}"), value);
    }
    for (algorithm, value) in &info.checksums.0 {
        set_header(&mut headers, algorithm.header_name(), value);
    }
    if let Some(class) = &info.storage_class {
        set_header(&mut headers, "x-amz-storage-class", class);
    }
    for (name, value) in &info.headers {
        headers.insert(name.clone(), value.clone());
    }
    for (parameter, header) in [
        ("response-content-type", "content-type"),
        ("response-content-language", "content-language"),
        ("response-expires", "expires"),
        ("response-cache-control", "cache-control"),
        ("response-content-disposition", "content-disposition"),
        ("response-content-encoding", "content-encoding"),
    ] {
        if let Some(value) = route.param(parameter) {
            set_header(&mut headers, header, value);
        }
    }
    headers
}

/// The `x-amz-copy-source` header: `bucket/key`, with or without a `/` in front, percent-encoded.
fn copy_source(headers: &HeaderMap) -> Result<(String, String), S3Error> {
    let raw = header_text(headers, "x-amz-copy-source").unwrap_or_default();
    let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
    if query.contains("versionId") {
        return Err(S3Error::new(code::NOT_IMPLEMENTED, "Copying a version is not supported"));
    }
    let decoded = String::from_utf8(thirtys3_core::encoding::percent_decode(path, false))
        .map_err(|_| invalid_argument("x-amz-copy-source", raw, "Copy Source must mention the source bucket and key: sourcebucket/sourcekey"))?;
    let decoded = decoded.strip_prefix('/').unwrap_or(&decoded);
    if decoded.starts_with("arn:") {
        return Err(S3Error::new(code::NOT_IMPLEMENTED, "Access points are not supported"));
    }
    match decoded.split_once('/') {
        Some((bucket, key)) if !bucket.is_empty() && !key.is_empty() => Ok((bucket.to_owned(), key.to_owned())),
        _ => Err(invalid_argument("x-amz-copy-source", raw, "Copy Source must mention the source bucket and key: sourcebucket/sourcekey")),
    }
}

fn location(parts: &Parts, bucket: &str, key: &str) -> String {
    let scheme = if header_text(&parts.headers, "x-forwarded-proto") == Some("https") { "https" } else { "http" };
    let host = header_text(&parts.headers, "host").unwrap_or("localhost");
    format!("{scheme}://{host}/{bucket}/{key}")
}

fn status_response(status: StatusCode) -> Response<ResponseBody> {
    empty_response(status)
}

impl<B: Backend> S3Service<B> {
    pub(crate) async fn dispatch(
        &self,
        ctx: &Ctx<'_>,
        route: &Route,
        auth: &Authenticated,
        parts: &Parts,
        body: IncomingBody,
    ) -> Result<Response<ResponseBody>, S3Error> {
        let bucket = route.bucket.as_deref().unwrap_or_default();
        let key = route.key.as_deref().unwrap_or_default();
        let backend = &self.inner.backend;
        match route.op {
            Op::ListBuckets => self.list_buckets(ctx, route).await,
            Op::HeadBucket => {
                backend.head_bucket(ctx, bucket).await?;
                let mut response = status_response(StatusCode::OK);
                set_header(response.headers_mut(), "x-amz-bucket-region", &self.inner.config.region);
                Ok(response)
            }
            Op::GetBucketLocation => {
                backend.head_bucket(ctx, bucket).await?;
                let region = &self.inner.config.region;
                Ok(xml_response(xml::LocationConstraint((region != "us-east-1").then(|| region.clone())).to_xml()))
            }
            Op::ListObjects { v2 } => self.list_objects(ctx, route, v2).await,
            Op::ListMultipartUploads => self.list_multipart_uploads(ctx, route).await,
            Op::DeleteObjects => self.delete_objects(ctx, route, auth, parts, body).await,
            Op::GetObject => self.get_object(ctx, route, parts, false).await,
            Op::HeadObject => self.get_object(ctx, route, parts, true).await,
            Op::PutObject => self.put_object(ctx, route, auth, parts, body).await,
            Op::CopyObject => self.copy_object(ctx, route, parts).await,
            Op::DeleteObject => {
                backend.delete_object(ctx, bucket, key).await?;
                Ok(status_response(StatusCode::NO_CONTENT))
            }
            Op::CreateMultipartUpload => self.create_multipart_upload(ctx, route, parts).await,
            Op::UploadPart => self.upload_part(ctx, route, auth, parts, body).await,
            Op::CompleteMultipartUpload => self.complete_multipart_upload(ctx, route, auth, parts, body).await,
            Op::AbortMultipartUpload => {
                backend.abort_multipart_upload(ctx, bucket, key, route.param("uploadId").unwrap_or_default()).await?;
                Ok(status_response(StatusCode::NO_CONTENT))
            }
            Op::ListParts => self.list_parts(ctx, route).await,
        }
    }

    async fn list_buckets(&self, ctx: &Ctx<'_>, route: &Route) -> Result<Response<ResponseBody>, S3Error> {
        let request = ListBucketsRequest {
            prefix: route.param("prefix").filter(|prefix| !prefix.is_empty()).map(str::to_owned),
            max_buckets: route.param("max-buckets").map(|_| count(route, "max-buckets", 10_000)).transpose()?,
            continuation_token: route.param("continuation-token").filter(|token| !token.is_empty()).map(str::to_owned),
        };
        let prefix = request.prefix.clone();
        let output = self.inner.backend.list_buckets(ctx, request).await?;
        let result = xml::ListAllMyBucketsResult {
            owner: output.owner,
            buckets: output.buckets.into_iter().map(|bucket| xml::Bucket { name: bucket.name, creation_date: bucket.created, region: None }).collect(),
            continuation_token: output.continuation_token,
            prefix,
        };
        Ok(xml_response(result.to_xml()))
    }

    async fn list_objects(&self, ctx: &Ctx<'_>, route: &Route, v2: bool) -> Result<Response<ResponseBody>, S3Error> {
        let config = &self.inner.config;
        let bucket = route.bucket.clone().unwrap_or_default();
        let prefix = route.param("prefix").unwrap_or_default().to_owned();
        let delimiter = route.param("delimiter").filter(|delimiter| !delimiter.is_empty()).map(str::to_owned);
        let max_keys = count(route, "max-keys", 1000)?.min(1000);
        let url = url_encoding(route)?;
        check_length("prefix", &prefix, config.max_listing_key_length)?;
        if let Some(delimiter) = &delimiter {
            check_length("delimiter", delimiter, config.max_delimiter_length)?;
        }
        let (marker, start_after, token) =
            (route.param("marker").unwrap_or_default(), route.param("start-after").unwrap_or_default(), route.param("continuation-token").unwrap_or_default());
        check_length("marker", marker, config.max_listing_key_length)?;
        check_length("start-after", start_after, config.max_listing_key_length)?;
        check_length("continuation-token", token, 8192)?;
        let start = if v2 {
            if !token.is_empty() {
                ListStart::Continuation(token.to_owned())
            } else if !start_after.is_empty() {
                ListStart::After(start_after.to_owned())
            } else {
                ListStart::Beginning
            }
        } else if marker.is_empty() {
            ListStart::Beginning
        } else {
            ListStart::After(marker.to_owned())
        };
        let page = self
            .inner
            .backend
            .list_objects(ctx, ListRequest { bucket: bucket.clone(), prefix: prefix.clone(), delimiter: delimiter.clone(), max_keys, start })
            .await?;
        if page.truncated && page.next.is_none() {
            tracing::error!("a backend returned a truncated page without saying where it stopped");
            return Err(S3Error::new(code::INTERNAL_ERROR, "We encountered an internal error. Please try again."));
        }
        let truncated = page.truncated;
        let next = page.next;
        let xml = if v2 {
            xml::ListObjectsV2Result {
                name: bucket,
                prefix,
                delimiter,
                max_keys,
                key_count: (page.objects.len() + page.common_prefixes.len()) as u32,
                is_truncated: truncated,
                continuation_token: (!token.is_empty()).then(|| token.to_owned()),
                next_continuation_token: next.map(|next| next.token).filter(|_| truncated),
                start_after: (!start_after.is_empty()).then(|| start_after.to_owned()),
                contents: page.objects,
                common_prefixes: page.common_prefixes,
                url_encoded: url,
            }
            .to_xml()
        } else {
            xml::ListObjectsV1Result {
                name: bucket,
                prefix,
                marker: marker.to_owned(),
                next_marker: next.map(|next| next.key).filter(|_| truncated),
                delimiter,
                max_keys,
                is_truncated: truncated,
                contents: page.objects,
                common_prefixes: page.common_prefixes,
                url_encoded: url,
            }
            .to_xml()
        };
        Ok(xml_response(xml))
    }

    async fn get_object(&self, ctx: &Ctx<'_>, route: &Route, parts: &Parts, head: bool) -> Result<Response<ResponseBody>, S3Error> {
        let (bucket, key) = (route.bucket.as_deref().unwrap_or_default(), route.key.as_deref().unwrap_or_default());
        let (info, source) = if head {
            (self.inner.backend.head_object(ctx, bucket, key).await?, None)
        } else {
            let data = self.inner.backend.get_object(ctx, bucket, key).await?;
            (data.info, Some(data.source))
        };
        let mut headers = object_headers(&info, route);
        match Conditions::from_headers(&parts.headers, false).evaluate(&info.etag, info.last_modified) {
            Outcome::PreconditionFailed => return Err(precondition_failed()),
            Outcome::NotModified => {
                let mut response = status_response(StatusCode::NOT_MODIFIED);
                for name in [http::header::ETAG, http::header::LAST_MODIFIED] {
                    if let Some(value) = headers.get(&name) {
                        response.headers_mut().insert(name, value.clone());
                    }
                }
                return Ok(response);
            }
            Outcome::Proceed => {}
        }
        let range = match header_text(&parts.headers, "range").and_then(parse_range) {
            Some(spec) => Some(spec.resolve(info.size)?),
            None => None,
        };
        let covered = range.clone().unwrap_or(0..info.size);
        set_header(&mut headers, "content-length", &(covered.end - covered.start).to_string());
        if range.is_some() {
            set_header(&mut headers, "content-range", &format!("bytes {}-{}/{}", covered.start, covered.end - 1, info.size));
        }
        let body = match source {
            Some(source) if covered.end > covered.start => {
                let stream = source.open(covered).await?;
                StreamBody::new(stream.map(|piece| piece.map(Frame::data))).boxed_unsync()
            }
            _ => full(Bytes::new()),
        };
        let mut response = Response::new(body);
        *response.status_mut() = if range.is_some() { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };
        *response.headers_mut() = headers;
        Ok(response)
    }

    async fn put_object(&self, ctx: &Ctx<'_>, route: &Route, auth: &Authenticated, parts: &Parts, body: IncomingBody) -> Result<Response<ResponseBody>, S3Error> {
        let plan = self.body_plan(parts, auth, self.inner.config.max_object_size)?;
        if plan.length.is_none() && matches!(plan.framing, Framing::Plain) {
            return Err(S3Error::new(code::MISSING_CONTENT_LENGTH, "You must provide the Content-Length HTTP header."));
        }
        let length = plan.length;
        let body = RequestBody::new(body, plan);
        let handle = body.handle();
        let request = PutObjectRequest {
            bucket: route.bucket.clone().unwrap_or_default(),
            key: route.key.clone().unwrap_or_default(),
            body,
            content_length: length,
            content_type: header_text(&parts.headers, "content-type").map(str::to_owned),
            metadata: user_metadata(&parts.headers)?,
            condition: write_condition(&parts.headers)?,
        };
        let output = self.inner.backend.put_object(ctx, request).await?;
        // An upload is acknowledged only if the whole body came through its checks, whatever the backend did.
        let digests = handle.get().ok_or_else(Self::unchecked)?;
        let mut response = status_response(StatusCode::OK);
        let headers = response.headers_mut();
        for (name, value) in &output.headers {
            headers.insert(name.clone(), value.clone());
        }
        set_header(headers, "etag", &output.etag);
        if let Some(version) = &output.version_id {
            set_header(headers, "x-amz-version-id", version);
        }
        Self::checksum_headers(digests, headers);
        Ok(response)
    }

    async fn copy_object(&self, ctx: &Ctx<'_>, route: &Route, parts: &Parts) -> Result<Response<ResponseBody>, S3Error> {
        let headers = &parts.headers;
        let (source_bucket, source_key) = copy_source(headers)?;
        let replace_metadata = match header_text(headers, "x-amz-metadata-directive").unwrap_or("COPY") {
            "COPY" => false,
            "REPLACE" => true,
            other => return Err(invalid_argument("x-amz-metadata-directive", other, "Unknown metadata directive.")),
        };
        let (bucket, key) = (route.bucket.clone().unwrap_or_default(), route.key.clone().unwrap_or_default());
        if source_bucket == bucket && source_key == key && !replace_metadata {
            return Err(S3Error::new(
                code::INVALID_REQUEST,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
            ));
        }
        let request = CopyObjectRequest {
            bucket,
            key,
            source_bucket,
            source_key,
            replace_metadata,
            content_type: header_text(headers, "content-type").map(str::to_owned),
            metadata: if replace_metadata { user_metadata(headers)? } else { Vec::new() },
            source_conditions: Conditions::from_headers(headers, true),
            condition: write_condition(headers)?,
        };
        let output = self.inner.backend.copy_object(ctx, request).await?;
        let mut response = xml_response(
            xml::CopyObjectResult { etag: output.etag, last_modified: output.last_modified, checksum_type: None, checksums: xml::Checksums::default() }.to_xml(),
        );
        for (name, value) in &output.headers {
            response.headers_mut().insert(name.clone(), value.clone());
        }
        Ok(response)
    }

    /// The XML document in the body of a request, read with the checks of an upload and the limit on the size of a document.
    async fn xml_body(&self, auth: &Authenticated, parts: &Parts, body: IncomingBody) -> Result<Bytes, S3Error> {
        // Too big is "too big" whether the length says so before the body is read or the body says so as it is read.
        let too_big =
            |error: S3Error| if error.code == code::ENTITY_TOO_LARGE { S3Error::new(code::MAX_MESSAGE_LENGTH_EXCEEDED, "Your request was too big.") } else { error };
        let plan = self.body_plan(parts, auth, self.inner.config.max_xml_bytes as u64).map_err(too_big)?;
        RequestBody::new(body, plan).collect().await.map(|(data, _)| data).map_err(too_big)
    }

    async fn delete_objects(
        &self,
        ctx: &Ctx<'_>,
        route: &Route,
        auth: &Authenticated,
        parts: &Parts,
        body: IncomingBody,
    ) -> Result<Response<ResponseBody>, S3Error> {
        let data = self.xml_body(auth, parts, body).await?;
        let request = xml::DeleteRequest::from_xml(&data).map_err(|error| S3Error::from(&error))?;
        if request.objects.is_empty() || request.objects.len() > 1000 {
            return Err(S3Error::new(code::MALFORMED_XML, "The XML you provided was not well-formed or did not validate against our published schema."));
        }
        if request.objects.iter().any(|object| object.key.is_empty() || object.key.len() > 1024) {
            return Err(S3Error::new(code::KEY_TOO_LONG, "Your key is empty or too long"));
        }
        let targets: Vec<DeleteTarget> =
            request.objects.iter().map(|object| DeleteTarget { key: object.key.clone(), version_id: object.version_id.clone() }).collect();
        let bucket = route.bucket.as_deref().unwrap_or_default();
        let results = self.inner.backend.delete_objects(ctx, bucket, &targets).await?;
        if results.len() != targets.len() {
            tracing::error!("a backend answered a request to delete {} objects with {} results", targets.len(), results.len());
            return Err(S3Error::new(code::INTERNAL_ERROR, "We encountered an internal error. Please try again."));
        }
        let mut result = xml::DeleteResult::default();
        for (target, outcome) in targets.into_iter().zip(results) {
            match outcome {
                Ok(()) if !request.quiet => {
                    result.deleted.push(xml::Deleted { key: target.key, version_id: target.version_id, delete_marker: None, delete_marker_version_id: None })
                }
                Ok(()) => {}
                Err(error) => result.errors.push(xml::DeleteFailure { key: target.key, version_id: target.version_id, code: error.code, message: error.message }),
            }
        }
        Ok(xml_response(result.to_xml()))
    }

    async fn create_multipart_upload(&self, ctx: &Ctx<'_>, route: &Route, parts: &Parts) -> Result<Response<ResponseBody>, S3Error> {
        let headers = &parts.headers;
        let checksum_algorithm = match header_text(headers, "x-amz-checksum-algorithm") {
            None => None,
            Some(name) => Some(
                ChecksumAlgorithm::from_name(name)
                    .ok_or_else(|| invalid_argument("x-amz-checksum-algorithm", name, "Checksum algorithm provided is unsupported."))?,
            ),
        };
        let (bucket, key) = (route.bucket.clone().unwrap_or_default(), route.key.clone().unwrap_or_default());
        if key.ends_with('/') {
            return Err(invalid_argument("key", &key, "A multipart upload is of an object, not of a folder."));
        }
        let request = CreateMultipartUploadRequest {
            bucket: bucket.clone(),
            key: key.clone(),
            content_type: header_text(headers, "content-type").map(str::to_owned),
            metadata: user_metadata(headers)?,
            checksum_algorithm,
        };
        let upload_id = self.inner.backend.create_multipart_upload(ctx, request).await?;
        let mut response = xml_response(xml::InitiateMultipartUploadResult { bucket, key, upload_id }.to_xml());
        if let Some(algorithm) = checksum_algorithm {
            set_header(response.headers_mut(), "x-amz-checksum-algorithm", algorithm.name());
        }
        Ok(response)
    }

    async fn upload_part(&self, ctx: &Ctx<'_>, route: &Route, auth: &Authenticated, parts: &Parts, body: IncomingBody) -> Result<Response<ResponseBody>, S3Error> {
        let number = route.param("partNumber").unwrap_or_default();
        let part_number = match number.parse::<u32>() {
            Ok(number) if (1..=10_000).contains(&number) => number,
            _ => return Err(invalid_argument("partNumber", number, "Part number must be an integer between 1 and 10000, inclusive")),
        };
        let upload_id = route.param("uploadId").unwrap_or_default();
        if upload_id.is_empty() {
            return Err(invalid_argument("uploadId", upload_id, "Invalid uploadId"));
        }
        let plan = self.body_plan(parts, auth, self.inner.config.max_object_size)?;
        if plan.length.is_none() && matches!(plan.framing, Framing::Plain) {
            return Err(S3Error::new(code::MISSING_CONTENT_LENGTH, "You must provide the Content-Length HTTP header."));
        }
        let length = plan.length;
        let body = RequestBody::new(body, plan);
        let handle = body.handle();
        let request = UploadPartRequest {
            bucket: route.bucket.clone().unwrap_or_default(),
            key: route.key.clone().unwrap_or_default(),
            upload_id: upload_id.to_owned(),
            part_number,
            body,
            content_length: length,
        };
        let output = self.inner.backend.upload_part(ctx, request).await?;
        let digests = handle.get().ok_or_else(Self::unchecked)?;
        let mut response = status_response(StatusCode::OK);
        set_header(response.headers_mut(), "etag", &output.etag);
        Self::checksum_headers(digests, response.headers_mut());
        Ok(response)
    }

    async fn complete_multipart_upload(
        &self,
        ctx: &Ctx<'_>,
        route: &Route,
        auth: &Authenticated,
        parts: &Parts,
        body: IncomingBody,
    ) -> Result<Response<ResponseBody>, S3Error> {
        let data = self.xml_body(auth, parts, body).await?;
        let request = xml::CompleteMultipartUploadRequest::from_xml(&data).map_err(|error| S3Error::from(&error))?;
        let (bucket, key) = (route.bucket.clone().unwrap_or_default(), route.key.clone().unwrap_or_default());
        let output = self
            .inner
            .backend
            .complete_multipart_upload(
                ctx,
                CompleteMultipartUploadRequest {
                    bucket: bucket.clone(),
                    key: key.clone(),
                    upload_id: route.param("uploadId").unwrap_or_default().to_owned(),
                    parts: request.parts,
                    condition: write_condition(&parts.headers)?,
                },
            )
            .await;
        let output = match output {
            Err(error) if error.status >= 500 && self.inner.config.complete_failures_in_ok_response => return Ok(xml_response(error.to_xml())),
            other => other?,
        };
        let location = location(parts, &bucket, &key);
        let mut response = xml_response(
            xml::CompleteMultipartUploadResult { location, bucket, key, etag: output.etag, checksums: xml::Checksums::default(), checksum_type: None }.to_xml(),
        );
        for (name, value) in &output.headers {
            response.headers_mut().insert(name.clone(), value.clone());
        }
        if let Some(version) = &output.version_id {
            set_header(response.headers_mut(), "x-amz-version-id", version);
        }
        Ok(response)
    }

    async fn list_parts(&self, ctx: &Ctx<'_>, route: &Route) -> Result<Response<ResponseBody>, S3Error> {
        let (bucket, key) = (route.bucket.clone().unwrap_or_default(), route.key.clone().unwrap_or_default());
        let upload_id = route.param("uploadId").unwrap_or_default().to_owned();
        let max_parts = count(route, "max-parts", 1000)?.min(1000);
        let marker = count(route, "part-number-marker", 0)?;
        let output = self
            .inner
            .backend
            .list_parts(ctx, ListPartsRequest { bucket: bucket.clone(), key: key.clone(), upload_id: upload_id.clone(), max_parts, part_number_marker: marker })
            .await?;
        let result = xml::ListPartsResult {
            bucket,
            key,
            upload_id,
            part_number_marker: Some(marker),
            next_part_number_marker: output.next_part_number_marker.filter(|_| output.truncated),
            max_parts,
            is_truncated: output.truncated,
            parts: output.parts,
            initiator: output.initiator,
            owner: output.owner,
            storage_class: output.storage_class,
            checksum_algorithm: None,
            checksum_type: None,
        };
        Ok(xml_response(result.to_xml()))
    }

    async fn list_multipart_uploads(&self, ctx: &Ctx<'_>, route: &Route) -> Result<Response<ResponseBody>, S3Error> {
        let config = &self.inner.config;
        let bucket = route.bucket.clone().unwrap_or_default();
        let prefix = route.param("prefix").unwrap_or_default().to_owned();
        let delimiter = route.param("delimiter").filter(|delimiter| !delimiter.is_empty()).map(str::to_owned);
        let (key_marker, upload_id_marker) =
            (route.param("key-marker").unwrap_or_default().to_owned(), route.param("upload-id-marker").unwrap_or_default().to_owned());
        check_length("prefix", &prefix, config.max_listing_key_length)?;
        check_length("key-marker", &key_marker, config.max_listing_key_length)?;
        if let Some(delimiter) = &delimiter {
            check_length("delimiter", delimiter, config.max_delimiter_length)?;
        }
        let max_uploads = count(route, "max-uploads", 1000)?.min(1000);
        let url = url_encoding(route)?;
        let output = self
            .inner
            .backend
            .list_multipart_uploads(
                ctx,
                ListUploadsRequest {
                    bucket: bucket.clone(),
                    prefix: prefix.clone(),
                    delimiter: delimiter.clone(),
                    max_uploads,
                    key_marker: key_marker.clone(),
                    upload_id_marker: upload_id_marker.clone(),
                },
            )
            .await?;
        let result = xml::ListMultipartUploadsResult {
            bucket,
            key_marker: Some(key_marker),
            upload_id_marker: Some(upload_id_marker),
            next_key_marker: output.next_key_marker.filter(|_| output.truncated),
            next_upload_id_marker: output.next_upload_id_marker.filter(|_| output.truncated),
            prefix: Some(prefix),
            delimiter,
            max_uploads,
            is_truncated: output.truncated,
            uploads: output.uploads,
            common_prefixes: output.common_prefixes,
            url_encoded: url,
        };
        Ok(xml_response(result.to_xml()))
    }
}
