//! S3 error responses: the `<Error>` document, the error codes with their HTTP status, and which errors are worth retrying.
//!
//! Follows "Error responses", the page of the S3 API reference that AWS has since removed from its documentation and that is kept in the
//! Internet Archive (<https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html>, snapshot of 2024-12-18): the structure of the
//! document (`Code`, `Message`, `Resource`, `RequestId`, and detail elements that depend on the error) and the table of error codes. The
//! `Error` element inside a `DeleteObjects` result is described on <https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html>.
//! Where the table is silent (it does not list `XAmzContentSHA256Mismatch`, for one) the code and status are those S3 uses and the entry says so.

use crate::error::SigError;
use crate::xml::{self, Element, Limits, XmlError, XmlWriter};

/// Error codes as strings, for the errors a file service answers with.
pub mod code {
    macro_rules! codes {
        ($($name:ident = $value:literal),* $(,)?) => { $(
            #[doc = concat!("`", $value, "`")]
            pub const $name: &str = $value;
        )* };
    }
    codes! {
        ACCESS_DENIED = "AccessDenied",
        AUTHORIZATION_HEADER_MALFORMED = "AuthorizationHeaderMalformed",
        AUTHORIZATION_QUERY_PARAMETERS_ERROR = "AuthorizationQueryParametersError",
        BAD_DIGEST = "BadDigest",
        BUCKET_ALREADY_EXISTS = "BucketAlreadyExists",
        BUCKET_NOT_EMPTY = "BucketNotEmpty",
        CONDITIONAL_REQUEST_CONFLICT = "ConditionalRequestConflict",
        ENTITY_TOO_LARGE = "EntityTooLarge",
        ENTITY_TOO_SMALL = "EntityTooSmall",
        EXPIRED_TOKEN = "ExpiredToken",
        INCOMPLETE_BODY = "IncompleteBody",
        INTERNAL_ERROR = "InternalError",
        INVALID_ACCESS_KEY_ID = "InvalidAccessKeyId",
        INVALID_ARGUMENT = "InvalidArgument",
        INVALID_BUCKET_NAME = "InvalidBucketName",
        INVALID_DIGEST = "InvalidDigest",
        INVALID_PART = "InvalidPart",
        INVALID_PART_ORDER = "InvalidPartOrder",
        INVALID_RANGE = "InvalidRange",
        INVALID_REQUEST = "InvalidRequest",
        KEY_TOO_LONG = "KeyTooLongError",
        MALFORMED_TRAILER = "MalformedTrailerError",
        MAX_MESSAGE_LENGTH_EXCEEDED = "MaxMessageLengthExceeded",
        METADATA_TOO_LARGE = "MetadataTooLarge",
        MALFORMED_XML = "MalformedXML",
        METHOD_NOT_ALLOWED = "MethodNotAllowed",
        MISSING_CONTENT_LENGTH = "MissingContentLength",
        MISSING_SECURITY_HEADER = "MissingSecurityHeader",
        NOT_IMPLEMENTED = "NotImplemented",
        NOT_MODIFIED = "NotModified",
        NO_SUCH_BUCKET = "NoSuchBucket",
        NO_SUCH_KEY = "NoSuchKey",
        NO_SUCH_UPLOAD = "NoSuchUpload",
        PERMANENT_REDIRECT = "PermanentRedirect",
        PRECONDITION_FAILED = "PreconditionFailed",
        REQUEST_TIMEOUT = "RequestTimeout",
        REQUEST_TIME_TOO_SKEWED = "RequestTimeTooSkewed",
        SERVICE_UNAVAILABLE = "ServiceUnavailable",
        SIGNATURE_DOES_NOT_MATCH = "SignatureDoesNotMatch",
        SLOW_DOWN = "SlowDown",
        // Not in the table of the documentation; S3 answers 400 when the payload hash in `x-amz-content-sha256` is not that of the body.
        X_AMZ_CONTENT_SHA256_MISMATCH = "XAmzContentSHA256Mismatch",
    }
}

/// The HTTP status of each error code in the table of the documentation (the main list, not those for Outposts, Select, replication and so on),
/// and the codes that are not in the table but that S3 uses.
pub const ERROR_STATUS: &[(&str, u16)] = &[
    ("AccessControlListNotSupported", 400),
    ("AccessDenied", 403),
    ("AccessPointAlreadyOwnedByYou", 409),
    ("AccountProblem", 403),
    ("AllAccessDisabled", 403),
    ("AmbiguousGrantByEmailAddress", 400),
    ("AuthorizationHeaderMalformed", 400),
    ("AuthorizationQueryParametersError", 400),
    ("BadDigest", 400),
    ("BucketAlreadyExists", 409),
    ("BucketAlreadyOwnedByYou", 409),
    ("BucketNotEmpty", 409),
    ("ClientTokenConflict", 409),
    ("ConnectionClosedByRequester", 400),
    ("ConditionalRequestConflict", 409),
    ("CredentialsNotSupported", 400),
    ("CrossLocationLoggingProhibited", 403),
    ("DeviceNotActiveError", 400),
    ("EndpointNotFound", 400),
    ("EntityTooSmall", 400),
    ("EntityTooLarge", 400),
    ("ExpiredToken", 400),
    ("IllegalLocationConstraintException", 400),
    ("IllegalVersioningConfigurationException", 400),
    ("IncompleteBody", 400),
    ("IncorrectEndpoint", 400),
    ("IncorrectNumberOfFilesInPostRequest", 400),
    ("InlineDataTooLarge", 400),
    ("InternalError", 500),
    ("InvalidAccessKeyId", 403),
    ("InvalidAccessPoint", 400),
    ("InvalidAccessPointAliasError", 400),
    ("InvalidArgument", 400),
    ("InvalidBucketAclWithObjectOwnership", 400),
    ("InvalidBucketName", 400),
    ("InvalidBucketOwnerAWSAccountID", 400),
    ("InvalidBucketState", 409),
    ("InvalidDigest", 400),
    ("InvalidEncryptionAlgorithmError", 400),
    ("InvalidHostHeader", 400),
    ("InvalidHttpMethod", 400),
    ("InvalidLocationConstraint", 400),
    ("InvalidObjectState", 403),
    ("InvalidPart", 400),
    ("InvalidPartOrder", 400),
    ("InvalidPayer", 403),
    ("InvalidPolicyDocument", 400),
    ("InvalidRange", 416),
    ("InvalidRequest", 400),
    ("InvalidSessionException", 400),
    ("InvalidSignature", 400),
    ("InvalidSecurity", 403),
    ("InvalidSOAPRequest", 400),
    ("InvalidStorageClass", 400),
    ("InvalidTargetBucketForLogging", 400),
    ("InvalidToken", 400),
    ("InvalidURI", 400),
    ("KeyTooLongError", 400),
    ("KMS.DisabledException", 400),
    ("KMS.InvalidKeyUsageException", 400),
    ("KMS.KMSInvalidStateException", 400),
    ("KMS.NotFoundException", 400),
    ("MalformedACLError", 400),
    ("MalformedPOSTRequest", 400),
    ("MalformedXML", 400),
    ("MaxMessageLengthExceeded", 400),
    ("MaxPostPreDataLengthExceededError", 400),
    ("MetadataTooLarge", 400),
    ("MethodNotAllowed", 405),
    ("MissingAttachment", 400),
    ("MissingAuthenticationToken", 403),
    ("MissingContentLength", 411),
    ("MissingRequestBodyError", 400),
    ("MissingSecurityElement", 400),
    ("MissingSecurityHeader", 400),
    ("NoLoggingStatusForKey", 400),
    ("NoSuchAsyncRequest", 404),
    ("NoSuchBucket", 404),
    ("NoSuchBucketPolicy", 404),
    ("NoSuchCORSConfiguration", 404),
    ("NoSuchKey", 404),
    ("NoSuchLifecycleConfiguration", 404),
    ("NoSuchMultiRegionAccessPoint", 404),
    ("NoSuchObjectLockConfiguration", 404),
    ("NoSuchWebsiteConfiguration", 404),
    ("NoSuchTagSet", 404),
    ("NoSuchUpload", 404),
    ("NoSuchVersion", 404),
    ("NotDeviceOwnerError", 400),
    ("NotImplemented", 501),
    ("NotModified", 304),
    ("NoTransformationDefined", 404),
    ("NotSignedUp", 403),
    ("ObjectLockConfigurationNotFoundError", 404),
    ("OwnershipControlsNotFoundError", 404),
    ("OperationAborted", 409),
    ("PermanentRedirect", 301),
    ("PermanentRedirectControlError", 301),
    ("PreconditionFailed", 412),
    ("Redirect", 307),
    ("RequestHeaderSectionTooLarge", 400),
    ("RequestIsNotMultiPartContent", 412),
    ("RequestTimeout", 400),
    ("RequestTimeTooSkewed", 403),
    ("RequestTorrentOfBucketError", 400),
    ("ResponseInterrupted", 400),
    ("RestoreAlreadyInProgress", 409),
    ("ServerSideEncryptionConfigurationNotFoundError", 400),
    ("ServiceUnavailable", 503),
    ("SignatureDoesNotMatch", 403),
    ("SlowDown", 503),
    ("TemporaryRedirect", 307),
    ("TokenCodeInvalidError", 400),
    ("TokenRefreshRequired", 400),
    ("TooManyAccessPoints", 400),
    ("TooManyBuckets", 400),
    ("TooManyMultiRegionAccessPointregionsError", 400),
    ("TooManyMultiRegionAccessPoints", 400),
    ("UnauthorizedAccessError", 403),
    ("UnexpectedContent", 400),
    ("UnexpectedIPError", 403),
    ("UnsupportedArgument", 400),
    ("UnsupportedSignature", 400),
    ("UnresolvableGrantByEmailAddress", 400),
    ("UserKeyMustBeSpecified", 400),
    ("NoSuchAccessPoint", 404),
    ("InvalidTag", 400),
    ("MalformedPolicy", 400),
    // Not in the table: S3 answers 400 when the hash in x-amz-content-sha256 is not the hash of the body, and when trailing headers are not well formed.
    ("XAmzContentSHA256Mismatch", 400),
    ("MalformedTrailerError", 400),
];

/// The HTTP status of an error code, when it is one this module knows.
pub fn status_of(code: &str) -> Option<u16> {
    ERROR_STATUS.iter().find(|(known, _)| *known == code).map(|(_, status)| *status)
}

/// An error response of S3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    /// The error code, such as `NoSuchKey`. It identifies the condition for programs.
    pub code: String,
    /// A description in English for people.
    pub message: String,
    /// The HTTP status.
    pub status: u16,
    /// The bucket or object involved, such as `/mybucket/myfoto.jpg`.
    pub resource: Option<String>,
    /// The ID of the request, as `RequestId`.
    pub request_id: Option<String>,
    /// The ID of the host, as `HostId`.
    pub host_id: Option<String>,
    /// More elements of the `Error`, which depend on the code: `Key` of `NoSuchKey`, `ExpectedDigest` and `CalculatedDigest` of `BadDigest`,
    /// `ArgumentName` and `ArgumentValue` of `InvalidArgument`, and so on.
    pub details: Vec<(String, String)>,
}

impl S3Error {
    /// An error with this code and message. The status is that of the table; an unknown code is a 500.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let status = status_of(&code).unwrap_or(500);
        Self { code, message: message.into(), status, resource: None, request_id: None, host_id: None, details: Vec::new() }
    }

    /// Adds the resource.
    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Adds the request ID.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Adds a detail element. The name must be a valid element name (letters, digits, `-`, `_`, `.`), or it is left out of the document.
    #[must_use]
    pub fn with_detail(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.push((name.into(), value.into()));
        self
    }

    /// The value of a detail element.
    pub fn detail(&self, name: &str) -> Option<&str> {
        self.details.iter().find(|(candidate, _)| candidate == name).map(|(_, value)| value.as_str())
    }

    /// The `<Error>` document: `Code`, `Message`, the details, `Resource`, `RequestId`, `HostId`. It has no namespace, as the one in the
    /// documentation. Send it with `Content-Type: application/xml`.
    pub fn to_xml(&self) -> String {
        let mut writer = XmlWriter::new("Error", false);
        writer.leaf("Code", &self.code).leaf("Message", &self.message);
        for (name, value) in &self.details {
            if XmlWriter::is_valid_name(name) && !matches!(name.as_str(), "Code" | "Message" | "Resource" | "RequestId" | "HostId") {
                writer.leaf(name, value);
            }
        }
        writer.leaf_opt("Resource", self.resource.as_deref()).leaf_opt("RequestId", self.request_id.as_deref()).leaf_opt("HostId", self.host_id.as_deref());
        writer.finish()
    }

    /// Reads an `<Error>` document received with this HTTP status. `Err` when the body is not such a document, which happens when something
    /// other than S3 answers (a proxy, for one).
    pub fn from_xml(body: &[u8], status: u16) -> Result<Self, XmlError> {
        let root = xml::parse_root(body, "Error", &Limits { max_bytes: 1024 * 1024, ..Limits::default() })?;
        Self::from_element(&root, status)
    }

    /// Reads an `Error` element, such as the ones in the result of `DeleteObjects` (which have `Code`, `Key`, `Message` and `VersionId`).
    pub(crate) fn from_element(element: &Element, status: u16) -> Result<Self, XmlError> {
        let mut error = Self::new(element.required_text("Code")?, element.child_text("Message").unwrap_or_default());
        error.status = status;
        for child in &element.children {
            let text = child.text.clone();
            match child.name.as_str() {
                "Code" | "Message" => {}
                "Resource" => error.resource = Some(text),
                "RequestId" => error.request_id = Some(text),
                "HostId" => error.host_id = Some(text),
                other if child.children.is_empty() => error.details.push((other.to_owned(), text)),
                _ => {}
            }
        }
        Ok(error)
    }

    /// Whether trying the same request again can work: the server was busy or failed (a 500, 502, 503 or 504, and the codes of throttling and
    /// time-outs), as opposed to a request that is wrong and will be wrong again.
    pub fn is_retryable(&self) -> bool {
        matches!(self.status, 500 | 502 | 503 | 504)
            || matches!(
                self.code.as_str(),
                "SlowDown"
                    | "RequestTimeout"
                    | "InternalError"
                    | "ServiceUnavailable"
                    | "Throttling"
                    | "ThrottlingException"
                    | "RequestThrottled"
                    | "RequestLimitExceeded"
            )
    }
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.code, self.status, self.message)
    }
}

impl std::error::Error for S3Error {}

impl From<&XmlError> for S3Error {
    /// A request body that could not be read is `MalformedXML`, with the message S3 gives.
    fn from(_: &XmlError) -> Self {
        Self::new(code::MALFORMED_XML, "The XML you provided was not well-formed or did not validate against our published schema.")
    }
}

impl From<&SigError> for S3Error {
    /// The S3 error for a request that failed authentication. The mapping follows the documentation of the codes; where it is silent (which
    /// code a header that was signed but is missing gets, for one) it is what S3 answers to the same mistake.
    fn from(error: &SigError) -> Self {
        let message = error.to_string();
        match error {
            SigError::MalformedAuthorization(_) | SigError::InvalidDate(_) => Self::new(code::AUTHORIZATION_HEADER_MALFORMED, message),
            SigError::MalformedQuery(_) | SigError::InvalidExpires(_) => Self::new(code::AUTHORIZATION_QUERY_PARAMETERS_ERROR, message),
            SigError::ConflictingAuthentication | SigError::UnsupportedAlgorithm(_) | SigError::InvalidPayloadHash(_) => Self::new(code::INVALID_ARGUMENT, message),
            SigError::MissingHeader(name) => Self::new(code::MISSING_SECURITY_HEADER, message).with_detail("MissingHeaderName", name.clone()),
            SigError::SignedHeaderMissing(_) | SigError::SignatureDoesNotMatch => Self::new(
                code::SIGNATURE_DOES_NOT_MATCH,
                "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
            ),
            SigError::HeadersNotSigned(names) => {
                Self::new(code::ACCESS_DENIED, "There were headers present in the request which were not signed").with_detail("HeadersNotSigned", names.join(", "))
            }
            SigError::RequestTimeTooSkewed { request_time, server_time } => {
                Self::new(code::REQUEST_TIME_TOO_SKEWED, "The difference between the request time and the current time is too large.")
                    .with_detail("RequestTime", request_time.iso8601())
                    .with_detail("ServerTime", server_time.iso8601())
                    .with_detail("MaxAllowedSkewMilliseconds", (crate::sigv4::MAX_CLOCK_SKEW * 1000).to_string())
            }
            SigError::Expired(at) => Self::new(code::ACCESS_DENIED, "Request has expired").with_detail("Expires", at.iso8601()),
        }
    }
}
