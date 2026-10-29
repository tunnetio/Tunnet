use std::io;
use std::str;
#[cfg(feature = "aio_tokio")]
use std::string::FromUtf8Error;

#[cfg(feature = "aio_tokio")]
use tokio::time::error::Elapsed;

/// Errors that can occur when sending the request to the gateway.
#[derive(thiserror::Error, Debug)]
pub enum RequestError {
    #[cfg(feature = "io_sync")]
    #[error("HTTP error {0}")]
    /// attohttp error
    AttoHttpError(#[from] attohttpc::Error),
    #[error("IO error: {0:?}")]
    /// IO Error
    IoError(#[from] io::Error),
    #[error("Invalid response from gateway: {}", _0)]
    /// The response from the gateway could not be parsed.
    InvalidResponse(String),
    /// The gateway returned an unhandled error code and description.
    #[error("Gateway response error {}: {}", _0, _1)]
    ErrorCode(u16, String),
    #[error("Action is not supported by the gateway: {}", _0)]
    /// Action is not supported by the gateway
    UnsupportedAction(String),
    /// When using the aio feature.
    #[cfg(feature = "aio_tokio")]
    #[error("Hyper Error: {0}")]
    HyperError(#[from] hyper::Error),
    /// When using the aio feature.
    #[cfg(feature = "aio_tokio")]
    #[error("Hyper Client Error: {0}")]
    HyperClientError(#[from] hyper_util::client::legacy::Error),

    /// http crate error type
    #[cfg(feature = "aio_tokio")]
    #[error("Http Error: {0}")]
    HttpError(#[from] http::Error),

    /// Error parsing HTTP body
    #[cfg(feature = "aio_tokio")]
    #[error("UTF-8 Error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
}

#[cfg(feature = "aio_tokio")]
impl From<Elapsed> for RequestError {
    fn from(_err: Elapsed) -> RequestError {
        RequestError::IoError(io::Error::new(io::ErrorKind::TimedOut, "control request timed out"))
    }
}

/// Errors returned by `Gateway::get_external_ip`
#[derive(thiserror::Error, Debug)]
pub enum GetExternalIpError {
    /// The client is not authorized to perform the operation.
    #[error("The client is not authorized to get the external IP address")]
    ActionNotAuthorized,
    /// Some other error occured performing the request.
    #[error("Request Error. {0}")]
    RequestError(#[source] RequestError),
}

impl From<io::Error> for GetExternalIpError {
    fn from(err: io::Error) -> GetExternalIpError {
        GetExternalIpError::RequestError(RequestError::from(err))
    }
}

/// Errors returned by `Gateway::remove_port`
#[derive(thiserror::Error, Debug)]
pub enum RemovePortError {
    /// The client is not authorized to perform the operation.
    #[error("The client is not authorized to remove the port")]
    ActionNotAuthorized,
    /// No such port mapping.
    #[error("The port was not mapped")]
    NoSuchPortMapping,
    /// Some other error occured performing the request.
    #[error("Request error. {0}")]
    RequestError(#[source] RequestError),
}

/// Errors returned by `Gateway::add_any_port` and `Gateway::get_any_address`
#[derive(thiserror::Error, Debug)]
pub enum AddAnyPortError {
    /// The client is not authorized to perform the operation.
    #[error("The client is not authorized to map this port.")]
    ActionNotAuthorized,
    /// Can not add a mapping for local port 0.
    #[error("Can not add a mapping for local port 0")]
    InternalPortZeroInvalid,
    /// The gateway does not have any free ports.
    #[error("The gateway does not have any free ports")]
    NoPortsAvailable,
    /// The gateway can only map internal ports to same-numbered external ports
    /// and this external port is in use.
    #[error(
        "The gateway can only map internal ports to same-numbered external ports and this external port is in use."
    )]
    ExternalPortInUse,
    /// The gateway only supports permanent leases (ie. a `lease_duration` of 0).
    #[error("The gateway only supports permanent leases (ie. a `lease_duration` of 0).")]
    OnlyPermanentLeasesSupported,
    /// The description was too long for the gateway to handle.
    #[error("The description was too long for the gateway to handle.")]
    DescriptionTooLong,
    /// Some other error occured performing the request.
    #[error("Request error. {0}")]
    RequestError(#[from] RequestError),
}

impl From<GetExternalIpError> for AddAnyPortError {
    fn from(err: GetExternalIpError) -> AddAnyPortError {
        match err {
            GetExternalIpError::ActionNotAuthorized => AddAnyPortError::ActionNotAuthorized,
            GetExternalIpError::RequestError(e) => AddAnyPortError::RequestError(e),
        }
    }
}

/// Errors returned by `Gateway::add_port`
#[derive(thiserror::Error, Debug)]
pub enum AddPortError {
    /// The client is not authorized to perform the operation.
    #[error("The client is not authorized to map this port.")]
    ActionNotAuthorized,
    /// Can not add a mapping for local port 0.
    #[error("Can not add a mapping for local port 0")]
    InternalPortZeroInvalid,
    /// External port number 0 (any port) is considered invalid by the gateway.
    #[error("External port number 0 (any port) is considered invalid by the gateway.")]
    ExternalPortZeroInvalid,
    /// The requested mapping conflicts with a mapping assigned to another client.
    #[error("The requested mapping conflicts with a mapping assigned to another client.")]
    PortInUse,
    /// The gateway requires that the requested internal and external ports are the same.
    #[error("The gateway requires that the requested internal and external ports are the same.")]
    SamePortValuesRequired,
    /// The gateway only supports permanent leases (ie. a `lease_duration` of 0).
    #[error("The gateway only supports permanent leases (ie. a `lease_duration` of 0).")]
    OnlyPermanentLeasesSupported,
    /// The description was too long for the gateway to handle.
    #[error("The description was too long for the gateway to handle.")]
    DescriptionTooLong,
    /// Some other error occured performing the request.
    #[error("Request error. {0}")]
    RequestError(#[source] RequestError),
}

/// Errors than can occur while trying to find the gateway.
#[derive(thiserror::Error, Debug)]
pub enum SearchError {
    /// Http/Hyper error
    #[cfg(feature = "io_sync")]
    #[error("HTTP error {0}")]
    HttpError(#[from] attohttpc::Error),
    /// Unable to process the response
    #[error("Invalid response")]
    InvalidResponse,
    /// Did not receive any valid response within timeout
    #[error("No response within timeout")]
    NoResponseWithinTimeout,
    /// IO Error
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    /// UTF-8 decoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] str::Utf8Error),
    /// XML processing error
    #[error("XML error: {0}")]
    XmlError(#[from] xmltree::ParseError),
    /// When using the aio feature.
    #[cfg(feature = "aio_tokio")]
    #[error("Hyper Error: {0}")]
    HyperError(#[from] hyper::Error),
    /// When using the aio feature.
    #[cfg(feature = "aio_tokio")]
    #[error("Hyper Client Error: {0}")]
    HyperClientError(#[from] hyper_util::client::legacy::Error),
    /// Error parsing URI
    #[cfg(feature = "aio_tokio")]
    #[error("InvalidUri Error: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
}

#[cfg(feature = "aio_tokio")]
impl From<Elapsed> for SearchError {
    fn from(_err: Elapsed) -> SearchError {
        SearchError::IoError(io::Error::new(io::ErrorKind::TimedOut, "search timed out"))
    }
}

/// Errors than can occur while getting a port mapping
#[derive(thiserror::Error, Debug)]
pub enum GetGenericPortMappingEntryError {
    /// The client is not authorized to perform the operation.
    #[error("The client is not authorized to look up port mappings.")]
    ActionNotAuthorized,
    /// The specified array index is out of bounds.
    #[error("The provided index into the port mapping list is invalid.")]
    SpecifiedArrayIndexInvalid,
    /// Some other error occured performing the request.
    #[error("{0}")]
    RequestError(#[source] RequestError),
}

impl From<RequestError> for GetGenericPortMappingEntryError {
    fn from(err: RequestError) -> GetGenericPortMappingEntryError {
        match err {
            RequestError::ErrorCode(606, _) => GetGenericPortMappingEntryError::ActionNotAuthorized,
            RequestError::ErrorCode(713, _) => GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid,
            other => GetGenericPortMappingEntryError::RequestError(other),
        }
    }
}

/// An error type that emcompasses all possible errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// `AddAnyPortError`
    #[error("{0}")]
    AddAnyPortError(#[from] AddAnyPortError),
    /// `AddPortError`
    #[error("{0}")]
    AddPortError(#[from] AddPortError),
    /// `GetExternalIpError`
    #[error("{0}")]
    GetExternalIpError(#[from] GetExternalIpError),
    /// `GetGenericPortMappingEntryError`
    #[error("{0}")]
    GetGenericPortMappingEntryError(#[from] GetGenericPortMappingEntryError),
    /// `RemovePortError`
    #[error("{0}")]
    RemovePortError(#[from] RemovePortError),
    /// An IPv6 firewall pinhole error.
    #[cfg(feature = "ipv6")]
    #[error("{0}")]
    PinholeError(#[from] PinholeError),
    /// `RequestError`
    #[error("{0}")]
    RequestError(#[from] RequestError),
    /// `SearchError`
    #[error("{0}")]
    SearchError(#[from] SearchError),
}

/// A result type where the error is `igd::Error`.
pub type Result<T = ()> = std::result::Result<T, Error>;

/// Errors returned by the IPv6 firewall pinhole operations.
#[cfg(feature = "ipv6")]
#[derive(thiserror::Error, Debug)]
pub enum PinholeError {
    /// The gateway did not advertise a `WANIPv6FirewallControl` service,
    #[error("the gateway does not provide a WANIPv6FirewallControl service")]
    FirewallControlUnavailable,
    /// The requested lease duration was outside the valid range for a pinhole.
    #[error("the pinhole lease duration must be between 1 and 86400 seconds")]
    InvalidLeaseDuration,
    /// The client is not authorized to perform the operation.
    #[error("the client is not authorized to perform this firewall operation")]
    ActionNotAuthorized,
    /// The gateway's pinhole table is full.
    #[error("the gateway's pinhole table is full")]
    PinholeSpaceExhausted,
    /// The gateway's IPv6 firewall is disabled.
    #[error("the gateway's IPv6 firewall is disabled")]
    FirewallDisabled,
    /// Inbound pinholes are not allowed by the gateway.
    #[error("inbound pinholes are not allowed by the gateway")]
    InboundPinholeNotAllowed,
    /// No pinhole exists with the given `UniqueID`.
    #[error("no pinhole exists with the given id")]
    NoSuchEntry,
    /// Some other error occurred performing the request.
    #[error("Request error. {0}")]
    RequestError(#[source] RequestError),
}
