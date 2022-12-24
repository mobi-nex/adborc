use crate::util::adb_utils::ScrCpyArgs;

use super::{supplier::SupplierStateMin, DeviceFilterVec, *};
use consumer::ConsumerStateMin;
use marketmaker::MarketMakerMinState;
use serde::Serialize;
use std::str::FromStr;

pub trait GetRequest {
    fn get_request(self) -> Request;
}

pub trait ToJson {
    fn to_json(self) -> String;
}

/// Wrapper enum for all the possible requests that can be sent to the
/// network node.
#[derive(Serialize, Deserialize)]
pub enum Request {
    System(SysStateRequest),
    MarketMaker(MarketMakerRequest),
    Supplier(SupplierRequest),
    Consumer(ConsumerRequest),
}

/// Wrapper enum for all the possible responses that can be sent from the
/// network node.
#[derive(Serialize, Deserialize)]
pub enum Response {
    System(SysStateResponse),
    MarketMaker(MarketMakerResponse),
    Supplier(SupplierResponse),
    Consumer(ConsumerResponse),
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Response::System(response) => write!(f, "{}", response),
            Response::MarketMaker(response) => write!(f, "{}", response),
            Response::Supplier(response) => write!(f, "{}", response),
            Response::Consumer(response) => write!(f, "{}", response),
        }
    }
}

#[derive(Debug)]
pub enum ParseResponseError {
    /// Failed to parse the string as a valid JSON `Response`.
    BadResponse,
    /// Failed to parse the Response JSON as a valid `SysStateResponse`.
    BadSystemResponse,
    /// Failed to parse the Response JSON as a valid `MarketMakerResponse`.
    BadMarketMakerResponse,
    /// Failed to parse the Response JSON as a valid `SupplierResponse`.
    BadSupplierResponse,
    /// Failed to parse the Response JSON as a valid `ConsumerResponse`.
    BadConsumerResponse,
}

impl Display for ParseResponseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ParseResponseError::BadResponse => write!(f, "Bad response"),
            ParseResponseError::BadSystemResponse => {
                write!(f, "Bad system response")
            }
            ParseResponseError::BadMarketMakerResponse => {
                write!(f, "Bad market maker response")
            }
            ParseResponseError::BadSupplierResponse => {
                write!(f, "Bad supplier response")
            }
            ParseResponseError::BadConsumerResponse => {
                write!(f, "Bad consumer response")
            }
        }
    }
}
/// List of valid requests for the SysState listener.
/// These requests are usually sent to the SysState Listener
/// from the local TCPClient.
#[derive(Serialize, Deserialize)]
pub enum SysStateRequest {
    CheckVersion {
        version: String,
    },
    GetState,
    GetPeerId,
    SystemCheck,
    SetAdbPath {
        adb_path: String,
    },
    SetScrcpyPath {
        scrcpy_path: String,
    },
    StartMarketMaker,
    StartSupplier {
        mm_host: String,
        mm_port: u16,
        name: Option<String>,
        secure_comms: bool,
    },
    StartConsumer {
        mm_host: String,
        mm_port: u16,
        name: Option<String>,
    },
    GetMarketMakerConfig,
    GetSupplierConfig,
    GetConsumerConfig,
    Shutdown,

    StopMarketMaker,
    StopSupplier,
    StopConsumer,
    GetAdbVersionInfo,
    GetScrcpyInfo,

    SupplierMarketMakerTerminating,
    ConsumerMarketMakerTerminating,
}

/// Responses for the SysState listener.
#[derive(Serialize, Deserialize, Debug)]
pub enum SysStateResponse {
    CurrentSysState {
        state: SysStateMin,
    },
    PeerId {
        peer_id: String,
    },
    SystemCheck {
        supplier_check: SupplierCheck,
        consumer_check: ConsumerCheck,
    },
    SetAdbPathSuccess,
    SetAdbPathFailure {
        reason: String,
    },
    SetScrcpyPathSuccess,
    SetScrcpyPathFailure {
        reason: String,
    },
    GetPeerIdFailure,
    ShutDownSuccess,
    ShutDownFailure,
    StartMarketMakerSuccess,
    StartMarketMakerFailed {
        reason: String,
    },
    StartSupplierSuccess,
    StartSupplierFailed {
        reason: String,
    },
    StartConsumerSuccess,
    StartConsumerFailed {
        reason: String,
    },
    StopMarketMakerSuccess,
    StopMarketMakerFailed,
    StopSupplierSuccess,
    StopSupplierFailed,
    StopConsumerSuccess,
    StopConsumerFailed,

    TerminationAcknowledged,

    AdbVersionInfo {
        info: AdbVersionInfo,
    },
    ScrcpyInfo {
        info: String,
    },

    RequestNotAllowed,
    InvalidRequest {
        request: String,
    },
    RequestProcessingError {
        reason: String,
    },
    ClientOk,
    ClientError {
        reason: String,
    },
}

impl Display for SysStateResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SysStateResponse::CurrentSysState { state } => write!(f, "{}", state),
            SysStateResponse::PeerId { peer_id } => write!(f, "PeerId: {}", peer_id),
            SysStateResponse::GetPeerIdFailure => write!(f, "Failed to retrieve peer id"),
            SysStateResponse::SystemCheck {
                supplier_check,
                consumer_check,
            } => {
                write!(
                    f,
                    "Consumer: {}\n\nSupplier: {}",
                    consumer_check, supplier_check
                )
            }
            SysStateResponse::SetAdbPathSuccess => {
                write!(f, "ADB path set successfully")
            }
            SysStateResponse::SetAdbPathFailure { reason } => {
                write!(f, "Failed to set ADB path\n{}", reason)
            }
            SysStateResponse::SetScrcpyPathSuccess => {
                write!(f, "SCRCPY path set successfully")
            }
            SysStateResponse::SetScrcpyPathFailure { reason } => {
                write!(f, "Failed to set SCRCPY path: {}", reason)
            }
            SysStateResponse::ShutDownSuccess => write!(f, "Shutdown successful"),
            SysStateResponse::ShutDownFailure => write!(f, "Shutdown failed"),
            SysStateResponse::StartMarketMakerSuccess => {
                write!(f, "MarketMaker started successfully")
            }
            SysStateResponse::StartMarketMakerFailed { reason } => {
                write!(f, "MarketMaker failed to start: {}", reason)
            }
            SysStateResponse::StartSupplierSuccess => write!(f, "Supplier started successfully"),
            SysStateResponse::StartSupplierFailed { reason } => {
                write!(f, "Supplier failed to start:\n{}", reason)
            }
            SysStateResponse::StartConsumerSuccess => write!(f, "Consumer started successfully"),
            SysStateResponse::StartConsumerFailed { reason } => {
                write!(f, "Consumer failed to start:\n{}", reason)
            }
            SysStateResponse::StopMarketMakerSuccess => {
                write!(f, "MarketMaker stopped successfully")
            }
            SysStateResponse::StopMarketMakerFailed => write!(f, "MarketMaker failed to stop"),
            SysStateResponse::StopSupplierSuccess => write!(f, "Supplier stopped successfully"),
            SysStateResponse::StopSupplierFailed => write!(f, "Supplier failed to stop"),
            SysStateResponse::StopConsumerSuccess => write!(f, "Consumer stopped successfully"),
            SysStateResponse::StopConsumerFailed => write!(f, "Consumer failed to stop"),
            SysStateResponse::TerminationAcknowledged => write!(f, "Termination acknowledged"),
            SysStateResponse::AdbVersionInfo { info } => write!(f, "{}", info),
            SysStateResponse::ScrcpyInfo { info } => write!(f, "{}", info),
            SysStateResponse::RequestNotAllowed => write!(f, "Request not allowed"),
            SysStateResponse::InvalidRequest { request } => {
                write!(f, "Invalid request: {}", request)
            }
            SysStateResponse::RequestProcessingError { reason } => {
                write!(f, "Error processesing request: {}", reason)
            }
            SysStateResponse::ClientOk => write!(f, "Client OK"),
            SysStateResponse::ClientError { reason } => write!(f, "{}", reason),
        }
    }
}

/// List of valid requests MarketMaker can handle.
#[derive(Serialize, Deserialize, Debug)]
pub enum MarketMakerRequest {
    // Local client requests.
    Status,
    Terminate,
    UseWhitelist,
    ResetWhitelist,
    WhitelistSupplier {
        key: String,
    },
    WhitelistConsumer {
        key: String,
    },
    UnwhitelistSupplier {
        key: String,
    },
    UnwhitelistConsumer {
        key: String,
    },

    // Supplier Requests.
    SupplierConnect {
        supplier: SupplierSpec,
    },
    SupplyDevices {
        devices: Vec<DeviceSpec>,
    },
    SupplierHeartBeat,
    SupplierDisconnect,
    ReclaimDevice {
        device_id: String,
        force: bool,
    },

    // Consumer Requests.
    ConsumerConnect {
        consumer: ConsumerSpec,
    },
    ReserveDevice {
        device_id: String,
    },
    ReleaseDevice {
        device_id: String,
    },
    ConsumerHeartBeat,
    ConsumerDisconnect,
    GetAvailableDevices,
    GetDevicesByFilter {
        filter_vec: DeviceFilterVec,
    },
    ReleaseAllDevices,
    StartScrcpyTunnel {
        // Request sent by the consumer to the market maker to start a scrcpy tunnel.
        // The market maker will then forward the request to the supplier. The supplier
        // will then start the scrcpy tunnel that listens on `scrcpy_port` and forwards
        // it to the `port` on the consumer's machine.
        device_id: String,
        supplier_id: String,
        port: u16,
        scrcpy_port: u16,
    },

    // Miscellaneous requests.
    Test,
    UpdateDevices {
        devices: Vec<DeviceSpec>,
    }, // both supplier and consumer can update devices.
}

/// Responses from MarketMaker.
#[derive(Serialize, Deserialize, Debug)]
pub enum MarketMakerResponse {
    // Responses to local client.
    Test,
    Status {
        state: MarketMakerMinState,
    },
    ShutDownSuccess,
    ShutDownFailure {
        reason: String,
    },
    UseWhitelistSuccess,
    ResetWhitelistSuccess,

    WhitelistSupplierSuccess,
    WhitelistSupplierFailure {
        reason: String,
    },
    WhitelistConsumerSuccess,
    WhitelistConsumerFailure {
        reason: String,
    },
    UnwhitelistSupplierSuccess,
    UnwhitelistSupplierFailure {
        reason: String,
    },
    UnwhitelistConsumerSuccess,
    UnwhitelistConsumerFailure {
        reason: String,
    },

    // Responses to Supplier.
    SupplierConnected {
        supplier: SupplierSpec,
        pub_key: String,
    },
    SupplierNotConnected {
        reason: String,
    },
    DevicesSupplied {
        supplied_devices: Vec<DeviceSpec>,
        failed_devices: Vec<DeviceSpec>,
    },
    DeviceReclaimed {
        device_id: String,
    },
    SupplierDisconnected,
    DeviceBeingUsed {
        device_id: String,
    },
    DeviceNotReclaimed {
        reason: String,
    },

    // Responses to Consumer.
    ConsumerConnected {
        consumer: ConsumerSpec,
        pub_key: String,
    },
    ConsumerNotConnected {
        reason: String,
    },
    DeviceReserved {
        device: DeviceSpec,
        peer_id: Option<String>,
    },
    DeviceNotReserved {
        reason: String,
    },
    DeviceReleased,
    DeviceNotReleased {
        reason: String,
    },
    ConsumerDisconnected,
    AvailableDevices {
        devices: Vec<DeviceSpec>,
    },
    DevicesByFilter {
        devices: Vec<DeviceSpec>,
        filter_vec: DeviceFilterVec,
    },
    ErrorGettingDevices {
        reason: String,
    },
    AllDeviceReleaseSuccess,
    AllDeviceReleaseFailure {
        reason: String,
    },
    ScrcpyTunnelSuccess,
    ScrcpyTunnelFailure {
        reason: String,
    },

    // Other Responses
    HeartBeatResponse,
    RequestNotAllowed,
    InvalidRequest {
        request: String,
    },
    RequestProcessingError {
        reason: String,
    },
}

impl Display for MarketMakerResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MarketMakerResponse::Test => write!(f, "Test"),
            MarketMakerResponse::Status { state } => write!(f, "{}", state),
            MarketMakerResponse::ShutDownSuccess => write!(f, "Termination success"),
            MarketMakerResponse::ShutDownFailure { reason } => {
                write!(f, "Termination failure: {}", reason)
            }

            MarketMakerResponse::UseWhitelistSuccess => write!(f, "Whitelist enabled"),
            MarketMakerResponse::ResetWhitelistSuccess => write!(f, "Whitelist disabled"),
            MarketMakerResponse::WhitelistSupplierSuccess => {
                write!(f, "Whitelist supplier success")
            }
            MarketMakerResponse::WhitelistSupplierFailure { reason } => {
                write!(f, "Whitelist supplier failure: {}", reason)
            }
            MarketMakerResponse::WhitelistConsumerSuccess => {
                write!(f, "Whitelist consumer success")
            }
            MarketMakerResponse::WhitelistConsumerFailure { reason } => {
                write!(f, "Whitelist consumer failure: {}", reason)
            }
            MarketMakerResponse::UnwhitelistSupplierSuccess => {
                write!(f, "Unwhitelist supplier success")
            }
            MarketMakerResponse::UnwhitelistSupplierFailure { reason } => {
                write!(f, "Unwhitelist supplier failure: {}", reason)
            }
            MarketMakerResponse::UnwhitelistConsumerSuccess => {
                write!(f, "Unwhitelist consumer success")
            }
            MarketMakerResponse::UnwhitelistConsumerFailure { reason } => {
                write!(f, "Unwhitelist consumer failure: {}", reason)
            }

            MarketMakerResponse::SupplierConnected { supplier, .. } => {
                write!(f, "Supplier connected:\n{}", supplier)
            }
            MarketMakerResponse::SupplierNotConnected { reason } => {
                write!(f, "Supplier not connected: {}", reason)
            }
            MarketMakerResponse::DevicesSupplied {
                supplied_devices,
                failed_devices: _,
            } => {
                writeln!(f, "Devices supplied:").unwrap();
                for d in supplied_devices {
                    writeln!(f, "{}", d).unwrap();
                }
                write!(f, "")
            }
            MarketMakerResponse::DeviceReclaimed { device_id } => {
                write!(f, "Device reclaimed: {}", device_id)
            }
            MarketMakerResponse::SupplierDisconnected => write!(f, "Supplier disconnected"),
            MarketMakerResponse::DeviceBeingUsed { device_id } => {
                write!(f, "Device being used: {}", device_id)
            }
            MarketMakerResponse::DeviceNotReclaimed { reason } => {
                write!(f, "Device not reclaimed: {}", reason)
            }

            MarketMakerResponse::ConsumerConnected { consumer, .. } => {
                write!(f, "Consumer connected:\n{}", consumer)
            }
            MarketMakerResponse::ConsumerNotConnected { reason } => {
                write!(f, "Consumer not connected: {}", reason)
            }
            MarketMakerResponse::DeviceReserved { device, peer_id: _ } => {
                write!(f, "Device reserved:\n{}", device)
            }
            MarketMakerResponse::DeviceNotReserved { reason } => {
                write!(f, "Device not reserved: {}", reason)
            }
            MarketMakerResponse::DeviceReleased => write!(f, "Device released"),
            MarketMakerResponse::DeviceNotReleased { reason } => {
                write!(f, "Device not released: {}", reason)
            }
            MarketMakerResponse::ConsumerDisconnected => write!(f, "Consumer disconnected"),
            MarketMakerResponse::AvailableDevices { devices } => {
                writeln!(f, "Available devices:").unwrap();
                for d in devices {
                    writeln!(f, "{}", d).unwrap();
                }
                write!(f, "")
            }
            MarketMakerResponse::DevicesByFilter {
                devices,
                filter_vec,
            } => {
                writeln!(f, "Devices by filter:").unwrap();
                writeln!(f, "{}", filter_vec).unwrap();
                for d in devices {
                    writeln!(f, "{}", d).unwrap();
                }
                write!(f, "")
            }
            MarketMakerResponse::ErrorGettingDevices { reason } => {
                write!(f, "Error getting devices: {}", reason)
            }
            MarketMakerResponse::AllDeviceReleaseSuccess => {
                write!(f, "All devices released successfully")
            }
            MarketMakerResponse::AllDeviceReleaseFailure { reason } => {
                write!(f, "All devices not released: {}", reason)
            }
            MarketMakerResponse::ScrcpyTunnelSuccess => {
                write!(f, "Scrcpy tunnel started successfully")
            }
            MarketMakerResponse::ScrcpyTunnelFailure { reason } => {
                write!(f, "Scrcpy tunnel failure: {}", reason)
            }

            MarketMakerResponse::HeartBeatResponse => write!(f, "HeartBeatResponse"),
            MarketMakerResponse::RequestNotAllowed => write!(f, "Request not allowed"),
            MarketMakerResponse::InvalidRequest { request } => {
                write!(f, "Invalid request: {}", request)
            }
            MarketMakerResponse::RequestProcessingError { reason } => {
                write!(f, "Error processing request: {}", reason)
            }
        }
    }
}

/// List of valid requests Supplier can handle.
#[derive(Serialize, Deserialize, Debug)]
pub enum SupplierRequest {
    // Requests from client.
    Test,
    Status,
    SupplyDevices {
        devices: Option<Vec<String>>,
    },
    ReclaimDevice {
        device_id: String,
        force: bool,
    },

    // Requests from MarketMaker.
    MarketMakerTerminating,
    StartSecureTunnel {
        device_id: String,
        port: u16,
        pub_key: String,
    },
    StopSecureTunnel {
        device_id: String,
    },
    StartScrcpyTunnel {
        // This request is sent by MarketMaker to Supplier when a Consumer
        // requests to use a device for scrcpy. The MarketMaker asks the Supplier
        // to start a scrcpy tunnel. If the device uses secure_comms, the Supplier
        // starts a PortForwarder in Encrypt mode that listens
        // plaintext traffic on `scrcpy_port`, encrypts it and forwards it to the
        // `port` on the consumer's machine (where presumably the consumer is running
        // a PortForwarder instance in Decrypt mode).
        // If the device does not use secure_comms, the Supplier starts a PortForwarder
        // in Plaintext mode that listens plaintext traffic on `scrcpy_port` and
        // forwards it to the `port` on the consumer's machine.
        device_id: String,
        peer_id: String,
        consumer_host: String,
        port: u16,
        scrcpy_port: u16,
    },
}

/// Responses from Supplier.
#[derive(Serialize, Deserialize, Debug)]
pub enum SupplierResponse {
    Test,
    Status {
        state: SupplierStateMin,
    },
    DevicesSupplied {
        supplied_devices: Vec<DeviceSpec>,
        failed_devices: Vec<DeviceSpec>,
    },
    DeviceSupplyFailure {
        reason: String,
    },
    TerminationAcknowledged,
    DeviceReclaimed {
        device_id: String,
    },
    DeviceNotReclaimed {
        reason: String,
    },
    SecureTunnelStarted {
        port: u16,
    },
    SecureTunnelStartFailure {
        reason: String,
    },
    SecureTunnelStopped,
    ScrcpyTunnelSuccess,
    ScrcpyTunnelFailure {
        reason: String,
    },

    RequestNotAllowed,
    InvalidRequest {
        request: String,
    },
    RequestProcessingError {
        reason: String,
    },
}

impl Display for SupplierResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SupplierResponse::Test => write!(f, "Test"),
            SupplierResponse::Status { state } => write!(f, "{}", state),
            SupplierResponse::DevicesSupplied {
                supplied_devices,
                failed_devices,
            } => {
                if !supplied_devices.is_empty() {
                    writeln!(f, "Devices supplied:").unwrap();
                    for d in supplied_devices {
                        writeln!(f, "{}", d).unwrap();
                    }
                }
                if !failed_devices.is_empty() {
                    writeln!(
                        f,
                        "\nFailed to supply some devices because of duplicate device_id(s)"
                    )
                    .unwrap();
                    writeln!(f, "Devices failed to supply:").unwrap();
                    for d in failed_devices {
                        writeln!(f, "{}", d).unwrap();
                    }
                }
                write!(f, "")
            }
            SupplierResponse::DeviceSupplyFailure { reason } => {
                write!(f, "Device supply failure: {}", reason)
            }
            SupplierResponse::TerminationAcknowledged => write!(f, "Termination acknowledged"),
            SupplierResponse::DeviceReclaimed { device_id } => {
                write!(f, "Device reclaimation success: {}", device_id)
            }
            SupplierResponse::DeviceNotReclaimed { reason } => {
                write!(f, "Device reclaimation failure: {}", reason)
            }
            SupplierResponse::SecureTunnelStarted { port } => {
                write!(f, "Secure tunnel started on: {}", port)
            }
            SupplierResponse::SecureTunnelStartFailure { reason } => {
                write!(f, "Secure tunnel start failure: {}", reason)
            }
            SupplierResponse::SecureTunnelStopped => write!(f, "Secure tunnel stopped"),
            SupplierResponse::ScrcpyTunnelSuccess => {
                write!(f, "Scrcpy tunnel started successfully")
            }
            SupplierResponse::ScrcpyTunnelFailure { reason } => {
                write!(f, "Scrcpy tunnel start failure: {}", reason)
            }
            SupplierResponse::RequestNotAllowed => write!(f, "Request not allowed"),
            SupplierResponse::InvalidRequest { request } => {
                write!(f, "Invalid request: {}", request)
            }
            SupplierResponse::RequestProcessingError { reason } => {
                write!(f, "Error processing request: {}", reason)
            }
        }
    }
}

/// List of valid requests Consumer can handle.
#[derive(Serialize, Deserialize, Debug)]
pub enum ConsumerRequest {
    // Requests from client.
    Test,
    Status,
    GetAvailableDevices,
    GetDevicesByFilter {
        filter_vec: DeviceFilterVec,
    },
    ReserveDevice {
        device_id: String,
        no_use: bool,
    },
    ReleaseDevice {
        device_id: String,
    },
    ReleaseAllDevices,
    UseDevice {
        device_id: String,
    },
    StartScrCpy {
        device_id: String,
        scrcpy_args: Vec<ScrCpyArgs>,
    },
    SetScrCpyDefaults {
        scrcpy_args: Vec<ScrCpyArgs>,
    },
    GetScrCpyDefaults,

    // Requests from MarketMaker.
    MarketMakerTerminating,
    SupplierDisconnected {
        device_id: String,
    },
}

/// Responses from Consumer.
#[derive(Serialize, Deserialize, Debug)]
pub enum ConsumerResponse {
    Test,
    Status {
        state: ConsumerStateMin,
    },
    TerminationAcknowledged,
    AvailableDevices {
        devices: Vec<DeviceSpec>,
    },
    DevicesByFilter {
        devices: Vec<DeviceSpec>,
        filter_vec: DeviceFilterVec,
    },
    DeviceReserved {
        device: DeviceSpec,
    },
    DeviceNotReserved {
        reason: String,
    },
    DeviceReleased {
        device_id: String,
    },
    DeviceNotReleased {
        reason: String,
    },
    AllDeviceReleaseSuccess,
    AllDeviceReleaseFailure {
        reason: String,
    },
    UseDeviceSuccess {
        device_id: String,
    },
    UseDeviceFailure {
        reason: String,
    },
    StartScrCpySuccess {
        device_id: String,
    },
    StartScrCpyFailure {
        reason: String,
    },
    ScrCpyDefaultsSet {
        args: Vec<ScrCpyArgs>,
    },
    ScrCpyDefaults {
        args: Vec<ScrCpyArgs>,
    },

    ErrorGettingDevices {
        reason: String,
    },
    RequestNotAllowed,
    InvalidRequest {
        request: String,
    },
    RequestProcessingError {
        reason: String,
    },
}

impl Display for ConsumerResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ConsumerResponse::Test => write!(f, "Test"),
            ConsumerResponse::Status { state } => write!(f, "{}", state),
            ConsumerResponse::TerminationAcknowledged => write!(f, "Termination acknowledged"),
            ConsumerResponse::AvailableDevices { devices } => {
                writeln!(f, "Available devices:").unwrap();
                for d in devices {
                    writeln!(f, "{}", d).unwrap();
                }
                write!(f, "")
            }
            ConsumerResponse::DevicesByFilter {
                devices,
                filter_vec,
            } => {
                writeln!(f, "Devices filtered by:").unwrap();
                writeln!(f, "{}", filter_vec).unwrap();
                if devices.is_empty() {
                    writeln!(f, "No devices found").unwrap();
                } else {
                    writeln!(f, "Devices found:\n").unwrap();
                    for d in devices {
                        writeln!(f, "{}", d).unwrap();
                    }
                }
                write!(f, "")
            }
            ConsumerResponse::DeviceReserved { device } => {
                write!(f, "Device reserved:\n{}", device)
            }
            ConsumerResponse::DeviceNotReserved { reason } => {
                write!(f, "Device not reserved: {}", reason)
            }
            ConsumerResponse::DeviceReleased { device_id } => {
                write!(f, "Device released: {}", device_id)
            }
            ConsumerResponse::DeviceNotReleased { reason } => {
                write!(f, "Device not released: {}", reason)
            }
            ConsumerResponse::AllDeviceReleaseSuccess => {
                write!(f, "All devices released successfully")
            }
            ConsumerResponse::AllDeviceReleaseFailure { reason } => {
                write!(f, "Error releasing devices: {}", reason)
            }
            ConsumerResponse::UseDeviceSuccess { device_id } => {
                write!(f, "Default device switched successfully to: {}", device_id)
            }
            ConsumerResponse::UseDeviceFailure { reason } => {
                write!(f, "Error switching default device: {}", reason)
            }
            ConsumerResponse::StartScrCpySuccess { device_id } => {
                write!(
                    f,
                    "Started screen mirroring successfully for device: {}",
                    device_id
                )
            }
            ConsumerResponse::StartScrCpyFailure { reason } => {
                write!(f, "Screen mirroring failed: {}", reason)
            }
            ConsumerResponse::ScrCpyDefaultsSet { args } => {
                writeln!(f, "ScrCpy defaults set:").unwrap();
                for a in args {
                    write!(f, "{}   ", a).unwrap();
                }
                writeln!(f)
            }
            ConsumerResponse::ScrCpyDefaults { args } => {
                writeln!(f, "ScrCpy defaults:").unwrap();
                for a in args {
                    write!(f, "{}   ", a).unwrap();
                }
                writeln!(f)
            }
            ConsumerResponse::ErrorGettingDevices { reason } => {
                write!(f, "Error getting devices: {}", reason)
            }
            ConsumerResponse::RequestNotAllowed => write!(f, "Request not allowed"),
            ConsumerResponse::InvalidRequest { request } => {
                write!(f, "Invalid request: {}", request)
            }
            ConsumerResponse::RequestProcessingError { reason } => {
                write!(f, "Error processing request: {}", reason)
            }
        }
    }
}

impl GetRequest for SysStateRequest {
    fn get_request(self) -> Request {
        Request::System(self)
    }
}

impl GetRequest for MarketMakerRequest {
    fn get_request(self) -> Request {
        Request::MarketMaker(self)
    }
}

impl GetRequest for SupplierRequest {
    fn get_request(self) -> Request {
        Request::Supplier(self)
    }
}

impl GetRequest for ConsumerRequest {
    fn get_request(self) -> Request {
        Request::Consumer(self)
    }
}

impl ToJson for SysStateResponse {
    fn to_json(self) -> String {
        serde_json::to_string(&Response::System(self)).unwrap()
    }
}
impl ToJson for MarketMakerResponse {
    fn to_json(self) -> String {
        serde_json::to_string(&Response::MarketMaker(self)).unwrap()
    }
}
impl ToJson for SupplierResponse {
    fn to_json(self) -> String {
        serde_json::to_string(&Response::Supplier(self)).unwrap()
    }
}
impl ToJson for ConsumerResponse {
    fn to_json(self) -> String {
        serde_json::to_string(&Response::Consumer(self)).unwrap()
    }
}

impl FromStr for Request {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl FromStr for Response {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl FromStr for SysStateResponse {
    type Err = ParseResponseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(response) = Response::from_str(s) {
            match response {
                Response::System(r) => Ok(r),
                _ => Err(ParseResponseError::BadSystemResponse),
            }
        } else {
            Err(ParseResponseError::BadResponse)
        }
    }
}

impl FromStr for MarketMakerResponse {
    type Err = ParseResponseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(response) = Response::from_str(s) {
            match response {
                Response::MarketMaker(r) => Ok(r),
                _ => Err(ParseResponseError::BadMarketMakerResponse),
            }
        } else {
            Err(ParseResponseError::BadResponse)
        }
    }
}

impl FromStr for SupplierResponse {
    type Err = ParseResponseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(response) = Response::from_str(s) {
            match response {
                Response::Supplier(r) => Ok(r),
                _ => Err(ParseResponseError::BadSupplierResponse),
            }
        } else {
            Err(ParseResponseError::BadResponse)
        }
    }
}

impl FromStr for ConsumerResponse {
    type Err = ParseResponseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(response) = Response::from_str(s) {
            match response {
                Response::Consumer(r) => Ok(r),
                _ => Err(ParseResponseError::BadConsumerResponse),
            }
        } else {
            Err(ParseResponseError::BadResponse)
        }
    }
}
