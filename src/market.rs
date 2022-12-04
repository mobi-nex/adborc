/// Request and response objects used for communication with the System node and
/// between System nodes.
pub mod request;

mod consumer;
mod marketmaker;
mod supplier;

use crate::net::{CommandServer, PortForwardMode, PortForwarder, ProcessFn, TCPClient};
use crate::util::{
    adb_utils::{self, AdbVersionInfo, DeviceInfo, ScrcpyVersionInfo},
    SysStateDefaultConfig, HEARTBEAT_INTERVAL, MIN_ADB_REV, MIN_ADB_VER, MIN_SCRCPY_VER,
    UNDERTAKER_INTERVAL,
};
use blake2::{digest::consts::U16, Blake2s, Digest};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json;
use snow::Keypair;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter, Result, Write};
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use consumer::{Consumer, ConsumerState};
use marketmaker::MarketMaker;
use request::*;
use supplier::{Supplier, SupplierState};
use tokio::task;

pub(crate) struct SystemKeypair {
    keypair: Option<Keypair>,
}

lazy_static! {
    static ref SYSTEM_KEYPAIR: RwLock<SystemKeypair> = RwLock::new(SystemKeypair { keypair: None });
}

impl SystemKeypair {
    pub fn set_keypair(keypair: Keypair) {
        let mut system_keypair = SYSTEM_KEYPAIR.write().unwrap();
        system_keypair.keypair = Some(keypair);
    }

    pub fn is_none() -> bool {
        SYSTEM_KEYPAIR.read().unwrap().keypair.is_none()
    }

    pub fn get_private_key() -> Option<Vec<u8>> {
        let system_keypair = SYSTEM_KEYPAIR.read().unwrap();
        system_keypair
            .keypair
            .as_ref()
            .map(|keypair| keypair.private.clone())
    }

    pub fn get_public_key() -> Option<Vec<u8>> {
        let system_keypair = SYSTEM_KEYPAIR.read().unwrap();
        system_keypair
            .keypair
            .as_ref()
            .map(|keypair| keypair.public.clone())
    }
}

pub(crate) type Key = Vec<u8>;

struct System;

/// This is a struct used to start the system and keep track of the modes running
/// in the current system. For example, if a system starts the network by running in
/// MarketMaker mode, then the MarketMaker mode will be added to the state. Now, if
/// the system decides to supply devices to the network, then the Supplier mode
/// will be added to the state.
pub struct SysState {
    market_maker: Option<MarketMaker>,
    supplier: Option<Supplier>,
    consumer: Option<Consumer>,
    initialized: bool,
}

/// System state information for currently operational mode.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SysStateMin {
    pub market_maker: bool,
    pub supplier: bool,
    pub consumer: bool,
    pub initialized: bool,
}

impl Display for SysStateMin {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            r"System status:
    Initialized : {}
    MarketMaker : {}
    Supplier    : {}
    Consumer    : {}",
            self.initialized, self.market_maker, self.supplier, self.consumer
        )
    }
}

lazy_static! {
    /// Creates a new uninitialized SysState struct.
    /// This struct is used to persist the system state.
    static ref SYS_STATE: RwLock<SysState> = RwLock::new(SysState::default());
}

impl Default for SysState {
    /// Creates a new uninitialized SysState struct.
    fn default() -> SysState {
        SysState {
            market_maker: None,
            supplier: None,
            consumer: None,
            initialized: false,
        }
    }
}

// Keeps accesses to the SYS_STATE static variable contained in small functions.
// This is to prevent deadlocks when accessing the SYS_STATE RwLock in multiple places.
// We should not need to lock the SYS_STATE RwLock outside of these functions.
// Note: Eager unwraps are used here because we should never be in a situation where
// the lock is poisoned. If the lock is poisoned, then the thread should panic.
impl SysState {
    // Write functions...

    /// Starts the system listener in uninitialized state.
    /// This function should only be called once.
    /// To initialize the system, send a [`request`] to the system listener
    /// to start any of the modes.
    #[inline(always)]
    #[tokio::main]
    pub async fn start_system() -> io::Result<()> {
        let mut listener = CommandServer {
            host: SysStateDefaultConfig::BIND_HOST.to_string(),
            port: SysStateDefaultConfig::BIND_PORT,
        };
        listener.start(System::process_command).await
    }

    #[inline(always)]
    fn reset_state() {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        *state = SysState::default();
    }

    #[inline(always)]
    fn set_market_maker(mm: MarketMaker) {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.market_maker = Some(mm);
    }

    #[inline(always)]
    fn set_supplier(supplier: Supplier) {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.supplier = Some(supplier);
    }

    #[inline(always)]
    fn set_consumer(consumer: Consumer) {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.consumer = Some(consumer);
    }

    #[inline(always)]
    fn set_initialized() {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.initialized = true;
    }

    #[inline(always)]
    fn reset_market_maker() {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.market_maker = None;
    }

    #[inline(always)]
    fn reset_supplier() {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.supplier = None;
    }

    #[inline(always)]
    fn reset_consumer() {
        if SYS_STATE.is_poisoned() {
            error!("SYS_STATE lock is poisoned");
            return;
        }
        let mut state = SYS_STATE.write().unwrap();
        state.consumer = None;
    }

    #[inline(always)]
    fn update_initialized() -> bool {
        let mut state = SYS_STATE.write().unwrap();
        state.initialized =
            state.market_maker.is_some() || state.supplier.is_some() || state.consumer.is_some();
        state.initialized
    }

    #[inline(always)]
    #[tokio::main]
    async fn stop_system() {
        let listener = CommandServer {
            host: SysStateDefaultConfig::BIND_HOST.to_string(),
            port: SysStateDefaultConfig::BIND_PORT,
        };
        listener.stop().await;
    }

    // Read functions...

    #[inline(always)]
    fn get_min_state() -> SysStateMin {
        let state = SYS_STATE.read().unwrap();
        SysStateMin {
            market_maker: state.market_maker.is_some(),
            supplier: state.supplier.is_some(),
            consumer: state.consumer.is_some(),
            initialized: state.initialized,
        }
    }

    #[inline(always)]
    fn is_initialized() -> bool {
        let state = SYS_STATE.read().unwrap();
        state.initialized
    }

    #[inline(always)]
    fn market_maker_is_some() -> bool {
        let state = SYS_STATE.read().unwrap();
        state.market_maker.is_some()
    }

    #[inline(always)]
    fn supplier_is_some() -> bool {
        let state = SYS_STATE.read().unwrap();
        state.supplier.is_some()
    }

    #[inline(always)]
    fn consumer_is_some() -> bool {
        let state = SYS_STATE.read().unwrap();
        state.consumer.is_some()
    }
}

impl System {
    /// Initializes the system state in a MarketMaker mode.
    pub fn start_market_maker() -> io::Result<()> {
        if !SysState::is_initialized() {
            match MarketMaker::new() {
                Ok(mm) => {
                    SysState::set_market_maker(mm);
                    SysState::set_initialized();
                    info!("Market maker started");
                }
                Err(e) => {
                    error!("Error starting market maker: {}", e);
                    return Err(e);
                }
            }
        } else {
            error!("System is already initialized");
            return Err(Error::new(
                ErrorKind::Other,
                "System is already initialized",
            ));
        }
        Ok(())
    }

    /// Stops the MarketMaker, if currently running.
    /// Returns true if the MarketMaker was stopped, false otherwise.
    pub fn stop_market_maker() -> bool {
        if SysState::market_maker_is_some() {
            MarketMaker::terminate();
            SysState::reset_market_maker();
            info!("Market maker stopped");
            if !SysState::update_initialized() {
                info!("System is uninitialized");
            }
            true
        } else {
            error!("Market maker is not running");
            false
        }
    }

    /// Initializes the system state in a Supplier mode.
    pub fn start_supplier_and_connect(
        mm_host: &str,
        mm_port: u16,
        name: Option<String>,
        secure_comms: bool,
    ) -> io::Result<()> {
        if SysState::supplier_is_some() {
            error!("Error starting supplier: Supplier is already running");
            return Err(Error::new(ErrorKind::Other, "Supplier is already running"));
        }
        match Supplier::new(mm_host.to_string(), mm_port, name, secure_comms) {
            Ok(supplier) => {
                SysState::set_supplier(supplier);
                SysState::set_initialized();
                info!("Supplier started");
            }
            Err(e) => {
                error!("Error starting supplier: {}", e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Stops the Supplier, if currently running.
    /// Returns true if the Supplier was stopped, false otherwise.
    pub fn stop_supplier(from_market_maker: bool) -> bool {
        if SysState::supplier_is_some() {
            if from_market_maker {
                Supplier::market_maker_terminate();
            } else {
                Supplier::terminate();
            }
            SysState::reset_supplier();
            info!("Supplier stopped");
            if !SysState::update_initialized() {
                info!("System is uninitialized");
            }
            true
        } else {
            warn!("Supplier is not running");
            false
        }
    }

    /// Initializes the system state in a Consumer mode.
    pub fn start_consumer_and_connect(
        mm_host: &str,
        mm_port: u16,
        name: Option<String>,
    ) -> io::Result<()> {
        if SysState::consumer_is_some() {
            error!("Error starting consumer: Consumer is already running");
            return Err(Error::new(ErrorKind::Other, "Consumer is already running"));
        }
        match Consumer::new(mm_host.to_string(), mm_port, name) {
            Ok(consumer) => {
                SysState::set_consumer(consumer);
                SysState::set_initialized();
                info!("Consumer started");
            }
            Err(e) => {
                error!("Error starting consumer: {}", e);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Stops the Consumer, if currently running.
    /// Returns true if the Consumer was stopped, false otherwise.
    pub fn stop_consumer(from_market_maker: bool) -> bool {
        if SysState::consumer_is_some() {
            if from_market_maker {
                Consumer::market_maker_terminate();
            } else {
                Consumer::terminate();
            }
            SysState::reset_consumer();
            info!("Consumer stopped");
            if !SysState::update_initialized() {
                info!("System is uninitialized");
            }
            true
        } else {
            warn!("Consumer is not running");
            false
        }
    }

    fn server_shutdown() {
        info!("Shutting down system state server");
        System::stop_market_maker();
        System::stop_supplier(false);
        System::stop_consumer(false);
        SysState::stop_system();
        SysState::reset_state();
    }

    fn check_system() -> (SupplierCheck, ConsumerCheck) {
        let adb_version = adb_utils::get_adb_version().unwrap_or_else(|e| {
            error!("Error getting adb version: {}", e);
            AdbVersionInfo::default()
        });
        let scrcpy_version = adb_utils::get_scrcpy_version().unwrap_or_else(|e| {
            error!("Error getting scrcpy version: {}", e);
            ScrcpyVersionInfo::default()
        });
        let consumer_info = ConsumerVerInfo {
            adb_info: adb_version.clone(),
            scrcpy_info: scrcpy_version,
        };
        let supplier_check = adb_version.into();
        let consumer_check = consumer_info.into();
        (supplier_check, consumer_check)
    }

    fn process_command(command: String, peer_addr: SocketAddr, peer_id: Arc<Key>) -> String {
        debug!(
            "Processing command: {}\tfrom peer: {}",
            command,
            base64::encode(peer_id.as_ref())
        );

        let request = serde_json::from_str::<Request>(&command);
        if request.is_err() {
            return serde_json::to_string(&SysStateResponse::InvalidRequest { request: command })
                .unwrap();
        }

        let request = request.unwrap();

        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.

        let is_supplier_mm =
            || SysState::supplier_is_some() && SupplierState::verify_market_maker(&peer_id);
        let is_consumer_mm =
            || SysState::consumer_is_some() && ConsumerState::verify_market_maker(&peer_id);

        match request {
            Request::System(SysStateRequest::SupplierMarketMakerTerminating)
                if is_supplier_mm() =>
            {
                thread::spawn(|| System::stop_supplier(true));
                serde_json::to_string(&SysStateResponse::TerminationAcknowledged).unwrap()
            }
            Request::System(SysStateRequest::ConsumerMarketMakerTerminating)
                if is_consumer_mm() =>
            {
                thread::spawn(|| System::stop_consumer(true));
                serde_json::to_string(&SysStateResponse::TerminationAcknowledged).unwrap()
            }
            Request::System(request) => System::process_request(request, peer_addr),
            Request::MarketMaker(request) if SysState::market_maker_is_some() => {
                MarketMaker::process_request(request, peer_addr, peer_id)
            }
            Request::Supplier(request) if SysState::supplier_is_some() => {
                Supplier::process_request(request, peer_addr, peer_id)
            }
            Request::Consumer(request) if SysState::consumer_is_some() => {
                Consumer::process_request(request, peer_addr, peer_id)
            }
            _ => serde_json::to_string(&SysStateResponse::RequestNotAllowed).unwrap(),
        }
    }

    fn process_request(request: SysStateRequest, peer_addr: SocketAddr) -> String {
        // Only requests from localhost client are allowed.
        if !(peer_addr.ip().is_loopback()) {
            return serde_json::to_string(&SysStateResponse::RequestNotAllowed).unwrap();
        }
        match request {
            SysStateRequest::GetState => {
                let state = SysState::get_min_state();
                serde_json::to_string(&SysStateResponse::CurrentSysState { state }).unwrap()
            }
            SysStateRequest::GetPeerId => {
                let pub_key = SystemKeypair::get_public_key();
                if pub_key.is_none() {
                    return serde_json::to_string(&SysStateResponse::GetPeerIdFailure).unwrap();
                }
                serde_json::to_string(&SysStateResponse::PeerId {
                    peer_id: base64::encode(pub_key.unwrap()),
                })
                .unwrap()
            }
            SysStateRequest::SystemCheck => {
                let (supplier_check, consumer_check) = System::check_system();
                serde_json::to_string(&SysStateResponse::SystemCheck {
                    supplier_check,
                    consumer_check,
                })
                .unwrap()
            }
            SysStateRequest::SetAdbPath { adb_path } => {
                let adb_path = PathBuf::from(adb_path);
                let result = adb_utils::set_adb_path(adb_path);
                if result.is_err() {
                    return serde_json::to_string(&SysStateResponse::SetAdbPathFailure {
                        reason: result.err().unwrap().to_string(),
                    })
                    .unwrap();
                }
                serde_json::to_string(&SysStateResponse::SetAdbPathSuccess).unwrap()
            }
            SysStateRequest::SetScrcpyPath { scrcpy_path } => {
                let scrcpy_path = PathBuf::from(scrcpy_path);
                let result = adb_utils::set_scrcpy_path(scrcpy_path);
                if result.is_err() {
                    return serde_json::to_string(&SysStateResponse::SetScrcpyPathFailure {
                        reason: result.err().unwrap().to_string(),
                    })
                    .unwrap();
                }
                serde_json::to_string(&SysStateResponse::SetScrcpyPathSuccess).unwrap()
            }
            SysStateRequest::Shutdown => {
                System::server_shutdown();
                serde_json::to_string(&SysStateResponse::ShutDownSuccess).unwrap()
            }
            SysStateRequest::StartMarketMaker => match System::start_market_maker() {
                Ok(_) => serde_json::to_string(&SysStateResponse::StartMarketMakerSuccess).unwrap(),
                Err(e) => serde_json::to_string(&SysStateResponse::StartMarketMakerFailed {
                    reason: e.to_string(),
                })
                .unwrap(),
            },
            SysStateRequest::StopMarketMaker => {
                if System::stop_market_maker() {
                    serde_json::to_string(&SysStateResponse::StopMarketMakerSuccess).unwrap()
                } else {
                    serde_json::to_string(&SysStateResponse::StopMarketMakerFailed).unwrap()
                }
            }
            SysStateRequest::StartSupplier {
                mm_host,
                mm_port,
                name,
                secure_comms,
            } => match System::start_supplier_and_connect(&mm_host, mm_port, name, secure_comms) {
                Ok(_) => serde_json::to_string(&SysStateResponse::StartSupplierSuccess).unwrap(),
                Err(e) => serde_json::to_string(&SysStateResponse::StartSupplierFailed {
                    reason: e.to_string(),
                })
                .unwrap(),
            },
            SysStateRequest::StopSupplier => {
                if System::stop_supplier(false) {
                    serde_json::to_string(&SysStateResponse::StopSupplierSuccess).unwrap()
                } else {
                    serde_json::to_string(&SysStateResponse::StopSupplierFailed).unwrap()
                }
            }
            SysStateRequest::StartConsumer {
                mm_host,
                mm_port,
                name,
            } => match System::start_consumer_and_connect(&mm_host, mm_port, name) {
                Ok(_) => serde_json::to_string(&SysStateResponse::StartConsumerSuccess).unwrap(),
                Err(e) => serde_json::to_string(&SysStateResponse::StartConsumerFailed {
                    reason: e.to_string(),
                })
                .unwrap(),
            },
            SysStateRequest::StopConsumer => {
                if System::stop_consumer(false) {
                    serde_json::to_string(&SysStateResponse::StopConsumerSuccess).unwrap()
                } else {
                    serde_json::to_string(&SysStateResponse::StopConsumerFailed).unwrap()
                }
            }
            _ => serde_json::to_string(&SysStateResponse::RequestNotAllowed).unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct MarketMakerSpec;

/// Information related to a Supplier on the network.
/// This information is exchanged with the MarketMaker.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SupplierSpec {
    /// The name of the Supplier on the network.
    pub name: String,
    /// The IP address of the Supplier on the network.
    pub bind_host: String,
    /// The port of the Supplier on the network.
    pub bind_port: u16,
    /// List of Devices supplied by the Supplier.
    pub devices: Vec<DeviceSpec>,
    /// Version info of the Supplier.
    ver_info: SupplierCheck,
    /// Public key of the Supplier.
    pub pub_key: String,
    /// Whether the Supplier forces secure communication for devices.
    pub secure_comms: bool,
}

impl Default for SupplierSpec {
    fn default() -> SupplierSpec {
        SupplierSpec {
            name: String::new(),
            bind_host: String::new(),
            bind_port: SysStateDefaultConfig::BIND_PORT,
            devices: Vec::new(),
            ver_info: SupplierCheck::default(),
            pub_key: SystemKeypair::get_public_key().map_or(String::new(), base64::encode),
            secure_comms: false,
        }
    }
}

impl Display for SupplierSpec {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            r"SupplierSpec:
    name: {}   bind_host: {}   bind_port: {}
    
    devices: {:#?}
    
    ver_info: {}",
            self.name, self.bind_host, self.bind_port, self.devices, self.ver_info
        )
    }
}

/// Information related to a Consumer on the network.
/// This information is exchanged with the MarketMaker.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsumerSpec {
    /// The name of the Consumer on the network.
    pub name: String,
    /// The IP address of the Consumer on the network.
    pub bind_host: String,
    /// The port of the Consumer on the network.
    pub bind_port: u16,
    /// Version info of the Consumer.
    ver_info: ConsumerCheck,
    /// Public key of the Consumer.
    pub pub_key: String,
}

impl Default for ConsumerSpec {
    fn default() -> ConsumerSpec {
        ConsumerSpec {
            name: String::new(),
            bind_host: String::new(),
            bind_port: SysStateDefaultConfig::BIND_PORT,
            ver_info: ConsumerCheck::default(),
            pub_key: SystemKeypair::get_public_key().map_or(String::new(), base64::encode),
        }
    }
}

impl Display for ConsumerSpec {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            r"ConsumerSpec:
    name: {}   bind_host: {}   bind_port: {}
    
    ver_info: {}",
            self.name, self.bind_host, self.bind_port, self.ver_info
        )
    }
}

/// Information related to a Device on the network.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct DeviceSpec {
    /// Device ID of the Device on the network.
    pub device_id: String,
    /// Android Serial of the device.
    pub android_serial: String,
    /// Details of the device.
    /// Contains device name, brand and model.
    pub device_details: String,
    /// Network ID of the Supplier for the device.
    available_at: String,
    /// Name of the Supplier for the device.
    available_at_name: String,
    /// IP address of the Supplier for the device.
    available_at_host: String,
    /// Port of the Supplier where the device is available.
    pub available_at_port: u16,
    /// Network ID of the Consumer for the device.
    used_by: String,
    /// Name of the Consumer for the device.
    used_by_name: String,
    // IP address of the Consumer for the device.
    used_by_host: String,
    /// Port of the Consumer where the device is used.
    pub used_by_port: u16,
    /// Whether the device uses secure tunnels for communication.
    pub secure_comms: bool,
}

impl Display for DeviceSpec {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            r"device_id: {}   android_serial: {}   {}",
            self.device_id, self.android_serial, self.device_details
        )
    }
}

/// Filters available to apply while searching for devices.
/// Actual filter used is a vector of this enum. See [`DeviceFilterVec`] for more details.
#[derive(Serialize, Deserialize, Debug)]
pub enum DeviceFilter {
    // Filter only available devices (or only reserved devices).
    IsAvailable(bool),
    // Device ID(s) to filter.
    DeviceIds(HashSet<String>),
    // Device names to filter.
    DeviceNames(HashSet<String>),
    // Device models to filter.
    DeviceModels(HashSet<String>),
    // Filter devices by supplier id.
    SupplierIds(HashSet<String>),
    // Filter devices by supplier name.
    SupplierNames(HashSet<String>),
    // Filter devices by supplier host.
    SupplierHosts(HashSet<String>),
    // Filter devices by consumer id.
    ConsumerIds(HashSet<String>),
    // Filter devices by consumer name.
    ConsumerNames(HashSet<String>),
    // Filter devices by consumer host.
    ConsumerHosts(HashSet<String>),
}

impl Display for DeviceFilter {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Self::IsAvailable(is_available) => {
                if *is_available {
                    write!(f, "available")
                } else {
                    write!(f, "reserved")
                }
            }
            Self::DeviceIds(device_ids) => write!(f, "device_ids: {:?}", device_ids),
            Self::DeviceNames(device_names) => write!(f, "device_names: {:?}", device_names),
            Self::DeviceModels(device_models) => write!(f, "device_models: {:?}", device_models),
            Self::SupplierIds(supplier_ids) => write!(f, "supplier_ids: {:?}", supplier_ids),
            Self::SupplierNames(supplier_names) => {
                write!(f, "supplier_names: {:?}", supplier_names)
            }
            Self::SupplierHosts(supplier_hosts) => {
                write!(f, "supplier_hosts: {:?}", supplier_hosts)
            }
            Self::ConsumerIds(consumer_ids) => write!(f, "consumer_ids: {:?}", consumer_ids),
            Self::ConsumerNames(consumer_names) => {
                write!(f, "consumer_names: {:?}", consumer_names)
            }
            Self::ConsumerHosts(consumer_hosts) => {
                write!(f, "consumer_hosts: {:?}", consumer_hosts)
            }
        }
    }
}

impl DeviceFilter {
    fn filter(&self, device: &DeviceSpec) -> bool {
        match self {
            Self::IsAvailable(is_available) => *is_available == device.used_by.is_empty(),
            Self::DeviceIds(device_ids) => device_ids.contains(&device.device_id),
            Self::DeviceNames(device_names) => {
                let device_name = DeviceInfo::from(device.device_details.clone()).name;
                device_names.contains(&device_name)
            }
            Self::DeviceModels(device_models) => {
                let device_model = DeviceInfo::from(device.device_details.clone()).model;
                device_models.contains(&device_model)
            }
            Self::SupplierIds(supplier_ids) => supplier_ids.contains(&device.available_at),
            Self::SupplierNames(supplier_names) => {
                supplier_names.contains(&device.available_at_name)
            }
            Self::SupplierHosts(supplier_hosts) => {
                supplier_hosts.contains(&device.available_at_host)
            }
            Self::ConsumerIds(consumer_ids) => consumer_ids.contains(&device.used_by),
            Self::ConsumerNames(consumer_names) => consumer_names.contains(&device.used_by_name),
            Self::ConsumerHosts(consumer_hosts) => consumer_hosts.contains(&device.used_by_host),
        }
    }
}

/// A filter composed of one or more [`DeviceFilter`] used to
/// filter devices on the network. Useful for searching for
/// devices on the network that satisfy certain properties.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DeviceFilterVec {
    pub filters: Vec<DeviceFilter>,
}

impl Display for DeviceFilterVec {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut availability_str = String::new();
        let mut filter_str = String::new();

        for filter in self.filters.iter() {
            match filter {
                DeviceFilter::IsAvailable(is_available) => {
                    availability_str = if *is_available {
                        "available".to_string()
                    } else {
                        "reserved".to_string()
                    }
                }
                _ => {
                    if filter_str.is_empty() {
                        writeln!(filter_str, "   with {}", filter).unwrap()
                    } else {
                        writeln!(filter_str, "   and {}", filter).unwrap()
                    }
                }
            }
        }

        write!(
            f,
            "Fetch {}devices in the network\n{}",
            availability_str, filter_str
        )
    }
}

/// Support level for `supplier` mode on the system node.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SupplierCheck {
    /// System is supported to run in Supplier mode
    Supported { ver_info: AdbVersionInfo },
    /// Supplier mode is NOT supported due to ADB version/revision conflict
    AdbNotSupported { ver_info: AdbVersionInfo },
    /// Supplier mode is NOT supported due to ADB not being found
    AdbNotFound { ver_info: AdbVersionInfo },
}

impl Default for SupplierCheck {
    fn default() -> SupplierCheck {
        SupplierCheck::AdbNotFound {
            ver_info: AdbVersionInfo::default(),
        }
    }
}

impl Display for SupplierCheck {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            SupplierCheck::Supported { .. } => write!(f, "Supported"),
            SupplierCheck::AdbNotSupported { ver_info } => {
                write!(f, "ADB not supported\n{}", ver_info)
            }
            SupplierCheck::AdbNotFound { .. } => write!(f, "ADB not found"),
        }
    }
}

impl From<AdbVersionInfo> for SupplierCheck {
    fn from(ver_info: AdbVersionInfo) -> Self {
        if ver_info.path.is_empty() {
            return SupplierCheck::AdbNotFound { ver_info };
        }
        let ver_number = ver_info
            .version
            .split('.')
            .last()
            .unwrap()
            .parse::<u8>()
            .unwrap_or(0);
        let rev_number = ver_info
            .revision
            .split('.')
            .next()
            .unwrap()
            .parse::<u8>()
            .unwrap_or(0);
        if ver_number >= MIN_ADB_VER && rev_number >= MIN_ADB_REV {
            SupplierCheck::Supported { ver_info }
        } else {
            SupplierCheck::AdbNotSupported { ver_info }
        }
    }
}

/// `ADB` and `SCRCPY` version information for the system node.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct ConsumerVerInfo {
    pub adb_info: AdbVersionInfo,
    pub scrcpy_info: ScrcpyVersionInfo,
}

impl Display for ConsumerVerInfo {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            r"Consumer version info:
    ADB Information
    ---------------

{}

    SCRCPY Information
    ------------------
{}",
            self.adb_info, self.scrcpy_info
        )
    }
}

impl ConsumerVerInfo {
    fn get() -> Self {
        let adb_info = adb_utils::get_adb_version().unwrap_or_default();
        let scrcpy_info = adb_utils::get_scrcpy_version().unwrap_or_default();
        ConsumerVerInfo {
            adb_info,
            scrcpy_info,
        }
    }
}

/// Support level for `consumer` mode on the system node.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConsumerCheck {
    /// System is supported to run in Consumer mode.
    /// Both ADB and SCRCPY are supported for the Consumer.
    FullSupport { ver_info: ConsumerVerInfo },
    /// System is supported to run in Consumer mode.
    /// Only ADB is supported for the Consumer.
    /// SCRCPY is NOT supported for the Consumer because
    /// of version conflict.
    ScrcpyNotSupported { ver_info: ConsumerVerInfo },
    /// System is supported to run in Consumer mode.
    /// Only ADB is supported for the Consumer.
    /// SCRCPY is NOT supported for the Consumer because
    /// it is not found.
    ScrcpyNotFound { ver_info: ConsumerVerInfo },
    /// System is NOT supported to run in Consumer mode.
    /// ADB is not supported for the Consumer.
    /// SCRCPY may or may not be supported.
    AdbNotSupported { ver_info: ConsumerVerInfo },
    /// System is NOT supported to run in Consumer mode.
    /// ADB is not found for the Consumer.
    /// SCRCPY may or may not be supported.
    AdbNotFound { ver_info: ConsumerVerInfo },
}

impl Default for ConsumerCheck {
    fn default() -> ConsumerCheck {
        ConsumerCheck::AdbNotFound {
            ver_info: ConsumerVerInfo::default(),
        }
    }
}

impl Display for ConsumerCheck {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            ConsumerCheck::FullSupport { ver_info } => {
                write!(f, "ADB and SCRCPY supported\n{}", ver_info)
            }
            ConsumerCheck::ScrcpyNotSupported { ver_info } => {
                write!(f, "ADB supported, SCRCPY not supported\n{}", ver_info)
            }
            ConsumerCheck::ScrcpyNotFound { ver_info } => {
                write!(f, "ADB supported, SCRCPY not found\n{}", ver_info)
            }
            ConsumerCheck::AdbNotSupported { ver_info } => {
                write!(f, "ADB not supported\n{}", ver_info)
            }
            ConsumerCheck::AdbNotFound { .. } => write!(f, "ADB not found"),
        }
    }
}

impl From<ConsumerVerInfo> for ConsumerCheck {
    fn from(ver_info: ConsumerVerInfo) -> Self {
        if ver_info.adb_info.path.is_empty() {
            return ConsumerCheck::AdbNotFound { ver_info };
        }
        if ConsumerCheck::check_adb(&ver_info.adb_info) {
            if ver_info.scrcpy_info.path.is_empty() {
                return ConsumerCheck::ScrcpyNotFound { ver_info };
            }
            if ConsumerCheck::check_scrcpy(&ver_info.scrcpy_info) {
                ConsumerCheck::FullSupport { ver_info }
            } else {
                ConsumerCheck::ScrcpyNotSupported { ver_info }
            }
        } else {
            ConsumerCheck::AdbNotSupported { ver_info }
        }
    }
}

impl ConsumerCheck {
    pub fn is_adb_supported(&self) -> bool {
        matches!(
            self,
            ConsumerCheck::FullSupport { .. }
                | ConsumerCheck::ScrcpyNotSupported { .. }
                | ConsumerCheck::ScrcpyNotFound { .. }
        )
    }

    fn check_adb(adb_info: &AdbVersionInfo) -> bool {
        let adb_ver_number = adb_info
            .version
            .split('.')
            .last()
            .unwrap()
            .parse::<u8>()
            .unwrap_or(0);
        adb_ver_number >= MIN_ADB_VER
    }

    fn check_scrcpy(scrcpy_info: &ScrcpyVersionInfo) -> bool {
        let scrcpy_ver_number = scrcpy_info
            .version
            .split('.')
            .last()
            .unwrap()
            .parse::<u8>()
            .unwrap_or(0);
        scrcpy_ver_number >= MIN_SCRCPY_VER
    }
}

struct DeviceKey {
    android_serial: String,
    android_id: String,
    model: String,
}

// Hash output size is 16 bytes.
type Blake2s16 = Blake2s<U16>;

impl DeviceKey {
    fn new(android_serial: &str, device_info: &DeviceInfo) -> Self {
        DeviceKey {
            android_serial: android_serial.to_owned(),
            android_id: device_info.android_id.clone(),
            model: device_info.model.clone(),
        }
    }

    fn get_uuid(&self) -> String {
        let mut hasher = Blake2s16::new();
        hasher.update(self.android_serial.as_bytes());
        hasher.update(self.android_id.as_bytes());
        hasher.update(self.model.as_bytes());
        let res = hasher.finalize();
        base64::encode(res)
    }
}

mod test_utils {
    use super::*;

    // Starts a dummy system server that initializes the SystemKeypair.
    #[allow(dead_code)]
    pub fn start_dummy_system_server(process_command: ProcessFn) {
        task::spawn(async move {
            let mut server = CommandServer {
                host: SysStateDefaultConfig::BIND_HOST.to_string(),
                port: SysStateDefaultConfig::BIND_PORT,
            };

            server.start(process_command).await.unwrap();
        });
    }

    #[allow(dead_code)]
    pub fn get_peer_with_key(key: &Key) -> (SocketAddr, Arc<Key>) {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        (socket_addr, Arc::new(key.clone()))
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::net::TCPClient;
    use crate::util::{test_with_logs, SysStateDefaultConfig};
    use request::{MarketMakerRequest, MarketMakerResponse, Request};
    use serial_test::serial;

    #[test]
    #[serial]
    fn init_and_stop_all_modes() {
        test_with_logs();

        assert!(!SysState::is_initialized());

        thread::spawn(|| SysState::start_system().unwrap());

        let client = TCPClient::new("localhost", SysStateDefaultConfig::BIND_PORT).unwrap();

        let data = serde_json::to_string(&Request::System(SysStateRequest::GetState)).unwrap();
        let response = client.send(&data, None).unwrap();
        let expected_response = serde_json::to_string(&SysStateResponse::CurrentSysState {
            state: SysStateMin::default(),
        })
        .unwrap();
        assert_eq!(response, expected_response);

        let data = serde_json::to_string(&Request::System(SysStateRequest::GetPeerId)).unwrap();
        let response = client.send(&data, None).unwrap();
        let pub_key = SystemKeypair::get_public_key().map_or(String::new(), base64::encode);
        let expected_response =
            serde_json::to_string(&SysStateResponse::PeerId { peer_id: pub_key }).unwrap();
        assert_eq!(response, expected_response);

        System::start_market_maker().unwrap();

        let data = serde_json::to_string(&Request::MarketMaker(MarketMakerRequest::Test)).unwrap();
        let response = client.send(&data, None).unwrap();
        let expected_response = serde_json::to_string(&MarketMakerResponse::Test).unwrap();
        assert_eq!(response, expected_response);

        System::start_supplier_and_connect(
            "localhost",
            SysStateDefaultConfig::BIND_PORT,
            None,
            false,
        )
        .unwrap();
        System::start_consumer_and_connect("localhost", SysStateDefaultConfig::BIND_PORT, None)
            .unwrap();

        assert!(SysState::is_initialized());
        assert!(SysState::market_maker_is_some());
        assert!(SysState::supplier_is_some());
        assert!(SysState::consumer_is_some());

        System::server_shutdown();

        assert!(!SysState::is_initialized());
        assert!(!SysState::market_maker_is_some());
        assert!(!SysState::supplier_is_some());
        assert!(!SysState::consumer_is_some());
    }
}
