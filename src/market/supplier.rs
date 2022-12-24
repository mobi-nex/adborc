#[cfg(test)]
mod tests;

use super::*;
use crate::util::adb_utils;
use portpicker;
use request::{
    MarketMakerRequest, MarketMakerResponse, Request, SupplierRequest, SupplierResponse,
};
use std::default::Default;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(super) struct Supplier;

#[derive(Default)]
struct ScrCpyState {
    portforwarders: HashMap<String, PortForwarder>,
}

lazy_static! {

    // TODO: Replace this static variable with a database.
    static ref SCRCPY_STATE: Mutex<ScrCpyState> = Mutex::new(ScrCpyState::default());
}

impl ScrCpyState {
    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn add_port_forwarder(device_id: &str, portforwarder: PortForwarder) {
        let mut state = SCRCPY_STATE.lock().unwrap();
        let init_forwarder = state
            .portforwarders
            .insert(device_id.to_string(), portforwarder);
        drop(state);
        if let Some(mut portforwarder) = init_forwarder {
            debug!(
                "Stopping existing scrcpy portforwarder for device {}",
                device_id
            );
            portforwarder.stop().await;
        }
    }

    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_port_forwarder(device_id: &str) {
        let mut state = SCRCPY_STATE.lock().unwrap();
        let portforwarder = state.portforwarders.remove(device_id);
        drop(state);
        if let Some(mut portforwarder) = portforwarder {
            debug!("Stopping scrcpy portforwarder for device {}", device_id);
            portforwarder.stop().await;
        }
    }

    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_all_port_forwarders() {
        let mut state = SCRCPY_STATE.lock().unwrap();
        let portforwarders = state
            .portforwarders
            .drain()
            .map(|(_, portforwarder)| portforwarder)
            .collect::<Vec<PortForwarder>>();
        drop(state);
        for mut portforwarder in portforwarders {
            debug!("Stopping scrcpy portforwarder");
            portforwarder.stop().await;
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct SupplierState {
    // host, port of the market maker it is connected to.
    mm_host: String,
    mm_port: u16,
    // SocketAddr of the market maker it is connected to.
    mm_addr: Option<SocketAddr>,
    // HashMap of exposed port numbers and device_details, hashed by device id.
    ports: HashMap<String, (u16, String)>,
    // Name of the supplier.
    name: String,
    // Public key of the Market Maker.
    mm_pub_key: Option<Key>,
    // Using secure channel or not.
    secure_comms: bool,
    // HashMap of PortForwarders, hashed by device id.
    port_forwarders: HashMap<String, PortForwarder>,
}

impl Display for SupplierState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current Supplier Status:
    Connected to Market Maker    : {}
    Supplier name on network     : {}
    Number of devices supplied   : {}
    Currently exposed ports are  : {}",
            self.mm_host,
            self.name,
            self.ports.len(),
            self.ports
                .values()
                .map(|(x, _)| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct SupplierStateMin {
    // host, port of the market maker it is connected to.
    mm_host: String,
    mm_port: u16,
    // Name of the supplier.
    name: String,
    // Using secure channel or not.
    secure_comms: bool,
    // HashMap of exposed port numbers, hashed by device id.
    ports: HashMap<String, (u16, String)>,
}

impl Display for SupplierStateMin {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current Supplier Status:
    Connected to Market Maker    : {}
    Supplier name on network     : {}
    Number of devices supplied   : {}",
            self.mm_host,
            self.name,
            self.ports.len(),
        )
        .unwrap();
        if !self.secure_comms {
            write!(
                f,
                r"

WARNING: Not using secure channel for device communications!!
    Currently exposed ports are  : {}",
                self.ports
                    .values()
                    .map(|(x, _)| x.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            )
            .unwrap();
        }
        write!(
            f,
            r"
        
                Supplied Devices
----------------------------------------------------------------------------
{:^27}|{:^35}|{:^10}
----------------------------------------------------------------------------
{}
----------------------------------------------------------------------------",
            "Device ID",
            "Device Details",
            "Port",
            self.ports
                .iter()
                .map(|(key, (port, details))| format!(
                    "{:^27}|{:^35}|{:^10}",
                    key,
                    strip_device_details(details),
                    port
                ))
                .collect::<Vec<String>>()
                .join("\n")
        )
    }
}

// Strip device details of the form:
// Brand: <brand>   Name: <name>   Model: <model>
// to: <brand> <name> <model>
fn strip_device_details(details: &str) -> String {
    details
        .split("   ")
        .map(|x| x.split(": ").nth(1).unwrap_or(""))
        .collect::<Vec<&str>>()
        .join(" ")
}

// Keeps accesses to the SUPPLIER_STATE static variable contained in small functions.
// This is to prevent deadlocks when accessing the SUPPLIER_STATE Mutex in multiple places.
// We should not need to lock the SUPPLIER_STATE Mutex outside of these functions.
// Note: Eager unwraps are used here because we should never be in a situation where
// the lock is poisoned. If the lock is poisoned, then the thread should panic.
impl SupplierState {
    // Write functions...

    #[inline(always)]
    fn update_host_port_name(host: Option<String>, port: Option<u16>, name: Option<String>) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        if let Some(host) = host {
            state.mm_host = host;
        }
        if let Some(port) = port {
            state.mm_port = port;
        }
        if let Some(name) = name {
            state.name = name;
        }
    }

    #[inline(always)]
    fn update_addr(addr: SocketAddr) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.mm_addr = Some(addr);
    }

    #[inline(always)]
    fn reset_state() {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        *state = Default::default();
    }

    #[inline(always)]
    fn insert_port(device_id: String, port: u16, device_details: String) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.ports.insert(device_id, (port, device_details));
    }

    #[inline(always)]
    pub(super) fn set_market_maker_key(key: Key) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.mm_pub_key = Some(key);
    }

    #[inline(always)]
    fn remove_port(device_id: &str) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.ports.remove(device_id);
    }

    #[inline(always)]
    fn insert_port_forwarder(device_id: String, port_forwarder: PortForwarder) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.port_forwarders.insert(device_id, port_forwarder);
    }

    #[inline(always)]
    fn set_secure_comms(secure_comms: bool) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        state.secure_comms = secure_comms;
    }

    // Read functions...

    #[inline(always)]
    fn get_min_state() -> SupplierStateMin {
        let state = SUPPLIER_STATE.lock().unwrap();
        SupplierStateMin {
            mm_host: state.mm_host.clone(),
            mm_port: state.mm_port,
            name: state.name.clone(),
            secure_comms: state.secure_comms,
            ports: state.ports.clone(),
        }
    }

    #[inline(always)]
    fn get_name() -> String {
        let state = SUPPLIER_STATE.lock().unwrap();
        state.name.clone()
    }

    #[inline(always)]
    fn get_addr() -> Option<SocketAddr> {
        let state = SUPPLIER_STATE.lock().unwrap();
        state.mm_addr
    }

    #[inline(always)]
    fn get_ports() -> HashMap<String, (u16, String)> {
        let state = SUPPLIER_STATE.lock().unwrap();
        state.ports.clone()
    }

    #[inline(always)]
    fn get_port_of_device(device_id: &str) -> Option<u16> {
        let state = SUPPLIER_STATE.lock().unwrap();
        let port = state.ports.get(device_id).map(|x| x.0);
        port
    }

    #[inline(always)]
    fn get_secure_comms() -> bool {
        let state = SUPPLIER_STATE.lock().unwrap();
        state.secure_comms
    }

    #[inline(always)]
    pub(super) fn verify_market_maker(key: &Key) -> bool {
        let state = SUPPLIER_STATE.lock().unwrap();
        state.mm_pub_key.as_ref() == Some(key)
    }

    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_port_forwarder(device_id: &str) {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        let portforwarder = state.port_forwarders.remove(device_id);
        drop(state);
        if let Some(mut portforwarder) = portforwarder {
            portforwarder.stop().await;
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_all_port_forwarders() {
        let mut state = SUPPLIER_STATE.lock().unwrap();
        let port_forwarders = state
            .port_forwarders
            .drain()
            .map(|(_, v)| v)
            .collect::<Vec<PortForwarder>>();
        drop(state);
        for mut portforwarder in port_forwarders {
            portforwarder.stop().await;
        }
    }
}

lazy_static! {
    /// Creates a new uninitialized SupplierState struct.
    /// This struct is used to persist the Supplier state.

    // TODO: Replace this static variable with a database.
    static ref SUPPLIER_STATE: Mutex<SupplierState> = Mutex::new(SupplierState::default());
}

impl Supplier {
    pub(super) fn new(
        mm_host: String,
        mm_port: u16,
        name: Option<String>,
        secure_comms: bool,
    ) -> io::Result<Supplier> {
        debug!("Checking adb version...");
        let ver_info = adb_utils::get_adb_version()?;
        debug!("ADB_VER_INFO: {}", ver_info);
        let ver_info = SupplierCheck::from(ver_info);
        if let SupplierCheck::Supported { .. } = ver_info {
            debug!("ADB version is compatible.");
        } else {
            error!("ADB version is not compatible.");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "ADB version is not compatible.",
            ));
        }

        let mut supplier_spec = SupplierSpec {
            ver_info,
            secure_comms,
            ..Default::default()
        };

        if let Some(name) = name {
            supplier_spec.name = name;
        } else {
            supplier_spec.name = hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
        }

        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.
        let client = TCPClient::new(&mm_host, mm_port)?;
        let supply_request = Request::MarketMaker(MarketMakerRequest::SupplierConnect {
            supplier: supplier_spec,
        });
        let response = client.send_request(&supply_request, None)?;

        let response = MarketMakerResponse::from_str(&response).unwrap();
        if let MarketMakerResponse::SupplierConnected {
            supplier: supplier_spec,
            pub_key,
        } = response
        {
            // Unwrapping is iffy here, but we can assume that the MM will always send a valid key.
            let mm_pub_key = base64::decode(&pub_key).unwrap();
            SupplierState::update_host_port_name(
                Some(mm_host),
                Some(mm_port),
                Some(supplier_spec.name),
            );
            SupplierState::update_addr(client.addr);
            SupplierState::set_market_maker_key(mm_pub_key);
            SupplierState::set_secure_comms(secure_comms);
            let supplier = Supplier;
            Supplier::start_heartbeat_thread();
            Ok(supplier)
        } else if let MarketMakerResponse::SupplierNotConnected { reason } = response {
            error!("Supplier not connected: {}", reason);
            Err(io::Error::new(io::ErrorKind::Other, reason))
        } else {
            error!("Unexpected response from Market Maker: {:?}", response);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected response from Market Maker: {:?}", response),
            ))
        }
    }

    fn start_heartbeat_thread() {
        thread::spawn(|| loop {
            thread::sleep(HEARTBEAT_INTERVAL);
            // Stop the thread if supplier has terminated.
            if !SysState::supplier_is_some() {
                break;
            }
            let mm_addr = SupplierState::get_addr();

            if mm_addr.is_none() {
                warn!("Market Maker address is not set. Skipping heartbeat.");
                continue;
            }

            let mm_addr = mm_addr.unwrap();
            let client = TCPClient::from(mm_addr);
            let heartbeat_request = Request::MarketMaker(MarketMakerRequest::SupplierHeartBeat);
            let response = match client.send_request(&heartbeat_request, None) {
                Ok(response) => response,
                Err(e) => {
                    error!("Failed to send heartbeat to Market Maker: {}", e);
                    System::stop_supplier(true);
                    break;
                }
            };
            let response = MarketMakerResponse::from_str(&response).unwrap();
            if let MarketMakerResponse::HeartBeatResponse = response {
                debug!("Heartbeat sent successfully.");
            } else {
                error!("Unexpected response from Market Maker: {:?}", response);
                System::stop_supplier(true);
                break;
            }
        });
    }

    /// Handle resetting of SupplierState.
    pub(super) fn terminate() {
        SupplierState::remove_all_port_forwarders();
        ScrCpyState::remove_all_port_forwarders();
        let used_ports = SupplierState::get_ports();
        for (_, (port, _)) in used_ports {
            adb_utils::kill_adb_server_for_port(port);
        }
        let mm_addr = SupplierState::get_addr();
        if let Some(addr) = mm_addr {
            let client = TCPClient::from(addr);
            let disconnect_request = Request::MarketMaker(MarketMakerRequest::SupplierDisconnect);
            client.send_no_wait(&disconnect_request);
        }
        SupplierState::reset_state();
    }

    /// Handle MarketMakerTerminate message.
    /// This message is sent by the Market Maker when it is shutting down.
    pub(super) fn market_maker_terminate() {
        SupplierState::remove_all_port_forwarders();
        ScrCpyState::remove_all_port_forwarders();
        let used_ports = SupplierState::get_ports();
        for (_, (port, _)) in used_ports {
            adb_utils::kill_adb_server_for_port(port);
        }
        SupplierState::reset_state();
    }

    /// Supply devices to the market maker.
    fn supply_devices(
        devices: Option<Vec<String>>,
    ) -> io::Result<(Vec<DeviceSpec>, Vec<DeviceSpec>)> {
        let supply_all = devices.is_none();
        let secure_comms = SupplierState::get_secure_comms();
        let num_devices = devices.as_ref().map(|d| d.len()).unwrap_or(0);
        let port_map = adb_utils::restart_adb_server_for_devices(devices, secure_comms);
        if port_map.is_none() {
            error!("Couldn't find the device(s) specifed. Please check the device(s) is/are connected.");
            if supply_all {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Couldn't find any devices to supply.\n\nPlease check the devices are connected and detected by ADB.",
                ));
            } else if num_devices > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Couldn't find the specifed devices.\n\nPlease check the devices are connected and detected by ADB.",
                ));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Couldn't find the specifed device.\n\nPlease check the device is connected and detected by ADB.",
                ));
            }
        }
        // Generate a uuid for each device.
        let port_map = port_map.unwrap();
        let devices = port_map
            .iter()
            .map(|(device, device_info, port)| {
                // Generate a uuid for each device.
                let device_id = DeviceKey::new(device, device_info).get_uuid();
                debug!("UUID for device {} is {}", device, device_id);
                DeviceSpec {
                    device_id,
                    android_serial: device.clone(),
                    device_details: format!("{}", device_info),
                    available_at_port: *port,
                    available_at: base64::encode(SystemKeypair::get_public_key().unwrap()),
                    available_at_name: SupplierState::get_name(),
                    secure_comms,
                    ..Default::default()
                }
            })
            .collect();

        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.
        let request = Request::MarketMaker(MarketMakerRequest::SupplyDevices { devices });
        let mm_addr = SupplierState::get_addr();
        if mm_addr.is_none() {
            error!("Market Maker address is not set. Skipping supply devices.");
            // Kill the restarted adb servers.
            for (_, _, port) in port_map {
                adb_utils::kill_adb_server_for_port(port);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Market Maker address is not set. Skipping supply devices.",
            ));
        }

        let mm_addr = mm_addr.unwrap();
        let client = TCPClient::from(mm_addr);
        let response = client.send_request(&request, None);
        if response.is_err() {
            error!(
                "Failed to send SupplyDevices request to Market Maker: {}",
                response.err().unwrap()
            );
            for (_, _, port) in port_map {
                adb_utils::kill_adb_server_for_port(port);
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to send Supply request to Market Maker.",
            ));
        }
        let response = response.unwrap();
        let response = MarketMakerResponse::from_str(&response).unwrap();
        if let MarketMakerResponse::DevicesSupplied {
            supplied_devices,
            failed_devices,
        } = response
        {
            for device_spec in supplied_devices.iter() {
                SupplierState::insert_port(
                    device_spec.device_id.clone(),
                    device_spec.available_at_port,
                    device_spec.device_details.clone(),
                );
            }
            for device_spec in failed_devices.iter() {
                adb_utils::kill_adb_server_for_port(device_spec.available_at_port);
            }
            Ok((supplied_devices, failed_devices))
        } else {
            error!("Error supplying devices: {}", response);
            for (_, _, port) in port_map {
                adb_utils::kill_adb_server_for_port(port);
            }
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error supplying devices: {}", response),
            ))
        }
    }

    /// Reclaim device from the Market Maker.
    fn reclaim_device(device_id: String, force: bool) -> String {
        let request = Request::MarketMaker(MarketMakerRequest::ReclaimDevice { device_id, force });
        let mm_addr = SupplierState::get_addr();
        if mm_addr.is_none() {
            error!("Market Maker address is not set. Skipping reclaim device.");
            return MarketMakerResponse::DeviceNotReclaimed {
                reason: "Fatal: Market Maker address not set.".to_string(),
            }
            .to_json();
        }

        let mm_addr = mm_addr.unwrap();
        let client = TCPClient::from(mm_addr);
        let response = client.send_request(&request, None);
        if response.is_err() {
            error!(
                "Failed to send ReclaimDevice request to Market Maker: {}",
                response.err().unwrap()
            );
            return SupplierResponse::DeviceNotReclaimed {
                reason: "Failed to send ReclaimDevice request to Market Maker".to_string(),
            }
            .to_json();
        }
        let response = response.unwrap();
        let response = MarketMakerResponse::from_str(&response).unwrap();
        match response {
            MarketMakerResponse::DeviceReclaimed { device_id } => {
                let port = SupplierState::get_port_of_device(&device_id);
                if port.is_none() {
                    // This should not happen.
                    error!("Device {} not found in port map", device_id);
                    return SupplierResponse::DeviceNotReclaimed {
                        reason: "Device not found in port map".to_string(),
                    }
                    .to_json();
                }
                let port = port.unwrap();
                adb_utils::kill_adb_server_for_port(port);
                SupplierState::remove_port(&device_id);
                SupplierState::remove_port_forwarder(&device_id);
                ScrCpyState::remove_port_forwarder(&device_id);
                SupplierResponse::DeviceReclaimed { device_id }.to_json()
            }
            MarketMakerResponse::DeviceNotReclaimed { reason } => {
                SupplierResponse::DeviceNotReclaimed { reason }.to_json()
            }
            _ => {
                error!("Unexpected response from Market Maker: {:?}", response);
                SupplierResponse::DeviceNotReclaimed {
                    reason: format!("Unexpected response from Market Maker: {:?}", response),
                }
                .to_json()
            }
        }
    }

    // Start a PortForwarder in Decrypt mode for the given device and return the exposed port.
    fn start_forwarder(device_id: &str, port: u16, peer_id: String) -> io::Result<u16> {
        let peer_id = base64::decode(peer_id);
        if peer_id.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid peer id"));
        }
        let peer_id = peer_id.unwrap();
        let available_at_port = SupplierState::get_port_of_device(device_id);
        if available_at_port.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Device not found in port map",
            ));
        }
        let available_at_port = available_at_port.unwrap();
        if available_at_port != port {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Device port does not match port map",
            ));
        }

        let exposed_port = portpicker::pick_unused_port();
        if exposed_port.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to find an available port",
            ));
        }
        let exposed_port = exposed_port.unwrap();
        let mut forwarder = PortForwarder::try_new(
            exposed_port,
            "127.0.0.1",
            port,
            PortForwardMode::Decrypt,
            Some(peer_id),
            true,
        )?;
        forwarder.forward()?;
        SupplierState::insert_port_forwarder(device_id.to_owned(), forwarder);
        Ok(exposed_port)
    }

    // Start a scrcpy tunnel for the given device and return the exposed port.
    // The tunnel is started in PortForwardMode::Encrypt mode.
    fn start_scrcpy_tunnel(
        peer_id: &str,
        consumer_host: &str,
        port: u16,
        scrcpy_port: u16,
        device_id: &str,
    ) -> io::Result<()> {
        let peer_id = base64::decode(peer_id);
        if peer_id.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid peer id"));
        }
        let peer_id = peer_id.unwrap();

        let mm_addr = SupplierState::get_addr();
        if mm_addr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Market Maker address not set",
            ));
        }
        let mm_addr = mm_addr.unwrap().ip().to_string();
        let dst_host = if consumer_host != "127.0.0.1" {
            consumer_host
        } else {
            mm_addr.as_str()
        };
        let mut forwarder = if SupplierState::get_secure_comms() {
            debug!("Starting scrcpy tunnel in Encrypt mode");
            PortForwarder::try_new(
                scrcpy_port,
                dst_host,
                port,
                PortForwardMode::Encrypt,
                Some(peer_id),
                true,
            )
        } else {
            debug!("Starting scrcpy tunnel in PlainText mode");
            PortForwarder::try_new(
                scrcpy_port,
                dst_host,
                port,
                PortForwardMode::PlainText,
                None,
                true,
            )
        }?;
        forwarder.forward()?;
        ScrCpyState::add_port_forwarder(device_id, forwarder);
        Ok(())
    }

    pub(super) fn process_request(
        request: SupplierRequest,
        peer_addr: SocketAddr,
        peer_id: Arc<Key>,
    ) -> String {
        debug!(
            "Processing request to Supplier: {:?} \tfrom :{}",
            request,
            base64::encode(peer_id.as_ref())
        );
        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.
        let is_market_maker = || SupplierState::verify_market_maker(&peer_id);
        match request {
            SupplierRequest::Test => SupplierResponse::Test.to_json(),

            SupplierRequest::Status if peer_addr.ip().is_loopback() => {
                let state = SupplierState::get_min_state();
                SupplierResponse::Status { state }.to_json()
            }

            SupplierRequest::SupplyDevices { devices } if peer_addr.ip().is_loopback() => {
                debug!("Supplying devices: {:?}", devices);
                match Supplier::supply_devices(devices) {
                    Ok((supplied_devices, failed_devices)) => SupplierResponse::DevicesSupplied {
                        supplied_devices,
                        failed_devices,
                    }
                    .to_json(),
                    Err(e) => SupplierResponse::DeviceSupplyFailure {
                        reason: e.to_string(),
                    }
                    .to_json(),
                }
            }

            SupplierRequest::ReclaimDevice { device_id, force } if peer_addr.ip().is_loopback() => {
                debug!("Reclaiming device: {}", device_id);
                Supplier::reclaim_device(device_id, force)
            }

            SupplierRequest::MarketMakerTerminating if is_market_maker() => {
                thread::spawn(Supplier::market_maker_terminate);
                SupplierResponse::TerminationAcknowledged.to_json()
            }

            SupplierRequest::StartSecureTunnel {
                device_id,
                port,
                pub_key,
            } if is_market_maker() => {
                debug!("Starting secure tunnel for device: {}", device_id);
                let port = Supplier::start_forwarder(&device_id, port, pub_key);
                match port {
                    Ok(port) => SupplierResponse::SecureTunnelStarted { port }.to_json(),
                    Err(e) => SupplierResponse::SecureTunnelStartFailure {
                        reason: e.to_string(),
                    }
                    .to_json(),
                }
            }

            SupplierRequest::StopSecureTunnel { device_id } if is_market_maker() => {
                debug!("Stopping secure tunnel for device: {}", device_id);
                SupplierState::remove_port_forwarder(&device_id);
                ScrCpyState::remove_port_forwarder(&device_id);
                SupplierResponse::SecureTunnelStopped.to_json()
            }

            SupplierRequest::StartScrcpyTunnel {
                peer_id,
                consumer_host,
                port,
                device_id,
                scrcpy_port,
            } if is_market_maker() => {
                debug!("Starting scrcpy tunnel for device: {}", peer_id);
                let port = Supplier::start_scrcpy_tunnel(
                    &peer_id,
                    &consumer_host,
                    port,
                    scrcpy_port,
                    &device_id,
                );
                match port {
                    Ok(_) => {
                        SupplierResponse::ScrcpyTunnelSuccess.to_json()
                    }
                    Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                        SupplierResponse::ScrcpyTunnelFailure {
                            reason: "Unable to allocate the required port on Supplier side.\nPlease try again.".to_string(),
                        }.to_json()
                    }
                    Err(e) => SupplierResponse::ScrcpyTunnelFailure {
                        reason: e.to_string(),
                    }.to_json(),
                }
            }

            _ => SupplierResponse::RequestNotAllowed.to_json(),
        }
    }
}
