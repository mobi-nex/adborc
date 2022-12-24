#[cfg(test)]
mod tests;

use super::*;
use crate::util::adb_utils::ScrCpyArgs;
use portpicker;
use request::{
    ConsumerRequest, ConsumerResponse, MarketMakerRequest, MarketMakerResponse, Request,
};
use std::default::Default;
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::{net::IpAddr, thread};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(super) struct Consumer;

#[derive(Debug, Default)]
pub(super) struct ConsumerState {
    // host, port of the market maker it is connected to.
    mm_host: String,
    mm_port: u16,
    // SocketAddr of the market maker it is connected to.
    mm_addr: Option<SocketAddr>,
    // HashMap of DeviceSpec, hashed by device id.
    devices: HashMap<String, DeviceSpec>,
    // HashMap of PortForwarders, hashed by device id.
    port_forwarders: HashMap<String, PortForwarder>,
    // If currently using a device, device id for the device.
    using_device: Option<String>,
    // Name of the consumer.
    name: String,
    // Public key of the MarketMaker.
    mm_pub_key: Option<Key>,
    scrcpy_args: HashSet<ScrCpyArgs>,
}

#[derive(Debug, Default)]
struct ScrCpyState {
    processes: Vec<Child>,
    portforwarders: HashMap<String, PortForwarder>,
}

impl ScrCpyState {
    #[inline(always)]
    fn add_process(process: Child) {
        let mut state = SCRCPY_STATE.lock().unwrap();
        state.processes.push(process);
    }

    #[inline(always)]
    fn kill_all() {
        let mut state = SCRCPY_STATE.lock().unwrap();
        for process in state.processes.iter_mut() {
            if let Err(e) = process.kill() {
                debug!("Failed to kill scrcpy process {}: {}", process.id(), e);
            }
        }
        state.processes.clear();
    }

    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn add_portforwarder(device_id: &str, portforwarder: PortForwarder) {
        let mut state = SCRCPY_STATE.lock().unwrap();
        let init_forwarder = state
            .portforwarders
            .insert(device_id.to_owned(), portforwarder);
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
    async fn remove_portforwarder(device_id: &str) {
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
            portforwarder.stop().await;
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct ConsumerStateMin {
    name: String,
    mm_host: String,
    mm_port: u16,
    pub devices: HashMap<String, DeviceSpec>,
    pub using_device: Option<String>,
    port_map: HashMap<String, u16>,
}

// Keeps accesses to the CONSUMER_STATE static variable contained in small functions.
// This is to prevent the need to lock the CONSUMER_STATE mutex in multiple places.
// We should not need to lock the CONSUMER_STATE mutex outside of these functions.
// Note: Eager unwraps are used here because we should never be in a situation where
// the lock is poisoned. If the lock is poisoned, then the thread should panic.
impl ConsumerState {
    // Write functions...

    #[inline(always)]
    fn reset_state() {
        let mut state = CONSUMER_STATE.lock().unwrap();
        *state = ConsumerState::default();
    }

    #[inline(always)]
    fn update_host_port_name(host: Option<String>, port: Option<u16>, name: Option<String>) {
        let mut state = CONSUMER_STATE.lock().unwrap();
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
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.mm_addr = Some(addr);
    }

    #[inline(always)]
    fn update_using_device(device_id: String) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.using_device = Some(device_id);
    }

    #[inline(always)]
    fn insert_device(device_id: String, device_spec: DeviceSpec) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.devices.insert(device_id, device_spec);
    }

    #[inline(always)]
    fn insert_port_forwarder(device_id: String, port_forwarder: PortForwarder) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.port_forwarders.insert(device_id, port_forwarder);
    }

    #[inline(always)]
    fn remove_device(device_id: &str) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.devices.remove(device_id);
        if state.using_device != Some(device_id.to_owned()) {
            return;
        }
        state.using_device = None;
    }

    #[inline(always)]
    fn remove_all_devices() {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.devices.clear();
        state.using_device = None;
    }

    #[inline(always)]
    fn set_scrcpy_defaults(args: std::slice::Iter<ScrCpyArgs>) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.scrcpy_args = HashSet::from_iter(args.cloned());
    }

    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_port_forwarder(device_id: &str) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        let portforwarder = state.port_forwarders.remove(device_id);
        drop(state);
        if let Some(mut portforwarder) = portforwarder {
            portforwarder.stop().await;
        }
    }

    // Turning off the clippy warning here because we explicitly drop
    // the lock on the state variable before calling await on the future.
    #[allow(clippy::await_holding_lock)]
    #[inline(always)]
    #[tokio::main]
    async fn remove_all_port_forwarders() {
        let mut state = CONSUMER_STATE.lock().unwrap();
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

    #[inline(always)]
    pub(super) fn set_market_maker_key(key: Key) {
        let mut state = CONSUMER_STATE.lock().unwrap();
        state.mm_pub_key = Some(key);
    }

    // Read functions...

    #[inline(always)]
    fn is_device_reserved(device_id: &str) -> bool {
        let state = CONSUMER_STATE.lock().unwrap();
        state.devices.contains_key(device_id)
    }

    #[inline(always)]
    fn is_using_some_device() -> bool {
        let state = CONSUMER_STATE.lock().unwrap();
        state.using_device.is_some()
    }

    #[inline(always)]
    fn get_using_device() -> Option<String> {
        let state = CONSUMER_STATE.lock().unwrap();
        state.using_device.clone()
    }

    #[inline(always)]
    fn get_addr() -> Option<SocketAddr> {
        let state = CONSUMER_STATE.lock().unwrap();
        state.mm_addr
    }

    #[inline(always)]
    fn get_device(device_id: &str) -> Option<DeviceSpec> {
        let state = CONSUMER_STATE.lock().unwrap();
        state.devices.get(device_id).cloned()
    }

    #[inline(always)]
    fn get_number_of_devices() -> usize {
        let state = CONSUMER_STATE.lock().unwrap();
        state.devices.len()
    }

    #[inline(always)]
    fn get_min_state() -> ConsumerStateMin {
        let state = CONSUMER_STATE.lock().unwrap();
        ConsumerStateMin {
            name: state.name.clone(),
            mm_host: state.mm_host.clone(),
            mm_port: state.mm_port,
            devices: state.devices.clone(),
            using_device: state.using_device.clone(),
            port_map: state
                .port_forwarders
                .iter()
                .map(|(device_id, forwarder)| (device_id.clone(), forwarder.src_port))
                .collect(),
        }
    }

    #[inline(always)]
    fn get_scrcpy_args() -> HashSet<ScrCpyArgs> {
        let state = CONSUMER_STATE.lock().unwrap();
        state.scrcpy_args.clone()
    }

    #[inline(always)]
    pub(super) fn verify_market_maker(key: &Key) -> bool {
        let state = CONSUMER_STATE.lock().unwrap();
        state.mm_pub_key.as_ref() == Some(key)
    }
}

impl Display for ConsumerStateMin {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current Consumer Status:
    Connected to Market Maker      : {}
    Consumer name on network       : {}
    Number of devices reserved     : {}
    Currently using device         : {}",
            self.mm_host,
            self.name,
            self.devices.len(),
            self.using_device.as_ref().unwrap_or(&"None".to_owned())
        )
    }
}

impl Display for ConsumerState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current Consumer Status:
    Connected to Market Maker      : {}
    Consumer name on network       : {}
    Number of devices reserved     : {}
    Currently using device         : {}",
            self.mm_host,
            self.name,
            self.devices.len(),
            self.using_device.as_ref().unwrap_or(&"None".to_owned())
        )
    }
}

lazy_static! {
    /// Creates a new uninitialized ConsumerState struct.
    /// This struct is used to persist the Consumer state.

    // TODO: Replace this static variable with a database.
    static ref CONSUMER_STATE: Mutex<ConsumerState> = Mutex::new(ConsumerState::default());
}

lazy_static! {
    /// Creates a new ScrCpyState struct.
    /// This struct is used to persist the ScrCpy state.
    static ref SCRCPY_STATE: Mutex<ScrCpyState> = Mutex::new(ScrCpyState::default());
}

impl Consumer {
    pub(super) fn new(mm_host: String, mm_port: u16, name: Option<String>) -> io::Result<Consumer> {
        debug!("Checking adb version...");
        let ver_info = ConsumerVerInfo::get();
        debug!("CONSUMER_VER_INFO: {:?}", ver_info);
        let ver_info = ConsumerCheck::from(ver_info);
        debug!("CONSUMER_CHECK: {:?}", ver_info);
        if ver_info.is_adb_supported() {
            debug!("ADB version is compatible.");
        } else {
            error!("ADB version is not compatible.");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "ADB version is not compatible.",
            ));
        }

        let mut consumer_spec = ConsumerSpec {
            ver_info,
            ..Default::default()
        };
        if let Some(name) = name {
            consumer_spec.name = name;
        } else {
            consumer_spec.name = hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
        }

        let client = TCPClient::new(mm_host.as_str(), mm_port)?;

        let connect_request = Request::MarketMaker(MarketMakerRequest::ConsumerConnect {
            consumer: consumer_spec,
        });
        let response = client.send_request(&connect_request, None)?;
        let response = MarketMakerResponse::from_str(&response).unwrap();
        if let MarketMakerResponse::ConsumerConnected {
            consumer: consumer_spec,
            pub_key,
        } = response
        {
            // Unwrapping is iffy here, but we can assume that the MM will always send a valid key.
            let mm_pub_key = base64::decode(&pub_key).unwrap();
            ConsumerState::update_host_port_name(
                Some(mm_host),
                Some(mm_port),
                Some(consumer_spec.name),
            );
            ConsumerState::update_addr(client.addr);
            ConsumerState::set_market_maker_key(mm_pub_key);
            Consumer::start_heartbeat_thread();
            let consumer = Consumer;
            Ok(consumer)
        } else if let MarketMakerResponse::ConsumerNotConnected { reason } = response {
            error!("Consumer not connected: {}", reason);
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
            // Stop the thread if consumer has terminated.
            if !SysState::consumer_is_some() {
                break;
            }
            let mm_addr = ConsumerState::get_addr();
            if mm_addr.is_none() {
                warn!("Market Maker address is not set. Skipping heartbeat.");
                continue;
            }
            let mm_addr = mm_addr.unwrap();
            let client = TCPClient::from(mm_addr);
            let heartbeat_request = Request::MarketMaker(MarketMakerRequest::ConsumerHeartBeat);
            let response = match client.send_request(&heartbeat_request, None) {
                Ok(response) => response,
                Err(e) => {
                    error!("Failed to send heartbeat to Market Maker: {}", e);
                    System::stop_consumer(true);
                    break;
                }
            };
            let response = MarketMakerResponse::from_str(&response).unwrap();
            if let MarketMakerResponse::HeartBeatResponse = response {
                debug!("Heartbeat sent successfully.");
            } else {
                error!("Unexpected response from Market Maker: {:?}", response);
                System::stop_consumer(true);
                break;
            }
        });
    }

    /// Handle resetting of ConsumerState.
    pub(super) fn terminate() {
        ConsumerState::remove_all_port_forwarders();
        ScrCpyState::kill_all();
        ScrCpyState::remove_all_port_forwarders();
        let mm_addr = ConsumerState::get_addr();
        if let Some(addr) = mm_addr {
            let client = TCPClient::from(addr);
            let disconnect_request = Request::MarketMaker(MarketMakerRequest::ConsumerDisconnect);
            client.send_no_wait(&disconnect_request);
        }
        ConsumerState::reset_state();
    }

    /// Handle MarketMakerTerminate message.
    /// This message is sent by the Market Maker when it is shutting down.
    pub(super) fn market_maker_terminate() {
        ConsumerState::remove_all_port_forwarders();
        ScrCpyState::kill_all();
        ScrCpyState::remove_all_port_forwarders();
        ConsumerState::reset_state();
    }

    fn reserve_device(
        device_id: String,
        device: DeviceSpec,
        peer_id: Option<String>,
        no_use: bool,
    ) -> io::Result<()> {
        // If currently not using a device, start a port forwarder for the device
        // listening on the default adb port (5037) to the remote port.
        // Otherwise, start a portforwarder at any available port.
        if ConsumerState::is_device_reserved(&device_id) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Device already reserved.",
            ));
        }

        let port = if !ConsumerState::is_using_some_device() && !no_use {
            5037
        } else {
            let maybe_port = portpicker::pick_unused_port();
            if maybe_port.is_none() {
                error!("Could not find an available port for port forwarding.");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not find an available port for port forwarding.",
                ));
            }
            maybe_port.unwrap()
        };
        // Kill any existing adb server at the port.
        adb_utils::kill_adb_server_for_port(port);
        let dst_host = device.available_at_host.clone();
        let dst_port = device.available_at_port;
        let mode = if peer_id.is_some() {
            PortForwardMode::Encrypt
        } else {
            PortForwardMode::PlainText
        };

        let mut forwarder = PortForwarder::try_new(
            port,
            &dst_host,
            dst_port,
            mode,
            peer_id.map(|id| base64::decode(&id).unwrap()),
            false,
        )?;
        forwarder.forward()?;
        if port == 5037 {
            ConsumerState::update_using_device(device_id.clone());
        }
        let mut device = device;
        device.used_by_port = port;
        ConsumerState::insert_device(device_id.clone(), device);
        ConsumerState::insert_port_forwarder(device_id, forwarder);
        Consumer::update_devices();
        Ok(())
    }

    fn use_device(device_id: &str) -> io::Result<()> {
        if !ConsumerState::is_device_reserved(device_id) {
            return Err(io::Error::new(io::ErrorKind::Other, "Device not reserved."));
        }
        let device = ConsumerState::get_device(device_id);
        if device.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Fatal: Error fetching the required device.",
            ));
        }
        let mut device = device.unwrap();
        if device.used_by_port == 5037 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Already a default device.",
            ));
        }

        // Check if any other device is currently in use.
        let device_in_use = ConsumerState::get_using_device();
        if let Some(device_in_use_id) = device_in_use {
            let device_in_use = ConsumerState::get_device(&device_in_use_id);
            if device_in_use.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Fatal: Error fetching the device in use.",
                ));
            }
            let mut device_in_use = device_in_use.unwrap();

            let port = portpicker::pick_unused_port();
            if port.is_none() {
                error!("Could not find an available port for port forwarding.");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not find an available port for port forwarding.",
                ));
            }
            let port = port.unwrap();
            let mode = if device_in_use.secure_comms {
                PortForwardMode::Encrypt
            } else {
                PortForwardMode::PlainText
            };
            let peer_key = if mode == PortForwardMode::Encrypt {
                Some(base64::decode(&device.available_at).unwrap())
            } else {
                None
            };
            let mut forwarder = PortForwarder::try_new(
                port,
                &device_in_use.available_at_host,
                device_in_use.available_at_port,
                mode,
                peer_key,
                false,
            )?;
            forwarder.forward()?;
            // Remove the current portforwarder.
            ConsumerState::remove_port_forwarder(&device_in_use_id);
            // Insert the new portforwarder.
            ConsumerState::insert_port_forwarder(device_in_use_id.clone(), forwarder);
            // Update the device.
            device_in_use.used_by_port = port;
            ConsumerState::insert_device(device_in_use_id, device_in_use);
        }

        let port = 5037;
        let mode = if device.secure_comms {
            PortForwardMode::Encrypt
        } else {
            PortForwardMode::PlainText
        };

        let peer_key = if mode == PortForwardMode::Encrypt {
            Some(base64::decode(&device.available_at).unwrap())
        } else {
            None
        };
        let mut forwarder = PortForwarder::try_new(
            port,
            &device.available_at_host,
            device.available_at_port,
            mode,
            peer_key,
            false,
        )?;
        forwarder.forward()?;
        // Remove the current portforwarder.
        ConsumerState::remove_port_forwarder(device_id);
        // Insert the new portforwarder.
        ConsumerState::insert_port_forwarder(device_id.to_string(), forwarder);
        device.used_by_port = 5037;
        ConsumerState::insert_device(device_id.to_string(), device);
        ConsumerState::update_using_device(device_id.to_string());
        Ok(())
    }

    fn start_scrcpy(device_id: &str, user_args: Vec<ScrCpyArgs>) -> io::Result<()> {
        let device = ConsumerState::get_device(device_id);
        if device.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "Device not reserved."));
        }
        let device = device.unwrap();
        let adb_port = device.used_by_port;
        let secure_comms = device.secure_comms;
        let scrcpy_port = portpicker::pick_unused_port();
        if scrcpy_port.is_none() {
            error!("Could not find an available port for scrcpy.");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Could not find an available port for scrcpy.",
            ));
        }
        let scrcpy_port = scrcpy_port.unwrap();
        let consumer_same_as_supplier = device.used_by == device.available_at;
        // If the device requires a secure connection, ask the marketmaker to establish
        // a secure connection from supplier's side.
        // This is not required if the consumer and supplier are the same.
        if !consumer_same_as_supplier {
            let portforwarder = Consumer::request_scrcpy_tunnel(
                device_id,
                &device.available_at,
                scrcpy_port,
                secure_comms,
            )?;
            ScrCpyState::add_portforwarder(device_id, portforwarder);
        }
        let mut scrcpy_defaults = ConsumerState::get_scrcpy_args();
        for arg in user_args {
            // Remove the default arg if it is being overridden by the user.
            scrcpy_defaults.replace(arg);
        }
        let scrcpy_args = scrcpy_defaults.into_iter().collect();
        let mut child = adb_utils::start_scrcpy(adb_port, scrcpy_port, scrcpy_args)?;
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let line = line.unwrap();
                debug!("SCRCPY: {}", line);
                if line.contains("INFO: Initial texture: ") {
                    // The scrcpy server has started.
                    break;
                }
                if line.contains("ERROR: ") {
                    // The scrcpy server has failed to start.
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Scrcpy server failed to start: {}", line),
                    ));
                }
            }
            ScrCpyState::add_process(child);
        }

        Ok(())
    }

    fn request_scrcpy_tunnel(
        device_id: &str,
        supplier_id: &str,
        scrcpy_port: u16,
        secure_comms: bool,
    ) -> io::Result<PortForwarder> {
        debug!("Requesting scrcpy tunnel from supplier.");
        let port = portpicker::pick_unused_port();
        if port.is_none() {
            error!("Could not find an available port for port forwarding.");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Could not find an available port for port forwarding.",
            ));
        }
        let port = port.unwrap();
        let portforwarder = if secure_comms {
            // Start Portforwarder in Decrypt mode.
            debug!("Starting scrcpy tunnel in Decrypt mode.");
            let peer_key = base64::decode(supplier_id);
            if peer_key.is_err() {
                error!("Could not decode peer key.");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Could not decode peer key.",
                ));
            }
            let peer_key = Some(peer_key.unwrap());
            let mut portforwarder = PortForwarder::try_new(
                port,
                "127.0.0.1",
                scrcpy_port,
                PortForwardMode::Decrypt,
                peer_key,
                false,
            )?;
            portforwarder.forward()?;
            portforwarder
        } else {
            // Start Portforwarder in PlainText mode.
            debug!("Starting scrcpy tunnel in PlainText mode listening on all interfaces.");
            let mut portforwarder = PortForwarder::try_new(
                port,
                "127.0.0.1",
                scrcpy_port,
                PortForwardMode::PlainTextAll,
                None,
                false,
            )?;
            portforwarder.forward()?;
            portforwarder
        };
        let request = Request::MarketMaker(MarketMakerRequest::StartScrcpyTunnel {
            device_id: device_id.to_string(),
            supplier_id: supplier_id.to_string(),
            port,
            scrcpy_port,
        });
        let mm_addr = ConsumerState::get_addr();
        if mm_addr.is_none() {
            error!("Could not get marketmaker address.");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Could not get marketmaker address.",
            ));
        }
        let mm_addr = mm_addr.unwrap();
        let client = TCPClient::from(mm_addr);
        let response = client.send_request(&request, None)?;
        let response = MarketMakerResponse::from_str(&response).map_err(|e| {
            error!("Error parsing response from Market Maker: {}", e);
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        match response {
            MarketMakerResponse::ScrcpyTunnelSuccess => Ok(portforwarder),
            MarketMakerResponse::ScrcpyTunnelFailure { reason } => {
                error!("Error starting scrcpy tunnel: {}", reason);
                Err(io::Error::new(io::ErrorKind::Other, reason))
            }
            _ => {
                error!("Unexpected response from Market Maker: {:?}", response);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Unexpected response from Market Maker: {:?}", response),
                ))
            }
        }
    }

    // TODO: Update the MarketMaker with the DeviceSpec for currently reserved devices.
    fn update_devices() {}

    pub(super) fn process_request(
        request: ConsumerRequest,
        peer_addr: SocketAddr,
        peer_id: Arc<Key>,
    ) -> String {
        debug!(
            "Processing request to Consumer: {:?} \tfrom :{}",
            request,
            base64::encode(peer_id.as_ref())
        );
        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.
        let is_market_maker = || ConsumerState::verify_market_maker(&peer_id);
        match request {
            // Client requests.
            ConsumerRequest::Test => ConsumerResponse::Test.to_json(),
            ConsumerRequest::Status if peer_addr.ip().is_loopback() => {
                let state = ConsumerState::get_min_state();
                ConsumerResponse::Status { state }.to_json()
            }
            ConsumerRequest::GetAvailableDevices if peer_addr.ip().is_loopback() => {
                // Get available devices from the market maker.
                let data = Request::MarketMaker(MarketMakerRequest::GetAvailableDevices);
                let mm_addr = ConsumerState::get_addr();

                if mm_addr.is_none() {
                    error!("Could not get marketmaker address.");
                    return ConsumerResponse::ErrorGettingDevices {
                        reason: "Could not get marketmaker address.".to_string(),
                    }
                    .to_json();
                }
                let mm_addr = mm_addr.unwrap();
                let client = TCPClient::from(mm_addr);
                let response = client.send_request(&data, None);
                if response.is_err() {
                    return ConsumerResponse::ErrorGettingDevices {
                        reason: format!(
                            "Could not get available devices from Market Maker: {}",
                            response.err().unwrap()
                        ),
                    }
                    .to_json();
                }
                let response = response.unwrap();
                let response = MarketMakerResponse::from_str(&response).unwrap();
                match response {
                    MarketMakerResponse::AvailableDevices { devices } => {
                        ConsumerResponse::AvailableDevices { devices }.to_json()
                    }
                    MarketMakerResponse::ErrorGettingDevices { reason } => {
                        ConsumerResponse::ErrorGettingDevices { reason }.to_json()
                    }
                    _ => ConsumerResponse::InvalidRequest {
                        request: response.to_json(),
                    }
                    .to_json(),
                }
            }
            ConsumerRequest::GetDevicesByFilter { filter_vec } if peer_addr.ip().is_loopback() => {
                // Get available devices from the market maker.
                let data =
                    Request::MarketMaker(MarketMakerRequest::GetDevicesByFilter { filter_vec });
                let mm_addr = ConsumerState::get_addr();

                if mm_addr.is_none() {
                    error!("Could not get marketmaker address.");
                    return ConsumerResponse::ErrorGettingDevices {
                        reason: "Could not get marketmaker address.".to_string(),
                    }
                    .to_json();
                }
                let mm_addr = mm_addr.unwrap();
                let client = TCPClient::from(mm_addr);
                let response = client.send_request(&data, None);
                if response.is_err() {
                    return ConsumerResponse::ErrorGettingDevices {
                        reason: format!(
                            "Could not get available devices from Market Maker: {}",
                            response.err().unwrap()
                        ),
                    }
                    .to_json();
                }
                let response = response.unwrap();
                let response = MarketMakerResponse::from_str(&response).unwrap();
                match response {
                    MarketMakerResponse::DevicesByFilter {
                        devices,
                        filter_vec,
                    } => ConsumerResponse::DevicesByFilter {
                        devices,
                        filter_vec,
                    }
                    .to_json(),
                    MarketMakerResponse::ErrorGettingDevices { reason } => {
                        ConsumerResponse::ErrorGettingDevices { reason }.to_json()
                    }
                    _ => ConsumerResponse::InvalidRequest {
                        request: response.to_json(),
                    }
                    .to_json(),
                }
            }
            ConsumerRequest::ReserveDevice { device_id, no_use }
                if peer_addr.ip().is_loopback() =>
            {
                // Reserve a device from the market maker.
                let data = Request::MarketMaker(MarketMakerRequest::ReserveDevice {
                    device_id: device_id.clone(),
                });
                let mm_addr = ConsumerState::get_addr();
                if mm_addr.is_none() {
                    error!("Could not get marketmaker address.");
                    return ConsumerResponse::DeviceNotReserved {
                        reason: "Could not get marketmaker address.".to_string(),
                    }
                    .to_json();
                }
                let mm_addr = mm_addr.unwrap();
                let client = TCPClient::from(mm_addr);
                let response = client.send_request(&data, None);
                if response.is_err() {
                    return ConsumerResponse::DeviceNotReserved {
                        reason: format!(
                            "Could not reserve device from Market Maker: {}",
                            response.err().unwrap()
                        ),
                    }
                    .to_json();
                }
                let response = response.unwrap();
                let response = MarketMakerResponse::from_str(&response).unwrap();
                match response {
                    MarketMakerResponse::DeviceReserved {
                        mut device,
                        peer_id,
                    } => {
                        // This unwrap seems Ok for now because the device is reserved from the Market Maker,
                        // and the Market Maker would have checked/updated the device spec.
                        let available_at_host = device.available_at_host.parse::<IpAddr>().unwrap();

                        // If available_at_host is a loopback address, replace it with the address of the marketmaker.
                        if available_at_host.is_loopback() {
                            device.available_at_host = client.addr.ip().to_string();
                        }
                        // Create a port forwarder for the device.
                        let device_clone = device.clone();
                        if let Err(e) = Consumer::reserve_device(
                            device_id.clone(),
                            device_clone,
                            peer_id,
                            no_use,
                        ) {
                            // Failed to reserve device. Inform the market maker to release the device.
                            let data = Request::MarketMaker(MarketMakerRequest::ReleaseDevice {
                                device_id,
                            });

                            client.send_no_wait(&data);
                            // Return error back to client.
                            ConsumerResponse::DeviceNotReserved {
                                reason: format!("Could not reserve device: {}", e),
                            }
                            .to_json()
                        } else {
                            ConsumerResponse::DeviceReserved { device }.to_json()
                        }
                    }
                    MarketMakerResponse::DeviceNotReserved { reason } => {
                        ConsumerResponse::DeviceNotReserved { reason }.to_json()
                    }
                    _ => ConsumerResponse::InvalidRequest {
                        request: response.to_json(),
                    }
                    .to_json(),
                }
            }
            ConsumerRequest::ReleaseDevice { device_id } if peer_addr.ip().is_loopback() => {
                if !ConsumerState::is_device_reserved(&device_id) {
                    return ConsumerResponse::DeviceNotReleased {
                        reason: "Cannot release a device that is not reserved.".to_string(),
                    }
                    .to_json();
                }
                // Send release request to the marketmaker device from the market maker.
                let data = Request::MarketMaker(MarketMakerRequest::ReleaseDevice {
                    device_id: device_id.clone(),
                });
                let mm_addr = ConsumerState::get_addr();
                if mm_addr.is_none() {
                    error!("Could not get marketmaker address.");
                    return ConsumerResponse::DeviceNotReleased {
                        reason: "Could not get marketmaker address.".to_string(),
                    }
                    .to_json();
                }
                let mm_addr = mm_addr.unwrap();
                let client = TCPClient::from(mm_addr);

                let response = client.send_request(&data, None);
                if response.is_err() {
                    return ConsumerResponse::DeviceNotReleased {
                        reason: format!(
                            "Could not release device from Market Maker: {}",
                            response.err().unwrap()
                        ),
                    }
                    .to_json();
                }
                let response = response.unwrap();
                let response = MarketMakerResponse::from_str(&response).unwrap();
                match response {
                    MarketMakerResponse::DeviceReleased => {
                        // Remove the port forwarder for the device.
                        ConsumerState::remove_port_forwarder(&device_id);
                        ConsumerState::remove_device(&device_id);
                        ScrCpyState::remove_portforwarder(&device_id);
                        // Return the response.
                        ConsumerResponse::DeviceReleased { device_id }.to_json()
                    }
                    MarketMakerResponse::DeviceNotReleased { reason } => {
                        ConsumerResponse::DeviceNotReleased { reason }.to_json()
                    }
                    _ => ConsumerResponse::DeviceNotReleased {
                        reason: "Unknown operation".to_string(),
                    }
                    .to_json(),
                }
            }

            ConsumerRequest::ReleaseAllDevices if peer_addr.ip().is_loopback() => {
                // Send release request to the marketmaker.
                let num_devices = ConsumerState::get_number_of_devices();
                if num_devices == 0 {
                    return ConsumerResponse::AllDeviceReleaseFailure {
                        reason: "No devices reserved.".to_string(),
                    }
                    .to_json();
                }
                let data = Request::MarketMaker(MarketMakerRequest::ReleaseAllDevices);
                let mm_addr = ConsumerState::get_addr();
                if mm_addr.is_none() {
                    error!("Could not get marketmaker address.");
                    return ConsumerResponse::AllDeviceReleaseFailure {
                        reason: "Could not get marketmaker address.".to_string(),
                    }
                    .to_json();
                }
                let mm_addr = mm_addr.unwrap();
                let client = TCPClient::from(mm_addr);

                let response = client.send_request(&data, None);
                if response.is_err() {
                    return ConsumerResponse::AllDeviceReleaseFailure {
                        reason: format!(
                            "Could not release device from Market Maker: {}",
                            response.err().unwrap()
                        ),
                    }
                    .to_json();
                }
                let response = response.unwrap();
                let response = MarketMakerResponse::from_str(&response).unwrap();
                match response {
                    MarketMakerResponse::AllDeviceReleaseSuccess => {
                        // Remove the port forwarder for the device.
                        ConsumerState::remove_all_port_forwarders();
                        ConsumerState::remove_all_devices();
                        ScrCpyState::kill_all();
                        ScrCpyState::remove_all_port_forwarders();
                        // Return the response.
                        ConsumerResponse::AllDeviceReleaseSuccess.to_json()
                    }
                    MarketMakerResponse::AllDeviceReleaseFailure { reason } => {
                        ConsumerResponse::AllDeviceReleaseFailure { reason }.to_json()
                    }
                    _ => ConsumerResponse::AllDeviceReleaseFailure {
                        reason: "Unknown operation".to_string(),
                    }
                    .to_json(),
                }
            }
            ConsumerRequest::UseDevice { device_id } => {
                let result = Consumer::use_device(&device_id);
                if let Err(e) = result {
                    ConsumerResponse::UseDeviceFailure {
                        reason: format!("{}", e),
                    }
                    .to_json()
                } else {
                    ConsumerResponse::UseDeviceSuccess { device_id }.to_json()
                }
            }

            ConsumerRequest::StartScrCpy {
                device_id,
                scrcpy_args,
            } if peer_addr.ip().is_loopback() => {
                if !ConsumerState::is_device_reserved(&device_id) {
                    return ConsumerResponse::StartScrCpyFailure {
                        reason: "Cannot start scrcpy for a device that is not reserved."
                            .to_string(),
                    }
                    .to_json();
                }
                if let Err(e) = Consumer::start_scrcpy(&device_id, scrcpy_args) {
                    ConsumerResponse::StartScrCpyFailure {
                        reason: format!("Could not start scrcpy: {}", e),
                    }
                    .to_json()
                } else {
                    ConsumerResponse::StartScrCpySuccess { device_id }.to_json()
                }
            }

            ConsumerRequest::SetScrCpyDefaults { scrcpy_args } if peer_addr.ip().is_loopback() => {
                ConsumerState::set_scrcpy_defaults(scrcpy_args.iter());

                ConsumerResponse::ScrCpyDefaultsSet { args: scrcpy_args }.to_json()
            }

            ConsumerRequest::GetScrCpyDefaults if peer_addr.ip().is_loopback() => {
                let args = ConsumerState::get_scrcpy_args().into_iter().collect();
                ConsumerResponse::ScrCpyDefaults { args }.to_json()
            }

            // Requests from Market Maker.
            ConsumerRequest::SupplierDisconnected { device_id } if is_market_maker() => {
                let device_id_clone = device_id.clone();
                thread::spawn(move || {
                    if ConsumerState::is_device_reserved(&device_id_clone) {
                        ConsumerState::remove_device(&device_id_clone);
                        ConsumerState::remove_port_forwarder(&device_id_clone);
                        ScrCpyState::remove_portforwarder(&device_id_clone);
                    }
                });
                ConsumerResponse::DeviceReleased { device_id }.to_json()
            }
            ConsumerRequest::MarketMakerTerminating if is_market_maker() => {
                thread::spawn(Consumer::market_maker_terminate);
                ConsumerResponse::TerminationAcknowledged.to_json()
            }

            _ => ConsumerResponse::RequestNotAllowed.to_json(),
        }
    }
}
