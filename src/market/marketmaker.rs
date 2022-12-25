#[cfg(test)]
mod tests;

use super::*;
use request::{MarketMakerRequest, MarketMakerResponse};
use std::thread;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(super) struct MarketMaker;

#[derive(Debug, Clone, Default)]
struct MarketMakerState {
    // HashMap of SupplierSpec, hashed by supplier peer_id.
    suppliers: HashMap<String, SupplierSpec>,
    // HashMap of ConsumerSpec, hashed by consumer peer_id.
    consumers: HashMap<String, ConsumerSpec>,
    // HashMap of MarketMakerSpec, hashed by address.
    market_makers: HashMap<String, MarketMakerSpec>,
    // HashMap of DeviceSpec, hashed by device id.
    devices: HashMap<String, DeviceSpec>,
    // HashMap of available DeviceSpec, hashed by device id.
    available_devices: HashMap<String, DeviceSpec>,
    // Whether the market maker uses whitelist or not.
    use_whitelists: bool,
    supplier_whitelist: HashSet<String>,
    consumer_whitelist: HashSet<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct MarketMakerMinState {
    // Number of suppliers.
    num_suppliers: usize,
    // Vector of SupplierSpec.
    suppliers: Vec<SupplierSpec>,
    // Number of consumers.
    num_consumers: usize,
    // Vector of ConsumerSpec.
    consumers: Vec<ConsumerSpec>,
    // Number of market makers.
    num_market_makers: usize,
    // HashMap of DeviceSpec, hashed by device id.
    devices: HashMap<String, DeviceSpec>,
    // HashMap of available DeviceSpec, hashed by device id.
    available_devices: HashMap<String, DeviceSpec>,
    // Whether the market maker uses whitelist or not.
    use_whitelists: bool,
    supplier_whitelist: HashSet<String>,
    consumer_whitelist: HashSet<String>,
}

#[derive(Debug, Default)]
struct HeartBeatState {
    suppliers: HashMap<String, u8>,
    consumers: HashMap<String, u8>,
    dead_suppliers: HashSet<String>,
    dead_consumers: HashSet<String>,
}

lazy_static! {
    static ref HEARTBEAT_STATE: RwLock<HeartBeatState> = RwLock::new(HeartBeatState::default());
}

impl HeartBeatState {
    #[inline(always)]
    fn reset_state() {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        state.suppliers.clear();
        state.consumers.clear();
        state.dead_suppliers.clear();
        state.dead_consumers.clear();
    }

    #[inline(always)]
    fn add_supplier(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        state.suppliers.insert(peer_id.to_string(), 1);
    }

    #[inline(always)]
    fn add_consumer(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        state.consumers.insert(peer_id.to_string(), 1);
    }

    #[inline(always)]
    fn remove_supplier(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        state.suppliers.remove(peer_id);
    }

    #[inline(always)]
    fn remove_dead_suppliers() {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        let dead_suppliers = state.dead_suppliers.drain().collect::<Vec<String>>();
        for peer_id in dead_suppliers {
            state.suppliers.remove(&peer_id);
        }
    }

    #[inline(always)]
    fn remove_consumer(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        state.consumers.remove(peer_id);
    }

    #[inline(always)]
    fn remove_dead_consumers() {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        let dead_consumers = state.dead_consumers.drain().collect::<Vec<String>>();
        for peer_id in dead_consumers {
            state.consumers.remove(&peer_id);
        }
    }

    #[inline(always)]
    fn supplier_heartbeat(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        if let Some(heartbeat) = state.suppliers.get_mut(peer_id) {
            if *heartbeat < 3 {
                *heartbeat += 1;
            }
        }
    }

    #[inline(always)]
    fn consumer_heartbeat(peer_id: &str) {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        if let Some(heartbeat) = state.consumers.get_mut(peer_id) {
            if *heartbeat < 3 {
                *heartbeat += 1;
            }
        }
    }

    #[inline(always)]
    fn decrement_heartbeats() {
        let mut state = HEARTBEAT_STATE.write().unwrap();
        let mut dead_suppliers = Vec::new();
        let mut dead_consumers = Vec::new();
        for (peer_id, heartbeat) in state.suppliers.iter_mut() {
            if *heartbeat == 0 {
                dead_suppliers.push(peer_id.to_string());
            } else {
                *heartbeat -= 1;
            }
        }
        dead_suppliers.iter().for_each(|peer_id| {
            state.dead_suppliers.insert(peer_id.to_string());
        });
        for (peer_id, heartbeat) in state.consumers.iter_mut() {
            if *heartbeat == 0 {
                dead_consumers.push(peer_id.to_string());
            } else {
                *heartbeat -= 1;
            }
        }
        dead_consumers.iter().for_each(|peer_id| {
            state.dead_consumers.insert(peer_id.to_string());
        });
    }

    #[inline(always)]
    fn get_dead_suppliers() -> HashSet<String> {
        let state = HEARTBEAT_STATE.read().unwrap();
        state.dead_suppliers.clone()
    }

    #[inline(always)]
    fn get_dead_consumers() -> HashSet<String> {
        let state = HEARTBEAT_STATE.read().unwrap();
        state.dead_consumers.clone()
    }
}

lazy_static! {
    /// Creates a new uninitialized MarketMakerState struct.
    /// This struct is used to persist the MarketMaker state.

    // TODO: Replace this static variable with a database.
    static ref MARKET_MAKER_STATE: RwLock<MarketMakerState> = RwLock::new(MarketMakerState::default());
}

impl Display for MarketMakerState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current MarketMaker Status:
    Number of connected Suppliers: {}
    Number of connected Consumers: {}
    Devices in the network       : {}
    Available Devices            : {}",
            self.suppliers.len(),
            self.consumers.len(),
            self.devices.len(),
            self.available_devices.len()
        )
    }
}

impl Display for MarketMakerMinState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            r"Current MarketMaker Status:
    Number of connected Suppliers: {}
    Number of connected Consumers: {}
    Devices in the network       : {}
    Available Devices            : {}",
            self.num_suppliers,
            self.num_consumers,
            self.devices.len(),
            self.available_devices.len()
        )
    }
}

// Keeps accesses to the MARKET_MAKER_STATE static variable contained in small functions.
// This is to prevent deadlocks when accessing the MARKET_MAKER_STATE RwLock in multiple places.
// We should not need to lock the MARKET_MAKER_STATE RwLock outside of these functions.
// Note: Eager unwraps are used here because we should never be in a situation where
// the lock is poisoned. If the lock is poisoned, then the thread should panic.
impl MarketMakerState {
    // Write functions...

    #[inline(always)]
    fn reset_state() {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        *state = MarketMakerState::default();
    }

    #[inline(always)]
    fn set_whitelists() {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.use_whitelists = true;
    }

    #[inline(always)]
    fn reset_whitelists() {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.use_whitelists = false;
    }

    #[inline(always)]
    fn update_available_devices() {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        // Iterate over all devices and update the available devices.
        let available_devices = state
            .devices
            .values()
            .cloned()
            .filter(|device| device.used_by_host.is_empty())
            .map(|device| (device.device_id.clone(), device))
            .collect();
        state.available_devices = available_devices;
    }

    #[inline(always)]
    fn insert_device(device: DeviceSpec) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.devices.insert(device.device_id.clone(), device);
    }

    #[inline(always)]
    fn insert_supplier(supplier: SupplierSpec) {
        let pub_key = supplier.pub_key.clone();
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.suppliers.insert(pub_key, supplier);
    }

    #[inline(always)]
    fn insert_consumer(consumer: ConsumerSpec) {
        let pub_key = consumer.pub_key.clone();
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.consumers.insert(pub_key, consumer);
    }

    #[inline(always)]
    fn remove_device_from_available(device_id: &str) -> Option<DeviceSpec> {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.available_devices.remove(device_id)
    }

    #[inline(always)]
    fn remove_device(device_id: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.devices.remove(device_id);
    }

    #[inline(always)]
    fn remove_supplier(supplier_pub_key: &str) -> Option<SupplierSpec> {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.suppliers.remove(supplier_pub_key)
    }

    #[inline(always)]
    fn remove_consumer(consumer_pub_key: &str) -> Option<ConsumerSpec> {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.consumers.remove(consumer_pub_key)
    }

    #[inline(always)]
    fn reclaim_devices_used_by(consumer_pub_key: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        for device in state.devices.values_mut() {
            if device.used_by == consumer_pub_key {
                device.used_by = Default::default();
                device.used_by_host = Default::default();
                device.used_by_port = Default::default();
            }
        }
    }

    #[inline(always)]
    fn release_device(device_id: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        let device = state.devices.get_mut(device_id);
        if let Some(device) = device {
            device.used_by = Default::default();
            device.used_by_name = Default::default();
            device.used_by_host = Default::default();
            device.used_by_port = Default::default();
        }
    }

    #[inline(always)]
    fn add_to_supplier_whitelist(key: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.supplier_whitelist.insert(key.to_owned());
    }

    #[inline(always)]
    fn add_to_consumer_whitelist(key: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.consumer_whitelist.insert(key.to_owned());
    }

    #[inline(always)]
    fn remove_from_supplier_whitelist(key: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.supplier_whitelist.remove(key);
    }

    #[inline(always)]
    fn remove_from_consumer_whitelist(key: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        state.consumer_whitelist.remove(key);
    }

    #[inline(always)]
    fn update_supplier_ip(supplier_id: &str, ip: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        if let Some(supplier) = state.suppliers.get_mut(supplier_id) {
            supplier.bind_host = ip.to_owned();
        }
    }

    #[inline(always)]
    fn update_device_supplier(device_id: &str, supplier_ip: &str) {
        let mut state = MARKET_MAKER_STATE.write().unwrap();
        if let Some(device) = state.devices.get_mut(device_id) {
            device.available_at_host = supplier_ip.to_owned();
        }
    }

    // Read functions...

    #[inline(always)]
    fn get_state() -> MarketMakerState {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.clone()
    }

    #[inline(always)]
    fn get_min_state() -> MarketMakerMinState {
        let state = MARKET_MAKER_STATE.read().unwrap();
        MarketMakerMinState {
            num_suppliers: state.suppliers.len(),
            suppliers: state.suppliers.values().cloned().collect(),
            num_consumers: state.consumers.len(),
            consumers: state.consumers.values().cloned().collect(),
            num_market_makers: state.market_makers.len(),
            devices: state.devices.clone(),
            use_whitelists: state.use_whitelists,
            available_devices: state.available_devices.clone(),
            supplier_whitelist: state
                .supplier_whitelist
                .iter()
                .map(base64::encode)
                .collect(),
            consumer_whitelist: state
                .consumer_whitelist
                .iter()
                .map(base64::encode)
                .collect(),
        }
    }

    #[inline(always)]
    fn verify_supplier_whitelist(key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        if state.use_whitelists {
            state.supplier_whitelist.contains(key)
        } else {
            true
        }
    }

    #[inline(always)]
    fn verify_consumer_whitelist(key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        if state.use_whitelists {
            state.consumer_whitelist.contains(key)
        } else {
            true
        }
    }

    #[inline(always)]
    fn supplier_exists(supplier_pub_key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.suppliers.contains_key(supplier_pub_key)
    }

    #[inline(always)]
    fn get_consumer(consumer_pub_key: &str) -> Option<ConsumerSpec> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.consumers.get(consumer_pub_key).cloned()
    }
    #[inline(always)]
    fn consumer_exists(consumer_pub_key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.consumers.contains_key(consumer_pub_key)
    }

    #[inline(always)]
    fn get_available_devices() -> Vec<DeviceSpec> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.available_devices.values().cloned().collect()
    }

    #[inline(always)]
    fn get_consumers_affected_by(supplier_pub_key: &str) -> Vec<(String, String, String)> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        // iterate through all the devices and find the ones that are affected by the supplier.
        state
            .devices
            .values()
            .filter_map(|device| {
                if device.available_at == supplier_pub_key {
                    Some((
                        device.used_by.clone(),
                        device.used_by_host.clone(),
                        device.device_id.clone(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    #[inline(always)]
    fn get_consumer_port(consumer_pub_key: &str) -> Option<u16> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state
            .consumers
            .get(consumer_pub_key)
            .map(|consumer| consumer.bind_port)
    }

    #[inline(always)]
    fn get_consumer_name(consumer_pub_key: &str) -> Option<String> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state
            .consumers
            .get(consumer_pub_key)
            .map(|consumer| consumer.name.clone())
    }

    #[inline(always)]
    fn is_device_used_by(device_id: &str, consumer_pub_key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        let device = state.devices.get(device_id);
        device.map_or(false, |device| device.used_by == consumer_pub_key)
    }

    #[inline(always)]
    fn get_device(device_id: &str) -> Option<DeviceSpec> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.devices.get(device_id).cloned()
    }

    #[inline(always)]
    fn verify_consumer(key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.consumers.contains_key(key)
    }

    #[inline(always)]
    fn verify_supplier(key: &str) -> bool {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.suppliers.contains_key(key)
    }

    #[inline(always)]
    fn get_supplier(supplier_pub_key: &str) -> Option<SupplierSpec> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state.suppliers.get(supplier_pub_key).cloned()
    }

    #[inline(always)]
    #[allow(dead_code)]
    fn filter_devices(filter_vec: &DeviceFilterVec) -> Vec<DeviceSpec> {
        let state = MARKET_MAKER_STATE.read().unwrap();
        state
            .devices
            .values()
            .filter(|device| {
                for device_filter in filter_vec.filters.iter() {
                    if !device_filter.filter(device) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    #[inline(always)]
    fn supplier_supported(supplier_version: &str) -> bool {
        debug!(
            "Checking if supplier version {} is supported",
            supplier_version
        );
        // We neither establish nor support any backwards compatibility
        // till we reach 1.0. What this means in practice is that,
        // for now, we only accept connections from suppliers that
        // have the same version as the market maker.
        ADBORC_VERSION == supplier_version
    }

    #[inline(always)]
    fn consumer_supported(consumer_version: &str) -> bool {
        debug!(
            "Checking if consumer version {} is supported",
            consumer_version
        );
        // We neither establish nor support any backwards compatibility
        // till we reach 1.0. What this means in practice is that,
        // for now, we only accept connections from consumers that
        // have the same version as the market maker.
        ADBORC_VERSION == consumer_version
    }
}

impl MarketMaker {
    /// Construct a new MarketMaker and start the listen server.
    pub(super) fn new() -> io::Result<MarketMaker> {
        MarketMaker::start_undertaker_thread();
        let market_maker = MarketMaker;
        Ok(market_maker)
    }

    fn start_undertaker_thread() {
        thread::spawn(|| {
            loop {
                thread::sleep(UNDERTAKER_INTERVAL);
                // Stop the thread if the market maker has terminated.
                if !SysState::market_maker_is_some() {
                    break;
                }
                HeartBeatState::decrement_heartbeats();
                let dead_suppliers = HeartBeatState::get_dead_suppliers();
                let dead_consumers = HeartBeatState::get_dead_consumers();

                HeartBeatState::remove_dead_suppliers();
                HeartBeatState::remove_dead_consumers();

                thread::spawn(move || {
                    for supplier in dead_suppliers.iter() {
                        MarketMakerState::remove_supplier(supplier);
                        let consumers = MarketMakerState::get_consumers_affected_by(supplier);
                        for (consumer_pub_key, host, device_id) in consumers {
                            MarketMakerState::remove_device(&device_id);
                            if host.is_empty() {
                                continue;
                            }
                            let port = MarketMakerState::get_consumer_port(&consumer_pub_key);
                            if let Some(port) = port {
                                if let Ok(client) = TCPClient::new(host.as_str(), port) {
                                    let request =
                                        ConsumerRequest::SupplierDisconnected { device_id };
                                    client.send_no_wait(request);
                                }
                            }
                        }
                    }
                    MarketMakerState::update_available_devices();
                    for consumer in dead_consumers.iter() {
                        MarketMakerState::remove_consumer(consumer);
                    }
                });
            }
        });
    }

    fn handle_supplier_ip_change(supplier_id: String, new_ip: String) {
        debug!("Supplier {} changed IP to {}", supplier_id, new_ip);
        MarketMakerState::update_supplier_ip(&supplier_id, &new_ip);
        let affected_consumers = MarketMakerState::get_consumers_affected_by(&supplier_id);
        for (consumer_pub_key, host, device_id) in affected_consumers {
            if host.is_empty() {
                continue;
            }
            let port = MarketMakerState::get_consumer_port(&consumer_pub_key);
            if let Some(port) = port {
                if let Ok(client) = TCPClient::new(host.as_str(), port) {
                    let request = ConsumerRequest::SupplierDisconnected {
                        device_id: device_id.clone(),
                    };
                    client.send_no_wait(request);
                }
            }
            MarketMaker::release_device(&device_id);
            // Update the device to reflect the new supplier ip.
            MarketMakerState::update_device_supplier(&device_id, &new_ip);
        }
        MarketMakerState::update_available_devices();
    }

    fn release_device(device_id: &str) {
        let device = MarketMakerState::get_device(device_id);
        if device.is_none() {
            return;
        }
        let device = device.unwrap();
        MarketMakerState::release_device(device_id);
        // If an encrypted tunnel was used, we need to notify the supplier.
        if device.secure_comms {
            let supplier_id = device.available_at.clone();
            let supplier = MarketMakerState::get_supplier(&supplier_id);
            if supplier.is_none() {
                return;
            }
            let supplier = supplier.unwrap();
            let host = supplier.bind_host.as_str();
            let port = supplier.bind_port;
            if let Ok(client) = TCPClient::new(host, port) {
                let request = SupplierRequest::StopSecureTunnel {
                    device_id: device.device_id,
                };
                client.send_no_wait(request);
            }
        }
    }

    /// Handle resetting of MarketMakerState before stopping the MarketMaker listen server.
    pub(super) fn terminate() {
        let state = MarketMakerState::get_state();

        let suppliers = state
            .suppliers
            .values()
            .map(|supplier| (supplier.bind_host.clone(), supplier.bind_port))
            .collect::<Vec<(String, u16)>>();
        let consumers = state
            .consumers
            .values()
            .map(|consumer| (consumer.bind_host.clone(), consumer.bind_port))
            .collect::<Vec<(String, u16)>>();

        for supplier in suppliers {
            let host = supplier.0.as_str();
            let port = supplier.1;
            if let Ok(client) = TCPClient::new(host, port) {
                let request = SysStateRequest::SupplierMarketMakerTerminating;
                client.send_no_wait(request);
            }
        }

        for consumer in consumers {
            let host = consumer.0.as_str();
            let port = consumer.1;
            if let Ok(client) = TCPClient::new(host, port) {
                let request = SysStateRequest::ConsumerMarketMakerTerminating;
                client.send_no_wait(request);
            }
        }
        thread::sleep(Duration::from_millis(1000));
        MarketMakerState::reset_state();
        HeartBeatState::reset_state();
    }

    pub(super) fn process_request(
        request: MarketMakerRequest,
        peer_addr: SocketAddr,
        peer_id: Arc<Key>,
    ) -> String {
        let peer_addr_ip = peer_addr.ip().to_string();
        let peer_id_str = base64::encode(peer_id.as_ref());
        debug!(
            "Processing request to MarketMaker: {:?} \tfrom :{}",
            request, peer_id_str
        );

        // Unwrapping of serialing/deserializing is safe, because we use request/response objects
        // that are known to be serializable/deserializable.
        let is_consumer = || MarketMakerState::verify_consumer(&peer_id_str);
        let is_supplier = || MarketMakerState::verify_supplier(&peer_id_str);
        match request {
            // Client requests.
            MarketMakerRequest::Test => MarketMakerResponse::Test.to_json(),
            MarketMakerRequest::Status if peer_addr.ip().is_loopback() => {
                let state = MarketMakerState::get_min_state();
                MarketMakerResponse::Status { state }.to_json()
            }
            MarketMakerRequest::UseWhitelist if peer_addr.ip().is_loopback() => {
                MarketMakerState::set_whitelists();
                MarketMakerResponse::UseWhitelistSuccess.to_json()
            }
            MarketMakerRequest::ResetWhitelist if peer_addr.ip().is_loopback() => {
                MarketMakerState::reset_whitelists();
                MarketMakerResponse::ResetWhitelistSuccess.to_json()
            }
            MarketMakerRequest::WhitelistSupplier { key } if peer_addr.ip().is_loopback() => {
                if base64::decode(key.clone()).is_ok() {
                    MarketMakerState::add_to_supplier_whitelist(&key);
                    MarketMakerResponse::WhitelistSupplierSuccess.to_json()
                } else {
                    MarketMakerResponse::WhitelistSupplierFailure {
                        reason: "Error processing key".to_string(),
                    }
                    .to_json()
                }
            }
            MarketMakerRequest::WhitelistConsumer { key } if peer_addr.ip().is_loopback() => {
                if base64::decode(key.clone()).is_ok() {
                    MarketMakerState::add_to_consumer_whitelist(&key);
                    MarketMakerResponse::WhitelistConsumerSuccess.to_json()
                } else {
                    MarketMakerResponse::WhitelistConsumerFailure {
                        reason: "Error processing key".to_string(),
                    }
                    .to_json()
                }
            }
            MarketMakerRequest::UnwhitelistSupplier { key } if peer_addr.ip().is_loopback() => {
                if base64::decode(key.clone()).is_ok() {
                    MarketMakerState::remove_from_supplier_whitelist(&key);
                    MarketMakerResponse::UnwhitelistSupplierSuccess.to_json()
                } else {
                    MarketMakerResponse::UnwhitelistSupplierFailure {
                        reason: "Error processing key".to_string(),
                    }
                    .to_json()
                }
            }
            MarketMakerRequest::UnwhitelistConsumer { key } if peer_addr.ip().is_loopback() => {
                if base64::decode(key.clone()).is_ok() {
                    MarketMakerState::remove_from_consumer_whitelist(&key);
                    MarketMakerResponse::UnwhitelistConsumerSuccess.to_json()
                } else {
                    MarketMakerResponse::UnwhitelistConsumerFailure {
                        reason: "Error processing key".to_string(),
                    }
                    .to_json()
                }
            }

            // Supplier Requests.
            MarketMakerRequest::SupplierConnect { mut supplier } => {
                if !MarketMakerState::verify_supplier_whitelist(&peer_id_str) {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Not in whitelist".to_string(),
                    }
                    .to_json();
                }
                let pub_key = supplier.pub_key.clone();
                if peer_id_str != pub_key {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Public key does not match peer id".to_string(),
                    }
                    .to_json();
                }
                if MarketMakerState::supplier_exists(&pub_key) {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Already connected".to_string(),
                    }
                    .to_json();
                }
                if !MarketMakerState::supplier_supported(&supplier.adborc_version) {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Unsupported Supplier version".to_string(),
                    }
                    .to_json();
                }
                if supplier.name.is_empty() {
                    supplier.name = peer_addr_ip.clone();
                }
                supplier.bind_host = peer_addr_ip;
                let client = TCPClient::new(&supplier.bind_host, supplier.bind_port);
                if client.is_err() {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Could not connect to supplier.".to_string(),
                    }
                    .to_json();
                }
                let client = client.unwrap();
                if client.test_connect().is_err() {
                    return MarketMakerResponse::SupplierNotConnected {
                        reason: "Could not connect to supplier".to_string(),
                    }
                    .to_json();
                }
                let supplier_clone = supplier.clone();
                // Update the supplier HeartBeatState in a separate thread.
                thread::spawn(move || {
                    HeartBeatState::add_supplier(&peer_id_str);
                });
                MarketMakerState::insert_supplier(supplier_clone);
                MarketMakerResponse::SupplierConnected {
                    supplier,
                    pub_key: base64::encode(SystemKeypair::get_public_key().unwrap()),
                }
                .to_json()
            }

            MarketMakerRequest::SupplyDevices { devices } if is_supplier() => {
                let mut supplied_devices = Vec::new();
                let mut failed_devices = Vec::new();
                // Add the devices to the network.
                for mut device in devices {
                    device.available_at_host = peer_addr_ip.clone();
                    if MarketMakerState::get_device(&device.device_id).is_none() {
                        MarketMakerState::insert_device(device.clone());
                        supplied_devices.push(device);
                    } else {
                        failed_devices.push(device);
                    }
                }
                // Update the available devices in state in a separate thread.
                thread::spawn(|| {
                    MarketMakerState::update_available_devices();
                });
                MarketMakerResponse::DevicesSupplied {
                    supplied_devices,
                    failed_devices,
                }
                .to_json()
            }

            MarketMakerRequest::ReclaimDevice { device_id, force } if is_supplier() => {
                // Check if the device exists.
                let device = MarketMakerState::get_device(&device_id);
                if device.is_none() {
                    return MarketMakerResponse::DeviceNotReclaimed {
                        reason: "Device not found".to_string(),
                    }
                    .to_json();
                }
                let device = device.unwrap();
                let device_available = device.used_by_host.is_empty();
                if !force && !device_available {
                    // Device is being used by a consumer and force is not set.
                    return MarketMakerResponse::DeviceNotReclaimed {
                        reason: "Device is being used by a consumer".to_string(),
                    }
                    .to_json();
                }
                // Check if the device is supplied by the supplier.
                if device.available_at_host != peer_addr_ip {
                    return MarketMakerResponse::DeviceNotReclaimed {
                        reason: "Device not supplied by supplier".to_string(),
                    }
                    .to_json();
                }

                // Can reclaim the device.

                // If the device is being used by a consumer, we need to ask the consumer to stop using the device.
                let consumer = MarketMakerState::get_consumer(&device.used_by);
                if let Some(consumer) = consumer {
                    let host = consumer.bind_host.as_str();
                    let port = consumer.bind_port;
                    if let Ok(client) = TCPClient::new(host, port) {
                        let request = ConsumerRequest::SupplierDisconnected {
                            device_id: device_id.clone(),
                        };
                        client.send_no_wait(request);
                    }
                }

                MarketMakerState::remove_device(&device_id);
                MarketMakerState::update_available_devices();

                MarketMakerResponse::DeviceReclaimed { device_id }.to_json()
            }

            MarketMakerRequest::SupplierDisconnect if is_supplier() => {
                // Get all devices supplied by the supplier.
                let consumers = MarketMakerState::get_consumers_affected_by(&peer_id_str);
                // Remove the supplier from the network.
                thread::spawn(move || {
                    MarketMakerState::remove_supplier(&peer_id_str);
                    HeartBeatState::remove_supplier(&peer_id_str);
                    for (consumer_pub_key, host, device_id) in consumers {
                        MarketMakerState::remove_device(&device_id);
                        if host.is_empty() {
                            continue;
                        }
                        let port = MarketMakerState::get_consumer_port(&consumer_pub_key);
                        if let Some(port) = port {
                            if let Ok(client) = TCPClient::new(host.as_str(), port) {
                                let request = ConsumerRequest::SupplierDisconnected { device_id };
                                client.send_no_wait(request);
                            }
                        }
                    }
                    MarketMakerState::update_available_devices();
                });
                MarketMakerResponse::SupplierDisconnected.to_json()
            }

            MarketMakerRequest::SupplierHeartBeat if is_supplier() => {
                debug!("Received heartbeat from supplier {}", peer_id_str);
                HeartBeatState::supplier_heartbeat(&peer_id_str);
                if peer_addr_ip
                    != MarketMakerState::get_supplier(&peer_id_str)
                        .unwrap()
                        .bind_host
                {
                    thread::spawn(move || {
                        MarketMaker::handle_supplier_ip_change(peer_id_str, peer_addr_ip)
                    });
                }
                MarketMakerResponse::HeartBeatResponse.to_json()
            }

            // Consumer Requests.
            MarketMakerRequest::ConsumerConnect { mut consumer } => {
                if !MarketMakerState::verify_consumer_whitelist(&peer_id_str) {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Not in whitelist".to_string(),
                    }
                    .to_json();
                }
                if MarketMakerState::consumer_exists(&peer_id_str) {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Already connected".to_string(),
                    }
                    .to_json();
                }
                let pub_key = consumer.pub_key.clone();
                if pub_key != peer_id_str {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Public key does not match peer id".to_string(),
                    }
                    .to_json();
                }
                if !MarketMakerState::consumer_supported(&consumer.adborc_version) {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Unsupported Consumer version".to_string(),
                    }
                    .to_json();
                }
                if consumer.name.is_empty() {
                    consumer.name = peer_addr_ip.clone();
                }
                consumer.bind_host = peer_addr_ip;
                let client = TCPClient::new(&consumer.bind_host, consumer.bind_port);
                if client.is_err() {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Could not connect to consumer.".to_string(),
                    }
                    .to_json();
                }
                let client = client.unwrap();
                if client.test_connect().is_err() {
                    return MarketMakerResponse::ConsumerNotConnected {
                        reason: "Could not connect to consumer.".to_string(),
                    }
                    .to_json();
                }
                let consumer_clone = consumer.clone();
                // Update the consumer HeartBeatState in a separate thread.
                thread::spawn(move || {
                    HeartBeatState::add_consumer(&peer_id_str);
                });
                MarketMakerState::insert_consumer(consumer_clone);
                MarketMakerResponse::ConsumerConnected {
                    consumer,
                    pub_key: base64::encode(SystemKeypair::get_public_key().unwrap()),
                }
                .to_json()
            }

            MarketMakerRequest::GetAvailableDevices if is_consumer() => {
                let devices = MarketMakerState::get_available_devices();
                MarketMakerResponse::AvailableDevices { devices }.to_json()
            }

            MarketMakerRequest::GetDevicesByFilter { filter_vec } if is_consumer() => {
                let devices = MarketMakerState::filter_devices(&filter_vec);
                MarketMakerResponse::DevicesByFilter {
                    devices,
                    filter_vec,
                }
                .to_json()
            }

            MarketMakerRequest::ReserveDevice { device_id } if is_consumer() => {
                let device = MarketMakerState::remove_device_from_available(&device_id);
                if device.is_none() {
                    return MarketMakerResponse::DeviceNotReserved {
                        reason: "Device not available".to_string(),
                    }
                    .to_json();
                }
                let consumer_name = MarketMakerState::get_consumer_name(&peer_id_str);
                if consumer_name.is_none() {
                    return MarketMakerResponse::DeviceNotReserved {
                        reason: "Fatal: Consumer not found".to_string(),
                    }
                    .to_json();
                }
                let mut device = device.unwrap();
                device.used_by = peer_id_str.clone();
                device.used_by_name = consumer_name.unwrap();
                device.used_by_host = peer_addr_ip;
                let device_clone = device.clone();

                // If supplier doesn't require secure connection, we can reserve the device.
                if !device.secure_comms {
                    // Update the device in state in a separate thread.
                    thread::spawn(|| {
                        MarketMakerState::insert_device(device_clone);
                    });
                    MarketMakerResponse::DeviceReserved {
                        device,
                        peer_id: None,
                    }
                    .to_json()
                } else {
                    let supplier_id = device.available_at.clone();
                    let supplier = MarketMakerState::get_supplier(&supplier_id);
                    if supplier.is_none() {
                        return MarketMakerResponse::DeviceNotReserved {
                            reason: "Supplier not found".to_string(),
                        }
                        .to_json();
                    }
                    let supplier = supplier.unwrap();
                    let host = supplier.bind_host.as_str();
                    let port = supplier.bind_port;
                    if let Ok(client) = TCPClient::new(host, port) {
                        let request = SupplierRequest::StartSecureTunnel {
                            device_id: device.device_id.clone(),
                            port: device.available_at_port,
                            pub_key: peer_id_str.clone(),
                        };
                        let response = client.send_request(request, None);
                        if response.is_err() {
                            return MarketMakerResponse::DeviceNotReserved {
                                reason: "Could not connect to supplier".to_string(),
                            }
                            .to_json();
                        }
                        let response = response.unwrap();
                        let response = SupplierResponse::from_str(&response);
                        if response.is_err() {
                            return MarketMakerResponse::DeviceNotReserved {
                                reason: "Failed to parse server response".to_string(),
                            }
                            .to_json();
                        }
                        let response = response.unwrap();
                        match response {
                            SupplierResponse::SecureTunnelStarted { port } => {
                                // Update the device in state in a separate thread.
                                thread::spawn(|| {
                                    MarketMakerState::insert_device(device_clone);
                                });
                                device.available_at_port = port;
                                MarketMakerResponse::DeviceReserved {
                                    device,
                                    peer_id: Some(supplier_id),
                                }
                                .to_json()
                            }
                            SupplierResponse::SecureTunnelStartFailure { reason } => {
                                MarketMakerResponse::DeviceNotReserved { reason }.to_json()
                            }
                            _ => MarketMakerResponse::DeviceNotReserved {
                                reason: "Unexpected response from supplier".to_string(),
                            }
                            .to_json(),
                        }
                    } else {
                        MarketMakerResponse::DeviceNotReserved {
                            reason: "Could not connect to supplier".to_string(),
                        }
                        .to_json()
                    }
                }
            }

            MarketMakerRequest::ReleaseDevice { device_id } if is_consumer() => {
                if MarketMakerState::is_device_used_by(&device_id, &peer_id_str) {
                    thread::spawn(move || {
                        MarketMaker::release_device(&device_id);
                        MarketMakerState::update_available_devices();
                    });
                    MarketMakerResponse::DeviceReleased.to_json()
                } else {
                    MarketMakerResponse::DeviceNotReleased {
                        reason: "Device is not used by the specified consumer. Access restricted."
                            .to_string(),
                    }
                    .to_json()
                }
            }

            MarketMakerRequest::ReleaseAllDevices if is_consumer() => {
                thread::spawn(move || {
                    MarketMakerState::reclaim_devices_used_by(&peer_id_str);
                    MarketMakerState::update_available_devices();
                });
                MarketMakerResponse::AllDeviceReleaseSuccess.to_json()
            }

            MarketMakerRequest::StartScrcpyTunnel {
                device_id,
                supplier_id,
                port,
                scrcpy_port,
            } if is_consumer() => {
                if MarketMakerState::is_device_used_by(&device_id, &peer_id_str) {
                    let supplier = MarketMakerState::get_supplier(&supplier_id);
                    if supplier.is_none() {
                        return MarketMakerResponse::ScrcpyTunnelFailure {
                            reason: "Supplier not found".to_string(),
                        }
                        .to_json();
                    }
                    let consumer_host = peer_addr_ip;

                    let supplier = supplier.unwrap();
                    let host = supplier.bind_host.as_str();
                    let supplier_port = supplier.bind_port;
                    if let Ok(client) = TCPClient::new(host, supplier_port) {
                        let request = SupplierRequest::StartScrcpyTunnel {
                            device_id,
                            port,
                            peer_id: peer_id_str.clone(),
                            consumer_host,
                            scrcpy_port,
                        };
                        let response = client.send_request(request, None);
                        if response.is_err() {
                            return MarketMakerResponse::ScrcpyTunnelFailure {
                                reason: "Could not connect to supplier".to_string(),
                            }
                            .to_json();
                        }
                        let response = response.unwrap();
                        let response = SupplierResponse::from_str(&response);
                        if response.is_err() {
                            return MarketMakerResponse::ScrcpyTunnelFailure {
                                reason: "Failed to parse server response".to_string(),
                            }
                            .to_json();
                        }
                        let response = response.unwrap();
                        match response {
                            SupplierResponse::ScrcpyTunnelSuccess => {
                                MarketMakerResponse::ScrcpyTunnelSuccess.to_json()
                            }
                            SupplierResponse::ScrcpyTunnelFailure { reason } => {
                                MarketMakerResponse::ScrcpyTunnelFailure { reason }.to_json()
                            }
                            _ => MarketMakerResponse::ScrcpyTunnelFailure {
                                reason: "Unexpected response from supplier".to_string(),
                            }
                            .to_json(),
                        }
                    } else {
                        MarketMakerResponse::ScrcpyTunnelFailure {
                            reason: "Could not connect to supplier to start scrcpy tunnel"
                                .to_string(),
                        }
                        .to_json()
                    }
                } else {
                    MarketMakerResponse::ScrcpyTunnelFailure {
                        reason: "Unauthorised access to device".to_string(),
                    }
                    .to_json()
                }
            }

            MarketMakerRequest::ConsumerDisconnect if is_consumer() => {
                // Remove the consumer from the network.
                thread::spawn(move || {
                    MarketMakerState::remove_consumer(&peer_id_str);
                    // Reclaim the devices used by the consumer.
                    MarketMakerState::reclaim_devices_used_by(&peer_id_str);
                    MarketMakerState::update_available_devices();
                    HeartBeatState::remove_consumer(&peer_id_str);
                });
                MarketMakerResponse::ConsumerDisconnected.to_json()
            }

            MarketMakerRequest::ConsumerHeartBeat if is_consumer() => {
                debug!("Received heartbeat from consumer {}", peer_id_str);
                HeartBeatState::consumer_heartbeat(&peer_id_str);
                MarketMakerResponse::HeartBeatResponse.to_json()
            }

            // Requests that are not allowed.
            _ => MarketMakerResponse::RequestNotAllowed.to_json(),
        }
    }
}
