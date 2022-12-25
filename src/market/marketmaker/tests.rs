use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr};
use tokio::task;

use super::*;
use crate::{market::test_utils, util::test_with_logs};

#[test]
#[serial]
fn test_status_request() {
    test_with_logs();
    MarketMakerState::reset_state();
    let request = MarketMakerRequest::Status;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let peer_id = Arc::new(Vec::new());
    let response = MarketMaker::process_request(request, peer_addr, peer_id);
    let expected_response = MarketMakerResponse::Status {
        state: MarketMakerMinState::default(),
    }
    .to_json();
    assert_eq!(response, expected_response);
}

#[tokio::test]
#[serial]
async fn test_supplier_connect() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::SupplierConnect {
        supplier: SupplierSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..SupplierSpec::default()
        },
    };
    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::SupplierConnected { supplier, pub_key } => {
            assert_eq!(base64::decode(supplier.pub_key).unwrap(), peer_pub_key);
            assert_eq!(
                pub_key,
                base64::encode(SystemKeypair::get_public_key().unwrap())
            );
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                suppliers: vec![SupplierSpec {
                    name: peer_addr.ip().to_string(),
                    bind_host: peer_addr.ip().to_string(),
                    pub_key: base64::encode(&peer_pub_key),
                    ..SupplierSpec::default()
                }],
                num_suppliers: 1,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_supplier_connect_secure_mode() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::SupplierConnect {
        supplier: SupplierSpec {
            pub_key: base64::encode(&peer_pub_key),
            secure_comms: true,
            ..SupplierSpec::default()
        },
    };

    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::SupplierConnected { supplier, pub_key } => {
            assert_eq!(base64::decode(supplier.pub_key).unwrap(), peer_pub_key);
            assert!(supplier.secure_comms);
            assert_eq!(
                pub_key,
                base64::encode(SystemKeypair::get_public_key().unwrap())
            );

            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                suppliers: vec![SupplierSpec {
                    name: peer_addr.ip().to_string(),
                    bind_host: peer_addr.ip().to_string(),
                    pub_key: base64::encode(&peer_pub_key),
                    secure_comms: true,
                    ..SupplierSpec::default()
                }],
                num_suppliers: 1,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_supplier_connect_pub_key_mismatch() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::SupplierConnect {
        supplier: SupplierSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..SupplierSpec::default()
        },
    };
    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&vec![0u8; 32]);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::SupplierNotConnected { reason } => {
            assert_eq!(reason, "Public key does not match peer id");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState::default();
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_supplier_connect_already_connected() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let supplier = SupplierSpec {
        pub_key: base64::encode(&peer_pub_key),
        ..SupplierSpec::default()
    };
    MarketMakerState::insert_supplier(supplier.clone());
    let request = MarketMakerRequest::SupplierConnect { supplier };

    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::SupplierNotConnected { reason } => {
            assert_eq!(reason, "Already connected");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                suppliers: vec![SupplierSpec {
                    pub_key: base64::encode(&peer_pub_key),
                    ..SupplierSpec::default()
                }],
                num_suppliers: 1,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_supplier_connect_not_in_whitelist() {
    test_with_logs();
    MarketMakerState::reset_state();
    MarketMakerState::set_whitelists();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::SupplierConnect {
        supplier: SupplierSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..SupplierSpec::default()
        },
    };
    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::SupplierNotConnected { reason } => {
            assert_eq!(reason, "Not in whitelist");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                use_whitelists: true,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_consumer_connect() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::ConsumerConnect {
        consumer: ConsumerSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..ConsumerSpec::default()
        },
    };

    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::ConsumerConnected { consumer, pub_key } => {
            assert_eq!(base64::decode(consumer.pub_key).unwrap(), peer_pub_key);
            assert_eq!(
                pub_key,
                base64::encode(SystemKeypair::get_public_key().unwrap())
            );
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                consumers: vec![ConsumerSpec {
                    name: peer_addr.ip().to_string(),
                    bind_host: peer_addr.ip().to_string(),
                    pub_key: base64::encode(&peer_pub_key),
                    ..ConsumerSpec::default()
                }],
                num_consumers: 1,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_consumer_connect_pub_key_mismatch() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::ConsumerConnect {
        consumer: ConsumerSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..ConsumerSpec::default()
        },
    };
    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&vec![0u8; 32]);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::ConsumerNotConnected { reason } => {
            assert_eq!(reason, "Public key does not match peer id");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState::default();
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_consumer_connect_already_connected() {
    test_with_logs();
    MarketMakerState::reset_state();
    let peer_pub_key = vec![255u8; 32];
    let consumer = ConsumerSpec {
        pub_key: base64::encode(&peer_pub_key),
        ..ConsumerSpec::default()
    };
    MarketMakerState::insert_consumer(consumer.clone());
    let request = MarketMakerRequest::ConsumerConnect { consumer };

    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::ConsumerNotConnected { reason } => {
            assert_eq!(reason, "Already connected");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                consumers: vec![ConsumerSpec {
                    pub_key: base64::encode(&peer_pub_key),
                    ..ConsumerSpec::default()
                }],
                num_consumers: 1,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}

#[tokio::test]
#[serial]
async fn test_consumer_connect_not_in_whitelist() {
    test_with_logs();
    MarketMakerState::reset_state();
    MarketMakerState::set_whitelists();
    let peer_pub_key = vec![255u8; 32];
    let request = MarketMakerRequest::ConsumerConnect {
        consumer: ConsumerSpec {
            pub_key: base64::encode(&peer_pub_key),
            ..ConsumerSpec::default()
        },
    };
    let (peer_addr, peer_id) = test_utils::get_peer_with_key(&peer_pub_key);

    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "Not in whitelist".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response =
        task::spawn_blocking(move || MarketMaker::process_request(request, peer_addr, peer_id))
            .await
            .unwrap();
    let response = MarketMakerResponse::from_str(&response).unwrap();
    match response {
        MarketMakerResponse::ConsumerNotConnected { reason } => {
            assert_eq!(reason, "Not in whitelist");
            let state = MarketMakerState::get_min_state();
            let expected_state = MarketMakerMinState {
                use_whitelists: true,
                ..MarketMakerMinState::default()
            };
            assert_eq!(state, expected_state);
            MarketMakerState::reset_state();
        }
        _ => {
            MarketMakerState::reset_state();
            panic!("Unexpected response")
        }
    }
}
