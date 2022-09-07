use super::*;
use crate::market::test_utils;
use crate::util::{test_with_logs, SysStateDefaultConfig};
use serial_test::serial;
use tokio::task;

#[tokio::test]
#[serial]
async fn test_status() {
    test_with_logs();
    SupplierState::reset_state();

    let mm_host = "localhost".to_string();
    let mm_port = SysStateDefaultConfig::BIND_PORT;
    let mm_key = vec![255u8; 32];

    SupplierState::update_host_port_name(Some(mm_host.clone()), Some(mm_port), None);
    SupplierState::set_market_maker_key(mm_key.clone());

    let request = SupplierRequest::Status;

    let (mm_addr, mm_id) = test_utils::get_peer_with_key(&mm_key);
    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response = task::spawn_blocking(move || Supplier::process_request(request, mm_addr, mm_id))
        .await
        .unwrap();

    let response = serde_json::from_str::<SupplierResponse>(&response).unwrap();
    match response {
        SupplierResponse::Status { state } => {
            let expected_state = SupplierStateMin {
                mm_host,
                mm_port,
                ..SupplierStateMin::default()
            };
            assert_eq!(state, expected_state);
        }
        _ => {
            panic!("Unexpected response");
        }
    }
}
