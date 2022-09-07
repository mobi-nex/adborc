use super::*;
use crate::market::test_utils;
use crate::util::{test_with_logs, SysStateDefaultConfig};
use serial_test::serial;
use tokio::task;

#[tokio::test]
#[serial]
async fn test_status() {
    test_with_logs();
    ConsumerState::reset_state();

    let mm_host = "localhost".to_string();
    let mm_port = SysStateDefaultConfig::BIND_PORT;
    let mm_key = vec![255u8; 32];

    ConsumerState::update_host_port_name(Some(mm_host.clone()), Some(mm_port), None);
    ConsumerState::set_market_maker_key(mm_key.clone());

    let request = ConsumerRequest::Status;

    let (mm_addr, mm_id) = test_utils::get_peer_with_key(&mm_key);
    fn process_command(_: String, _: SocketAddr, _: Arc<Key>) -> String {
        "OK".to_string()
    }
    test_utils::start_dummy_system_server(process_command);

    let response = task::spawn_blocking(move || Consumer::process_request(request, mm_addr, mm_id))
        .await
        .unwrap();

    let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
    match response {
        ConsumerResponse::Status { state } => {
            let expected_state = ConsumerStateMin {
                mm_host,
                mm_port,
                ..ConsumerStateMin::default()
            };
            assert_eq!(state, expected_state);
        }
        _ => {
            panic!("Unexpected response");
        }
    }
}
