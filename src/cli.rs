use crate::market::{request::*, DeviceFilter, DeviceFilterVec, SysState};
use crate::net::TCPClient;
use crate::util::SysStateDefaultConfig;
use clap::{Parser, Subcommand};

use log::error;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

#[derive(Parser)]
#[clap(name="adborc", author, version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Starts the system listener
    Init,
    /// Get the current status of the system. Returns if the system
    /// is initialized, and if it is, the mode(s) currently active.
    Status,
    /// Shutdown the system. Terminates all active modes (MarketMaker/Supplier/Consumer).
    Shutdown,
    /// Get the network_id of system.
    GetNetworkId,
    /// Check if `adb` and `scrcpy` are installed and compatible.
    /// Outputs which modes (MarketMaker/Supplier/Consumer) are
    /// available to be run on the system.
    Check,
    /// Set the path to the `adb` executable, if not in PATH.
    /// The specified path must be an absolute path to the `adb` executable.
    /// For example: `C:\Users\user\Downloads\platform-tools_r30.0.4-windows\adb.exe`
    SetAdbPath {
        #[clap(value_parser)]
        path: String,
    },
    /// Set the path to the `scrcpy` executable, if not in PATH.
    /// The specified path must be an absolute path to the `scrcpy` executable.
    /// For example: `C:\Users\user\Downloads\scrcpy-win64-v1.17\scrcpy.exe`
    SetScrcpyPath {
        #[clap(value_parser)]
        path: String,
    },
    #[cfg(feature = "mangen")]
    /// Generate manual page for `adborc`.
    Mangen {
        /// Optional path to place generated man page in.
        /// Path must be an existing directory. Man page will be placed
        /// in that directory with the name `adborc.man`.
        /// If path is not specified, man page will be placed
        /// in the current executable's directory with the name `adborc.man`.
        #[clap(short, long, value_parser)]
        path: Option<String>,
    },

    /// MarketMaker subcommand. Commands to MarketMaker, if the system is running in
    /// MarketMaker mode. Use `adborc marketmaker help` for more information.
    #[clap(subcommand)]
    Marketmaker(MarketMakerCommands),
    /// Supplier subcommand. Commands to Supplier, if the system is running in
    /// Supplier mode. Use `adborc supplier help` for more information.
    #[clap(subcommand)]
    Supplier(SupplierCommands),
    /// Consumer subcommand. Commands to Consumer, if the system is running in
    /// Consumer mode. Use `adborc consumer help` for more information.
    #[clap(subcommand)]
    Consumer(ConsumerCommands),
}

#[derive(Subcommand)]
pub enum MarketMakerCommands {
    /// Get the current status of MarketMaker.
    Status,
    /// Start a network by running MarketMaker mode on the system.
    Start,
    /// Terminate the MarketMaker on the system.
    /// WARNING: This will terminate the entire network of Suppliers and Consumers
    /// connected to the MarketMaker.
    Stop,
    /// Enable MarketMaker whitelisting for authenticating
    /// Suppliers and Consumers. When whitelisting is enabled,
    /// only Suppliers and Consumers whose `network_id` (Use `adborc get-network-id`)
    /// is added to the whitelist will be able to connect to the network.
    /// Use `adborc marketmaker add-supplier` and `adborc marketmaker add-consumer`
    /// to add Suppliers and Consumers to the whitelist.
    /// Whitelist is disabled by default.
    UseWhitelist,
    /// Remove the whitelisting requirement for Suppliers and Consumers.
    ResetWhitelist,
    /// Add a supplier to the whitelist.
    AddSupplier {
        /// The network_id of Supplier.
        peer_id: String,
    },
    /// Remove a supplier from the whitelist.
    /// Note: This will not terminate the Supplier from the network if it is already
    /// connected to the MarketMaker.
    RemoveSupplier {
        /// The `network_id` of Supplier.
        peer_id: String,
    },
    /// Add a consumer to the whitelist.
    AddConsumer {
        /// The `network_id` of Consumer.
        peer_id: String,
    },
    /// Remove a consumer from the whitelist.
    /// Note: This will not terminate the Consumer from the network if it is already
    /// connected to the MarketMaker.
    RemoveConsumer {
        /// The `network_id` of Consumer.
        peer_id: String,
    },
}

#[derive(Subcommand)]
pub enum SupplierCommands {
    /// Get the current status of Supplier.
    Status,
    /// Connect to a network (MarketMaker) and start Supplier mode on the system.
    Start {
        /// Hostname or IP address of the MarketMaker.
        #[clap(value_parser)]
        remote: String,
        /// Port of the MarketMaker.
        #[clap(short, long, value_parser, default_value_t = SysStateDefaultConfig::BIND_PORT)]
        port: u16,
        /// Optional name to be specified for the Supplier.
        /// This name will be used to identify the Supplier in the network.
        /// Defaults to hostname of the Supplier machine.
        /// Note: This name is for reference only and does not affect the
        /// functionality of the Supplier. There is no need to specify a unique name.
        #[clap(short, long, value_parser)]
        user: Option<String>,
        /// Use encrypted communication channels for device. This is recommended.
        /// If not specified, all device communication will be unencrypted.
        /// If specified, encrypted tunnels will be created for device communication.
        #[clap(short, long, action)]
        secure: bool,
    },
    /// Terminate Supplier mode on the system. Supplier will be removed from the
    /// network and all supplied devices will be reclaimed.
    Stop,
    /// Supply devices to the network.
    Supply {
        /// List of devices, specified by their `ANDROID_SERIAL`, to supply.
        /// If no devices are specified, all devices detected on `ADB` will be supplied.
        /// Devices must be separated by a comma.
        /// Example: adborc supply --devices "serial1,serial2,serial3"
        #[clap(long, value_parser, use_value_delimiter = true)]
        devices: Option<Vec<String>>,
    },
    /// Reclaim a device from the network.
    /// If the device is currently in use, reclaim will fail.
    /// Use option `-f/--force` to force the reclaim.
    Reclaim {
        /// Device to reclaim, specified by its device_id.
        #[clap(value_parser)]
        device: String,
        /// Optional flag to force the reclaim.
        #[clap(short, long, action)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConsumerCommands {
    /// Get the current status of Consumer.
    Status,
    /// Connect to a network (MarketMaker) and start Consumer mode on the system.
    Start {
        /// Hostname or IP address of the MarketMaker.
        #[clap(value_parser)]
        remote: String,
        /// Port of the MarketMaker.
        #[clap(short, long, value_parser, default_value_t = SysStateDefaultConfig::BIND_PORT)]
        port: u16,
        /// Optional name to be specified for the Consumer.
        /// This name will be used to identify the Consumer in the network.
        /// Defaults to hostname of the Consumer machine.
        /// Note: This name is for reference only and does not affect the
        /// functionality of the Consumer. There is no need to specify a unique name.
        #[clap(short, long, value_parser)]
        user: Option<String>,
    },
    /// Terminate Consumer mode on the system. Consumer will be removed from the
    /// network and all reserved devices will be added back to the network.
    Stop,
    /// Request to reserve a device from the MarketMaker. If the device is available,
    /// it will be reserved for the Consumer and tunnels (encrypted, if the device
    /// Supplier uses secure mode) will be setup for device communication. The device
    /// will be available for use on the Consumer system using `adb` on the specified port.
    /// If the device is not available, the request will fail.
    Reserve {
        /// `device_id` of the device to reserve.
        /// Use `adborc consumer list-available` for a list of available devices.
        #[clap(value_parser)]
        device: String,
        /// Optional flag to not make the device default.
        /// A default device is available on the system using `adb` without specifying
        /// the port number for the device.
        /// If not specified and default device not already set, the device
        /// will be set as the default device.
        #[clap(long, action)]
        no_default: bool,
    },
    /// Release a device. If not specified, all reserved devices will be released.
    Release {
        /// `device_id` of the device to be released.
        /// Use `adborc consumer list-reserved` for a list of reserved devices.
        #[clap(value_parser)]
        device: Option<String>,
    },
    /// Get a list of all available devices on the network.
    ListAvailable,
    /// Get devices in the network and filter them by some criteria.
    GetDevices {
        /// If `is_available` is true, only available devices will be returned.
        /// If `is_available` is false, only reserved devices will be returned.
        /// If `is_available` is not specified, all devices will be returned.
        #[clap(long, value_parser)]
        is_available: Option<bool>,
        /// List of device_ids to filter devices by.
        /// If specified, only devices with device_ids in the list will be returned.
        /// Devices must be separated by a comma.
        /// Example: adborc consumer get-devices --device_ids "id1,id2,id3"
        #[clap(long, value_parser, use_value_delimiter = true)]
        device_ids: Option<Vec<String>>,
        /// List of device names to filter devices by.
        /// If specified, only devices with names in the list will be returned.
        /// Names must be separated by a comma.
        /// Example: adborc consumer get-devices --device_names "name1,name2,name3"
        #[clap(long, value_parser, use_value_delimiter = true)]
        device_names: Option<Vec<String>>,
        /// List of device models to filter devices by.
        /// If specified, only devices with models in the list will be returned.
        /// Models must be separated by a comma.
        /// Example: adborc consumer get-devices --device_models "model1,model2,model3"
        #[clap(long, value_parser, use_value_delimiter = true)]
        device_models: Option<Vec<String>>,
        /// List of device supplier names to filter devices by.
        /// If specified, only devices supplied by the specified supplier(s) in the list will be returned.
        /// Suppliers must be separated by a comma.
        /// Example: adborc consumer get-devices --device_suppliers "supplier1,supplier2,supplier3"
        #[clap(long, value_parser, use_value_delimiter = true)]
        supplied_by: Option<Vec<String>>,
        /// List of device consumer names to filter devices by.
        /// If specified, only devices reserved by the specified consumer(s) in the list will be returned.
        #[clap(long, value_parser, use_value_delimiter = true)]
        reserved_by: Option<Vec<String>>,
    },
    /// Show currently reserved devices.
    ListReserved,
    /// Set a device as the default device.
    SetDefault {
        /// `device_id` of the device.
        #[clap(value_parser)]
        device: String,
    },
    /// Start device screen mirroring using `scrcpy` for a device.
    /// Checkout: `<https://github.com/Genymobile/scrcpy>` for more information on `scrcpy`.
    Scrcpy {
        /// `device_id` of the device to start scrcpy for.
        #[clap(value_parser)]
        device: String,
        /// Limit both the width and height of the video to value. The other dimension is computed so that the device
        /// aspect-ratio is preserved. Default: 1920.
        #[clap(short, long, value_parser)]
        max_size: Option<u16>,
        /// Limit the frame rate of screen capture (officially supported since Android 10, but may work on earlier
        /// versions). Default: 30.
        #[clap(long, value_parser)]
        max_fps: Option<u8>,
        /// Encode the video at the gitven bit-rate, expressed in bits/s. Default: 2000000.
        #[clap(short, long, value_parser)]
        bit_rate: Option<u32>,
    },
    /// Set the default arguments for `scrcpy`.
    SetScrcpyArgs {
        /// Limit both the width and height of the video to value. The other dimension is computed so that the device
        /// aspect-ratio is preserved. Default: 1920.
        #[clap(short, long, value_parser)]
        max_size: Option<u16>,
        /// Limit the frame rate of screen capture (officially supported since Android 10, but may work on earlier
        /// versions). Default: 30.
        #[clap(long, value_parser)]
        max_fps: Option<u8>,
        /// Encode the video at the gitven bit-rate, expressed in bits/s. Unit suffixes are supported: 'K' (x1000) and 'M'
        /// (x1000000). Default: 2000000.
        #[clap(short, long, value_parser)]
        bit_rate: Option<u32>,
    },
}

fn check_listener() -> bool {
    let addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        SysStateDefaultConfig::BIND_PORT,
    );
    let stream = TcpStream::connect(addr);
    stream.is_ok()
}

fn init_listener() -> io::Result<()> {
    println!("Starting system listener...");
    SysState::start_system()
}

#[cfg(feature = "mangen")]
fn mangen(path: &Option<String>) {
    use clap::CommandFactory;
    use clap_mangen::Man;
    use std::env;
    use std::fs::File;
    use std::path::PathBuf;

    let path = if path.is_none() {
        env::current_exe().unwrap().parent().unwrap().to_path_buf()
    } else {
        let temp_path = PathBuf::from(path.as_ref().unwrap());
        if temp_path.exists() && temp_path.is_dir() {
            temp_path
        } else {
            println!("Invalid path specified");
            return;
        }
    };
    let out_file = File::create(path.join("adborc.man"));
    if out_file.is_err() {
        println!(
            "Error creating output file: {}\n{}",
            path.join("adborc.man").display(),
            out_file.unwrap_err()
        );
        return;
    }
    let mut out_file = out_file.unwrap();
    let cli_command = Cli::command();
    let marketmaker_subcommand = cli_command.find_subcommand("marketmaker").unwrap();
    let supplier_subcommand = cli_command.find_subcommand("supplier").unwrap();
    let consumer_subcommand = cli_command.find_subcommand("consumer").unwrap();

    let result = Man::new(cli_command.clone()).render_title(&mut out_file);

    if result.is_err() {
        println!("Error generating man page title: {}", result.unwrap_err());
    }

    let result = Man::new(cli_command.clone()).render_name_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page name section: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(cli_command.clone()).render_synopsis_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page synopsis: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(cli_command.clone()).render_description_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page description: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(cli_command.clone()).render_options_section(&mut out_file);

    if result.is_err() {
        println!("Error generating man page options: {}", result.unwrap_err());
    }

    let result = Man::new(cli_command.clone()).render_subcommands_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page subcommands: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(marketmaker_subcommand.clone()).render_subcommands_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error writing MarketMaker subcommands: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(supplier_subcommand.clone()).render_subcommands_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error writing Supplier subcommands: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(consumer_subcommand.clone()).render_subcommands_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error writing Consumer subcommands: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(cli_command.clone()).render_version_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page version section: {}",
            result.unwrap_err()
        );
    }

    let result = Man::new(cli_command.clone()).render_authors_section(&mut out_file);

    if result.is_err() {
        println!(
            "Error generating man page authors section: {}",
            result.unwrap_err()
        );
    }

    println!("Wrote man page to {}", path.join("adborc.man").display());
    return;
}

impl Cli {
    pub fn process(&self) {
        #[cfg(feature = "mangen")]
        {
            // Process 'mangen' command separately.
            if let Commands::Mangen { path } = &self.command {
                mangen(path);
                return;
            }
        }

        // Process 'init' command separately.
        if let Commands::Init = self.command {
            if check_listener() {
                println!(
                    "Either the default port ({}) is occupied or system listener is already running",
                    SysStateDefaultConfig::BIND_PORT
                );
                return;
            } else {
                // Daemonize the thread, if possible.
                #[cfg(windows)]
                {
                    log::warn!("Running as a background Windows service is not supported yet");
                    println!("Let the server instance run in the current console window or press Ctrl+C to exit");
                }

                #[cfg(unix)]
                {
                    use crate::util::{PID_FILE, STDERR_LOGFILE, STDOUT_LOGFILE};
                    use daemonize::Daemonize;
                    use log::info;
                    use std::env;
                    use std::fs::OpenOptions;

                    let current_exe = env::current_exe().unwrap();
                    let executable_directory = current_exe.parent().unwrap();
                    let stdout_logfile = executable_directory.join(STDOUT_LOGFILE);
                    let stderr_logfile = executable_directory.join(STDERR_LOGFILE);
                    let pid_file = executable_directory.join(PID_FILE);

                    let stdout = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(stdout_logfile)
                        .unwrap();
                    let stderr = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(stderr_logfile)
                        .unwrap();

                    let daemonize = Daemonize::new()
                        .pid_file(pid_file)
                        .chown_pid_file(true)
                        .working_directory(executable_directory)
                        .stdout(stdout)
                        .stderr(stderr);

                    // Start the daemon.
                    if let Err(e) = daemonize.start() {
                        error!("Error daemonzing process:, {}", e);
                    } else {
                        info!("Daemonized successfully");
                    }
                }

                let init_result = init_listener();

                if init_result.is_ok() {
                    return;
                } else {
                    error!("Failed to start system listener");
                    println!(
                        "Failed to start system listener\n{}",
                        init_result.unwrap_err()
                    );
                    return;
                }
            }
        } else if !check_listener() {
            println!(
                "System listener is not running. Use \"adborc init\" to start the system listener."
            );
            return;
        }

        let client = TCPClient::new("127.0.0.1", SysStateDefaultConfig::BIND_PORT).unwrap();

        match &self.command {
            Commands::Status => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::GetState)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::Shutdown => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::Shutdown)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::GetNetworkId => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::GetPeerId)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::Check => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::SystemCheck)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::SetAdbPath { path } => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::SetAdbPath {
                        adb_path: path.to_owned(),
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::SetScrcpyPath { path } => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::SetScrcpyPath {
                        scrcpy_path: path.to_owned(),
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            Commands::Marketmaker(cmd) => Self::process_market_maker_commands(cmd, client),
            Commands::Supplier(cmd) => Self::process_supplier_commands(cmd, client),
            Commands::Consumer(cmd) => Self::process_consumer_commands(cmd, client),
            _ => {
                println!("Not yet implemented");
            }
        }
    }

    fn process_market_maker_commands(command: &MarketMakerCommands, client: TCPClient) {
        match command {
            MarketMakerCommands::Status => {
                let request =
                    serde_json::to_string(&Request::MarketMaker(MarketMakerRequest::Status))
                        .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::Start => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StartMarketMaker))
                        .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::Stop => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StopMarketMaker))
                        .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::UseWhitelist => {
                let request =
                    serde_json::to_string(&Request::MarketMaker(MarketMakerRequest::UseWhitelist))
                        .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::ResetWhitelist => {
                let request = serde_json::to_string(&Request::MarketMaker(
                    MarketMakerRequest::ResetWhitelist,
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::AddSupplier { peer_id } => {
                let request = serde_json::to_string(&Request::MarketMaker(
                    MarketMakerRequest::WhitelistSupplier {
                        key: peer_id.clone(),
                    },
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::RemoveSupplier { peer_id } => {
                let request = serde_json::to_string(&Request::MarketMaker(
                    MarketMakerRequest::UnwhitelistSupplier {
                        key: peer_id.clone(),
                    },
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::AddConsumer { peer_id } => {
                let request = serde_json::to_string(&Request::MarketMaker(
                    MarketMakerRequest::WhitelistConsumer {
                        key: peer_id.clone(),
                    },
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
            MarketMakerCommands::RemoveConsumer { peer_id } => {
                let request = serde_json::to_string(&Request::MarketMaker(
                    MarketMakerRequest::UnwhitelistConsumer {
                        key: peer_id.clone(),
                    },
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<MarketMakerResponse>(&response).unwrap();
                println!("{}", response);
            }
        }
    }

    fn process_supplier_commands(command: &SupplierCommands, client: TCPClient) {
        match command {
            SupplierCommands::Status => {
                let request =
                    serde_json::to_string(&Request::Supplier(SupplierRequest::Status)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SupplierResponse>(&response).unwrap();
                println!("{}", response);
            }
            SupplierCommands::Start {
                remote,
                port,
                user,
                secure,
            } => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StartSupplier {
                        mm_host: remote.to_owned(),
                        mm_port: *port,
                        name: user.to_owned(),
                        secure_comms: *secure,
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            SupplierCommands::Stop => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StopSupplier)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            SupplierCommands::Supply { devices } => {
                let request =
                    serde_json::to_string(&Request::Supplier(SupplierRequest::SupplyDevices {
                        devices: devices.to_owned(),
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SupplierResponse>(&response).unwrap();
                println!("{}", response);
            }
            SupplierCommands::Reclaim { device, force } => {
                let request =
                    serde_json::to_string(&Request::Supplier(SupplierRequest::ReclaimDevice {
                        device_id: device.to_owned(),
                        force: *force,
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SupplierResponse>(&response).unwrap();
                println!("{}", response);
            }
        }
    }

    fn process_consumer_commands(command: &ConsumerCommands, client: TCPClient) {
        match command {
            ConsumerCommands::Status => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::Status)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::Start { remote, port, user } => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StartConsumer {
                        mm_host: remote.to_owned(),
                        mm_port: *port,
                        name: user.to_owned(),
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::Stop => {
                let request =
                    serde_json::to_string(&Request::System(SysStateRequest::StopConsumer)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<SysStateResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::Reserve { device, no_default } => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::ReserveDevice {
                        device_id: device.to_owned(),
                        no_use: *no_default,
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::Release { device } => {
                let request = if device.is_some() {
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::ReleaseDevice {
                        device_id: device.as_ref().unwrap().to_string(),
                    }))
                    .unwrap()
                } else {
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::ReleaseAllDevices))
                        .unwrap()
                };
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::ListAvailable => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::GetAvailableDevices))
                        .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::GetDevices {
                is_available,
                device_ids,
                device_names,
                device_models,
                supplied_by,
                reserved_by,
            } => {
                let mut filters = Vec::new();

                if let Some(is_available) = is_available {
                    filters.push(DeviceFilter::IsAvailable(*is_available));
                }

                if let Some(device_ids) = device_ids.as_ref() {
                    let device_ids = HashSet::from_iter(device_ids.iter().cloned());
                    filters.push(DeviceFilter::DeviceIds(device_ids));
                }
                if let Some(device_names) = device_names.as_ref() {
                    let device_names = HashSet::from_iter(device_names.iter().cloned());
                    filters.push(DeviceFilter::DeviceNames(device_names));
                }
                if let Some(device_models) = device_models.as_ref() {
                    let device_models = HashSet::from_iter(device_models.iter().cloned());
                    filters.push(DeviceFilter::DeviceModels(device_models));
                }
                if let Some(supplied_by) = supplied_by.as_ref() {
                    let supplied_by = HashSet::from_iter(supplied_by.iter().cloned());
                    filters.push(DeviceFilter::SupplierNames(supplied_by));
                }
                if let Some(reserved_by) = reserved_by.as_ref() {
                    let reserved_by = HashSet::from_iter(reserved_by.iter().cloned());
                    filters.push(DeviceFilter::ConsumerNames(reserved_by));
                }
                let filter_vec = DeviceFilterVec { filters };
                let request = serde_json::to_string(&Request::Consumer(
                    ConsumerRequest::GetDevicesByFilter { filter_vec },
                ))
                .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::ListReserved => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::Status)).unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                match response {
                    ConsumerResponse::Status { state } => {
                        let reserved_devices = state.devices;
                        let using_device = state.using_device.unwrap_or_default();
                        println!("Reserved devices:");
                        for (_, device) in reserved_devices.iter() {
                            println!("{}", device);
                            if device.device_id == using_device {
                                println!(
                                    r"        |
        |----> Current default device"
                                );
                            } else {
                                println!(
                                    r"        |
        |----> Available on port: {}",
                                    device.used_by_port
                                );
                            }
                        }
                        println!();
                    }
                    _ => println!("Unexpected response: {}", response),
                }
            }
            ConsumerCommands::SetDefault { device } => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::UseDevice {
                        device_id: device.to_owned(),
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::Scrcpy {
                device,
                max_size,
                max_fps,
                bit_rate,
            } => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::StartScrCpy {
                        device_id: device.to_owned(),
                        max_size: *max_size,
                        max_fps: *max_fps,
                        bit_rate: *bit_rate,
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
            ConsumerCommands::SetScrcpyArgs {
                max_fps,
                bit_rate,
                max_size,
            } => {
                let request =
                    serde_json::to_string(&Request::Consumer(ConsumerRequest::SetScrCpyDefaults {
                        max_fps: *max_fps,
                        bit_rate: *bit_rate,
                        max_size: *max_size,
                    }))
                    .unwrap();
                let response = client.send(&request, None).unwrap();
                let response = serde_json::from_str::<ConsumerResponse>(&response).unwrap();
                println!("{}", response);
            }
        }
    }
}
