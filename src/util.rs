use std::time::Duration;

/// Constants used by the system.
pub struct SysStateDefaultConfig;

impl SysStateDefaultConfig {
    /// Default host address for the system listener.
    /// Bind to all interfaces.
    pub const BIND_HOST: &'static str = "0.0.0.0";
    /// Default port for the system listener.
    pub const BIND_PORT: u16 = 16063;
}

/// Minimum `adb` major version supported by the system.
pub const MIN_ADB_VER: u8 = 41;
/// Minimum `adb` revision required for `supplier` mode on the system.
pub const MIN_ADB_REV: u8 = 33;
/// Minimim `scrcpy` version required. Only used for `consumer` mode.
/// This is required if device screen mirroring and control is required.
pub const MIN_SCRCPY_VER: u8 = 13;

/// Interval used for sending `heartbeat` messages to the marketmaker.
/// This is used by both `consumer` and `supplier` modes.
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// Interval used by marketmaker to check for heartbeat messages from
/// peer systems. If a system does not send a heartbeat message within
/// this interval, for three consecutive times, it is considered dead
/// and removed from the network.
pub(crate) const UNDERTAKER_INTERVAL: Duration = Duration::from_secs(60);
/// Connection timeout for TCP connections.
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
/// Byte representation of the string "0009host:kill".
pub(crate) const ADB_KILL_SERVER_COMMAND: &[u8; 13] =
    b"\x30\x30\x30\x39\x68\x6f\x73\x74\x3a\x6b\x69\x6c\x6c";

/// Logfile name for logging standard output of the executable.
pub const STDOUT_LOGFILE: &str = "adborc_stdout.log";
/// Logfile name for logging standard error of the executable.
pub const STDERR_LOGFILE: &str = "adborc_stderr.log";
/// PID file name. To be used for checking if the system is already running.
/// Note: This is available only on unix systems.
pub const PID_FILE: &str = "adborc.pid";
/// Environment variable to check, if `adb` messages should be logged.
pub const ADBORC_LOG_ADB: &str = "ADBORC_LOG_ADB";

#[allow(dead_code)]
pub(crate) fn test_with_logs() {
    let debug_test = std::env::var("ADBORC_DEBUG_TEST").unwrap_or_default() == "true";
    if debug_test {
        use env_logger::Builder;
        use log::LevelFilter;
        let mut builder = Builder::from_default_env();
        let _ = builder.filter(None, LevelFilter::Debug).try_init();
    }
}

/// Utils related to `adb` and `scrcpy`.
pub mod adb_utils {

    use super::*;
    use lazy_static::lazy_static;
    use log::{debug, error};
    use pathsearch;
    use portpicker;
    use serde::{Deserialize, Serialize};
    use std::fmt::{self, Display, Formatter};
    use std::io::{self, Error, ErrorKind};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;

    /// Struct to hold adb version information.
    #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
    pub struct AdbVersionInfo {
        /// The major version of adb.
        pub version: String,
        /// The revision of adb.
        pub revision: String,
        /// Path to the adb executable.
        pub path: String,
    }

    impl Display for AdbVersionInfo {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            writeln!(
                f,
                "ADB Version: {}\tRevision: {}\nPath: {}",
                self.version, self.revision, self.path
            )
        }
    }

    /// Struct to hold scrcpy version information.
    #[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
    pub struct ScrcpyVersionInfo {
        /// The major version of scrcpy.
        pub version: String,
        /// Path to the scrcpy executable.
        pub path: String,
    }

    impl Display for ScrcpyVersionInfo {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            writeln!(f, "Scrcpy Version: {}\nPath: {}", self.version, self.path)
        }
    }

    /// Struct to hold information about device.
    #[derive(Serialize, Deserialize, Debug, Default)]
    pub struct DeviceInfo {
        /// Brand of the device.
        pub brand: String,
        /// Name of the device.
        pub name: String,
        /// Model of the device.
        pub model: String,
        /// Android Serial of the device.
        pub android_id: String,
    }

    impl Display for DeviceInfo {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            let s = format!(
                "Brand: {}   Name: {}   Model: {}",
                self.brand, self.name, self.model
            );
            write!(f, "{}", s)
        }
    }

    // DeviceInfo from String of the form: "Brand: <brand>   Name: <name>   Model: <model>"
    // Should return: DeviceInfo {
    //    brand: <brand>,
    //    name: <name>,
    //    model: <model>,
    //    android_id: ""
    // }
    // If the string is not in the expected format, return default DeviceInfo.
    impl From<String> for DeviceInfo {
        fn from(s: String) -> Self {
            let mut device_info = Self::default();
            let split = s.split("   ").collect::<Vec<&str>>();
            if split.len() == 3 {
                device_info.brand = split[0].split(": ").last().unwrap_or_default().to_string();
                device_info.name = split[1].split(": ").last().unwrap_or_default().to_string();
                device_info.model = split[2].split(": ").last().unwrap_or_default().to_string();
            }
            device_info
        }
    }

    /// Arguments to be passed to the `SCRCPY` executable.
    /// Currently supported arguments:
    /// - `--max-fps`: Maximum frames per second.
    /// - `--bit-rate`: Bit rate in Mbps.
    /// - `--max-size`: Maximum size of the device screen.
    #[derive(Serialize, Deserialize, Debug, Clone, Copy)]
    pub struct ScrCpyArgs {
        /// Maximum frames per second. Corresponds to the `--max-fps` argument.
        pub max_fps: u8,
        /// Bit rate in Mbps. Corresponds to the `--bit-rate` argument.
        pub bit_rate: u32,
        /// Maximum size of the device screen.
        /// Corresponds to the `--max-size` argument.
        pub max_size: u16,
    }

    impl Default for ScrCpyArgs {
        fn default() -> Self {
            ScrCpyArgs {
                max_fps: 30,
                bit_rate: 2_000_000,
                max_size: 1920,
            }
        }
    }
    impl Display for ScrCpyArgs {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(
                f,
                "max-fps: {}\nbit-rate: {}\nmax-size: {}",
                self.max_fps, self.bit_rate, self.max_size
            )
        }
    }

    impl ScrCpyArgs {
        pub fn to_vec(&self) -> Vec<String> {
            vec![
                format!("--max-fps={}", self.max_fps),
                format!("--bit-rate={}", self.bit_rate),
                format!("--max-size={}", self.max_size),
            ]
        }
    }

    #[derive(Default)]
    pub(crate) struct ToolsPath {
        adb: Option<PathBuf>,
        scrcpy: Option<PathBuf>,
    }

    lazy_static! {
        static ref TOOLS_PATH: Mutex<ToolsPath> = Mutex::new(ToolsPath::default());
    }

    impl ToolsPath {
        fn set_adb(adb_path: PathBuf) {
            let mut tools_path = TOOLS_PATH.lock().unwrap();
            tools_path.adb = Some(adb_path);
        }

        fn set_scrcpy(scrcpy_path: PathBuf) {
            let mut tools_path = TOOLS_PATH.lock().unwrap();
            tools_path.scrcpy = Some(scrcpy_path);
        }

        fn get_adb() -> Option<PathBuf> {
            let tools_path = TOOLS_PATH.lock().unwrap();
            tools_path.adb.clone()
        }

        fn get_scrcpy() -> Option<PathBuf> {
            let tools_path = TOOLS_PATH.lock().unwrap();
            tools_path.scrcpy.clone()
        }
    }

    pub(crate) fn set_adb_path(adb_path: PathBuf) -> io::Result<()> {
        // Check if the path is valid.
        if !adb_path.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Invalid path specified: {}", adb_path.display()),
            ));
        }
        // Check if the path is a directory.
        if adb_path.is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path is a directory: {}", adb_path.display()),
            ));
        }
        // Check if the path is not absolute.
        if !adb_path.is_absolute() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path is not absolute: {}", adb_path.display()),
            ));
        }
        // Check if the path is "adb".
        if adb_path.file_stem().unwrap_or_default() != "adb" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path not pointing to adb: {}", adb_path.display()),
            ));
        }
        ToolsPath::set_adb(adb_path);
        Ok(())
    }

    pub(crate) fn set_scrcpy_path(scrcpy_path: PathBuf) -> io::Result<()> {
        // Check if the path is valid.
        if !scrcpy_path.exists() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("Invalid path specified: {}", scrcpy_path.display()),
            ));
        }
        // Check if the path is a directory.
        if scrcpy_path.is_dir() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path is a directory: {}", scrcpy_path.display()),
            ));
        }
        // Check if the path is not absolute.
        if !scrcpy_path.is_absolute() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path is not absolute: {}", scrcpy_path.display()),
            ));
        }
        // Check if the path is "scrcpy".
        if scrcpy_path.file_stem().unwrap_or_default() != "scrcpy" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Path not pointing to scrcpy: {}", scrcpy_path.display()),
            ));
        }
        ToolsPath::set_scrcpy(scrcpy_path);
        Ok(())
    }

    /// Get the adb version info.
    /// Returns the version string if successful, otherwise returns an error.
    pub(crate) fn get_adb_version() -> io::Result<AdbVersionInfo> {
        let adb_path = match ToolsPath::get_adb() {
            Some(path) => path,
            None => {
                let adb_path = pathsearch::find_executable_in_path("adb").ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        "adb not found in PATH. Please install adb and try again.",
                    )
                })?;
                ToolsPath::set_adb(adb_path.clone());
                adb_path
            }
        };
        debug!("ADB Path: {}", adb_path.display());
        let output = Command::new(adb_path)
            .arg("version")
            .output()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        if output.status.success() {
            let version =
                String::from_utf8(output.stdout).map_err(|e| Error::new(ErrorKind::Other, e))?;
            // Version info is of the form:
            // Android Debug Bridge version <version>
            // Version <rev>
            // Installed as <path>
            // Result versionInfo is of the form:
            // ADB_VERSION:<ver> REVISION_NO:<rev> ADB_PATH:<path>
            let version_info = version
                .lines()
                .map(|line| line.split(' ').last().unwrap_or_default())
                .collect::<Vec<&str>>();
            Ok(AdbVersionInfo {
                version: version_info[0].to_string(),
                revision: version_info[1].to_string(),
                path: version_info[2].to_string(),
            })
        } else {
            let stderr =
                String::from_utf8(output.stderr).map_err(|e| Error::new(ErrorKind::Other, e))?;
            Err(Error::new(ErrorKind::Other, stderr))
        }
    }

    /// Check if adb version is valid.
    /// Minimum supported adb version is 1.0.41.
    /// For suppliers, minimum adb revision no. required is 33.
    /// Returns true if valid, otherwise returns false.
    #[allow(dead_code)]
    pub(crate) fn check_adb_version(ver_info: &AdbVersionInfo, is_supplier: bool) -> bool {
        let ver_number = ver_info
            .version
            .split('.')
            .last()
            .unwrap_or_default()
            .parse::<u8>()
            .unwrap_or(0);
        if is_supplier {
            let rev_number = ver_info
                .revision
                .split('.')
                .next()
                .unwrap_or_default()
                .parse::<u8>()
                .unwrap_or(0);
            ver_number >= MIN_ADB_VER && rev_number >= MIN_ADB_REV
        } else {
            ver_number >= MIN_ADB_VER
        }
    }

    /// Get the scrcpy version info.
    /// Returns the version string if successful, otherwise returns an error.
    pub(crate) fn get_scrcpy_version() -> io::Result<ScrcpyVersionInfo> {
        let scrcpy_path = match ToolsPath::get_scrcpy() {
            Some(path) => path,
            None => {
                let scrcpy_path =
                    pathsearch::find_executable_in_path("scrcpy").ok_or_else(|| {
                        Error::new(
                            ErrorKind::NotFound,
                            "scrcpy not found in PATH. Please install scrcpy and try again.",
                        )
                    })?;
                ToolsPath::set_scrcpy(scrcpy_path.clone());
                scrcpy_path
            }
        };
        debug!("SCRCPY Path: {}", scrcpy_path.display());
        let output = Command::new(scrcpy_path.clone())
            .arg("-v")
            .output()
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        if output.status.success() {
            let version =
                String::from_utf8(output.stdout).map_err(|e| Error::new(ErrorKind::Other, e))?;
            // Version info is of the form:
            // scrcpy 1.17 <https://github.com/Genymobile/scrcpy>
            // ...
            // ...
            // Result versionInfo is of the form:
            // SCRCPY_VERSION:<ver>
            let version_info = version
                .lines()
                .take(1)
                .map(|line| line.split(' ').nth(1).unwrap_or_default())
                .collect::<Vec<&str>>();
            Ok(ScrcpyVersionInfo {
                version: version_info[0].to_string(),
                path: scrcpy_path.to_string_lossy().to_string(),
            })
        } else {
            let stderr =
                String::from_utf8(output.stderr).map_err(|e| Error::new(ErrorKind::Other, e))?;
            Err(Error::new(ErrorKind::Other, stderr))
        }
    }

    /// Get the devices connected on the system.
    pub fn get_connected_devices() -> Option<Vec<(String, DeviceInfo)>> {
        let stdio = if std::env::var(ADBORC_LOG_ADB).is_ok() {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        // Start the adb server if not already started.
        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args(["server", "nodaemon"])
            .stdout(Stdio::inherit())
            .stderr(stdio)
            .spawn()
            .expect("Failed to start adb server");

        let output = Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .arg("devices")
            .output()
            .ok()?;
        if output.status.success() {
            let devices = String::from_utf8(output.stdout).ok()?;
            let mut devices_lines = devices.lines().skip(1).collect::<Vec<&str>>();
            devices_lines.pop();
            let devices_list = devices_lines
                .iter()
                .map(|line| line.split('\t').next().unwrap_or_default().to_string())
                .collect::<Vec<String>>();
            let mut ret_vec: Vec<(String, DeviceInfo)> = Vec::new();
            for device in devices_list {
                let device_info = get_device_info(&device, None);

                ret_vec.push((device, device_info));
            }
            Some(ret_vec)
        } else {
            None
        }
    }

    fn get_device_info(device_id: &str, port: Option<u16>) -> DeviceInfo {
        let mut device_info = DeviceInfo::default();
        let port = port.unwrap_or(5037);
        let output = Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args([
                "-s",
                device_id,
                "-P",
                port.to_string().as_str(),
                "shell",
                "getprop",
                "ro.product.brand",
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let brand = String::from_utf8_lossy(&output.stdout).to_string();
                device_info.brand = brand.trim().to_string();
            } else {
                error!("`getprop ro.product.brand` returned failure. Failed to get device brand");
            }
        } else {
            error!("Failed to get device brand");
        }

        let output = Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args([
                "-s",
                device_id,
                "-P",
                port.to_string().as_str(),
                "shell",
                "getprop",
                "ro.product.name",
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).to_string();
                device_info.name = name.trim().to_string();
            } else {
                error!("`getprop ro.product.name` returned failure. Failed to get device name");
            }
        } else {
            error!("Failed to get device name");
        }

        let output = Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args([
                "-s",
                device_id,
                "-P",
                port.to_string().as_str(),
                "shell",
                "getprop",
                "ro.product.model",
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let model = String::from_utf8_lossy(&output.stdout).to_string();
                device_info.model = model.trim().to_string();
            } else {
                error!("`getprop ro.product.model` returned failure. Failed to get device model");
            }
        } else {
            error!("Failed to get device model");
        }

        let output = Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args([
                "-s",
                device_id,
                "-P",
                port.to_string().as_str(),
                "shell",
                "settings",
                "get",
                "secure",
                "android_id",
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let android_id = String::from_utf8_lossy(&output.stdout).to_string();
                device_info.android_id = android_id.trim().to_string();
            } else {
                error!("`settings get secure android_id` returned failure. Failed to get secure android_id");
            }
        } else {
            error!("Failed to get device secure android id");
        }

        device_info
    }

    /// Restart the adb server for specific devices at different TCP ports.
    /// Eg: If there are two devices, restart the adb server for each device at different TCP ports.
    /// Takes an Optional vector of device_ids as an argument.
    /// If the Option is None, restart the adb server for all devices.
    /// Returns an Optional vector of tuples (device_id, port).
    pub(crate) fn restart_adb_server_for_devices(
        devices: Option<Vec<String>>,
        secure_comms: bool,
    ) -> Option<Vec<(String, DeviceInfo, u16)>> {
        // Extract the connected devices in the system into a Vector.
        let connected_devices = get_connected_devices()?;

        debug!("Connected devices: {:?}", connected_devices);

        // First, kill the adb server at default port.
        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .arg("kill-server")
            .output()
            .ok()?;
        debug!("Killed adb server at default port");

        // Then, iterate throught the connected_devices list.
        // If the devices vector is None, restart the adb server for all devices.
        // Else, check if the connected device is in the devices list.
        // If it is found, get an available port in the range 20000:21000.
        // Start the adb server for device at the available port.
        let mut ret_vec = Vec::new();

        if let Some(devices) = devices {
            for (device, device_info) in connected_devices {
                if devices.contains(&device) {
                    let port = start_adb_server_for_device(device.clone(), secure_comms);
                    ret_vec.push((device, device_info, port));
                }
            }
        } else {
            for (device, device_info) in connected_devices {
                let port = start_adb_server_for_device(device.clone(), secure_comms);
                ret_vec.push((device, device_info, port));
            }
        }

        if ret_vec.is_empty() {
            None
        } else {
            debug!("Restarted adb server for devices: {:?}", ret_vec);
            Some(ret_vec)
        }
    }

    /// Starts an adb server for a device (identified by `android_serial`) at a random port.
    fn start_adb_server_for_device(device: String, secure_comms: bool) -> u16 {
        let port = portpicker::pick_unused_port().expect("Failed to get an available port");
        debug!("Port allocated for device {} is: {}", device, port);
        let port_as_str = port.to_string();
        let port_as_str = port_as_str.as_str();

        // In windows, `adb --one-device <device_id> start-server` command is not working.
        // So, we use the `adb --one-device <device_id> server nodaemon` command instead.
        let mut start_server_args = vec![
            "--one-device",
            &device,
            "-P",
            port_as_str,
            "server",
            "nodaemon",
        ];

        // Listen on all interfaces if secure comms is disabled.
        if !secure_comms {
            start_server_args.push("-a");
        }

        let stdio = if std::env::var(ADBORC_LOG_ADB).is_ok() {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args(start_server_args)
            .stdout(Stdio::inherit())
            .stderr(stdio)
            .spawn()
            .expect("Failed to start adb server for device");

        port
    }

    pub(crate) fn kill_adb_server_for_port(port: u16) {
        let stdio = if std::env::var(ADBORC_LOG_ADB).is_ok() {
            Stdio::inherit()
        } else {
            Stdio::null()
        };
        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
            .args(["-P", port.to_string().as_str(), "kill-server"])
            .stdout(Stdio::inherit())
            .stderr(stdio)
            .output()
            .expect("Failed to kill adb server for port");
    }

    #[tokio::main]
    pub(crate) async fn start_scrcpy(
        adb_port: u16,
        port: u16,
        scrcpy_args: ScrCpyArgs,
    ) -> io::Result<Child> {
        debug!("Port allocated for scrcpy is: {}", port);
        let port_as_str = port.to_string();
        let scrcpy_args_vec = scrcpy_args.to_vec();
        let mut scrcpy_args_vec = scrcpy_args_vec.iter().map(|s| s.as_str()).collect();

        let mut args = vec!["--port", port_as_str.as_str()];

        args.append(&mut scrcpy_args_vec);

        debug!("Scrcpy args: {:?}", args);

        let scrcpy_path = ToolsPath::get_scrcpy().unwrap_or_else(|| PathBuf::from("scrcpy"));

        Command::new(scrcpy_path)
            .env("ADB_SERVER_SOCKET", format!("tcp:127.0.0.1:{}", adb_port))
            .args(&args)
            .stderr(Stdio::piped())
            .spawn()
    }

    #[cfg(test)]

    mod tests {
        use super::*;

        #[test]
        fn test_get_adb_version() {
            let ver_info = adb_utils::get_adb_version().unwrap();
            assert_eq!(ver_info.version, "1.0.41");
            #[cfg(target_os = "windows")]
            {
                assert_eq!(ver_info.revision, "33.0.1-8253317");
            }
            #[cfg(not(target_os = "windows"))]
            assert_eq!(ver_info.revision, "33.0.2-8557947");
        }

        #[test]
        fn test_check_adb_version() {
            let ver_info = adb_utils::get_adb_version().unwrap();
            assert!(adb_utils::check_adb_version(&ver_info, false));
            let ver_info = adb_utils::get_adb_version().unwrap();
            assert!(adb_utils::check_adb_version(&ver_info, true));
        }

        #[test]
        fn test_restart_adb_server_for_devices() {
            let devices = None;
            let port_map = adb_utils::restart_adb_server_for_devices(devices, false);
            // Since these are device-only tests, we only check if the test does not panic,
            // incase no device is attached to test machine.
            if let Some(port_map) = port_map {
                for (device, _, port) in port_map {
                    let output =
                        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")))
                            .args(["-P", port.to_string().as_str(), "devices"])
                            .output()
                            .unwrap();
                    assert!(String::from_utf8(output.stdout).unwrap().contains(&device));
                }
            }
        }
    }
}
