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

pub(crate) const ADBORC_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    #[cfg(windows)]
    use std::os::windows::process::CommandExt;

    #[allow(dead_code)]
    const CREATE_NO_WINDOW: u32 = 0x08000000;

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
        /// Complete version string of scrcpy.
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

    /// Arguments that may be passed to the `SCRCPY` executable.
    /// Currently supported arguments:
    /// - `--max-fps`: Maximum frames per second.
    /// - `--bit-rate`: Bit rate in Mbps.
    /// - `--max-size`: Maximum size of the device screen.
    #[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq)]
    pub enum ScrCpyArgs {
        /// Maximum frames per second. Corresponds to the `--max-fps` argument.
        MaxFps(u8),
        /// Bit rate in Mbps. Corresponds to the `--bit-rate` argument.
        BitRate(u32),
        /// Maximum size of the device screen.
        /// Corresponds to the `--max-size` argument.
        MaxSize(u16),
    }

    // Implement PartialEq for ScrCpyArgs such that, ScrCpyArgs::MaxFps(30) and ScrCpyArgs::MaxFps(60)
    // are equal.
    impl PartialEq for ScrCpyArgs {
        fn eq(&self, other: &Self) -> bool {
            matches!(
                (self, other),
                (ScrCpyArgs::MaxFps(_), ScrCpyArgs::MaxFps(_))
                    | (ScrCpyArgs::BitRate(_), ScrCpyArgs::BitRate(_))
                    | (ScrCpyArgs::MaxSize(_), ScrCpyArgs::MaxSize(_))
            )
        }
    }

    // implment hashing for ScrCpyArgs such that, ScrCpyArgs::MaxFps(30) and ScrCpyArgs::MaxFps(60)
    // have same hash value.
    impl std::hash::Hash for ScrCpyArgs {
        fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
            match self {
                ScrCpyArgs::MaxFps(_) => {
                    "max-fps".hash(state);
                }
                ScrCpyArgs::BitRate(_) => {
                    "bit-rate".hash(state);
                }
                ScrCpyArgs::MaxSize(_) => {
                    "max-size".hash(state);
                }
            }
        }
    }

    impl Display for ScrCpyArgs {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            match self {
                ScrCpyArgs::MaxFps(max_fps) => write!(f, "--max-fps={}", max_fps),
                ScrCpyArgs::BitRate(bit_rate) => write!(f, "--bit-rate={}", bit_rate),
                ScrCpyArgs::MaxSize(max_size) => write!(f, "--max-size={}", max_size),
            }
        }
    }

    #[allow(clippy::match_single_binding)]
    fn get_min_required_version(arg: &ScrCpyArgs) -> f32 {
        match arg {
            // Add any arguments that have version requirements higher than MIN_SCRCPY_VER here.
            // Eg:
            // ScrCpyArgs::BitRate(_) => 1.17,

            // Default case. Minimum required version is MIN_SCRCPY_VER.
            // NOTE: This will break if MIN_SCRCPY_VER > 100. We will handle
            // that case when it arises. This will also break if SCRCPY_MAJOR_VER
            // is bumped to 2. But a lot of things will break if that happens.
            _ => 1.0 + (MIN_SCRCPY_VER as f32) / 100.0,
        }
    }

    fn check_scrcpy_arg_version(arg: &ScrCpyArgs, scrcpy_version: f32) -> bool {
        let min_required_version = get_min_required_version(arg);
        scrcpy_version >= min_required_version
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

        fn find_scrcpy_in_path() -> Option<PathBuf> {
            use std::env;
            let current_exe = env::current_exe().unwrap();
            let current_exe_dir = current_exe.parent().unwrap();
            // During bundling, the `scrcpy` executable is copied to the
            // same location as that of the `adborc` executable.
            // So, we check if it is in the executable directory.
            let scrcpy_exe = if cfg!(windows) {
                current_exe_dir.join("scrcpy").with_extension("exe")
            } else {
                current_exe_dir.join("scrcpy")
            };

            if scrcpy_exe.exists() {
                Some(scrcpy_exe)
            } else {
                pathsearch::find_executable_in_path("scrcpy")
            }
        }

        fn find_adb_in_path() -> Option<PathBuf> {
            use std::env;
            let current_exe = env::current_exe().unwrap();
            let current_exe_dir = current_exe.parent().unwrap();
            // During bundling, the `adb` executable is copied to the
            // same location as that of the `adborc` executable.
            // So, we check if it is in the executable directory.
            let adb_exe = if cfg!(windows) {
                current_exe_dir.join("adb").with_extension("exe")
            } else {
                current_exe_dir.join("adb")
            };

            if adb_exe.exists() {
                Some(adb_exe)
            } else {
                pathsearch::find_executable_in_path("adb")
            }
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
                let adb_path = ToolsPath::find_adb_in_path().ok_or_else(|| {
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
        let mut command = Command::new(adb_path);

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command.arg("version");
        let output = command
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
                let scrcpy_path = ToolsPath::find_scrcpy_in_path().ok_or_else(|| {
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
        let mut command = Command::new(scrcpy_path.clone());
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command.arg("--version");

        let output = command
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
        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command
            .args(["start-server"])
            .stdout(Stdio::inherit())
            .stderr(stdio)
            .output()
            .expect("Failed to start adb server");

        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let output = command.arg("devices").output().ok()?;
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
        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let output = command
            .args([
                "-P",
                &port.to_string(),
                "-s",
                device_id,
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

        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let output = command
            .args([
                "-P",
                &port.to_string(),
                "-s",
                device_id,
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

        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let output = command
            .args([
                "-P",
                &port.to_string(),
                "-s",
                device_id,
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

        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let output = command
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
        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command.args(["kill-server"]).output().ok()?;

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
        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command
            .args(&start_server_args)
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
        let mut command =
            Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command
            .args(["-P", port.to_string().as_str(), "kill-server"])
            .stdout(Stdio::inherit())
            .stderr(stdio)
            .output()
            .expect("Failed to kill adb server for port");
    }

    pub(crate) fn start_scrcpy(
        adb_port: u16,
        port: u16,
        scrcpy_args: Vec<ScrCpyArgs>,
    ) -> io::Result<Child> {
        let scrcpy_version = get_scrcpy_version()?.version;
        let scrcpy_version = scrcpy_version.parse::<f32>().unwrap_or(0.0);
        debug!("Port allocated for scrcpy is: {}", port);
        let port_as_str = port.to_string();
        let scrcpy_args_vec = scrcpy_args
            .iter()
            .filter(|&s| check_scrcpy_arg_version(s, scrcpy_version))
            .map(|s| format!("{}", s))
            .collect::<Vec<String>>();
        let mut scrcpy_args_vec = scrcpy_args_vec.iter().map(|s| s.as_str()).collect();

        let mut args = vec!["--port", port_as_str.as_str()];

        args.append(&mut scrcpy_args_vec);

        debug!("Scrcpy args: {:?}", args);

        let scrcpy_path = ToolsPath::get_scrcpy().unwrap_or_else(|| PathBuf::from("scrcpy"));

        let mut command = Command::new(scrcpy_path);

        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        command
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
                    let mut command =
                        Command::new(ToolsPath::get_adb().unwrap_or_else(|| PathBuf::from("adb")));
                    #[cfg(windows)]
                    command.creation_flags(CREATE_NO_WINDOW);

                    command.args(["-P", port.to_string().as_str(), "devices"]);

                    let output = command.output().unwrap();
                    assert!(String::from_utf8(output.stdout).unwrap().contains(&device));
                }
            }
        }
    }
}
