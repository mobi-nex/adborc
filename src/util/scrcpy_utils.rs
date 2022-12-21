//! This module contains utility functions for scrcpy.
//! The contents of this module were part of the crate::util::adb_utils module.
//! However, they were moved to this module because they got too big.
//! This module is not meant to be used directly by the user.
//! To avoid re-organizing the code, all the functions (which were part of adb_utils earlier)
//! in this module are re-exported by the crate::util::adb_utils module.

use super::*;
use clap::Args;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

pub const SCRCPY_SHORTCUT_HELP: &str = r"
    In the following list, MOD is the shortcut modifier. By default, it's (left) Alt or (left) Super.

    MOD+f
        Switch fullscreen mode

    MOD+Left
        Rotate display left

    MOD+Right
        Rotate display right

    MOD+g
        Resize window to 1:1 (pixel-perfect)

    MOD+w
    Double-click on black borders
        Resize window to remove black borders

    MOD+h
    Middle-click
        Click on HOME

    MOD+b
    MOD+Backspace
    Right-click (when screen is on)
        Click on BACK

    MOD+s
    4th-click
        Click on APP_SWITCH

    MOD+m
        Click on MENU

    MOD+Up
        Click on VOLUME_UP

    MOD+Down
        Click on VOLUME_DOWN

    MOD+p
        Click on POWER (turn screen on/off)

    Right-click (when screen is off)
        Power on

    MOD+o
        Turn device screen off (keep mirroring)

    MOD+Shift+o
        Turn device screen on

    MOD+r
        Rotate device screen

    MOD+n
    5th-click
        Expand notification panel

    MOD+Shift+n
        Collapse notification panel

    MOD+c
        Copy to clipboard (inject COPY keycode, Android >= 7 only)

    MOD+x
        Cut to clipboard (inject CUT keycode, Android >= 7 only)

    MOD+v
        Copy computer clipboard to device, then paste (inject PASTE keycode, Android >= 7 only)

    MOD+Shift+v
        Inject computer clipboard text as a sequence of key events

    MOD+i
        Enable/disable FPS counter (print frames/second in logs)

    Ctrl+click-and-move
        Pinch-to-zoom from the center of the screen

    Drag & drop APK file
        Install APK from computer

    Drag & drop non-APK file
        Push file to device (see --push-target)";

#[derive(Args)]
pub struct ScrcpyCliArgs {
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
    /// Set a custom window title.
    #[clap(long, value_parser)]
    window_title: Option<String>,
    /// Set the initial window horizontal position.
    #[clap(long, value_parser)]
    window_x: Option<i16>,
    /// Set the initial window vertical position.
    #[clap(long, value_parser)]
    window_y: Option<i16>,
    /// Set the initial window width.
    #[clap(long, value_parser)]
    window_width: Option<u16>,
    /// Set the initial window height.
    #[clap(long, value_parser)]
    window_height: Option<u16>,
    /// Specify the display id to mirror.
    #[clap(long, value_parser)]
    display: Option<u16>,
    /// Record the device screen to a file.
    /// The file format is determined from `--record-format` option if specified,
    /// otherwise it is deduced from the file extension.
    #[clap(short, long, value_parser)]
    record: Option<String>,
    /// Force recording format. One of: mp4, mkv
    #[clap(long, value_parser)]
    record_format: Option<String>,
    /// Make the window always-on-top.
    #[clap(long, action)]
    always_on_top: bool,
    /// Start in fullscreen.
    #[clap(short, long, action)]
    fullscreen: bool,
    /// Show touches.
    #[clap(short = 't', long, action)]
    show_touches: bool,
    /// Turn the device screen off.
    #[clap(short = 'S', long, action)]
    turn_screen_off: bool,
    /// Disable the window decorations
    #[clap(long, action)]
    window_borderless: bool,
    /// Keep the device screen on while mirroring, when the device is plugged in.
    #[clap(short = 'w', long, action)]
    stay_awake: bool,
    /// Disable device control (mirror the device in read-only mode).
    #[clap(short, long, action)]
    no_control: bool,
    /// Do not display the device screen (only when screen recording is enabled).
    #[clap(short = 'N', long, action)]
    no_display: bool,
}

pub(crate) fn get_scrcpy_args(args: ScrcpyCliArgs) -> Vec<ScrCpyArgs> {
    let mut scrcpy_args = Vec::new();
    if let Some(max_size) = args.max_size {
        scrcpy_args.push(ScrCpyArgs::MaxSize(max_size));
    }
    if let Some(max_fps) = args.max_fps {
        scrcpy_args.push(ScrCpyArgs::MaxFps(max_fps));
    }
    if let Some(bit_rate) = args.bit_rate {
        scrcpy_args.push(ScrCpyArgs::BitRate(bit_rate));
    }
    if let Some(window_title) = args.window_title {
        scrcpy_args.push(ScrCpyArgs::WindowTitle(window_title));
    }
    if let Some(window_x) = args.window_x {
        scrcpy_args.push(ScrCpyArgs::WindowX(window_x));
    }
    if let Some(window_y) = args.window_y {
        scrcpy_args.push(ScrCpyArgs::WindowY(window_y));
    }
    if let Some(window_width) = args.window_width {
        scrcpy_args.push(ScrCpyArgs::WindowWidth(window_width));
    }
    if let Some(window_height) = args.window_height {
        scrcpy_args.push(ScrCpyArgs::WindowHeight(window_height));
    }
    if let Some(display) = args.display {
        scrcpy_args.push(ScrCpyArgs::Display(display));
    }
    if let Some(record) = args.record {
        scrcpy_args.push(ScrCpyArgs::Record(record));
    }
    if let Some(record_format) = args.record_format {
        scrcpy_args.push(ScrCpyArgs::RecordFormat(record_format));
    }
    if args.always_on_top {
        scrcpy_args.push(ScrCpyArgs::AlwaysOnTop);
    }
    if args.fullscreen {
        scrcpy_args.push(ScrCpyArgs::Fullscreen);
    }
    if args.stay_awake {
        scrcpy_args.push(ScrCpyArgs::StayAwake);
    }
    if args.show_touches {
        scrcpy_args.push(ScrCpyArgs::ShowTouches);
    }
    if args.turn_screen_off {
        scrcpy_args.push(ScrCpyArgs::TurnScreenOff);
    }
    if args.window_borderless {
        scrcpy_args.push(ScrCpyArgs::WindowBorderless);
    }
    if args.no_control {
        scrcpy_args.push(ScrCpyArgs::NoControl);
    }
    if args.no_display {
        scrcpy_args.push(ScrCpyArgs::NoDisplay);
    }
    scrcpy_args
}

/// Arguments that may be passed to the `scrcpy` executable.
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub enum ScrCpyArgs {
    /// Maximum frames per second. Corresponds to the `--max-fps` argument.
    MaxFps(u8),
    /// Bit rate in Mbps. Corresponds to the `--bit-rate` argument.
    BitRate(u32),
    /// Maximum size of the device screen.
    /// Corresponds to the `--max-size` argument.
    MaxSize(u16),
    /// Window title.
    /// Corresponds to the `--window-title` argument.
    WindowTitle(String),
    /// Window x position.
    /// Corresponds to the `--window-x` argument.
    WindowX(i16),
    /// Window y position.
    /// Corresponds to the `--window-y` argument.
    WindowY(i16),
    /// Window width.
    /// Corresponds to the `--window-width` argument.
    WindowWidth(u16),
    /// Window height.
    /// Corresponds to the `--window-height` argument.
    WindowHeight(u16),
    /// Specify the display to mirror.
    /// Corresponds to the `--display` argument.
    Display(u16),
    /// Record the device screen.
    /// Corresponds to the `--record` argument.
    Record(String),
    /// Force recording format.
    /// Corresponds to the `--record-format` argument.
    RecordFormat(String),
    /// Make scrcpy window always on top.
    /// Corresponds to the `--always-on-top` argument.
    AlwaysOnTop,
    /// Make scrcpy window fullscreen.
    /// Corresponds to the `--fullscreen` argument.
    Fullscreen,
    /// Show touches on the device screen.
    /// Corresponds to the `--show-touches` argument.
    ShowTouches,
    /// Turn the device screen off immediately.
    /// Corresponds to the `--turn-screen-off` argument.
    TurnScreenOff,
    /// Disable window decorations.
    /// Corresponds to the `--window-borderless` argument.
    WindowBorderless,
    /// Stay awake while device is in use.
    /// Corresponds to the `--stay-awake` argument.
    StayAwake,
    /// Disable device control.
    /// Corresponds to the `--no-control` argument.
    NoControl,
    /// Do not mirror the device screen.
    /// Corresponds to the `--no-display` argument.
    NoDisplay,
}

// Implement PartialEq for ScrCpyArgs such that, ScrCpyArgs::MaxFps(30) and ScrCpyArgs::MaxFps(60)
// are equal.
impl PartialEq for ScrCpyArgs {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

// implment hashing for ScrCpyArgs such that, ScrCpyArgs::MaxFps(30) and ScrCpyArgs::MaxFps(60)
// have same hash value.
impl std::hash::Hash for ScrCpyArgs {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
    }
}

impl Display for ScrCpyArgs {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ScrCpyArgs::MaxFps(max_fps) => write!(f, "--max-fps={}", max_fps),
            ScrCpyArgs::BitRate(bit_rate) => write!(f, "--bit-rate={}", bit_rate),
            ScrCpyArgs::MaxSize(max_size) => write!(f, "--max-size={}", max_size),
            ScrCpyArgs::WindowTitle(window_title) => {
                write!(f, "--window-title={}", window_title)
            }
            ScrCpyArgs::WindowX(window_x) => write!(f, "--window-x={}", window_x),
            ScrCpyArgs::WindowY(window_y) => write!(f, "--window-y={}", window_y),
            ScrCpyArgs::WindowWidth(window_width) => {
                write!(f, "--window-width={}", window_width)
            }
            ScrCpyArgs::WindowHeight(window_height) => {
                write!(f, "--window-height={}", window_height)
            }
            ScrCpyArgs::Display(display) => write!(f, "--display={}", display),
            ScrCpyArgs::Record(record) => write!(f, "--record={}", record),
            ScrCpyArgs::RecordFormat(record_format) => {
                write!(f, "--record-format={}", record_format)
            }
            ScrCpyArgs::NoControl => write!(f, "--no-control"),
            ScrCpyArgs::NoDisplay => write!(f, "--no-display"),
            ScrCpyArgs::TurnScreenOff => write!(f, "--turn-screen-off"),
            ScrCpyArgs::StayAwake => write!(f, "--stay-awake"),
            ScrCpyArgs::AlwaysOnTop => write!(f, "--always-on-top"),
            ScrCpyArgs::Fullscreen => write!(f, "--fullscreen"),
            ScrCpyArgs::ShowTouches => write!(f, "--show-touches"),
            ScrCpyArgs::WindowBorderless => write!(f, "--window-borderless"),
        }
    }
}

#[inline(always)]
fn get_min_required_version(arg: &ScrCpyArgs) -> u8 {
    match arg {
        // Add any arguments that have version requirements higher than MIN_SCRCPY_VER here.
        // Eg:
        // ScrCpyArgs::BitRate(_) => 17,
        ScrCpyArgs::StayAwake => 14,

        // Default case. Minimum required version is MIN_SCRCPY_VER.
        // NOTE: This will break if MIN_SCRCPY_VER > 100. We will handle
        // that case when it arises. This will also break if SCRCPY_MAJOR_VER
        // is bumped to 2. But a lot of things will break if that happens.
        _ => MIN_SCRCPY_VER,
    }
}

pub(crate) fn check_scrcpy_arg_version(arg: &ScrCpyArgs, ver_number: u8) -> bool {
    let min_required_version = get_min_required_version(arg);
    ver_number >= min_required_version
}
