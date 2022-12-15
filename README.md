# AdbOrc

*AdbOrc* makes it easy to create psuedo-distributed network of android devices.
It is a simple wrapper around `adb` that allows you to easily share
devices with other users on your network. Securely share your devices
within your network for testing, debugging or development.

## Overview

There are three modes of operation for a network node in AdbOrc:

1. *Supplier* - A machine on the network that has one or more android
    devices attached to it. *Supplier*, as the name implies, supplies
    devices to the network. There can be any number of *Supplier*s on
    the network.

2. *Consumer* - A machine on the network that wants to use one or more
    android devices. *Consumer*, as the name implies, consumes devices
    from the network. There can be any number of *Consumer*s on the
    network.

3. *MarketMaker* - A machine on the network that acts as a middleman
    between *Supplier*s and *Consumer*s. MarketMaker is responsible
    for matching Suppliers and Consumers and handling all the metadata
    of the network. There is exactly one *MarketMaker* on the network.
    For Suppliers and Consumers, MarketMaker serves as a proxy
    for the network.

A system on the network can be operating in any combination of the
above modes. For example, a system can be a *Supplier* and a *Consumer*
at the same time. It can also be a *MarketMaker* and a *Consumer* at
the same time.

Supplying devices to the network is as simple as joining the network
as a *Supplier* and choosing the devices you wish to supply.

To use devices from the network, you need to join the network as a
*Consumer* and list the available devices within the network.
You can then choose the devices you wish to use and ask *MarketMaker*
to reserve them for you. Once you are done using the devices, you can
release them back to the network.

All reserved devices are available for use only to the *Consumer* that
reserved them. The devices are available directly via `adb`. Device
screen mirroring for reserved devices is also supported directly by
AdbOrc via [`scrcpy`](https://github.com/Genymobile/scrcpy).

All communications between *Supplier*s, *Consumer*s and *MarketMaker*
are encrypted using the Noise Protocol Framework. The encryption keys
are generated using the *X25519* curve and the *ChaChaPoly* cipher suite
with *Blake2s* as the hash function. The 
*XX_25519_ChaChaPoly_BLAKE2s* handshake pattern is used.

By default, device communications within the network between *Supplier*s
and *Consumer*s are **NOT** encrypted. However, *Supplier*s can choose to
encrypt device communications with *Consumer*s using the same Noise
protocol cipher suites (uses `KK` pattern). This is done by simply enabling
`secure_mode` while joining the network as a *Supplier*. 


## Usage

Start the network by starting *MarketMaker* on a machine:

```bash
$ adborc marketmaker start
```

Join the network as a *Supplier* from another machine:

```bash
$ adborc supplier start <MarketMaker_IP>

# Or, if you wish to enable secure mode
$ adborc supplier start <MarketMaker_IP> --secure

# Supply specific devices to the network
$ adborc supplier supply --devices "<android_serial1>,<android_serial2>,..."

# Or, supply all connected devices
$ adborc supplier supply
```

Join the network as a *Consumer* from another machine:

```bash
$ adborc consumer start <MarketMaker_IP>

# List available devices
$ adborc consumer list-available

# Reserve devices
$ adborc consumer reserve <device_id>

# Use the devices via adb
$ adb shell

# Or, use the devices via scrcpy
$ adborc consumer scrcpy <device_id>
```

For a more detailed usage, see the [command reference][REFERENCE]

[REFERENCE]: REFERENCE.md


## Installation

### From source

```bash
# Assuming you have the rust toolchain installed
$ cargo install --git https://github.com/mobi-nex/adborc.git 

# Or, if you want to build from local source
$ git clone https://github.com/mobi-nex/adborc.git
$ cd adborc

$ cargo install --path .
```

### From crates.io

```bash
# Assuming you have the rust toolchain installed
$ cargo install adborc
```

*Note*: AdbOrc in *Consumer*/*Supplier* mode requires `adb` to be installed on the system. It also
requires `scrcpy` to be installed on the system if you wish to use
device screen mirroring. See [dependencies](#dependencies) section for more details. 

### From releases (Windows only)

You can download the latest release from [here](https://github.com/mobi-nex/adborc/releases).
The release contains all dependencies bundled, including `adb` and `scrcpy`.
Just extract the archive and run `adborc.exe` on the command line from the
extracted directory.

## Dependencies

AdbOrc depends on the following:
1. [`adb`](https://developer.android.com/studio/releases/platform-tools) - Android Debug Bridge
2. [`scrcpy`](https://github.com/Genymobile/scrcpy) - *Optional*, for screen mirroring

For *MarketMaker* mode, none of the above are required.

For *Consumer* mode to work, minimum version of `adb` required is *1.0.41*.

Optionally, `scrcpy` can be used for screen mirroring. Minimum version of
`scrcpy` required is *1.13*.

For *Supplier* mode to work, minimum version of `adb` required is *1.0.41*, with
minimum revision number of *33.0.1*.

*Note:* `scrcpy` is not required for *Supplier* mode.

You can override the default `adb` and `scrcpy` used by:
```bash
# Full path to the adb executable
$ adborc set-adb-path <path_to_adb>

# Full path to the scrcpy executable
$ adborc set-scrcpy-path <path_to_scrcpy>
```

See [command reference][REFERENCE] for more details.

## Contributing

Contributions are welcome! Please feel free to open issues and pull requests.

Just make sure to run `cargo fmt` and `cargo clippy` before submitting a PR.

## License

AdbOrc is licensed under the Apache License 2.0. See [LICENSE] for more details.

[LICENSE]: LICENSE