# ADBORC command reference

## Table of Contents

- [Usage](#usage)
- [System Commands](#system-commands)
    - [init](#init)
    - [status](#status)
    - [shutdown](#shutdown)
    - [get-network-id](#get-network-id)
    - [check](#check)
    - [set-adb-path](#set-adb-path)
    - [set-scrcpy-path](#set-scrcpy-path)
- [Marketmaker Commands](#marketmaker-commands)
    - [start](#start)
    - [stop](#stop)
    - [status](#status-1)
    - [use-whitelist](#use-whitelist)
    - [reset-whitelist](#reset-whitelist)
    - [add-supplier](#add-supplier)
    - [remove-supplier](#remove-supplier)
    - [add-consumer](#add-consumer)
    - [remove-consumer](#remove-consumer)
- [Supplier Commands](#supplier-commands)
    - [start](#start-1)
    - [stop](#stop-1)
    - [status](#status-2)
    - [supply](#supply)
    - [reclaim](#reclaim)
- [Consumer Commands](#consumer-commands)
    - [start](#start-2)
    - [stop](#stop-2)
    - [status](#status-3)
    - [list-available](#list-available)
    - [get-devices](#get-devices)
    - [list-reserved](#list-reserved)
    - [reserve](#reserve)
    - [release](#release)
    - [scrcpy](#scrcpy)
    - [set-scrcpy-args](#set-scrcpy-args)
    - [get-scrcpy-args](#get-scrcpy-args)
    - [set-default](#set-default)
- [License](#license)


## Usage

*AdbOrc* commands are organized into subcommands. There are four types of subcommands:

1. *System* commands
2. *MarketMaker* commands
3. *Supplier* commands
4. *Consumer* commands

The `marketmaker`, `supplier` and `consumer` commands are prefixed with the respective role. For example, `adborc marketmaker start` starts the marketmaker. The `system` commands are not prefixed with any role. For example, `adborc init` initializes the system.

The `system` commands are used to initialize the system and interact with system as a whole. The `marketmaker` commands are used to start the system in *MarketMaker* mode and interact with the *marketmaker*. Similarly, the `supplier` and `consumer` commands are used to start the system in *Supplier* and *Consumer* mode and interact with the respective roles.


## System Commands

Following are the `system` commands and their usage:

### init

```bash
adborc init
```

Starts the system listener service. This command must be run before any other command.

### status

```bash
adborc status
```

Get the current status of the system. Returns if the system
is initialized, and if it is, the mode(s) currently active.

### shutdown

```bash
adborc shutdown
```

Shutdown the system. Terminates all active modes (`MarketMaker` / `Supplier` / `Consumer`).

### get-network-id

```bash
adborc get-network-id
```

Get the `network_id` of system.

### check

```bash
adborc check
```

Check if `adb` and `scrcpy` are installed and compatible.
Outputs which modes (`MarketMaker` / `Supplier` / `Consumer`) are
available to be run on the system.

### set-adb-path

```bash
adborc set-adb-path <path>
```

Set the path to the `adb` executable, if not already in `PATH`.
The specified path must be an absolute path to the `adb` executable.

For example: `C:\Users\user\Downloads\platform-tools_r30.0.4-windows\adb.exe`

### set-scrcpy-path

```bash
adborc set-scrcpy-path <path>
```

Set the path to the `scrcpy` executable, if not already in `PATH`.
The specified path must be an absolute path to the `scrcpy` executable.

For example: `C:\Users\user\Downloads\scrcpy-win64-v1.17\scrcpy.exe`

## Marketmaker Commands

Following are the `marketmaker` commands and their usage.

Use `adborc marketmaker <command> help` for more information on each.

### start

```bash
adborc marketmaker start
```

Start a network by running MarketMaker mode on the system.

### stop

```bash
adborc marketmaker stop
```

Terminate the MarketMaker on the system.

__WARNING__: This will terminate the entire network of `Supplier`s and `Consumer`s
connected to the `MarketMaker`.

### status

```bash
adborc marketmaker status
```

Get the current status of MarketMaker.

### use-whitelist

```bash
adborc marketmaker use-whitelist
```

Enable MarketMaker whitelisting for authenticating
`Suppliers` and `Consumers`. When whitelisting is enabled,
only `Suppliers` and `Consumers` whose `network_id` (See: [get-network-id](#get-network-id))
is added to the whitelist will be able to connect to the network.

Use [add-supplier](#add-supplier) and [add-consumer](#add-consumer)
to add `Suppliers` and `Consumers` to the whitelist.
Whitelist is disabled by default.

### reset-whitelist

```bash
adborc marketmaker reset-whitelist
```

Remove the whitelisting requirement for `Supplier`s and `Consumer`s.

### add-supplier

```bash
adborc marketmaker add-supplier <peer-id>
```

Add a `Supplier` to the whitelist. The `peer-id` is the `network_id` of the `Supplier`.

### remove-supplier

```bash
adborc marketmaker remove-supplier <supplier-id>
```

Remove a `Supplier` from the whitelist. The `supplier-id` is the `network_id` of the `Supplier`.

**Note:** This will not terminate the `Supplier` from the network if it is already
connected to the `MarketMaker`.

### add-consumer

```bash
adborc marketmaker add-consumer <peer-id>
```

Add a `Consumer` to the whitelist. The `peer-id` is the `network_id` of the `Consumer`.

### remove-consumer

```bash
adborc marketmaker remove-consumer <peer-id>
```

Remove a `Consumer` from the whitelist. The `peer-id` is the `network_id` of the `Consumer`.

**Note:** This will not terminate the `Consumer` from the network if it is already
connected to the `MarketMaker`.

## Supplier Commands

Following are the `supplier` commands and their usage.

Use `adborc supplier <command> help` for more information on each.

### start

```bash
adborc supplier start <Marketmaker_IP> [-s/--secure] [-u/--user <username>]
```

Connect to a network (`MarketMaker`) and start `Supplier` mode on the system

If `secure` is specified, the `Supplier` will be started in secure mode and
encrypted tunnels will be used for all device communications with the `Consumer`.

If `user` is specified, the specified `username` will be used
to identify the `Supplier` in the network. If not specified, the `Supplier`
will be identified by its ip address. This is for representation purposes only
and does not affect the functionality of the `Supplier`.

### stop

```bash
adborc supplier stop
```

Terminate `Supplier` mode on the system. `Supplier` will be removed from the
network and all supplied devices will be reclaimed.

### status

```bash
adborc supplier status
```

Get the current status of `Supplier`.

### supply

```bash
adborc supplier supply [--devices "serial1,serial2,..."]
```

Supply devices to the network.

If `devices` is not specified, all connected devices will be supplied.

### reclaim

```bash
adborc supplier reclaim <device-id> [-f/--force]
```

Reclaim a device from the network. If the device is currently being used by a `Consumer`,
the reclaim will fail unless `force` is specified.

## Consumer Commands

Following are the `consumer` commands and their usage.

Use `adborc consumer <command> help` for more information on each.

### start

```bash
adborc consumer start <Marketmaker_IP> [-u/--user <username>]
```

Connect to a network (`MarketMaker`) and start `Consumer` mode on the system.


If `user` is specified, the specified `username` will be used
to identify the `Consumer` in the network. If not specified, the `Consumer`
will be identified by its ip address. This is for representation purposes only
and does not affect the functionality of the `Consumer`.

### stop

```bash
adborc consumer stop
```

Terminate `Consumer` mode on the system. `Consumer` will be removed from the
network and all reserved devices will be added back to the network.


### status

```bash
adborc consumer status
```

Get the current status of `Consumer`.

### list-available

```bash
adborc consumer list-available
```

Get a list of available devices in the network.

### get-devices

```bash
adborc consumer get-devices [--is-available <true/false>] [--device-ids <"id1,id2,...">] \
 [--device-names <"name1,name2,...">] [--device-models <"model1,model2,...">] \
 [--supplied-by <"supplier1,supplier2,...">] [--reserved-by <"consumer1,consumer2,...">]
```

Get devices in the network and filter them by some criteria.

If `is_available` is true, only available devices will be returned.

If `is_available` is false, only reserved devices will be returned.

If `is_available` is not specified, all devices will be returned.

If `device_ids` is specified, only devices with the specified ids will be returned.

If `device_names` is specified, only devices with the specified names will be returned.

If `device_models` is specified, only devices with the specified models will be returned.

If `supplied_by` is specified, only devices supplied by the specified `Supplier`s will be returned.

If `reserved_by` is specified, only devices reserved by the specified `Consumer`s will be returned.

### list-reserved

```bash
adborc consumer list-reserved
```

Get a list of reserved devices in the network.

### reserve

```bash
adborc consumer reserve <device-id>
```

Request to reserve a device from the `MarketMaker`. If the device is available,
it will be reserved for the `Consumer` and tunnels (encrypted, if the device
`Supplier` uses secure mode) will be setup for device communication. The device
will be available for use on the `Consumer` system using `adb` on the specified port.
If the device is not available, the request will fail.

See [list-available](#list-available) to get a list of available devices.

### release

```bash
adborc consumer release [device-id]
```

Release a device from the `Consumer`. The device will be added back to the network
and will be available for use by other `Consumer`s.

If no `device-id` is specified, all reserved devices will be released.

### scrcpy

```bash
adborc consumer scrcpy <device-id> [scrcpy-args]
```

Start device screen mirroring using [`scrcpy`](https://github.com/Genymobile/scrcpy) for a device.

`scrcpy-args` are optional arguments to be passed to `scrcpy`. To get a list of available arguments,
run:

`adborc consumer scrcpy --help`.


### set-scrcpy-args

```bash
adborc consumer set-scrcpy-args [scrcpy-args]
```

Set the default arguments to be used when starting `scrcpy` for a device. To get a list of
available arguments, run:

`adborc consumer set-scrcpy-args --help`.

### get-scrcpy-args

```bash
adborc consumer get-scrcpy-args
```

Get the currently set default arguments to be used when starting `scrcpy` for a device.

### set-default

```bash
adborc consumer set-default <device-id>
```

Set a device as the default device. The default device will be available for use
on the `Consumer` system using `adb` on the default port `5037` and extra port arguments
are not required to access the device over `adb`.

## License
*AdbOrc* is licensed under the Apache License 2.0. See [LICENSE] for the full license text.

[LICENSE]: LICENSE