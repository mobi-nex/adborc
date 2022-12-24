//! This crate provides methods for creating and managing
//! a network of android devices, so that they can be used
//! remotely from any other system on the network. The library
//! is useful if you want to write a program that can control
//! the network programmatically, or if you want to write a
//! wrapper around the library to provide a UI for controlling
//! the network. If you just want to use the network CLI, you
//! should use the `adborc` binary instead.
//!
//! ## Usage
//!
//! This crate is available on [crates.io](https://crates.io/crates/adborc) and can be
//! used by adding `adborc` to the dependencies in your project's `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! adborc = "0.1.0"
//! ```
//!
//! The main module of the library is [`market`]. This module
//! contains the [`market::SysState`] struct, which is the main entry point
//! for starting a network node. The module also contains a
//! submodule called [`market::request`], which contains the
//! formats for sending TCP requests to the network node. Once started,
//! all communication with the network node is done through TCP requests.
//!
//! ## Terminology Used
//!
//! - `System`: A network node. This is the main struct that
//! represents a computer on the network.
//!
//! - `mode`: The mode of a system. This can be either `consumer`,
//! `supplier`, or `marketmaker`. A system can be in any combination
//! of these modes. For example, a system can be consumer and
//! supplier at the same time.
//!
//! - `marketmaker`: This is a system that is the main entry point for
//! the network and sometimes also refered as just the network.
//! It is the only system that can be in marketmaker mode in
//! a given network. It is responsible for managing the network, and all
//! the metadata about the network.
//!
//! - `consumer`: A system that can make requests for using a device on
//! the network. For a system to be a consumer, it has to join a network
//! (a system where marketmaker is started).
//!
//! - `supplier`: A system that can provide a device to be used on the
//! network. For a system to be a supplier, it has to join a network
//! (a system where marketmaker is started).
//!
//! - `devices`: The android devices that are connected to supplier systems
//! on the network. Once a device is supplied by the supplier, it can be
//! used by any consumer on the network.
//!
//! ## Example
//!
//! The following example shows how to start a network node, and then
//! start a `marketmaker` on it.
//!
//! ```rust no_run
//! # use std::thread;
//! use adborc::{
//!     market::{SysState, request::
//!             {Request, SysStateRequest, SysStateResponse}},
//!     net::TCPClient,
//!     util::SysStateDefaultConfig
//! };
//! # use serde_json;
//!
//! // start the system in a separate thread.
//! thread::spawn(|| SysState::start_system().unwrap());
//!
//! let client = TCPClient::new("localhost", SysStateDefaultConfig::BIND_PORT).unwrap();
//! // Construct a request to start the marketmaker.
//! let request = Request::System(SysStateRequest::StartMarketMaker);
//! let response = client.send_request(&request, None).unwrap();
//! let expected_response = Response(System(SysStateResponse::StartMarketMakerSuccess));
//! assert_eq!(response, serde_json::to_string(&expected_response).unwrap());
//! ```
//!

pub mod net;

pub mod market;

pub mod util;

mod noise;
