use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use snow::TransportState;
use socket2::{Domain, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{
    mpsc::{self, Receiver, Sender, TryRecvError},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    task,
    time::timeout,
};

use crate::market::{request::ToJson, Key, SystemKeypair};
use crate::noise::Noise;
use crate::util::{ADB_KILL_SERVER_COMMAND, CONNECTION_TIMEOUT};

/// Networking client which is used to send encrypted commands,
/// receive encrypted responses from the server and decrypt them.
/// The frontend application will use this to interact with the running system,
/// and the system will use it to communicate with each other.
/// NOTE: System above refers to an adborc server operating in any of the modes.
pub struct TCPClient {
    /// The socket address of the server.
    pub(crate) addr: SocketAddr,
    /// Hostname or IP of the server.
    host: String,
    /// Port number of the server.
    port: u16,
}

pub(crate) type StopSender = Mutex<Option<Sender<()>>>;

lazy_static! {
    static ref STOP_SENDER: StopSender = Mutex::new(None);
}

impl From<SocketAddr> for TCPClient {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }
}

impl TCPClient {
    /// Create a new TCPClient with the given destination host and port.
    #[tokio::main]
    pub async fn new(host: &str, port: u16) -> io::Result<TCPClient> {
        let addr = parse_addr(host, port, false).await?;
        Ok(TCPClient {
            addr,
            host: host.to_string(),
            port,
        })
    }

    /// Check if the destination server is running and return the TCPstream if it is running.
    #[tokio::main]
    pub(crate) async fn test_connect(&self) -> io::Result<TcpStream> {
        let timeout_result = timeout(CONNECTION_TIMEOUT, TcpStream::connect(self.addr)).await;
        match timeout_result {
            Ok(stream) => stream,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Connection failed/timed out",
            )),
        }
    }

    /// Send any string to the server with the given timeout and return the response, if received.
    #[tokio::main]
    pub async fn send(&self, data: &str, timeout_in_sec: Option<u64>) -> io::Result<String> {
        debug!(
            "Request received to send data: {}\t\tto host: {}\tat port: {}",
            data, self.host, self.port
        );
        let mut stream = match timeout(CONNECTION_TIMEOUT, TcpStream::connect(self.addr)).await {
            Ok(stream) => stream,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Connection failed/timed out",
                ))
            }
        }?;
        debug!("Connection established");
        let timeout = timeout_in_sec.map(|t| Duration::new(t, 0));
        stream.set_linger(timeout)?;

        let private_key = SystemKeypair::get_private_key();
        let noise;

        if let Some(private_key) = private_key {
            noise = Noise::build_initiator_with_key(private_key)?;
        } else {
            (noise, _) = Noise::build_initiator()?;
        }

        // Allocate a buffer of 65536 bytes.
        let mut buf = [0u8; 65536];
        let mut noise = Noise::initiator_handshake(noise, &mut stream, &mut buf).await?;
        Noise::encrypt_and_send(&mut noise, &mut stream, data.as_bytes(), &mut buf).await?;
        let response = Noise::decrypt_message(&mut noise, &mut stream, &mut buf).await?;
        Ok(response)
    }

    /// Send a [`crate::market::request::Request`] to the server with the given timeout and
    /// return the response, if received.
    pub fn send_request<T>(&self, request: T, timeout_in_sec: Option<u64>) -> io::Result<String>
    where
        T: ToJson,
    {
        // Unwrapping is safe here because we are using a known enum variant
        // which is guaranteed to be serializable.
        let request = request.to_json();
        self.send(request.as_str(), timeout_in_sec)
    }

    /// Send a [`crate::market::request::Request`] to the server without waiting for a response.
    #[tokio::main]
    pub async fn send_no_wait<T>(&self, data: T)
    where
        T: ToJson,
    {
        // Unwrapping is safe here because we are using a known enum variant
        // which is guaranteed to be serializable.
        let data = data.to_json();
        debug!(
            "Sending data: {}\t\tto host: {}\tat port: {}",
            data, self.host, self.port
        );
        let stream = match timeout(CONNECTION_TIMEOUT, TcpStream::connect(self.addr)).await {
            Ok(stream) => stream,
            Err(_) => {
                error!("Connection timed out");
                return;
            }
        };
        if let Ok(mut stream) = stream {
            debug!("Connection established");
            let private_key = SystemKeypair::get_private_key();
            let noise;
            if let Some(private_key) = private_key {
                let result = Noise::build_initiator_with_key(private_key);
                if result.is_err() {
                    error!("Error while building initiator: {}", result.err().unwrap());
                    return;
                }
                noise = result.unwrap();
            } else {
                let result = Noise::build_initiator();
                if result.is_err() {
                    error!("Error while building initiator: {}", result.err().unwrap());
                    return;
                }
                (noise, _) = result.unwrap();
            }

            // Allocate a buffer of 65536 bytes.
            let mut buf = [0u8; 65536];
            let noise = Noise::initiator_handshake(noise, &mut stream, &mut buf).await;
            if noise.is_err() {
                error!("Error while performing handshake: {}", noise.err().unwrap());
                return;
            }
            let mut noise = noise.unwrap();
            let result =
                Noise::encrypt_and_send(&mut noise, &mut stream, data.as_bytes(), &mut buf).await;
            if result.is_err() {
                error!("Error while sending message: {}", result.err().unwrap());
            }
        } else {
            error!("Connection failed");
        }
    }
}

/// Networking server which is used to receive commands from the client.
/// Commands are forwarded to the appropriate command handler.
pub(crate) struct CommandServer {
    pub host: String,
    pub port: u16,
}

pub(crate) type ProcessFn = fn(String, SocketAddr, Arc<Key>) -> String;

impl CommandServer {
    pub async fn start(&mut self, process_command: ProcessFn) -> io::Result<()> {
        debug!("Starting server on {}:{}", self.host, self.port);
        let (tx, rx) = mpsc::channel::<()>();
        Self::update_tx(tx);
        // Generate a keypair for the server, if not already created.
        if SystemKeypair::is_none() {
            let (_, keypair) = Noise::build_responder()?;
            debug!("Public key is: {}", base64::encode(&keypair.public));
            SystemKeypair::set_keypair(keypair);
        }
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        let address = parse_addr(&self.host, self.port, false).await?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        let listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(listener)?;
        debug!("Server started on {}:{}", self.host, self.port);
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                task::spawn(async move {
                    debug!("Connection established");
                    if let Ok(()) = stream.readable().await {
                        Self::handle_stream(stream, process_command).await;
                    }
                });
                match rx.try_recv() {
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        debug!("Received stop signal, shutting down server");
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        // Continue.
                    }
                };
            }
        }
        info!("Server stopped");
        Ok(())
    }
    async fn handle_stream(mut stream: TcpStream, process_command: ProcessFn) {
        let init_msg = Noise::recv(&mut stream).await;
        if init_msg.is_err() {
            debug!(
                "Connection without a message/Unauthenticated access: {}",
                init_msg.err().unwrap()
            );
            return;
        }
        let init_msg = init_msg.unwrap();
        let private_key = SystemKeypair::get_private_key();
        if private_key.is_none() {
            error!("Private key not set");
            return;
        }
        let private_key = private_key.unwrap();

        let noise = Noise::build_responder_with_key(private_key);
        if noise.is_err() {
            error!("Error building responder: {}", noise.err().unwrap());
            return;
        }
        let noise = noise.unwrap();

        // Allocate 65KB buffer for reading request from client.
        let mut buf = [0_u8; 65535];
        // It seems ok to unwrap the address here because handle_stream is only
        // called on a valid stream and in a separate thread so it should not
        // cause the main server to panic.
        let peer_addr = stream
            .peer_addr()
            .expect("Unable to get peer address of stream");
        let noise = Noise::responder_handshake(noise, &mut stream, &mut buf, init_msg).await;
        if noise.is_err() {
            error!(
                "Error performing handshake with client: {}\t{}",
                peer_addr,
                noise.err().unwrap()
            );
            return;
        }
        debug!("Handshake completed with client: {}", peer_addr);
        let mut noise = noise.unwrap();
        let peer_id = noise.get_remote_static();
        if peer_id.is_none() {
            error!("Unable to get peer id");
            return;
        }
        let peer_id = Arc::new(peer_id.unwrap().to_vec());
        loop {
            let request = Noise::decrypt_message(&mut noise, &mut stream, &mut buf).await;
            if request.is_err() {
                debug!(
                    "Connection closed for client: {}\t{}",
                    peer_addr,
                    request.err().unwrap()
                );
                return;
            }
            let request = request.unwrap();
            debug!("Received client request: {}", request);
            let peer_id = peer_id.clone();
            let handle = task::spawn_blocking(move || process_command(request, peer_addr, peer_id));
            let response = handle.await.unwrap();
            debug!("Sending response to client: {}", response);
            let result =
                Noise::encrypt_and_send(&mut noise, &mut stream, response.as_bytes(), &mut buf)
                    .await;
            if result.is_err() {
                warn!(
                    "Error sending response to client: {}\t{}",
                    peer_addr,
                    result.err().unwrap()
                );
                return;
            }
            debug!("Response sent to client: {}", peer_addr);
        }
    }
    pub async fn stop(&self) {
        if let Some(tx) = Self::get_tx() {
            match tx.send(()) {
                Ok(_) => {
                    debug!("Sent stop signal to server");
                    // Server checks for stop signal only when a new connection is received.
                    // Force a new connection to be established to stop the server.
                    if let Err(e) = TcpStream::connect(format!("127.0.0.1:{}", self.port)).await {
                        error!("Error connecting to server: {}", e);
                        error!("Error establishing connection for stopping the server. Maybe the server is already stopped.");
                    };
                }
                Err(e) => {
                    error!("Error sending stop signal to server: {}", e);
                }
            }
        } else {
            warn!("Cannot stop listener: tx is None");
        }
    }

    fn update_tx(tx: Sender<()>) {
        if STOP_SENDER.is_poisoned() {
            error!("Unable to update stop sender, channel is poisoned");
            return;
        }
        let mut sender = STOP_SENDER.lock().unwrap();
        *sender = Some(tx);
    }
    fn get_tx() -> Option<Sender<()>> {
        if STOP_SENDER.is_poisoned() {
            error!("Unable to get stop sender, channel is poisoned");
            return None;
        }

        let sender = STOP_SENDER.lock();
        if sender.is_err() {
            error!("Unable to acquire lock on stop sender. Server may not stop");
            return None;
        }
        let sender = sender.unwrap();
        sender.as_ref().cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortForwardMode {
    /// Insecure mode. No authentication is performed.
    PlainText,
    /// Insecure mode listening on all interfaces.
    PlainTextAll,
    /// Encrypt mode. Authentication is performed using Noise protocol.
    /// Plaintext data is received at the source port and forwarded to
    /// the destination port, which is presumably running a PortForwarder
    /// in Decrypt mode. The source is typically a local client and the
    /// destination is typically a remote server (Decrypt mode portforwarder).
    Encrypt,
    /// Decrypt mode. Authentication is performed using Noise protocol.
    /// Encrypted data (presumably from a PortForwarder instance in Encrypt
    /// mode) is received at the source port and forwarded as plaintext
    /// to the destination port. The destination is typically a server listening
    /// on local interface and the source is typically a remote client (Encrypt
    /// mode portforwarder).
    Decrypt,
}

#[derive(Debug)]
pub(crate) struct PortForwarder {
    pub src_port: u16,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    pub mode: PortForwardMode,
    peer_key: Option<Key>,
    // Sender to stop the port forwarder.
    stop_tx: Option<Sender<()>>,
}

impl PortForwarder {
    /// Try to create a new PortForwarder instance.
    /// Returns an error if the destination address is invalid/unreachable.
    #[tokio::main]
    pub async fn try_new(
        src_port: u16,
        dst_host: &str,
        dst_port: u16,
        mode: PortForwardMode,
        peer_key: Option<Key>,
        lookup_dst: bool,
    ) -> io::Result<PortForwarder> {
        debug!(
            "Initializing PortForwarder with src_port: {}\tdst_host: {}\tdst_port: {}",
            src_port, dst_host, dst_port
        );

        // In Decrypt and PlainTextAll mode, we are listening on all interfaces because the
        // source is a remote client sending encrypted data. For both the other
        // modes, we are listening on localhost only.
        let src_ip = if mode == PortForwardMode::Decrypt || mode == PortForwardMode::PlainTextAll {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };

        let src_addr = SocketAddr::new(src_ip, src_port);
        let dst_addr = parse_addr(dst_host, dst_port, lookup_dst).await?;
        let private_key = SystemKeypair::get_private_key();

        match mode {
            PortForwardMode::PlainText => {
                debug!("Initializing Portforwarder in PlainText mode");
            }
            PortForwardMode::PlainTextAll => {
                debug!("Initializing Portforwarder in PlainText mode listening on all interfaces");
            }
            PortForwardMode::Decrypt => {
                debug!("Initializing Portforwarder in Decrypt mode");
                if private_key.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unable to get private key",
                    ));
                }
                if peer_key.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Peer key is required in Decrypt mode",
                    ));
                }
            }
            PortForwardMode::Encrypt => {
                debug!("Initializing Portforwarder in Encrypt mode");
                if private_key.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Unable to get private key",
                    ));
                }
                if peer_key.is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Peer key is required in Encrypt mode",
                    ));
                }
                // If the mode is Encrypt, we need to check if the destination is a valid
                // PortForwardMode::Decrypt instance.
                // let peer_key = peer_key.clone().unwrap();
                // let private_key = private_key.unwrap();
                // let noise = Noise::build_portforwarder_initiator(&private_key, &peer_key)?;

                // let mut buf = [0_u8; 65535];
                // let mut stream = TcpStream::connect(dst_addr).await?;
                // Noise::portforwarder_initiator_handshake(noise, &mut stream, &mut buf).await?;
            }
        }

        Ok(PortForwarder {
            src_port,
            src_addr,
            dst_addr,
            mode,
            peer_key,
            stop_tx: None,
        })
    }
    /// Start the port forwarder and return the handle to the forwarding thread.
    pub fn forward(&mut self) -> io::Result<thread::JoinHandle<()>> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        self.update_tx(stop_tx);
        debug!("Starting listener on forwarding port: {}", self.src_port);
        let src_addr = self.src_addr;
        let dst_addr = self.dst_addr;
        let peer_key = self.peer_key.clone();
        let mode = self.mode.clone();
        let handle = thread::spawn(move || {
            Self::listener(src_addr, dst_addr, stop_rx, started_tx, peer_key, mode).unwrap();
        });
        started_rx.recv().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error starting listener: {}", e),
            )
        })?;
        Ok(handle)
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.clone() {
            match tx.send(()) {
                Ok(_) => {
                    debug!("Sent stop signal to portforwarder");
                    // Portforwader checks for stop signal only when a new connection is received.
                    // Force a new connection to be established to stop the server.
                    if TcpStream::connect(format!("127.0.0.1:{}", self.src_port))
                        .await
                        .is_err()
                    {
                        warn!(
                            "Error establishing connection for stopping the Portforwader. Maybe the server is already stopped.");
                    };
                }
                Err(e) => {
                    error!("Error sending stop signal to Portforwader: {}", e);
                }
            }
        } else {
            warn!("Cannot stop Portforwader: tx is None");
        }
    }

    fn update_tx(&mut self, tx: Sender<()>) {
        self.stop_tx = Some(tx);
    }

    // This method starts listener for incoming connections from client on
    // src_host:src_port and forwards them to dst_host:dst_port.
    #[tokio::main]
    async fn listener(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        stop_rx: Receiver<()>,
        started_tx: Sender<()>,
        peer_key: Option<Key>,
        mode: PortForwardMode,
    ) -> io::Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&src_addr.into())?;
        socket.listen(128)?;
        let listener: std::net::TcpListener = socket.into();
        let listener = TcpListener::from_std(listener)?;
        // Let the port forwarder know that the listener is ready.
        started_tx.send(()).map_err(|e| {
            error!("Error sending started signal to portforwarder: {}", e);
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error sending started signal from listener: {}", e),
            )
        })?;

        let handle = tokio::spawn(async move {
            let peer_key = peer_key.clone().unwrap_or_default();
            loop {
                let result = listener.accept().await;
                match result {
                    Ok((stream, peer_addr)) => {
                        debug!("Received connection from {}", peer_addr);
                        Self::handle(stream, dst_addr, &peer_key, &mode).await;
                        debug!("Returned from handle()");
                    }
                    Err(e) => {
                        error!("Error in listener: {}", e);
                    }
                }
                match stop_rx.try_recv() {
                    Ok(_) | Err(TryRecvError::Disconnected) => {
                        debug!("Received stop signal, shutting down server");
                        break;
                    }
                    Err(TryRecvError::Empty) => {
                        // Continue.
                    }
                };
            }
        });
        handle.await.unwrap();
        Ok(())
    }

    // This method handles incoming connection from client and forwards it to dst_host:dst_port.
    async fn handle(
        client_stream: TcpStream,
        dst_addr: SocketAddr,
        peer_key: &Key,
        mode: &PortForwardMode,
    ) {
        debug!("Entering _handle");
        debug!("Connecting to destination address: {}", dst_addr);
        let connection = TcpStream::connect(dst_addr).await;
        if connection.is_err() {
            error!("Error connecting to destination address: {}", dst_addr);
            return;
        }
        debug!("Connected to destination address: {}", dst_addr);
        let server_stream = connection.unwrap();
        match mode {
            PortForwardMode::PlainText | PortForwardMode::PlainTextAll => {
                Self::handle_plaintext(client_stream, server_stream).await;
            }

            PortForwardMode::Encrypt => {
                // Unwrapping the following should be safe because we have already checked
                // during initialization that the peer_key is not None and private_key is not none.
                let private_key =
                    SystemKeypair::get_private_key().expect("Unable to get private key");
                Self::handle_encrypt(client_stream, server_stream, peer_key, &private_key).await;
            }

            PortForwardMode::Decrypt => {
                // Unwrapping the following should be safe because we have already checked
                // during initialization that the peer_key is not None and private_key is not none.
                let private_key =
                    SystemKeypair::get_private_key().expect("Unable to get private key");
                Self::handle_decrypt(client_stream, server_stream, peer_key, &private_key).await;
            }
        }
    }

    async fn handle_plaintext(client_stream: TcpStream, server_stream: TcpStream) {
        let (mut client_reader, mut client_writer) = client_stream.into_split();
        let (mut server_reader, mut server_writer) = server_stream.into_split();
        task::spawn(async move {
            trace!("Starting _forward_stream thread 1");
            Self::forward_stream(&mut client_reader, &mut server_writer, 1).await;
            trace!("Returned from _forward_stream thread 1");
        });
        task::spawn(async move {
            trace!("Starting _forward_stream thread 2");
            Self::forward_stream(&mut server_reader, &mut client_writer, 2).await;
            trace!("Returned from _forward_stream thread 2");
        });
    }

    async fn handle_encrypt(
        client_stream: TcpStream,
        mut server_stream: TcpStream,
        peer_key: &Key,
        private_key: &Key,
    ) {
        let mut buf = vec![0_u8; 65535];
        // For each connection, we do two authenticated handshakes.
        // One for reading from the client and writing to the server, and
        // one for reading from the server and writing to the client.

        debug!("Starting portforwarder initiator handshake in encrypt mode");
        let enc_transport =
            Self::initiator_handshake(peer_key, private_key, &mut server_stream, &mut buf[..])
                .await;
        if enc_transport.is_err() {
            error!(
                "Error in portforwarder initiator handshake in encrypt mode: {}",
                enc_transport.err().unwrap()
            );
            return;
        }
        let mut enc_transport = enc_transport.unwrap();
        debug!("Portforwarder initiator handshake completed in encrypt mode");

        debug!("Starting portforwarder responder in encrypt mode");
        let dec_transport =
            Self::responder_handshake(peer_key, private_key, &mut server_stream, &mut buf[..])
                .await;
        if dec_transport.is_err() {
            error!(
                "Error in portforwarder responder handshake in encrypt mode: {}",
                dec_transport.err().unwrap()
            );
            return;
        }
        let mut dec_transport = dec_transport.unwrap();
        debug!("Portforwarder responder handshake completed in encrypt mode");

        let (mut client_reader, mut client_writer) = client_stream.into_split();
        let (mut server_reader, mut server_writer) = server_stream.into_split();
        task::spawn(async move {
            trace!("Starting _forward_stream thread 1");
            Self::forward_stream_encrypt(
                &mut client_reader,
                &mut server_writer,
                &mut enc_transport,
            )
            .await;
            trace!("Returned from _forward_stream thread 1");
        });
        task::spawn(async move {
            trace!("Starting _forward_stream thread 2");
            Self::forward_stream_decrypt(
                &mut server_reader,
                &mut client_writer,
                &mut dec_transport,
            )
            .await;
            trace!("Returned from _forward_stream thread 2");
        });
    }

    async fn handle_decrypt(
        mut client_stream: TcpStream,
        server_stream: TcpStream,
        peer_key: &Key,
        private_key: &Key,
    ) {
        let mut buf = vec![0_u8; 65535];
        // For each connection, we do two authenticated handshakes.
        // One for reading from the server and writing to the client, and
        // one for reading from the client and writing to the server.

        debug!("Starting portforwarder responder handshake in decrypt mode");
        let dec_transport =
            Self::responder_handshake(peer_key, private_key, &mut client_stream, &mut buf[..])
                .await;
        if dec_transport.is_err() {
            error!(
                "Error in portforwarder responder handshake in decrypt mode: {}",
                dec_transport.err().unwrap()
            );
            return;
        }
        let mut dec_transport = dec_transport.unwrap();
        debug!("Portforwarder responder handshake completed in decrypt mode");

        debug!("Starting portforwarder initiator in decrypt mode");
        let enc_transport =
            Self::initiator_handshake(peer_key, private_key, &mut client_stream, &mut buf[..])
                .await;
        if enc_transport.is_err() {
            error!(
                "Error in portforwarder initiator handshake in decrypt mode: {}",
                enc_transport.err().unwrap()
            );
            return;
        }
        let mut enc_transport = enc_transport.unwrap();
        debug!("Portforwarder initiator handshake completed in decrypt mode");

        let (mut client_reader, mut client_writer) = client_stream.into_split();
        let (mut server_reader, mut server_writer) = server_stream.into_split();
        task::spawn(async move {
            trace!("Starting _forward_stream thread 1");
            Self::forward_stream_decrypt(
                &mut client_reader,
                &mut server_writer,
                &mut dec_transport,
            )
            .await;
            trace!("Returned from _forward_stream thread 1");
        });
        task::spawn(async move {
            trace!("Starting _forward_stream thread 2");
            Self::forward_stream_encrypt(
                &mut server_reader,
                &mut client_writer,
                &mut enc_transport,
            )
            .await;
            trace!("Returned from _forward_stream thread 2");
        });
    }

    async fn initiator_handshake(
        peer_key: &Key,
        private_key: &Key,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<TransportState> {
        let initiator = Noise::build_portforwarder_initiator(private_key, peer_key)?;
        Noise::portforwarder_initiator_handshake(initiator, stream, buf).await
    }

    async fn responder_handshake(
        peer_key: &Key,
        private_key: &Key,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<TransportState> {
        let responder = Noise::build_portforwarder_responder(private_key, peer_key)?;
        Noise::portforwarder_responder_handshake(responder, stream, buf).await
    }

    // This function reads the packets received from one TcpStream and
    // forwards them to another TcpStream.
    async fn forward_stream(
        src_stream: &mut OwnedReadHalf,
        dst_stream: &mut OwnedWriteHalf,
        thread_num: u8,
    ) {
        // Read all the data from the source stream and write it to the destination stream.
        trace!("Entering _forward_stream thread: {}", thread_num);
        let mut buf = [0_u8; 1024];
        loop {
            match src_stream.read(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if n == 13 && &buf[..n] == ADB_KILL_SERVER_COMMAND {
                        // This is the adb kill-server command. Do not forward it to the destination.
                        // We do not want the consumer to be able to kill the destination adb server.
                        warn!("Received adb kill-server command. Not forwarding to server and closing connection");
                        break;
                    }
                    if let Err(e) = dst_stream.write_all(&buf[..n]).await {
                        error!("Error while writing to destination stream: {}", e);
                        break;
                    };
                }
                Err(e) => {
                    error!("Error reading client request: {}", e);
                    // Return early.
                    return;
                }
            }
        }
        trace!(
            "Forwarded all data. Returning from _forward_stream thread: {}",
            thread_num
        );
    }

    // This function reads plaintext data from the source stream, encrypts it and writes
    // it to the destination stream.
    async fn forward_stream_encrypt(
        src_stream: &mut OwnedReadHalf,
        dst_stream: &mut OwnedWriteHalf,
        noise: &mut TransportState,
    ) {
        let mut buf = [0_u8; 65535];
        let mut msg = [0_u8; 65500];
        loop {
            match src_stream.read(&mut msg).await {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if let Err(e) =
                        Noise::encrypt_and_send(noise, dst_stream, &msg[..n], &mut buf).await
                    {
                        warn!(
                            "Error while writing encrypted message to destination stream: {}",
                            e
                        );
                        break;
                    };
                }
                Err(e) => {
                    warn!("Error reading plaintext client request: {}", e);
                    // Return early.
                    return;
                }
            }
        }
    }
    // This function reads encrypted data from the source stream, decrypts it and writes
    // it to the destination stream.
    async fn forward_stream_decrypt(
        src_stream: &mut OwnedReadHalf,
        dst_stream: &mut OwnedWriteHalf,
        noise: &mut TransportState,
    ) {
        let mut buf = [0_u8; 65535];
        loop {
            match Noise::decrypt_data(noise, src_stream, &mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    if n == 13 && &buf[..n] == ADB_KILL_SERVER_COMMAND {
                        // This is the adb kill-server command. Do not forward it to the destination.
                        // We do not want the consumer to be able to kill the destination adb server.
                        warn!("Received adb kill-server command. Not forwarding to server and closing connection");
                        break;
                    }
                    if let Err(e) = dst_stream.write_all(&buf[..n]).await {
                        warn!(
                            "Error while writing decrypted message to destination stream: {}",
                            e
                        );
                        break;
                    };
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("Error reading encrypted client request: {}", e);
                    // Return early.
                    return;
                }
                Err(e) => {
                    warn!("Error reading encrypted client request: {}", e);
                    // Return early.
                    return;
                }
            }
        }
    }
}

/// Utility function to convert a string to a socket address.
pub(crate) async fn parse_addr(host: &str, port: u16, lookup_dst: bool) -> io::Result<SocketAddr> {
    // Try to parse the host as an IP address.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // Try to resolve the host as a domain name.
    let addr = format!("{}:{}", host, port);
    let addrs = match addr.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(e) => return Err(e),
    };
    let mut last_err = None;
    for addr in addrs {
        if addr.is_ipv6() {
            continue;
        }
        if !lookup_dst {
            return Ok(addr);
        }
        debug!("Trying to connect to address: {addr}");
        match TcpStream::connect(addr).await {
            Ok(..) => return Ok(addr),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    error!("Error processing socket address for: {addr}");
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )
    }))
}

// Unit tests for net module.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::market::{request::*, SystemKeypair};
    use crate::util::test_with_logs;
    use portpicker;

    struct ServerSpec;

    impl ServerSpec {
        fn host() -> &'static str {
            "0.0.0.0"
        }
    }

    // MockEncryptedListener. Always sends 'Ok' response.
    // This is an encrypted TCP listener.
    struct MockEncryptedListener {
        listener: CommandServer,
    }

    impl MockEncryptedListener {
        fn new(host: &str, port: u16) -> MockEncryptedListener {
            MockEncryptedListener {
                listener: CommandServer {
                    host: host.into(),
                    port,
                },
            }
        }
        async fn start(&mut self) -> io::Result<()> {
            self.listener.start(Self::process_command).await
        }
        fn process_command(command: String, _peer_addr: SocketAddr, _key: Arc<Key>) -> String {
            debug!("Command received by MockListener: {}", command);
            "Ok".to_string()
        }
    }

    // MockListener. Always sends 'Ok' response.
    // This is a plaintext TCP listener.
    struct MockListener {
        listener: TcpListener,
    }

    impl MockListener {
        async fn new(host: &str, port: u16) -> MockListener {
            MockListener {
                listener: TcpListener::bind((host, port)).await.unwrap(),
            }
        }
        async fn start(&mut self) -> io::Result<()> {
            loop {
                let (mut stream, _peer_addr) = self.listener.accept().await?;
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    let command = String::from_utf8_lossy(&buf[..n]);
                    debug!("Command received by MockListener: {}", command);
                    stream.write_all(b"Ok").await.unwrap();
                });
            }
        }
    }

    fn tcp_client_init_send(
        host: &str,
        port: u16,
        data: &str,
        timeout: Option<u64>,
    ) -> io::Result<String> {
        let tcp_client = TCPClient::new(host, port)?;
        tcp_client.send(data, timeout)
    }

    fn tcp_client_init_send_no_wait<T>(host: &str, port: u16, data: T) -> io::Result<()>
    where
        T: ToJson,
    {
        let tcp_client = TCPClient::new(host, port)?;
        tcp_client.send_no_wait(data);
        Ok(())
    }

    fn tcp_client_init_send_request<T>(
        host: &str,
        port: u16,
        data: T,
        timeout: Option<u64>,
    ) -> io::Result<String>
    where
        T: ToJson,
    {
        let tcp_client = TCPClient::new(host, port)?;
        tcp_client.send_request(data, timeout)
    }

    #[tokio::main]
    async fn unauthenticated_tcp_client_init_send(
        host: &str,
        port: u16,
        data: &str,
    ) -> io::Result<String> {
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))
            .await
            .unwrap();
        stream.write_all(data.as_bytes()).await.unwrap();
        let mut buf = [0_u8; 1024];
        match stream.read(&mut buf).await {
            Ok(n) => {
                let response = String::from_utf8_lossy(&buf[..n]).to_string();
                println!("Server Response: {}", response);
                Ok(response)
            }
            Err(e) => {
                println!("Error reading server response: {}", e);
                // Return early.
                Err(e)
            }
        }
    }

    #[tokio::test]
    async fn tcpclient_connect_and_send() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);

        task::spawn(async move { listener.start().await.unwrap() });

        let result = task::spawn_blocking(move || {
            tcp_client_init_send("localhost", listen_port, "hello", Some(5))
        })
        .await
        .unwrap();

        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_with_timeout_none() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);

        task::spawn(async move { listener.start().await.unwrap() });

        let result = task::spawn_blocking(move || {
            tcp_client_init_send("localhost", listen_port, "hello", None)
        })
        .await
        .unwrap();

        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_no_wait() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);

        task::spawn(async move { listener.start().await.unwrap() });

        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_no_wait("localhost", listen_port, request)
        })
        .await
        .unwrap();

        match result {
            Ok(_) => println!("Test passes; data sent successfully.",),
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_request() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);

        task::spawn(async move { listener.start().await.unwrap() });

        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_request("localhost", listen_port, request, Some(5))
        })
        .await
        .unwrap();

        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_request_no_timeout() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);

        task::spawn(async move { listener.start().await.unwrap() });

        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_request("localhost", listen_port, request, None)
        })
        .await
        .unwrap();

        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_with_key() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);
        task::spawn(async move { listener.start().await.unwrap() });
        let result = task::spawn_blocking(move || {
            tcp_client_init_send("localhost", listen_port, "hello", Some(5))
        })
        .await
        .unwrap();
        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_no_wait_with_key() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);
        task::spawn(async move { listener.start().await.unwrap() });
        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_no_wait("localhost", listen_port, request)
        })
        .await
        .unwrap();
        match result {
            Ok(_) => println!("Test passes; data sent successfully.",),
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_request_with_key() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);
        task::spawn(async move { listener.start().await.unwrap() });
        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_request("localhost", listen_port, request, Some(5))
        })
        .await
        .unwrap();
        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn tcpclient_send_request_no_timeout_with_key() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();
        let mut listener = MockEncryptedListener::new(ServerSpec::host(), listen_port);
        task::spawn(async move { listener.start().await.unwrap() });
        let result = task::spawn_blocking(move || {
            let request = SysStateRequest::GetState;
            tcp_client_init_send_request("localhost", listen_port, request, None)
        })
        .await
        .unwrap();
        match result {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn test_forwarding() {
        test_with_logs();
        let listen_port = portpicker::pick_unused_port().unwrap();

        // start listener listening for incoming connections on port listen_port.
        task::spawn(async move {
            let mut listener = MockListener::new(ServerSpec::host(), listen_port).await;
            listener.start().await.unwrap()
        });

        let port = portpicker::pick_unused_port().unwrap();

        // Configure PortForwader to forward `port` to `listen_port`
        let mut forwarder = task::spawn_blocking(move || {
            PortForwarder::try_new(
                port,
                "localhost",
                listen_port,
                PortForwardMode::PlainText,
                None,
                false,
            )
            .unwrap()
        })
        .await
        .unwrap();

        forwarder.forward().unwrap();

        // Configure a TCPClient to send data to `port`.
        let result = task::spawn_blocking(move || {
            unauthenticated_tcp_client_init_send("localhost", port, "hello")
        });

        match result.await.unwrap() {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }

    #[tokio::test]
    async fn test_forwarding_encrypted() {
        test_with_logs();

        let builder = snow::Builder::new("Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        SystemKeypair::set_keypair(keypair);
        let public_key = SystemKeypair::get_public_key().unwrap();
        let public_key_clone = public_key.clone();

        let listen_port = portpicker::pick_unused_port().unwrap();
        // start listener listening for incoming connections on `listen_port`.
        task::spawn(async move {
            let mut listener = MockListener::new(ServerSpec::host(), listen_port).await;
            listener.start().await.unwrap()
        });

        let decrypt_port = portpicker::pick_unused_port().unwrap();

        // Encrypted pipeline: Plaintext -> encrypt_port ------> decrypt_port -> Plaintext -> listen_port

        // Configure PortForwader to forward `decrypt_port` to `listen_port`.
        let mut forwarder_consumer = task::spawn_blocking(move || {
            PortForwarder::try_new(
                decrypt_port,
                "localhost",
                listen_port,
                PortForwardMode::Decrypt,
                Some(public_key),
                false,
            )
            .unwrap()
        })
        .await
        .unwrap();

        // Start forwarder listening for incoming connections on `decrypt_port`.
        forwarder_consumer.forward().unwrap();

        let encrypt_port = portpicker::pick_unused_port().unwrap();
        // Configure PortForwader to forward `encrypt_port` to `decrypt_port` (encrypted-channel)
        let mut forwarder_supplier = task::spawn_blocking(move || {
            PortForwarder::try_new(
                encrypt_port,
                "localhost",
                decrypt_port,
                PortForwardMode::Encrypt,
                Some(public_key_clone),
                false,
            )
            .unwrap()
        })
        .await
        .unwrap();

        forwarder_supplier.forward().unwrap();

        // Configure a TCPClient to send data to port `encrypt_port`.
        let result = task::spawn_blocking(move || {
            unauthenticated_tcp_client_init_send("localhost", encrypt_port, "hello")
        });

        match result.await.unwrap() {
            Ok(response) => {
                assert_eq!(&response, "Ok");
                println!(
                    "Test passes; data sent successfully with response: {}",
                    response
                )
            }
            Err(err) => panic!("TCP send failed with err:\n{}", err),
        };
    }
}
