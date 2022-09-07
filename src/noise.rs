use lazy_static::lazy_static;
use log::{debug, error};
use snow::{params::NoiseParams, Builder, HandshakeState, Keypair, TransportState};
use std::io;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

lazy_static! {
    static ref PARAMS: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    static ref PORTFORWARDER_PARAMS: NoiseParams =
        "Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
}

pub struct Noise;

impl Noise {
    pub fn build_initiator() -> io::Result<(HandshakeState, Keypair)> {
        let builder = Builder::new(PARAMS.clone());
        let keypair = builder.generate_keypair().map_err(transform_error)?;
        let noise = builder
            .local_private_key(&keypair.private)
            .build_initiator()
            .map_err(transform_error)?;
        Ok((noise, keypair))
    }

    pub fn build_initiator_with_key(private_key: Vec<u8>) -> io::Result<HandshakeState> {
        let builder = Builder::new(PARAMS.clone());
        let noise = builder.local_private_key(&private_key).build_initiator();
        noise.map_err(transform_error)
    }

    pub async fn initiator_handshake(
        mut noise: HandshakeState,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<TransportState> {
        // -> e
        let len = noise.write_message(&[], buf).map_err(|e| {
            error!("Failed to write message 1 of initiator handshake");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;

        // <- e, ee, s, es
        let message = Self::recv(stream).await?;
        noise.read_message(&message, buf).map_err(|e| {
            error!("Failed to read message 2 of initiator handshake");
            transform_error(e)
        })?;

        // -> s, se
        let len = noise.write_message(&[], buf).map_err(|e| {
            error!("Failed to write message 3 of initiator handshake");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;

        noise.into_transport_mode().map_err(transform_error)
    }

    pub fn build_responder() -> io::Result<(HandshakeState, Keypair)> {
        let builder = Builder::new(PARAMS.clone());
        let keypair = builder.generate_keypair().map_err(transform_error)?;
        let noise = builder
            .local_private_key(&keypair.private)
            .build_responder()
            .map_err(transform_error)?;
        Ok((noise, keypair))
    }

    pub fn build_responder_with_key(private_key: Vec<u8>) -> io::Result<HandshakeState> {
        let builder = Builder::new(PARAMS.clone());
        builder
            .local_private_key(&private_key)
            .build_responder()
            .map_err(transform_error)
    }

    pub async fn responder_handshake(
        mut noise: HandshakeState,
        stream: &mut TcpStream,
        buf: &mut [u8],
        init_message: Vec<u8>,
    ) -> io::Result<TransportState> {
        // <- e
        noise.read_message(&init_message, buf).map_err(|e| {
            error!("Failed to read message 1 of responder handshake");
            transform_error(e)
        })?;

        // -> e, ee, s, es
        let len = noise.write_message(&[], buf).map_err(|e| {
            error!("Failed to write message 2 of responder handshake");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;

        // <- s, se
        let message = Self::recv(stream).await?;
        noise.read_message(&message, buf).map_err(|e| {
            error!("Failed to read message 3 of responder handshake");
            transform_error(e)
        })?;
        noise.into_transport_mode().map_err(transform_error)
    }

    pub fn build_portforwarder_initiator(
        local_private_key: &[u8],
        peer_pub_key: &[u8],
    ) -> io::Result<HandshakeState> {
        let builder = Builder::new(PORTFORWARDER_PARAMS.clone());
        let noise = builder
            .local_private_key(local_private_key)
            .remote_public_key(peer_pub_key)
            .build_initiator();
        noise.map_err(transform_error)
    }

    pub fn build_portforwarder_responder(
        local_private_key: &[u8],
        peer_pub_key: &[u8],
    ) -> io::Result<HandshakeState> {
        let builder = Builder::new(PORTFORWARDER_PARAMS.clone());
        let noise = builder
            .local_private_key(local_private_key)
            .remote_public_key(peer_pub_key)
            .build_responder();
        noise.map_err(transform_error)
    }

    pub async fn portforwarder_initiator_handshake(
        mut noise: HandshakeState,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<TransportState> {
        // -> e, es, ss
        let len = noise.write_message(&[], buf).map_err(|e| {
            error!("Failed to write message 1 of portforwarder initiator handshake");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;
        debug!("Sent portforwarder initiator handshake message 1");

        // <- e, ee, se
        let message = Self::recv(stream).await?;
        noise.read_message(&message, buf).map_err(|e| {
            error!("Failed to read message 2 of portforwarder initiator handshake");
            transform_error(e)
        })?;

        debug!("Received portforwarder initiator handshake message 2");

        assert!(noise.is_handshake_finished());

        noise.into_transport_mode().map_err(transform_error)
    }

    pub async fn portforwarder_responder_handshake(
        mut noise: HandshakeState,
        stream: &mut TcpStream,
        buf: &mut [u8],
    ) -> io::Result<TransportState> {
        // <- e, es, ss
        let message = Self::recv(stream).await?;
        noise.read_message(&message, buf).map_err(|e| {
            error!("Failed to read message 1 of portforwarder responder handshake");
            transform_error(e)
        })?;

        debug!("Received portforwarder responder handshake message 1");

        // -> e, ee, se
        let len = noise.write_message(&[], buf).map_err(|e| {
            error!("Failed to write message 2 of portforwarder responder handshake");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;

        debug!("Sent portforwarder responder handshake message 2");

        assert!(noise.is_handshake_finished());

        noise.into_transport_mode().map_err(transform_error)
    }

    pub async fn recv<T>(stream: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin,
    {
        let mut msg_len_buf = [0u8; 2];
        stream.read_exact(&mut msg_len_buf).await?;
        let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
        let mut msg = vec![0u8; msg_len];
        stream.read_exact(&mut msg).await?;
        Ok(msg)
    }

    async fn send<T>(stream: &mut T, buf: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
        stream.write_all(&msg_len_buf).await?;
        stream.write_all(buf).await?;
        Ok(())
    }

    pub async fn encrypt_and_send<T>(
        noise: &mut TransportState,
        stream: &mut T,
        message: &[u8],
        buf: &mut [u8],
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let len = noise.write_message(message, buf).map_err(|e| {
            error!("Failed to encrypt message");
            transform_error(e)
        })?;
        Self::send(stream, &buf[..len]).await?;
        Ok(())
    }

    pub async fn decrypt_message<T>(
        noise: &mut TransportState,
        stream: &mut T,
        buf: &mut [u8],
    ) -> io::Result<String>
    where
        T: AsyncRead + Unpin,
    {
        let message = Self::recv(stream).await?;
        let len = noise.read_message(&message, buf).map_err(|e| {
            error!("Failed to decrypt message");
            transform_error(e)
        })?;
        let decoded_message = String::from_utf8_lossy(&buf[..len]).to_string();
        Ok(decoded_message)
    }

    pub async fn decrypt_data<T>(
        noise: &mut TransportState,
        stream: &mut T,
        buf: &mut [u8],
    ) -> io::Result<usize>
    where
        T: AsyncRead + Unpin,
    {
        let message = Self::recv(stream).await?;
        noise.read_message(&message, buf).map_err(transform_error)
    }
}

fn transform_error(err: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}
