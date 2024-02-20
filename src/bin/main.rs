use std::{net::SocketAddr, time::Duration};

use btc_handshake::{
    message::{
        verack::Verack, version::Version, DeserializationError, Deserialize, Message, Serialize,
    },
    PORT_MAINNET,
};
use clap::Parser;
use futures::future::join_all;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{lookup_host, TcpStream},
};

#[derive(Debug, Error)]
enum HandshakeError {
    #[error("nonce conflict")]
    NonceConflict,

    #[error(transparent)]
    DeserializationError(#[from] DeserializationError),
}

#[derive(Debug, Parser)]
struct Args {
    /// Bitcoin DNS seed domain.
    dns_seed: String,

    /// Target's TCP port.
    #[arg(short, long, default_value_t = PORT_MAINNET)]
    port: u16,

    /// Handshake timeout, in seconds.
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(start(
        args.dns_seed,
        args.port,
        Duration::from_secs(args.timeout),
    ))
}

async fn start(dns_seed: String, port: u16, timeout: Duration) -> anyhow::Result<()> {
    tracing::info!("Resolving DNS seed: {}:{}", dns_seed, port);
    let resolved_addresses: Vec<_> = lookup_host((dns_seed, port)).await?.collect();

    let mut succeeded = 0;
    let mut failed = 0;

    for result in join_all(
        resolved_addresses
            .into_iter()
            .map(|address| tokio::time::timeout(timeout, handshake(address))),
    )
    .await
    .into_iter()
    {
        match result {
            Ok(Ok(_)) => succeeded += 1,
            Ok(Err(e)) => {
                failed += 1;
                tracing::warn!("{}", e)
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("{}", e)
            }
        }
    }
    tracing::info!("finished with {} SUCCESS & {} FAILED", succeeded, failed);

    Ok(())
}

async fn handshake(address: SocketAddr) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(address).await?;
    version_exchange(address, &mut stream).await?;
    verack_exchange(&mut stream).await
}

#[tracing::instrument(name = "version", skip(stream))]
async fn version_exchange(address: SocketAddr, stream: &mut TcpStream) -> anyhow::Result<()> {
    let version = Version::new_with_defaults(address, stream.local_addr()?, 0, false)?;
    let sent_version = Message::new(version);
    let frame = sent_version.serialize()?;

    stream.write_all(&frame).await?;
    tracing::debug!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received_bytes = reader.fill_buf().await?;
    let received_n = received_bytes.len();

    tracing::debug!("Received {} bytes", received_bytes.len());

    let received_version = Message::<Version>::deserialize(&mut received_bytes)?;

    if sent_version.payload.nonce == received_version.payload.nonce {
        Err(HandshakeError::NonceConflict)?
    }

    if sent_version.payload.version > received_version.payload.version {
        tracing::warn!("received version ({}) which is lower than the currently implemented one ({}) trying to proceed",
            sent_version.payload.version,
            received_version.payload.version);
    }

    reader.consume(received_n);

    Ok(())
}

/// Perform the `verack` part of the handshake.
///
/// According to "official" sources, the `verack` is required.
/// * https://developer.bitcoin.org/devguide/p2p_network.html#connecting-to-peers
/// * https://en.bitcoin.it/wiki/Protocol_documentation#version
///
/// However, people report the protocol to be fine even if the `verack` is skipped.
/// * https://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
#[tracing::instrument(name = "verack", skip(stream))]
async fn verack_exchange(stream: &mut TcpStream) -> anyhow::Result<()> {
    let sent_verack = Message::new(Verack);
    let frame = sent_verack.serialize()?;
    stream.write_all(&frame).await?;
    tracing::debug!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received_bytes = reader.fill_buf().await?;
    let received_n = received_bytes.len();
    if received_n == 0 {
        tracing::warn!("server skipped verack message");
        return Ok(());
    }

    Message::<Verack>::deserialize(&mut received_bytes)?;

    reader.consume(received_n);

    Ok(())
}
