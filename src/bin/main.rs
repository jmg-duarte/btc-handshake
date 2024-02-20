use std::net::SocketAddr;

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
    dns_seed: String,

    #[arg(short, long, default_value_t = PORT_MAINNET)]
    port: u16,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(start(args.dns_seed, args.port))
}

async fn start(dns_seed: String, port: u16) -> anyhow::Result<()> {
    tracing::info!("Resolving DNS seed: {}:{}", dns_seed, port);
    let resolved_addresses: Vec<_> = lookup_host((dns_seed, port)).await?.collect();

    let mut succeeded = 0;
    let mut failed = 0;

    for result in join_all(resolved_addresses.into_iter().map(handshake))
        .await
        .into_iter()
    {
        tracing::info!("finished with {:?}", result);
        if result.is_ok() {
            succeeded += 1;
        } else {
            failed += 1;
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

async fn version_exchange(address: SocketAddr, stream: &mut TcpStream) -> anyhow::Result<()> {
    let version = Version::new_with_defaults(address, stream.local_addr()?, 0, false)?;
    let sent_version = Message::new(version);
    let frame = sent_version.serialize()?;

    stream.write_all(&frame).await?;
    tracing::debug!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received = reader.fill_buf().await?;
    tracing::debug!("Received {} bytes", received.len());

    let received_version = Message::<Version>::deserialize(&mut received)?;

    if sent_version.payload.nonce != received_version.payload.nonce {
        Err(HandshakeError::NonceConflict)?
    }

    if sent_version.payload.version > received_version.payload.version {
        tracing::warn!("received version ({}) which is lower than the currently implemented one ({}) trying to proceed",
            sent_version.payload.version,
            received_version.payload.version);
    }

    Ok(())
}

async fn verack_exchange(stream: &mut TcpStream) -> anyhow::Result<()> {
    let sent_verack = Message::new(Verack);
    let frame = sent_verack.serialize()?;
    stream.write_all(&frame).await?;
    tracing::debug!("Sent {} bytes", frame.len());

    let mut reader = BufReader::new(stream);
    let mut received = reader.fill_buf().await?;
    tracing::debug!("Received {} bytes", received.len());

    let received_message = Message::<Verack>::deserialize(&mut received)?;

    Ok(())
}
