pub mod message;

use std::fmt::Display;

use sha2::{Digest, Sha256};

/// Magic header bytes for the Bitcoin Mainnet.
pub const MAGIC_BYTES_MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Magic header bytes for the Bitcoin Testnet/Regtest.
pub const MAGIC_BYTES_REGNET: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

/// Magic header bytes for the Bitcoin Testnet3.
pub const MAGIC_BYTES_TESTNET3: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];

/// Magic header bytes for the Bitcoin Signet.
pub const MAGIC_BYTES_SIGNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xfe];

/// The 4 networks defined in the original Bitcoin Github repo:
/// * https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/test/functional/test_framework/messages.py#L77-L82
#[derive(Debug, Clone)]
pub enum Network {
    /// Alias for [`MAGIC_BYTES_MAINNET`].
    Mainnet,
    /// Alias for [`MAGIC_BYTES_REGNET`].
    Regnet,
    /// Alias for [`MAGIC_BYTES_TESTNET3`].
    Testnet3,
    /// Alias for [`MAGIC_BYTES_SIGNET`].
    Signet,
}

impl Network {
    /// Get the respective magic bytes.
    const fn magic_bytes(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Regnet => [0xfa, 0xbf, 0xb5, 0xda],
            Network::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Network::Signet => [0xf9, 0xbe, 0xb4, 0xfe],
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "{}", "mainnet"),
            Network::Regnet => write!(f, "{}", "regnet"),
            Network::Testnet3 => write!(f, "{}", "testnet3"),
            Network::Signet => write!(f, "{}", "signet"),
        }
    }
}

/// Bitcoin mainnet's nodes default port.
pub const PORT_MAINNET: u16 = 8333;

/// The implemented protocol version.
pub const PROTOCOL_VERSION: i32 = 70015;

/// User Agent's string maximum length.
pub const MAX_USER_AGENT_LENGTH: usize = 256;

/// Message checksum size, as defined in:
/// * https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/src/protocol.h#L33
pub const CHECKSUM_SIZE: usize = 4;

/// Perform a `sha256(sha256(b))` where `b` is an arbitrary byte slice and return the first 4 bytes of the result.
pub fn sha256_sha256(data: &[u8]) -> [u8; CHECKSUM_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    let mut buf = [0u8; CHECKSUM_SIZE];
    buf.clone_from_slice(&hash[..CHECKSUM_SIZE]);

    buf
}
