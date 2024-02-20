pub mod message;

use sha2::{Digest, Sha256};

pub const START_STRING_MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

/// Bitcoin mainnet's nodes default port.
pub const PORT_MAINNET: u16 = 8333;

/// The implemented protocol version.
pub const PROTOCOL_VERSION: i32 = 70015;

/// User Agent's string maximum length.
pub const MAX_USER_AGENT_LENGTH: usize = 256;

pub const CHECKSUM_SIZE: usize = 4;

pub fn sha256_sha256(data: &[u8]) -> [u8; 4] {
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
