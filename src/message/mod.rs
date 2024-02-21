pub mod verack;
pub mod version;

use std::{io, string};
use thiserror::Error;

use crate::Network;

/// Command maximum length, as defined in:
/// * https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/src/protocol.h#L31
pub const COMMAND_MAX_LENGTH: usize = 12;

/// Serialize to a `Vec<u8>`. The resulting buffer should be sent over the network
/// or used in the serialization of a bigger frame.
///
/// For example, you may implement [`BtcSerialize`] for [`version::Message<Version>`](`Message`),
/// which will recursively call [`version::Version`] before sending the whole frame through the network.
pub trait BtcSerialize {
    fn serialize(&self) -> Result<Vec<u8>, io::Error>;
}

/// A possible error when deserializing bytes into a Bitcoin type defined in this crate.
#[derive(Debug, Error)]
pub enum DeserializationError {
    #[error("magic bytes mismatch")]
    MagicBytesMismatch,

    #[error("command mismatch")]
    CommandMismatch,

    #[error("invalid payload size")]
    InvalidPayloadSize,

    #[error("checksum mismatch: {received} & {calculated}")]
    ChecksumMismatch {
        received: String,
        calculated: String,
    },

    #[error(transparent)]
    Utf8Error(#[from] string::FromUtf8Error),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

/// Deserialize from a [`io::Read`] stream.
pub trait BtcDeserialize {
    fn deserialize(data: &mut impl io::Read) -> Result<Self, DeserializationError>
    where
        Self: Sized;
}

/// A Bitcoin protocol message header.
///
/// This implementation aims to be safe by construction by enforcing:
/// * type-safe initialization — the constructor does not allow any type to be used as a payload
/// * type-safe serialization — only types that implement [`BtcSerialize`] will be accepted
/// * type-safe deserialization — you cannot construct an undefined type, hence, unknown payloads will fail serialization
pub struct Message<T: BtcSerialize> {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown.
    pub magic: [u8; 4],

    /// The message payload.
    pub payload: T,
}

impl<T> Message<T>
where
    T: BtcSerialize,
{
    /// Build a new (type-safe) [`Message`] using the provided [`Network`] and payload.
    pub fn new(network: &Network, payload: T) -> Self {
        Self {
            magic: network.magic_bytes(),
            payload,
        }
    }
}

trait Command {
    /// Command name.
    const NAME: &'static str;

    /// Check if the provided slice of bytes is a valid command.
    ///
    /// To be considered a valid command:
    /// * the slice must have length equal to 12
    /// * the first bytes must match the [`Command::NAME`]
    /// * the bytes following must be `0x00`
    fn is_valid_command(bytes: &[u8]) -> bool {
        if bytes.len() != COMMAND_MAX_LENGTH {
            return false;
        }
        for (idx, c) in Self::NAME.char_indices() {
            if bytes[idx] != (c as u8) {
                return false;
            }
        }
        for idx in Self::NAME.len()..COMMAND_MAX_LENGTH {
            if bytes[idx] != 0 {
                return false;
            }
        }
        true
    }

    /// Get the byte payload for the this command.
    fn command_bytes() -> [u8; 12] {
        let mut buffer = [0u8; COMMAND_MAX_LENGTH];
        for (i, c) in Self::NAME.char_indices() {
            buffer[i] = c as u8;
        }
        buffer
    }
}
