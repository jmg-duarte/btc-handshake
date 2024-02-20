pub mod verack;
pub mod version;

use std::{io, marker::PhantomData, string};
use thiserror::Error;

use crate::START_STRING_MAINNET;

pub const COMMAND_MAX_LENGTH: usize = 12;

pub trait Serialize {
    fn serialize(&self) -> Result<Vec<u8>, io::Error>;
}

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

pub trait Deserialize {
    fn deserialize(data: &mut impl io::Read) -> Result<Self, DeserializationError>
    where
        Self: Sized;
}

pub struct Message<T: Serialize> {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown.
    magic: [u8; 4],

    /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected).
    command: Command<T>,

    /// The message payload.
    pub payload: T,
}

impl<T> Message<T>
where
    T: Serialize,
{
    pub fn new(payload: T) -> Self {
        Self {
            magic: START_STRING_MAINNET,
            command: Command::new(),
            payload,
        }
    }
}

#[derive(Debug)]
pub struct Command<P>(PhantomData<P>);

impl<P> Command<P> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

trait Name {
    const NAME: &'static str;
}

impl<P> Serialize for Command<P>
where
    Self: Name,
{
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buffer = vec![0u8; COMMAND_MAX_LENGTH];
        for (i, c) in Self::NAME.char_indices() {
            buffer[i] = c as u8;
        }
        Ok(buffer)
    }
}
