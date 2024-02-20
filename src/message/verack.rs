use std::io::Write;
use std::marker::PhantomData;

use byteorder::ReadBytesExt;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::message::DeserializationError;
use crate::sha256_sha256;
use crate::START_STRING_MAINNET;

use super::Command;
use super::Deserialize;
use super::Message;
use super::Name;
use super::Serialize;
use super::COMMAND_MAX_LENGTH;

pub struct Verack;

impl Command<Verack> {
    fn is_verack(bytes: &[u8]) -> bool {
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
}

impl Name for Command<Verack> {
    const NAME: &'static str = "verack";
}

impl Serialize for Verack {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        Ok(vec![])
    }
}

impl Serialize for Message<Verack> {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buffer = Vec::with_capacity(
            4 + /* magic */
            COMMAND_MAX_LENGTH +
            4 + /* length */
            4, /* checksum */
        );
        buffer.write_all(&self.magic)?;
        buffer.write_all(&self.command.serialize()?)?;
        buffer.write_u32::<LittleEndian>(0)?;
        buffer.write_all(&sha256_sha256(&[0u8; 4]))?;
        Ok(buffer)
    }
}

impl Deserialize for Message<Verack> {
    fn deserialize(data: &mut impl std::io::Read) -> Result<Self, super::DeserializationError>
    where
        Self: Sized,
    {
        let mut magic = [0u8; 4];
        data.read_exact(&mut magic)?;
        if magic != START_STRING_MAINNET {
            return Err(DeserializationError::MagicBytesMismatch);
        }

        let mut command_name = [0u8; COMMAND_MAX_LENGTH];
        data.read_exact(&mut command_name)?;
        if !Command::<Verack>::is_verack(&command_name) {
            return Err(DeserializationError::CommandMismatch);
        }

        let payload_length = data.read_u32::<LittleEndian>()? as usize;
        if payload_length != 0 {
            return Err(DeserializationError::InvalidPayloadSize);
        }

        tracing::debug!("payload size {}", payload_length);

        let mut received_checksum = [0u8; 4];
        data.read_exact(&mut received_checksum)?;

        Ok(Self {
            magic,
            command: Command::<Verack>(PhantomData),
            payload: Verack,
        })
    }
}
