use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::message::DeserializationError;
use crate::sha256_sha256;
use crate::MAGIC_BYTES_MAINNET;

use super::BtcDeserialize;
use super::BtcSerialize;
use super::Command;
use super::Message;
use super::COMMAND_MAX_LENGTH;

pub struct Verack;

impl Command for Verack {
    const NAME: &'static str = "verack";
}

impl BtcSerialize for Verack {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        Ok(vec![])
    }
}

impl BtcSerialize for Message<Verack> {
    fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buffer = Vec::with_capacity(
            4 + /* magic */
            COMMAND_MAX_LENGTH +
            4 + /* length */
            4, /* checksum */
        );
        buffer.write_all(&self.magic)?;
        buffer.write_all(&Verack::command_bytes())?;
        buffer.write_u32::<LittleEndian>(0)?;
        buffer.write_all(&sha256_sha256(&[0u8; 4]))?;
        Ok(buffer)
    }
}

impl BtcDeserialize for Message<Verack> {
    #[tracing::instrument("deserialize", skip(data))]
    fn deserialize(data: &mut impl std::io::Read) -> Result<Self, super::DeserializationError>
    where
        Self: Sized,
    {
        let mut magic = [0u8; 4];
        data.read_exact(&mut magic)?;
        if magic != MAGIC_BYTES_MAINNET {
            return Err(DeserializationError::MagicBytesMismatch);
        }

        let mut command_name = [0u8; COMMAND_MAX_LENGTH];
        data.read_exact(&mut command_name)?;
        if !Verack::is_valid_command(&command_name) {
            return Err(DeserializationError::CommandMismatch);
        }

        // "payload"
        data.read_exact(&mut [0; 4])?;

        let mut received_checksum = [0u8; 4];
        data.read_exact(&mut received_checksum)?;

        Ok(Self {
            magic,
            payload: Verack,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::message::Command;

    use super::Verack;

    #[test]
    fn valid_command() {
        let command: [u8; 12] = [
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(Verack::is_valid_command(&command));
    }

    #[test]
    fn invalid_command() {
        let command: [u8; 12] = [
            0x76, 0x64, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!Verack::is_valid_command(&command));
    }

    #[test]
    fn invalid_padding() {
        let command: [u8; 12] = [
            0x76, 0x65, 0x72, 0x61, 0x63, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        assert!(!Verack::is_valid_command(&command));
    }
}
