use bitflags::bitflags;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{self, Cursor, Read, Write},
    marker::PhantomData,
    mem::size_of,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4},
    string::FromUtf8Error,
    time::{SystemTime, SystemTimeError},
};
use thiserror::Error;

use crate::{
    message::{DeserializationError, Deserialize, Serialize},
    sha256_sha256, MAX_USER_AGENT_LENGTH, PROTOCOL_VERSION, START_STRING_MAINNET,
};

use super::{Command, Message, Name, COMMAND_MAX_LENGTH};

/// Maximum payload size, as defined by the oficial Bitcoin implementation.
///
/// https://github.com/bitcoin/bitcoin/blob/60abd463ac2eaa8bc1d616d8c07880dc53d97211/src/serialize.h#L23
pub const PAYLOAD_MAX_SIZE: usize = 0x02000000;

struct NetworkAddress {
    services: Services,
    ip: IpAddr,
    port: u16,
}

impl NetworkAddress {
    fn from_socket_addr(addr: SocketAddr, services: Services) -> Self {
        Self {
            services,
            ip: addr.ip(),
            port: addr.port(),
        }
    }
}

impl Serialize for NetworkAddress {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer =
            Vec::with_capacity(size_of::<Services>() + 16 /* 16 * u8 */ + 2 /* u16 */);
        buffer.write_u64::<LittleEndian>(self.services.bits())?;
        // NOTE: hoping that RFC 1700 is enforced
        // https://www.rfc-editor.org/rfc/rfc1700
        match self.ip {
            IpAddr::V4(ip) => {
                buffer.write_u128::<BigEndian>(u128::from_ne_bytes(ip.to_ipv6_mapped().octets()))?
            }
            IpAddr::V6(ip) => buffer.write_u128::<BigEndian>(u128::from_ne_bytes(ip.octets()))?,
        };
        buffer.write_u16::<LittleEndian>(self.port)?;
        Ok(buffer)
    }
}

impl Deserialize for NetworkAddress {
    fn deserialize(data: &mut impl Read) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        let services = Services::from_bits_truncate(data.read_u64::<LittleEndian>()?);
        let ip = IpAddr::V6(Ipv6Addr::from(data.read_u128::<BigEndian>()?));
        let port = data.read_u16::<BigEndian>()?;
        Ok(Self { services, ip, port })
    }
}

impl From<NetworkAddress> for SocketAddr {
    fn from(value: NetworkAddress) -> Self {
        match value.ip {
            IpAddr::V4(ip) => SocketAddr::new(ip.into(), value.port),
            IpAddr::V6(ip) => SocketAddr::new(ip.into(), value.port),
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("User Agent cannot be longer than {MAX_USER_AGENT_LENGTH}")]
    UserAgentTooLong,

    #[error("Invalid timestamp")]
    InvalidTimestamp(#[from] SystemTimeError),
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct Services: u64 {
        const NODE_NETWORK = 1;
        const NODE_GETUTXO = 2;
        const NODE_BLOOM = 4;
        const NODE_WITNESS = 8;
        const NODE_XTHIN = 16;
        const NODE_COMPACT_FILTERS = 64;
        const NODE_NETWORK_LIMITED = 1024;
    }
}

pub struct Version {
    /// Identifies protocol version being used by the node.
    pub version: i32,

    /// Bitfield of features to be enabled for this connection.
    pub services: Services,

    /// Standard UNIX timestamp in seconds.
    pub timestamp: i64,

    /// The network address of the node receiving this message.
    pub addr_recv: SocketAddr,

    /// Field is ignored (according to the docs at https://en.bitcoin.it/wiki/Protocol_documentation#version).
    ///
    /// This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the version message.
    pub addr_from: SocketAddr,

    /// Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
    pub nonce: u64,

    /// Node user agent. See [BIP 0014](https://github.com/bitcoin/bips/blob/master/bip-0014.mediawiki).
    pub user_agent: String,

    /// The last block received by the emitting node .
    pub start_height: i32,

    /// Whether the remote peer should announce relayed transactions or not, see [BIP 0037](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki).
    pub relay: bool,
}

impl Version {
    fn new(
        version: i32,
        services: Services,
        timestamp: i64,
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        nonce: u64,
        user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Result<Self, MessageError> {
        if user_agent.len() > MAX_USER_AGENT_LENGTH {
            return Err(MessageError::UserAgentTooLong);
        }
        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }

    pub fn new_with_defaults(
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        start_height: i32,
        relay: bool,
    ) -> Result<Self, MessageError> {
        Self::new(
            PROTOCOL_VERSION,
            Services::NODE_NETWORK,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs() as i64,
            addr_recv,
            addr_from,
            rand::random(),
            "".to_string(),
            start_height,
            relay,
        )
    }
}

impl Serialize for Version {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        // User Agent > 0 will cause a reallocation
        let mut buffer = Vec::with_capacity(
            4 + /* version */
            8 + /* services */
            8 + /* timestamp */
            26 + /* addr_recv */
            26 + /* addr_from */
            8 + /* nonce */
            4 + /* start_height */
            1, /* relay */
        );
        buffer.write_i32::<LittleEndian>(self.version)?;
        buffer.write_u64::<LittleEndian>(self.services.bits())?;
        buffer.write_i64::<LittleEndian>(self.timestamp)?;
        buffer.write_all(
            &NetworkAddress::from_socket_addr(self.addr_recv, self.services).serialize()?,
        )?;
        buffer.write_all(
            &NetworkAddress::from_socket_addr(self.addr_from, self.services).serialize()?,
        )?;
        buffer.write_u64::<LittleEndian>(self.nonce)?;
        buffer.write_u8(self.user_agent.len() as u8)?;
        buffer.write_all(self.user_agent.as_bytes())?;
        buffer.write_i32::<LittleEndian>(self.start_height)?;
        buffer.write_u8(self.relay.into())?;
        Ok(buffer)
    }
}

impl Deserialize for Version {
    fn deserialize(data: &mut impl Read) -> Result<Self, DeserializationError>
    where
        Self: Sized,
    {
        let version = data.read_i32::<LittleEndian>()?;
        let services = Services::from_bits_truncate(data.read_u64::<LittleEndian>()?);
        let timestamp = data.read_i64::<LittleEndian>()?;
        let addr_recv = NetworkAddress::deserialize(data)?.into();
        let addr_from = NetworkAddress::deserialize(data)?.into();
        let nonce = data.read_u64::<LittleEndian>()?;
        let user_agent_length = data.read_u8()? as usize;
        let mut user_agent = vec![0u8; user_agent_length];
        data.read_exact(&mut user_agent)?;
        let user_agent = String::from_utf8(user_agent)?;
        let start_height = data.read_i32::<LittleEndian>()?;
        let relay = data.read_u8()? != 0;
        Ok(Self {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        })
    }
}

impl Command<Version> {
    fn is_version(bytes: &[u8]) -> bool {
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

impl Name for Command<Version> {
    const NAME: &'static str = "version";
}

impl Serialize for Message<Version> {
    fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let payload = self.payload.serialize()?;
        let checksum = sha256_sha256(&payload);

        let mut buffer = Vec::with_capacity(
            4 + /* magic */
            COMMAND_MAX_LENGTH +
            4 + /* length */
            4 + /* checksum */
            payload.len(),
        );
        buffer.write_all(&self.magic)?;
        buffer.write_all(&self.command.serialize()?)?;
        buffer.write_u32::<LittleEndian>(payload.len() as u32)?;
        buffer.write_all(&checksum)?;
        buffer.write_all(&payload)?;
        Ok(buffer)
    }
}

impl Deserialize for Message<Version> {
    fn deserialize(data: &mut impl Read) -> Result<Self, DeserializationError>
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
        if !Command::<Version>::is_version(&command_name) {
            return Err(DeserializationError::CommandMismatch);
        }

        let payload_length = data.read_u32::<LittleEndian>()? as usize;
        if payload_length > PAYLOAD_MAX_SIZE {
            return Err(DeserializationError::InvalidPayloadSize);
        }

        tracing::debug!("payload size {}", payload_length);

        let mut received_checksum = [0u8; 4];
        data.read_exact(&mut received_checksum)?;

        let mut payload = vec![0u8; payload_length];
        data.read_exact(&mut payload)?;

        let calculated_checksum = sha256_sha256(&payload);

        if received_checksum != calculated_checksum {
            return Err(DeserializationError::ChecksumMismatch {
                received: format!("{:#x}", i32::from_ne_bytes(received_checksum)),
                calculated: format!("{:#x}", i32::from_ne_bytes(calculated_checksum)),
            });
        }

        let payload = Version::deserialize(&mut payload.as_slice())?;

        Ok(Self {
            magic,
            command: Command::<Version>(PhantomData),
            payload,
        })
    }
}
