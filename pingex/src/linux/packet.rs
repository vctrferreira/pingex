use byteorder::{BigEndian, ByteOrder};

fn sum_big_endian_words(bs: &[u8]) -> u32 {
    if bs.len() == 0 {
        return 0;
    }

    let len = bs.len();
    let mut data = &bs[..];
    let mut sum = 0u32;
    // Iterate by word which is two bytes.
    while data.len() >= 2 {
        sum += BigEndian::read_u16(&data[0..2]) as u32;
        // remove the first two bytes now that we've already summed them
        data = &data[2..];
    }

    if (len % 2) != 0 {
        // If odd then checksum the last byte
        sum += (data[0] as u32) << 8;
    }
    return sum;
}

#[derive(Debug, PartialEq)]
pub enum IcmpPacketBuildError {}

pub trait WithEchoRequest {
    type Packet;

    fn with_echo_request(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError>;
}

pub trait WithEchoReply {
    type Packet;

    fn with_echo_reply(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError>;
}

#[derive(Debug)]
pub enum IcmpV4Message {
    Echo {
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    EchoReply {
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
}

impl IcmpV4Message {
    // pub fn create_icmp_request_packet(
    //     buf: &mut [u8; MutableEchoRequestPacket::minimum_packet_size()],
    //     seq: u16,
    //     identifier: u16,
    // ) -> MutableEchoRequestPacket {
    //     let mut packet = MutableEchoRequestPacket::new(buf).unwrap();

    //     packet.set_icmp_type(IcmpTypes::EchoRequest);
    //     packet.set_icmp_code(IcmpCode(0));
    //     packet.set_sequence_number(seq);
    //     packet.set_identifier(identifier);

    //     let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(packet.packet()).unwrap());
    //     packet.set_checksum(checksum);

    //     packet
    // }

    pub fn get_sequence(&self) -> u16 {
        match self {
            Self::Echo { sequence, .. } | Self::EchoReply { sequence, .. } => *sequence,
        }
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        match self {
            Self::Echo {
                // type 8
                identifier,
                sequence,
                payload,
            }
            | Self::EchoReply {
                //  type 0
                identifier,
                sequence,
                payload,
            } => {
                let mut buf = vec![0; 2];
                BigEndian::write_u16(&mut buf, *identifier);
                bytes.append(&mut buf);
                buf.resize(2, 0);
                BigEndian::write_u16(&mut buf, *sequence);
                bytes.append(&mut buf);
                bytes.extend_from_slice(payload);
            }
        }
        bytes
    }
}

#[derive(Debug)]
pub enum PacketParseError {
    PacketTooSmall(usize),
    UnrecognizedICMPType(u8),
}

#[derive(Debug)]
pub struct IcmpV4Packet {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub message: IcmpV4Message,
}

impl IcmpV4Packet {
    pub fn parse<B: AsRef<[u8]>>(bytes: B) -> Result<Self, PacketParseError> {
        let mut bytes = bytes.as_ref();
        let packet_len = bytes.len();
        if bytes.len() < 28 {
            return Err(PacketParseError::PacketTooSmall(packet_len));
        }
        bytes = &bytes[20..];
        let (typ, code, checksum) = (bytes[0], bytes[1], BigEndian::read_u16(&bytes[2..4]));
        let message = match typ {
            8 => IcmpV4Message::Echo {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            0 => IcmpV4Message::EchoReply {
                identifier: BigEndian::read_u16(&bytes[4..6]),
                sequence: BigEndian::read_u16(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            },
            t => {
                dbg!(bytes);
                return Err(PacketParseError::UnrecognizedICMPType(t));
            }
        };
        return Ok(Self {
            typ: typ,
            code: code,
            checksum: checksum,
            message: message,
        });
    }

    /// Get this packet serialized to bytes suitable for sending on the wire.
    pub fn get_bytes(&self, with_checksum: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.typ);
        bytes.push(self.code);
        let mut buf = vec![0; 2];
        BigEndian::write_u16(&mut buf, if with_checksum { self.checksum } else { 0 });
        bytes.append(&mut buf);
        bytes.append(&mut self.message.get_bytes());
        return bytes;
    }

    // Calculate the checksum for the packet given the provided source and destination
    // addresses.
    pub fn calculate_checksum(&self) -> u16 {
        // First sum the pseudo header
        let mut sum = 0u32;

        // Then sum the len of the message bytes and then the message bytes starting
        // with the message type field and with the checksum field set to 0.
        let bytes = self.get_bytes(false);
        sum += sum_big_endian_words(&bytes);

        // handle the carry
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        !sum as u16
    }

    // Populate the checksum field of this Packet.
    pub fn with_checksum(mut self) -> Self {
        self.checksum = self.calculate_checksum();
        self
    }
}

impl TryFrom<&[u8]> for IcmpV4Packet {
    type Error = PacketParseError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        IcmpV4Packet::parse(b)
    }
}

impl WithEchoRequest for IcmpV4Packet {
    type Packet = IcmpV4Packet;

    fn with_echo_request(
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    ) -> Result<Self::Packet, IcmpPacketBuildError> {
        Ok(Self {
            typ: 8,
            code: 0,
            checksum: 0,
            message: IcmpV4Message::Echo {
                identifier,
                sequence,
                payload,
            },
        })
    }
}
