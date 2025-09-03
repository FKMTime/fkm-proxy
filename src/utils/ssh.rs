#[derive(Debug)]
pub struct SshPacketHeader {
    pub packet_type: SshPacketType,
    pub length: u32,
}

impl SshPacketHeader {
    pub const HEADER_LENGTH: usize = 6;

    pub fn to_buf(&self) -> [u8; Self::HEADER_LENGTH] {
        let mut tmp = [0; Self::HEADER_LENGTH];
        tmp[0] = self.packet_type.to_u8();
        tmp[1..5].copy_from_slice(&self.length.to_be_bytes());
        tmp
    }

    pub fn from_buf(buf: &[u8; Self::HEADER_LENGTH]) -> Self {
        Self {
            packet_type: SshPacketType::from_u8(buf[0]),
            length: u32::from_be_bytes(buf[1..5].try_into().expect("Cannot fail")),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SshPacketType {
    Invalid = 0,
    PtyResize = 1,
    Data = 2,
    User = 3,
}

impl SshPacketType {
    pub fn to_u8(&self) -> u8 {
        match self {
            SshPacketType::Invalid => 0,
            SshPacketType::PtyResize => 1,
            SshPacketType::Data => 2,
            SshPacketType::User => 3,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => SshPacketType::PtyResize,
            2 => SshPacketType::Data,
            3 => SshPacketType::User,
            _ => SshPacketType::Invalid,
        }
    }
}
