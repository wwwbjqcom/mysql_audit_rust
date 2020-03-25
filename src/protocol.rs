

#[derive(Debug, Copy, Clone)]
pub enum ServerProtocl{
    OKPacket,
    EOFPacket,
    ERRpacket,
    HandshakePacket,
    TextResult
}


impl ServerProtocl{
    pub fn new(code: u8) -> ServerProtocl{
        match code{
            0x00 => ServerProtocl::OKPacket,
            0xfe => ServerProtocl::EOFPacket,
            0xff => ServerProtocl::ERRpacket,
            0x09 => ServerProtocl::HandshakePacket,
            0x0a => ServerProtocl::HandshakePacket,
            _ => ServerProtocl::TextResult
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub enum ClientProtocol{
    ComQuery,
    ComQuit,
    ComInitDb,
    ComFieldList,
    ComPrefresh,
    ComStatistics,
    ComProcessInfo,
    ComProcessKill,
    ComDebug,
    ComPing,
    ComChangeUser,
    ComResetConnection,
    ComSetOption,
    ComStmtPrepare,
    ComStmtExecute,
    ComStmtClose,
    ComStmtReset,
    ComStmtSendLongData,
    Null
}
impl ClientProtocol{
    pub fn new(code: u8) -> ClientProtocol{
        match code {
            0x03 => ClientProtocol::ComQuery,
            0x01 => ClientProtocol::ComQuit,
            0x02 => ClientProtocol::ComInitDb,
            0x04 => ClientProtocol::ComFieldList,
            0x07 => ClientProtocol::ComPrefresh,
            0x08 => ClientProtocol::ComStatistics,
            0x0A => ClientProtocol::ComProcessInfo,
            0x0C => ClientProtocol::ComProcessKill,
            0x0D => ClientProtocol::ComDebug,
            0x0E => ClientProtocol::ComPing,
            0x11 => ClientProtocol::ComChangeUser,
            0x1F => ClientProtocol::ComResetConnection,
            0x1A => ClientProtocol::ComSetOption,
            0x16 => ClientProtocol::ComStmtPrepare,
            0x17 => ClientProtocol::ComStmtExecute,
            0x19 => ClientProtocol::ComStmtClose,
            0x18 => ClientProtocol::ComStmtSendLongData,
            _ => ClientProtocol::Null
        }

    }
}