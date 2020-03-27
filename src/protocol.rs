use crate::opacket::{SessionInfo, HostInfo};
use std::error::Error;
use std::io::{Read, Seek, Cursor};
use byteorder::ReadBytesExt;
use std::io;
use std;
use crate::Tell;

#[derive(Debug, Copy, Clone)]
pub enum ServerProtocl{
    OKPacket,
    EOFPacket,
    ERRpacket,
    HandshakePacket,
    TextResult
}


impl ServerProtocl{
    pub fn new(cur: &mut Cursor<&[u8]>) -> std::result::Result<ServerProtocl, Box<dyn Error>>{
        let code = cur.read_u8()?;
        match code{
            0x00 => Ok(ServerProtocl::OKPacket),
            0xfe => Ok(ServerProtocl::EOFPacket),
            0xff => Ok(ServerProtocl::ERRpacket),
            0x0a => Ok(ServerProtocl::HandshakePacket),
            _ => Ok(ServerProtocl::TextResult)
        }
    }

    pub fn server_pro_unpacket(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo, host_info: &HostInfo) -> std::result::Result<(), Box<dyn Error>> {
        match self{
            ServerProtocl::OKPacket =>{
                self.unpacket_ok_packet(session_info, host_info);
            }
            ServerProtocl::ERRpacket => {
                self.unpacket_err_packet(cur, session_info, host_info)?;
            }
            ServerProtocl::HandshakePacket => {
                self.unpacket_handshake_packet(session_info, host_info);
            }
            ServerProtocl::EOFPacket => {
                self.unpacket_eof_packet(session_info, host_info);
            }
            ServerProtocl::TextResult => {
                self.unpacket_text_result(session_info, host_info);
            }
        }
        Ok(())
    }

    fn unpacket_handshake_packet(&self, session_info: &mut SessionInfo, host_info: &HostInfo) {
        /*
        Initial Handshake Packet

        When the client connects to the server the server sends a handshake packet to the client.
        Depending on the server version and configuration options different variants of the initial packet are sent

        Protocol::HandshakeV9:  0x09
        Protocol::HandshakeV10: 0x10
        */
        session_info.server_response = ServerProtocl::HandshakePacket;
        session_info.connection_pre = true;
        session_info.end_time = host_info.ts.clone();
    }

    fn unpacket_text_result(&self, session_info: &mut SessionInfo, host_info: &HostInfo) {
        /*
        A Text Resultset is a possible COM_QUERY Response.

        It is made up of 2 parts:

        the column definitions (a.k.a. the metadata)
        the actual rows

        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html

        */
        session_info.server_response = ServerProtocl::TextResult;
        session_info.end_time = host_info.ts.clone();
        session_info.out_info();
    }

    fn unpacket_eof_packet(&self, session_info: &mut SessionInfo, host_info: &HostInfo){
        /*
        If CLIENT_PROTOCOL_41 is enabled, the EOF packet contains a warning count and status flags.

        In the MySQL client/server protocol, the EOF_Packet and OK_Packet packets serve the same purpose,
        to mark the end of a query execution result. Due to changes in MySQL 5.7 in the OK_Packet packets (such as session state tracking),
        and to avoid repeating the changes in the EOF_Packet packet, the OK_Packet is deprecated as of MySQL 5.7.5

        Type	Name	Description
        int<1>	header	0xFE EOF packet header
        ...........................
        */
        session_info.server_response = ServerProtocl::EOFPacket;
        session_info.end_time = host_info.ts.clone();
        session_info.connection_pre = false;
        session_info.out_info();
    }

    fn unpacket_err_packet(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo, host_info: &HostInfo) -> std::result::Result<(), Box<dyn Error>> {
        /*
        This packet signals that an error occurred.

        It contains a SQL state value if CLIENT_PROTOCOL_41 is enabled

        Type	    Name	            Description
        int<1>	    header	            0xFF ERR packet header
        int<2>	    error_code	        error-code
        if capabilities & CLIENT_PROTOCOL_41 {
        string[1]	sql_state_marker	# marker of the SQL state
        string[5]	sql_state	        SQL state
        }
        string<EOF>	error_message	    human readable error message

        see:  https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
        */
        cur.seek(io::SeekFrom::Current(2))?;
        let mut tmp: Vec<u8> = vec![];
        cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = String::from_utf8_lossy(&tmp).to_string();
        session_info.server_response = ServerProtocl::ERRpacket;
        session_info.end_time = host_info.ts.clone();
        session_info.connection_pre = false;
        session_info.out_info();
        Ok(())
    }

    fn unpacket_ok_packet(&self, session_info: &mut SessionInfo, host_info: &HostInfo) {
        /*
        An OK packet is sent from the server to the client to signal successful completion of a command.

        As of MySQL 5.7.5, OK packes are also used to indicate EOF, and EOF packets are deprecated

        Type	        Name	            Description
        int<1>	        header	            0x00 or 0xFE the OK packet header
        int<lenenc>	    affected_rows	    affected rows
        int<lenenc>	    last_insert_id	    last insert-id
        ..................................................
        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_ok_packet.html

        :return:
        */
        session_info.server_response = ServerProtocl::OKPacket;
        session_info.end_time = host_info.ts.clone();
        session_info.connection_pre = false;
        session_info.out_info();
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
    ComStmtSendLongData,
    Null
}
impl ClientProtocol{
    pub fn new(cur: &mut Cursor<&[u8]>) -> std::result::Result<ClientProtocol, Box<dyn Error>>{
        let code = cur.read_u8()?;
        match code {
            0x03 => Ok(ClientProtocol::ComQuery),
            0x01 => Ok(ClientProtocol::ComQuit),
            0x02 => Ok(ClientProtocol::ComInitDb),
            0x04 => Ok(ClientProtocol::ComFieldList),
            0x07 => Ok(ClientProtocol::ComPrefresh),
            0x08 => Ok(ClientProtocol::ComStatistics),
            0x0A => Ok(ClientProtocol::ComProcessInfo),
            0x0C => Ok(ClientProtocol::ComProcessKill),
            0x0D => Ok(ClientProtocol::ComDebug),
            0x0E => Ok(ClientProtocol::ComPing),
            0x11 => Ok(ClientProtocol::ComChangeUser),
            0x1F => Ok(ClientProtocol::ComResetConnection),
            0x1A => Ok(ClientProtocol::ComSetOption),
            0x16 => Ok(ClientProtocol::ComStmtPrepare),
            0x17 => Ok(ClientProtocol::ComStmtExecute),
            0x19 => Ok(ClientProtocol::ComStmtClose),
            0x18 => Ok(ClientProtocol::ComStmtSendLongData),
            _ => Ok(ClientProtocol::Null)
        }

    }

    pub fn client_pro_unpacket(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo) -> std::result::Result<(), Box<dyn Error>> {
        match self{
            ClientProtocol::ComQuery => {
                self.unpacket_com_query(cur, session_info)?;
            }
            ClientProtocol::ComInitDb => {
                self.unpacket_com_initdb(cur,session_info)?;
            }
            ClientProtocol::ComStmtPrepare => {
                self.unpacket_com_stmt_prepare(cur,session_info)?;
            }
            ClientProtocol::ComQuit => {
                self.unpacket_com_quit(session_info);
            }
            ClientProtocol::ComProcessKill => {
                self.unpacket_com_process_kill(session_info);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn unpacket_com_query(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Type	    Name	Description
        int<1>	    command	0x03: COM_QUERY
        string<EOF>	query	the text of the SQL query to execute
        */
        let mut tmp: Vec<u8> = vec![];
        println!("{:?}", cur.tell());
        cur.read_exact(tmp.as_mut())?;
        println!("{:?}", cur.tell());
        let a = String::from_utf8_lossy(&tmp).to_string();
        println!("{:?}", a);
        session_info.execute_sql = a;
        session_info.client_request = ClientProtocol::ComQuery;
        session_info.is_ok = true;
        Ok(())
    }

    pub fn unpacket_com_initdb(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Type	    Name	    Description
        int<1>	    command	    0x02: COM_INIT_DB
        string<EOF>	schema name	name of the schema to change to

        server return:
            OK_Packet on success
            ERR_Packet on error
        */
        let mut tmp: Vec<u8> = vec![];
        cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = format!("use database {}",String::from_utf8_lossy(&tmp).to_string());
        session_info.client_request = ClientProtocol::ComInitDb;
        session_info.is_ok = true;
        Ok(())

    }

    pub fn unpacket_com_stmt_prepare(&self, cur: &mut Cursor<&[u8]>, session_info: &mut SessionInfo) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Creates a prepared statement for the passed query string

        Type	    Name	        Description
        int<1>	    command	        0x16: COM_STMT_PREPARE
        string<EOF>	query	        The query to prepare

        server return:
            COM_STMT_PREPARE_OK on success, ERR_Packet otherwise
        */
        let mut tmp: Vec<u8> = vec![];
        cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = String::from_utf8_lossy(&tmp).to_string();
        session_info.client_request = ClientProtocol::ComStmtPrepare;
        session_info.is_ok = true;
        Ok(())
    }

    pub fn unpacket_com_quit(&self, session_info: &mut SessionInfo) {
        /*
        Type	Name	    Description
        int<1>	command	    0x01: COM_QUIT

        Server closes the connection or returns ERR_Packet.
        */
        session_info.execute_sql = String::from("close connection");
        session_info.client_request = ClientProtocol::ComQuit;
        session_info.out_info();
    }

    pub fn unpacket_com_process_kill(&self, session_info: &mut SessionInfo) {
        /*
        As of MySQL 5.7.11, COM_PROCESS_KILL is deprecated and will be removed in a future version of MySQL. Instead,
        use COM_QUERY and a KILL command

        Type	Name	        Description
        int<1>	command	        0x0C: COM_PROCESS_KILL
        int<4>	connection_id	The connection to kill

        server return:
            ERR_Packet or OK_Packet
        */
        session_info.execute_sql = String::from("kill connection");
        session_info.client_request = ClientProtocol::ComProcessKill;
        session_info.out_info();
    }

}