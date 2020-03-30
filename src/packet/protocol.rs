/*
@author: xiao cai niao
@datetime: 2020/3/28
*/
use std::error::Error;
use std::io::{Read, Seek};
use std::io;
use std;
use byteorder::{ReadBytesExt, LittleEndian};
use crate::packet::{MysqlProtocol, StreamType, MysqlProtocolHeader, StreamPacket};
use crate::session::{SessionHostInfo, SessionInfo};

impl MysqlProtocol{
    pub fn new(stream_packet: &mut StreamPacket) -> Result<MysqlProtocol, Box<dyn Error>>{
        let code = stream_packet.data_cur.read_u8()?;
        match code{
            0x00 => Ok(MysqlProtocol::OKPacket),
            0xfe => Ok(MysqlProtocol::EOFPacket),
            0xff => Ok(MysqlProtocol::ERRpacket),
            0x0a => Ok(MysqlProtocol::HandshakePacket),
            0x03 => Ok(MysqlProtocol::ComQuery),
            0x01 => Ok(MysqlProtocol::ComQuit),
            0x02 => Ok(MysqlProtocol::ComInitDb),
            0x0C => Ok(MysqlProtocol::ComProcessKill),
            0x16 => Ok(MysqlProtocol::ComStmtPrepare),
            _ => {
                match stream_packet.s_type{
                    StreamType::Response => Ok(MysqlProtocol::TextResult),
                    StreamType::Request => Ok(MysqlProtocol::Null),
                }
            }
        }
    }

    ///
    /// 检查返回包类型的正确性
    pub fn check_response_packet(&self, response: &MysqlProtocol) -> bool {
        match self{
            MysqlProtocol::ComQuery => {
                return self.check_com_query_response(response);
            }
            MysqlProtocol::ComInitDb => {
                return self.check_ok_err_eof_response(response);
            }
            MysqlProtocol::ComStmtPrepare => {
                return self.check_com_prepare_response(response);
            }
            MysqlProtocol::ComProcessKill => {
                return self.check_com_killprocess_response(response);
            }
            MysqlProtocol::HandshakePacket => {
                return self.check_ok_err_eof_response(response);
            }
            _ => {}
        }
        false
    }

    fn check_com_query_response(&self, response: &MysqlProtocol) -> bool{
        match response{
            MysqlProtocol::TextResult => true,
            MysqlProtocol::OKPacket => true,
            MysqlProtocol::ERRpacket => true,
            MysqlProtocol::EOFPacket => true,
            _ => false
        }
    }

    fn check_com_prepare_response(&self, response: &MysqlProtocol) -> bool{
        match response{
            MysqlProtocol::OKPacket => true,
            MysqlProtocol::ERRpacket => true,
            _ => false
        }
    }

    fn check_ok_err_eof_response(&self, response: &MysqlProtocol) -> bool{
        match response{
            MysqlProtocol::OKPacket => true,
            MysqlProtocol::ERRpacket => true,
            MysqlProtocol::EOFPacket => true,
            _ => false
        }
    }

    fn check_com_killprocess_response(&self, response: &MysqlProtocol) -> bool{
        match response{
            MysqlProtocol::OKPacket => true,
            MysqlProtocol::ERRpacket => true,
            _ => false
        }
    }


    pub fn protocol_unpacket(&self, stream_packet: &mut StreamPacket, session_info: &mut SessionInfo) -> std::result::Result<(), Box<dyn Error>> {
        match self{
            MysqlProtocol::OKPacket =>{
                self.unpacket_ok_packet(session_info, stream_packet);
            } MysqlProtocol::ERRpacket => {
                self.unpacket_err_packet(session_info, stream_packet)?;
            } MysqlProtocol::HandshakePacket => {
                self.unpacket_handshake_packet(session_info, stream_packet);
            } MysqlProtocol::EOFPacket => {
                self.unpacket_eof_packet(session_info, stream_packet);
            } MysqlProtocol::TextResult => {
                self.unpacket_text_result(session_info, stream_packet);
            } MysqlProtocol::ComQuery => {
                self.unpacket_com_query(session_info, stream_packet)?;
            } MysqlProtocol::ComInitDb => {
                self.unpacket_com_initdb(session_info, stream_packet)?;
            } MysqlProtocol::ComStmtPrepare => {
                self.unpacket_com_stmt_prepare(session_info, stream_packet)?;
            } MysqlProtocol::ComQuit => {
                self.unpacket_com_quit(session_info);
            } MysqlProtocol::ComProcessKill => {
                self.unpacket_com_process_kill(session_info, stream_packet)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn unpacket_handshake_packet(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) {
        /*
        Initial Handshake Packet

        When the client connects to the server the server sends a handshake packet to the client.
        Depending on the server version and configuration options different variants of the initial packet are sent

        Protocol::HandshakeV9:  0x09
        Protocol::HandshakeV10: 0x10
        */
        session_info.server_response = MysqlProtocol::HandshakePacket;
        session_info.connection_pre = true;
        session_info.is_ok = true;
        session_info.end_time = stream_packet.ts.clone();
    }

    fn unpacket_text_result(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) {
        /*
        A Text Resultset is a possible COM_QUERY Response.

        It is made up of 2 parts:

        the column definitions (a.k.a. the metadata)
        the actual rows

        see: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html

        */
        if session_info.connection_pre{
            return;
        }
        session_info.server_response = MysqlProtocol::TextResult;
        session_info.end_time = stream_packet.ts.clone();
    }

    fn unpacket_eof_packet(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket){
        /*
        If CLIENT_PROTOCOL_41 is enabled, the EOF packet contains a warning count and status flags.

        In the MySQL client/server protocol, the EOF_Packet and OK_Packet packets serve the same purpose,
        to mark the end of a query execution result. Due to changes in MySQL 5.7 in the OK_Packet packets (such as session state tracking),
        and to avoid repeating the changes in the EOF_Packet packet, the OK_Packet is deprecated as of MySQL 5.7.5

        Type	Name	Description
        int<1>	header	0xFE EOF packet header
        ...........................
        */
        session_info.server_response = MysqlProtocol::EOFPacket;
        session_info.end_time = stream_packet.ts.clone();
        session_info.connection_pre = false;
    }

    fn unpacket_err_packet(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) -> std::result::Result<(), Box<dyn Error>> {
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
        stream_packet.data_cur.seek(io::SeekFrom::Current(2))?;
        let mut tmp: Vec<u8> = vec![];
        stream_packet.data_cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = String::from_utf8_lossy(&tmp).to_string();
        session_info.server_response = MysqlProtocol::ERRpacket;
        session_info.end_time = stream_packet.ts.clone();
        session_info.connection_pre = false;
        Ok(())
    }

    fn unpacket_ok_packet(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) {
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
        session_info.server_response = MysqlProtocol::OKPacket;
        session_info.end_time = stream_packet.ts.clone();
        session_info.connection_pre = false;
    }

    pub fn unpacket_com_query(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Type	    Name	Description
        int<1>	    command	0x03: COM_QUERY
        string<EOF>	query	the text of the SQL query to execute
        */
        let mut tmp: Vec<u8> = vec![];
        stream_packet.data_cur.read_to_end(tmp.as_mut())?;
        session_info.execute_sql = String::from_utf8_lossy(&tmp).to_string();
        session_info.client_request = MysqlProtocol::ComQuery;
        session_info.is_ok = true;
        Ok(())
    }

    pub fn unpacket_com_initdb(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Type	    Name	    Description
        int<1>	    command	    0x02: COM_INIT_DB
        string<EOF>	schema name	name of the schema to change to

        server return:
            OK_Packet on success
            ERR_Packet on error
        */
        let mut tmp: Vec<u8> = vec![];
        stream_packet.data_cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = format!("use database {}",String::from_utf8_lossy(&tmp).to_string());
        session_info.client_request = MysqlProtocol::ComInitDb;
        session_info.is_ok = true;
        Ok(())

    }

    pub fn unpacket_com_stmt_prepare(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) -> std::result::Result<(), Box<dyn Error>> {
        /*
        Creates a prepared statement for the passed query string

        Type	    Name	        Description
        int<1>	    command	        0x16: COM_STMT_PREPARE
        string<EOF>	query	        The query to prepare

        server return:
            COM_STMT_PREPARE_OK on success, ERR_Packet otherwise
        */
        let mut tmp: Vec<u8> = vec![];
        stream_packet.data_cur.read_exact(tmp.as_mut())?;
        session_info.execute_sql = String::from_utf8_lossy(&tmp).to_string();
        session_info.client_request = MysqlProtocol::ComStmtPrepare;
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
        session_info.client_request = MysqlProtocol::ComQuit;
    }

    pub fn unpacket_com_process_kill(&self, session_info: &mut SessionInfo, stream_packet: &mut StreamPacket) -> Result<(), Box<dyn Error>> {
        /*
        As of MySQL 5.7.11, COM_PROCESS_KILL is deprecated and will be removed in a future version of MySQL. Instead,
        use COM_QUERY and a KILL command

        Type	Name	        Description
        int<1>	command	        0x0C: COM_PROCESS_KILL
        int<4>	connection_id	The connection to kill

        server return:
            ERR_Packet or OK_Packet
        */
        let connection_id = stream_packet.data_cur.read_u32::<LittleEndian>()?;
        session_info.execute_sql = format!("kill connection {}", connection_id);
        session_info.client_request = MysqlProtocol::ComProcessKill;
        Ok(())
    }
}

impl MysqlProtocolHeader{
    pub fn new(stream_packet: &mut StreamPacket) -> Result<MysqlProtocolHeader, Box<dyn Error>>{
        let payload = stream_packet.data_cur.read_u24::<LittleEndian>()?;
        let seq_id = stream_packet.data_cur.read_u8()?;
        let protocol_type = MysqlProtocol::new(stream_packet)?;
        Ok(MysqlProtocolHeader{
            payload,
            seq_id,
            protocol_type
        })
    }
}

