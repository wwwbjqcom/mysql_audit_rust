/*
@author: xiao cai niao
@datetime: 2020/3/28
*/
mod protocol;
use std::error::Error;
use std::io::{Cursor, Seek, Read};
use byteorder::{ReadBytesExt, BigEndian};
use std::io;
use crate::Config;
use crate::session;
use crate::session::{SessionInfo, SessionHostInfo};
use std::convert::TryInto;


#[derive(Clone, Debug)]
pub struct UnixTime{
    pub tv_sec: u64,
    pub tv_usec: u64
}

impl UnixTime{
    pub fn new(ts: &libc::timeval) -> Result<UnixTime,Box<dyn Error>>{
        Ok(UnixTime{
            tv_sec: ts.tv_sec.try_into()?,
            tv_usec: ts.tv_usec.try_into()?,
        })
    }
}


///
/// 解析出的ip结构
///
#[derive(Debug, Clone)]
pub struct Ip{
    pub ip_first: u8,
    pub ip_two: u8,
    pub ip_three: u8,
    pub ip_four: u8
}
impl Ip{
    pub fn new(cur: &mut Cursor<&[u8]>) -> Ip{
        let ip_first = cur.read_u8().unwrap();
        let ip_two = cur.read_u8().unwrap();
        let ip_three = cur.read_u8().unwrap();
        let ip_four = cur.read_u8().unwrap();
        Ip {
            ip_first,
            ip_two,
            ip_three,
            ip_four
        }
    }

    pub fn format_ip(&self) -> String{
        format!("{}.{}.{}.{}", self.ip_first.clone(), self.ip_two.clone(), self.ip_three.clone(),self.ip_four.clone())
    }
}

///
/// 数据包方向(请求/回应)
#[derive(Clone, Debug)]
pub enum StreamType{
    Request,
    Response
}

///
/// mysql协议类型
#[derive(Debug, Clone)]
pub enum MysqlProtocol{
    OKPacket,
    EOFPacket,
    ERRpacket,
    HandshakePacket,
    TextResult,
    ComQuery,
    ComQuit,
    ComInitDb,
    ComProcessKill,
    ComStmtPrepare,
    Null
}

///
/// 记录mysql协议包头部分及该包类型
#[derive(Debug, Clone)]
pub struct  MysqlProtocolHeader{
    pub payload: u32,
    pub seq_id: u8,
    pub protocol_type: MysqlProtocol
}


pub struct StreamPacket{
    pub data_cur: Cursor<Vec<u8>>,
    pub packet_flag: u8,
    pub ts: UnixTime,
    pub len: u32,
    pub source: Ip,
    pub destination: Ip,
    pub source_port: u16,
    pub destination_port: u16,
    pub s_type: StreamType,
    pub session_host_info: SessionHostInfo,
    pub protocol_header: MysqlProtocolHeader,
}

impl StreamPacket{
    pub fn new(packet: &pcap::Packet) -> Result<StreamPacket, Box<dyn Error>>{
        let ts = UnixTime::new(&packet.header.ts)?;
        let len= packet.header.len;

        let mut cur = Cursor::new(packet.data);
        cur.seek(io::SeekFrom::Current(26)).unwrap();
        let source = Ip::new(&mut cur);
        let destination = Ip::new(&mut cur);
        let source_port = cur.read_u16::<BigEndian>().unwrap();
        let destination_port = cur.read_u16::<BigEndian>().unwrap();

        cur.seek(io::SeekFrom::Current(9)).unwrap();
        let packet_flag = cur.read_u8().unwrap();

        cur.seek(io::SeekFrom::Current(18))?;
        let mut packet_data: Vec<u8> = vec![];
        cur.read_to_end(packet_data.as_mut())?;
        let data_cur = Cursor::new(packet_data);
        Ok(StreamPacket{
            data_cur,
            packet_flag,
            ts,
            len,
            source,
            destination,
            source_port,
            destination_port,
            s_type: StreamType::Request,
            session_host_info: SessionHostInfo::new(),
            protocol_header: MysqlProtocolHeader {
                payload: 0,
                seq_id: 0,
                protocol_type: MysqlProtocol::Null
            }
        })
    }

    ///
    /// 判断获取到的数据流是请求还是响应
    ///
    pub fn set_stream_type(&mut self,conf: &Config) -> Result<String, Box<dyn Error>> {
        if conf.dtype == String::from("src"){
            return self.check_src(conf);
        }else {
            return self.check_des(conf);
        }
    }

    ///
    /// 监听模式为src的情况， 即本机为源
    fn check_src(&mut self,conf: &Config) -> Result<String, Box<dyn Error>>{
        let mut session_key = String::from("");
        if &self.source.format_ip() == &conf.host{
            session_key = format!("{}:{}", conf.host.clone(), self.source_port.clone());
            self.session_host_info.set(conf.host.clone(),
                                       self.destination.format_ip(),
                                       self.source_port.clone(),
                                       self.destination_port.clone());
            self.s_type = StreamType::Request;
        }else {
            session_key = format!("{}:{}", self.destination.format_ip(), self.destination_port.clone());
            self.session_host_info.set(self.destination.format_ip(),
                                       self.source.format_ip(),
                                       self.destination_port.clone(),
                                       self.source_port.clone());
            self.s_type = StreamType::Response;
        }
        Ok(session_key)
    }

    ///
    /// 监听模式为des的情况， 即本机为目标
    fn check_des(&mut self,conf: &Config) -> Result<String, Box<dyn Error>>{
        let mut session_key = String::from("");
        if self.destination.format_ip() == conf.host{
            session_key = format!("{}:{}", self.source.format_ip(), self.source_port.clone());
            self.session_host_info.set(self.source.format_ip(),
                                       self.destination.format_ip(),
                                       self.source_port.clone(),
                                       self.destination_port.clone());
            self.s_type = StreamType::Request;
        }else {
            session_key = format!("{}:{}", self.destination.format_ip(), self.destination_port.clone());
            self.session_host_info.set(self.destination.format_ip(),
                                       self.source.format_ip(),
                                       self.destination_port.clone(),
                                       self.source_port.clone());
            self.s_type = StreamType::Response;
        }
        Ok(session_key)
    }

    ///
    /// 获取当前包的mysql协议的payload、seq_id、Mysqlprotocol_type
    pub fn get_mysql_protocol_header(&mut self) -> Result<(), Box<dyn Error>>{
        let protocol_header = MysqlProtocolHeader::new(self)?;
        self.protocol_header = protocol_header;
        Ok(())
    }

    pub fn check_port(&self, conf: &Config) -> bool{
        if conf.port == 0{
            return true;
        }
        else if self.source_port == conf.port{
            return true;
        }else if self.destination_port == conf.port{
            return true;
        }else{
            return false;
        }
    }

    ///
    /// 操作session数据
    /// 包含解析内容，如果结束类的包将打印
    pub fn op_session_info(&mut self, session_key: &String, all_session: &mut session::AllSessionInfo) -> Result<(), Box<dyn Error>>{
        match self.s_type{
            StreamType::Request => {
                match all_session.aluino.get(session_key){
                    Some(v) => {
                        let mut local_session = v.clone();
                        if v.connection_pre{
                            // 准备创建连接
                            local_session.unpacket_handshake_response(self)?;
                            local_session.insert(all_session, session_key)?;
                        }else {
                            local_session.session_unpacket(self, session_key, all_session)?;
                        }
                    }
                    None => {
                        let mut new_session = SessionInfo::new(self)?;
                        new_session.session_unpacket(self, session_key, all_session)?;
                    }
                }
            }
            StreamType::Response => {
                match self.protocol_header.protocol_type {
                    MysqlProtocol::HandshakePacket => {
                        //准备创建连接
                        let mut new_session = SessionInfo::new(self)?;
                        MysqlProtocol::HandshakePacket.protocol_unpacket(self, &mut new_session)?;
                        new_session.insert(all_session, session_key)?;
                    }
                    _ => {
                        match all_session.aluino.get(session_key){
                            Some(v) => {
                                if v.connection_pre {
                                    if v.create_conn_auth{
                                        // 已收到连接验证信息，判断返回包类型， 如果为结束类型包将做打印和删除操作
                                        if v.server_response.check_response_packet(&self.protocol_header.protocol_type){
                                            v.out_info();
                                            all_session.remove(session_key);
                                        }
                                    }
                                    // 已存在准备连接的session信息但未收到连接验证信息， 不做处理
                                    return Ok(())
                                }
                                else if v.seq_id + 1 == self.protocol_header.seq_id{
                                    // 包seq_id为顺序， 表示正常, 进行解包
                                    let mut local_session = v.clone();
                                    local_session.session_unpacket(self, session_key, all_session)?;
                                }
                            }
                            None => {}
                        }
                    }
                }
            }
        }
        Ok(())
    }



}