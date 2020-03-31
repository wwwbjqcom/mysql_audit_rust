/*
@author: xiao cai niao
@datetime: 2020/3/28
*/
use std::io::{Seek};
use std::io;
use std;
use byteorder::{ReadBytesExt};
use crate::packet::{MysqlProtocol, StreamPacket, StreamType};
use crate::packet::UnixTime;
use std::collections::HashMap;
use std::error::Error;
use std::str::from_utf8;
use crate::Tell;

///
/// 记录session ip端口信息
#[derive(Debug, Clone)]
pub struct SessionHostInfo{
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16
}

impl SessionHostInfo{
    pub fn new() -> SessionHostInfo{
        SessionHostInfo{
            source: "".to_string(),
            destination: "".to_string(),
            source_port: 0,
            destination_port: 0
        }
    }
    pub fn set(&mut self, source: String, destination: String, source_port: u16, destionation_port: u16) {
        self.source = source.clone();
        self.destination = destination.clone();
        self.source_port = source_port.clone();
        self.destination_port = destionation_port.clone();
    }
}

///
/// 该结构记录client一次请求到结束的流程
///
#[derive(Clone, Debug)]
pub struct SessionInfo{
    pub source: String,                         // 源地址
    pub destination: String,                    // 目标地址
    pub source_port: u16,                       // 源端口
    pub destination_port: u16,                  // 目标端口
    pub client_request: MysqlProtocol,          // 请求协议类型
    pub server_response: MysqlProtocol,         // 返回协议类型
    pub user_name: String,                      // 连接使用的用户名
    pub create_conn_auth: bool,                 // 是否已接收到创建连接所使用的验证信息
    pub execute_sql: String,                    // 执行的请求语句
    pub response_value: String,                 // 返回的情况
    pub connection_pre: bool,                   // 准备建立连接
    pub seq_id: u8,                             // 当前包的seq_id
    pub start_time: UnixTime,                   // 开始时间
    pub end_time: UnixTime,                     // 结束时间
    pub is_ok: bool,                            // 是否为需要的包， 不需要的不会插入
}

impl SessionInfo{
    pub fn new(stream_packet: &mut StreamPacket) -> Result<SessionInfo, Box<dyn Error>>{
        Ok(SessionInfo{
            source: stream_packet.session_host_info.source.clone(),
            destination: stream_packet.session_host_info.destination.clone(),
            source_port: stream_packet.session_host_info.source_port.clone(),
            destination_port: stream_packet.session_host_info.destination_port.clone(),
            client_request: MysqlProtocol::Null,
            server_response: MysqlProtocol::Null,
            user_name: "".to_string(),
            create_conn_auth: false,
            execute_sql: "".to_string(),
            response_value: "".to_string(),
            connection_pre: false,
            seq_id: stream_packet.protocol_header.seq_id.clone(),
            start_time: stream_packet.ts.clone(),
            end_time: UnixTime{ tv_sec: 0, tv_usec: 0 },
            is_ok: false
        })
    }

    ///
    /// 解包并写入或清除
    pub fn session_unpacket(&mut self, stream_packet: &mut StreamPacket, session_key: &String, all_session: &mut AllSessionInfo) -> Result<(), Box<dyn Error>> {
        //let mut local_session = self.clone();   //复制一个全新的session， 用于可变
        let protocol_type = stream_packet.protocol_header.protocol_type.clone();
        protocol_type.protocol_unpacket(stream_packet, self)?;
        match stream_packet.s_type{
            StreamType::Request => {
                //插入session缓存
                self.insert(all_session, session_key)?;
            }
            StreamType::Response => {
                //打印并删除
                self.out_info();
                all_session.remove(session_key);
            }
        }
        Ok(())
    }

    ///
    /// 操作client创建链接时回的handshake包， 从中获取user_name
    /// 如果数据包id不为顺序表示存在问题，返回false，替换该session
    pub fn unpacket_handshake_response(&mut self, stream_packet: &mut StreamPacket) -> std::result::Result<(), Box<dyn Error>>{
        if stream_packet.protocol_header.seq_id == self.seq_id + 1{
            stream_packet.data_cur.seek(io::SeekFrom::Current(31))?;
            println!("{}, {}, {}", stream_packet.data_cur.tell()?, stream_packet.protocol_header.payload, stream_packet.len);
            let mut user_name_packet: Vec<u8> = vec![];
            loop {
                let a = stream_packet.data_cur.read_u8()?;
                if &a == &0x00 {
                    break;
                } else {
                    user_name_packet.push(a);
                }
            }
            let user_name = from_utf8(user_name_packet.as_ref())?;
            self.user_name = user_name.parse()?;
            self.create_conn_auth = true;
        }
        Ok(())
    }

    pub fn insert(&self, all_session_info: &mut AllSessionInfo, session_key: &String) -> std::result::Result<(), Box<dyn Error>> {
        if self.is_ok{
            all_session_info.aluino.insert(session_key.parse()?, self.clone());
        }
        Ok(())
    }

    ///
    /// 输出信息
    pub fn out_info(&self) {
        println!("{:?}", self);
    }
}

///
/// 存放每个连接与用户的对应关系
#[derive(Debug)]
pub struct Connection{
    pub host: String,
    pub port: u16,
    pub user_name: String
}

///
/// 记录所有客户端操作流程信息， 已源ip:port作为唯一键
/// 一个会话操作结束会删除对应信息
///
#[derive(Debug)]
pub struct AllSessionInfo {
    pub aluino: HashMap<String, SessionInfo>,
    pub connections: HashMap<String, Connection>
}
impl AllSessionInfo{
    pub fn new() -> AllSessionInfo{
        AllSessionInfo{ aluino: HashMap::new(), connections: HashMap::new() }
    }

    pub fn remove(&mut self, session_key: &String){
        self.aluino.remove(session_key);
    }

}
