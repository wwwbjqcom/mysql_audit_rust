use std::io::{Seek, Cursor};
use std::io;
use std;
use libc;
use byteorder::{ReadBytesExt, BigEndian};
use crate::protocol::{ClientProtocol,ServerProtocl};
use crate::Config;
use std::collections::HashMap;
use std::error::Error;
use std::str::from_utf8;
use std::convert::TryInto;


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


#[derive(Clone, Debug)]
pub enum StreamType{
    Request,
    Response,
    Null
}
impl StreamType{
    pub fn streamtype_unpacket(&self, all_session: &mut AllSessionInfo, session_key: &String, cur: &mut Cursor<&[u8]>, host_info: &HostInfo, conf: &Config) -> std::result::Result<(), Box<dyn Error>>{
        cur.seek(io::SeekFrom::Current(31))?;   //跳过网络层协议包内容及mysql协议前3字节payload的部分
        match self{
            StreamType::Response => {
                //响应包
                let seq_id = cur.read_u8()?;
                if !self.check_handshake_response(all_session, session_key, cur, host_info, conf)?{
                    match all_session.aluino.get(session_key){
                        Some(session) =>{
                            let mut session = session.clone();
                            if session.connection_pre{
                                session.session_unpacket(cur, &StreamType::Response, host_info)?;
                            }
                            else if seq_id == session.seq_id + 1{
                                session.session_unpacket(cur, &StreamType::Response, host_info)?;
                            };
                            //如果为连接建立， 需要多次来回，在这不删除，直到成功或失败
                            if !session.connection_pre{
                                all_session.remove(session_key);
                            }
                        }
                        _ =>{
                        }
                    }
                }
            },
            StreamType::Request => {
                //请求包
                match all_session.aluino.get(session_key){
                    Some(session) => {
                        let mut session = session.clone();
                        if !session.connection_pre{
                            let mut new_session = session.replace(host_info, cur, &StreamType::Request)?;
                            new_session.session_unpacket(cur, &StreamType::Request, host_info)?;
                            new_session.insert(all_session, session_key)?;
                        }else {
                            session.unpacket_handshake_response(cur)?;
                            //let new_session = session.replace(host_info, cur, &StreamType::Request)?;
                            session.insert(all_session, session_key)?;
                        }

                        return Ok(());
                    }
                    None => {
                        let mut new_session = SessionInfo::new(conf, &host_info, cur)?;
                        new_session.session_unpacket(cur, &StreamType::Request, host_info)?;
                        new_session.insert(all_session, session_key)?;
                    }
                }
            },
            StreamType::Null =>{}
        }
        Ok(())
    }


    fn check_handshake_response(&self, all_session: &mut AllSessionInfo, session_key: &String, cur: &mut Cursor<&[u8]>, host_info: &HostInfo, conf: &Config) -> Result<bool, Box<dyn Error>>{
        let pro= ServerProtocl::new(cur)?;
        match pro{
            ServerProtocl::HandshakePacket => {
                let mut new_session = SessionInfo::new(conf, &host_info, cur)?;
                pro.server_pro_unpacket(cur, &mut new_session, host_info)?;
                new_session.insert(all_session, session_key)?;
                return Ok(true)
            }
            _ => {}
        }
        cur.seek(io::SeekFrom::Current(-1))?;
        Ok(false)
    }
}

///
/// 数据包中解析出的源/目的ip和端口信息
///
#[derive(Clone, Debug)]
pub struct HostInfo{
    pub source: Ip,
    pub destination: Ip,
    pub source_port: u16,
    pub destination_port: u16,
    pub ts: UnixTime,
    pub rtype: StreamType           //记录该包是request还是response
}
impl HostInfo{
    pub fn new(mut cur: &mut Cursor<&[u8]>, ts: &UnixTime) -> HostInfo{
        cur.seek(io::SeekFrom::Current(26)).unwrap();
        let source = Ip::new(&mut cur);
        let destination = Ip::new(&mut cur);
        let source_port = cur.read_u16::<BigEndian>().unwrap();
        let destination_port = cur.read_u16::<BigEndian>().unwrap();
        HostInfo{
            source,
            destination,
            source_port,
            destination_port,
            ts: ts.clone(),
            rtype: StreamType::Null
        }
    }

    ///
    /// 判断包的session， 返回分别为源ip port 目标ip 端口
    pub fn get_source_destination_info(&self, conf: &Config) -> (String, u16, String, u16){
        let des_ip = self.destination.format_ip();
        let src_ip = self.source.format_ip();
        if conf.dtype == "src".to_string(){
            if conf.host == des_ip{
                return (des_ip, self.destination_port.clone(), src_ip, self.source_port.clone());
            }else {
                return (src_ip, self.source_port.clone(), des_ip, self.destination_port.clone());
            }
        }else {
            if conf.host == des_ip{
                return (src_ip, self.source_port.clone(), des_ip, self.destination_port.clone());
            }
            else {
                return (des_ip, self.destination_port.clone(), src_ip, self.source_port.clone());
            }
        }
    }

    ///
    /// 检查获取的端口是否与配置的相匹配
    ///
    pub fn check_port(&self,port: &u16) -> bool{
        if port == &0{
            return true;
        }
        else if &self.source_port == port{
            return true;
        }else if &self.destination_port == port{
            return true;
        }else{
            return false;
        }
    }

    ///
    /// 判断获取到的数据流是请求还是响应
    ///
    pub fn check_request_respons(&mut self,conf: &Config, all_session: &mut AllSessionInfo, cur: &mut Cursor<&[u8]>) -> std::result::Result<(), Box<dyn Error>> {
        if conf.dtype == String::from("src"){
            self.check_src(conf, all_session, cur)?;
        }else {
            self.check_des(conf, all_session, cur)?;
        }
        Ok(())
    }

    ///
    /// 监听模式为src的情况， 即本机为源
    fn check_src(&mut self,conf: &Config, all_session: &mut AllSessionInfo, cur: &mut Cursor<&[u8]>) -> std::result::Result<(), Box<dyn Error>>{
        let mut session_key = String::from("");
        if &self.source.format_ip() == &conf.host{
            session_key = format!("{}:{}", conf.host.clone(), self.source_port.clone());
            self.rtype = StreamType::Request;
        }else {
            session_key = format!("{}:{}", self.destination.format_ip(), self.destination_port.clone());
            self.rtype = StreamType::Response;
        }
        self.rtype.streamtype_unpacket(all_session, &session_key, cur, &self, conf)?;
        Ok(())
    }

    ///
    /// 监听模式为des的情况， 即本机为目标
    fn check_des(&mut self,conf: &Config, all_session: &mut AllSessionInfo, cur: &mut Cursor<&[u8]>) -> std::result::Result<(), Box<dyn Error>>{
        let mut session_key = String::from("");
        if self.destination.format_ip() == conf.host{
            session_key = format!("{}:{}", self.source.format_ip(), self.source_port.clone());
            self.rtype = StreamType::Request;
        }else {
            session_key = format!("{}:{}", self.destination.format_ip(), self.destination_port.clone());
            self.rtype = StreamType::Response;
        }
        self.rtype.streamtype_unpacket(all_session, &session_key, cur, &self, conf)?;
        Ok(())
    }
}

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
/// 该结构记录client一次请求到结束的流程
///
#[derive(Clone, Debug)]
pub struct SessionInfo{
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub client_request: ClientProtocol,
    pub server_response: ServerProtocl,
    pub user_name: String,
    pub execute_sql: String,
    pub response_value: String,
    pub connection_pre: bool,
    pub seq_id: u8,
    pub start_time: UnixTime,
    pub end_time: UnixTime,
    pub is_ok: bool,        //是否为需要的包， 不需要的不会插入
}

impl SessionInfo{
    pub fn new(conf: &Config, host_info: &HostInfo, cur: &mut Cursor<&[u8]>) -> Result<SessionInfo, Box<dyn Error>>{
        let (source, source_port, destination, destination_port) = host_info.get_source_destination_info(conf);
        let seq_id = cur.read_u8()?;
        Ok(SessionInfo{
            source,
            destination,
            source_port,
            destination_port,
            client_request: ClientProtocol::Null,
            server_response: ServerProtocl::TextResult,
            user_name: "".to_string(),
            execute_sql: "".to_string(),
            response_value: "".to_string(),
            connection_pre: false,
            seq_id,
            start_time: host_info.ts.clone(),
            end_time: UnixTime{ tv_sec: 0, tv_usec: 0 },
            is_ok: false
        })
    }

    ///
    /// 用于重置session信息
    ///
    pub fn replace(&self, host_info: &HostInfo, cur: &mut Cursor<&[u8]>, rtype: &StreamType) -> std::result::Result<SessionInfo, Box<dyn Error>>{
        let seq_id = cur.read_u8()?;
        let mut si = SessionInfo{
            source: host_info.source.format_ip(),
            destination: host_info.destination.format_ip(),
            source_port: host_info.source_port.clone(),
            destination_port: host_info.destination_port.clone(),
            client_request: ClientProtocol::Null,
            server_response: ServerProtocl::TextResult,
            user_name: "".to_string(),
            execute_sql: "".to_string(),
            response_value: "".to_string(),
            connection_pre: false,
            seq_id,
            start_time: host_info.ts.clone(),
            end_time: UnixTime{ tv_sec: 0, tv_usec: 0 },
            is_ok: false
        };
        si.session_unpacket(cur, rtype, host_info)?;
        return Ok(si);
    }

    fn session_unpacket(&mut self, cur: &mut Cursor<&[u8]>, rtype: &StreamType, host_info: &HostInfo) -> std::result::Result<(), Box<dyn Error>> {
        match rtype{
            StreamType::Request =>{
                let pro= ClientProtocol::new(cur)?;
                pro.client_pro_unpacket(cur, self)?;
            }
            StreamType::Response => {
                let pro = ServerProtocl::new(cur)?;
                pro.server_pro_unpacket(cur, self, host_info)?;
            }
            _ =>{}
        }
        Ok(())

    }

    ///
    /// 操作client创建链接时回的handshake包， 从中获取user_name
    /// 如果数据包id不为顺序表示存在问题，返回false，替换该session
    fn unpacket_handshake_response(&mut self, cur: &mut Cursor<&[u8]>) -> std::result::Result<(), Box<dyn Error>>{
        let seq_id = cur.read_u8()?;
        if seq_id == self.seq_id + 1{
            cur.seek(io::SeekFrom::Current(32))?;
            let mut user_name_packet: Vec<u8> = vec![];
            loop {
                let a = cur.read_u8()?;
                if &a == &0x00 {
                    break;
                } else {
                    user_name_packet.push(a);
                }
            }
            let user_name = from_utf8(user_name_packet.as_ref())?;
            self.user_name = user_name.parse()?;
        }
        Ok(())
    }

    fn insert(&self, all_session_info: &mut AllSessionInfo, session_key: &String) -> std::result::Result<(), Box<dyn Error>> {
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





