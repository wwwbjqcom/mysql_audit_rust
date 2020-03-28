use pcap::{Device, Capture, Packet};
use structopt::StructOpt;
mod protocol;
mod opacket;

use std::io::{Seek, SeekFrom, Result, Cursor};
use std::io;
use crate::protocol::ClientProtocol;
use byteorder::ReadBytesExt;


pub trait Tell: Seek {
    fn tell(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T> Tell for T where T: Seek { }

#[derive(Debug, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
pub struct Opt {
    #[structopt(long = "host", short= "h", help="本机地址, 默认127.0.0.1")]
    pub host: Option<String>,

    #[structopt(long = "dtype", short= "t", help="本机所属方向(发送方/接受方), 可佩src/des, 默认des")]
    pub dtype: Option<String>,

    #[structopt(long = "port", short= "p", help="监听那个端口的数据流，默认所有")]
    pub port: Option<String>,

    #[structopt(long = "ethernet", short= "e", help="监听的网卡，默认eth0")]
    pub ethernet: Option<String>,

}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub dtype: String,
    pub ethernet: String,
    pub port: u16,
}

impl Config{
    pub fn new(args: Opt) -> Config {
        let mut host = String::from("127.0.0.1");
        let mut dtype = String::from("des");
        let mut ethernet = String::from("eth0");
        let mut port : u16 = 0;

        match args.host {
            Some(t) => host = t,
            _ => {}
        }

        match args.dtype {
            Some(t) => dtype = t,
            _ => {}
        }

        match args.port {
            Some(t) => {port = t.parse().unwrap()}
            _ => {}
        }

        match args.ethernet {
            Some(t) => ethernet = t,
            _ => {}
        }

        Config{
            host,
            dtype,
            port,
            ethernet
        }
    }
}

fn main() {
    let args = Opt::from_args();
    let conf = Config::new(args);
    let mut all_session_info = opacket::AllSessionInfo::new();
    let devices = Device::list().unwrap();
    'all: for device in devices{
        if &device.name == &conf.ethernet {
            let mut cap = Capture::from_device(device).unwrap()
                .promisc(true)
                .snaplen(65535).open().unwrap();
            'inner: while let Ok(packet) = cap.next() {
                if packet.header.len < 73{
                    continue 'inner;
                }

                let mut cur = Cursor::new(packet.data);
                let ts = opacket::UnixTime::new(&packet.header.ts).unwrap();
                let mut host_info = opacket::HostInfo::new(&mut cur, &ts);
                if !check_ack_syn(&mut cur){
                    continue 'inner;
                }
                if host_info.check_port(&conf.port){
                    println!("{:?}", &all_session_info);
                    host_info.check_request_respons(&conf, &mut all_session_info, &mut cur).unwrap();
                }
            }
        }
    }
}

///
/// 判断协议类型
fn check_ack_syn(cur: &mut Cursor<&[u8]>) -> bool{
    cur.seek(io::SeekFrom::Current(9)).unwrap();
    let flags = cur.read_u8().unwrap();
    match flags{
        0x12 => false,
        0x02 => false,
        _ => true,
    }
}


