/*
@author: xiao cai niao
@datetime: 2020/3/25
*/

mod packet;
mod session;
use pcap::{Device, Capture};
use structopt::StructOpt;
use std::io::{Seek, SeekFrom, Result};
use std::error::Error;


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

pub fn op_run() -> std::result::Result<(), Box<dyn Error>> {
    let args = Opt::from_args();
    let conf = Config::new(args);
    let mut all_session_info = session::AllSessionInfo::new();
    let devices = Device::list().unwrap();
    'all: for device in devices{
        if &device.name == &conf.ethernet {
            let mut cap = Capture::from_device(device).unwrap()
                .promisc(true)
                .snaplen(65535).open().unwrap();
            //let mut sfile = cap.savefile("acc.pcap").unwrap();

            'inner: while let Ok(packet) = cap.next() {
                if packet.header.len < 73{                                                          // 判断是否为ack/syc包大小
                    continue 'inner;
                }
                let mut my_packet = packet::StreamPacket::new(&packet)?;               // 解析网络包协议部分内容

                if !check_ack_syn(&my_packet){                                                      // 根据flag头再次判断是否为ack/syc包
                    continue 'inner;
                }


                //println!("{:?}",&my_packet.protocol_header);
                if my_packet.check_port(&conf){                                                     // 判断数据流向端口是否为给定的端口
                    //println!("{:?}, tell:{}, len:{}", my_packet.protocol_header, my_packet.data_cur.tell().unwrap(), my_packet.len);
                    //sfile.write(&packet);
                    let session_key = my_packet.set_stream_type(&conf)?;
                    my_packet.get_mysql_protocol_header()?;                                             // 获取mysql协议header部分
                    //println!("{:?}, {:?}, {:?}", my_packet.session_host_info, my_packet.s_type, my_packet.protocol_header);
                    //println!("{:?}", all_session_info);
                    my_packet.op_session_info(&session_key, &mut all_session_info)?;
                }
            }
        }
    }
    Ok(())
}

///
/// 判断协议类型
fn check_ack_syn(my_packet: &packet::StreamPacket) -> bool{
    match my_packet.packet_flag{
        0x12 => false,
        0x02 => false,
        0x18 => true,
        _ => false
    }
}


