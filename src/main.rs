use pcap::{Device,Capture, Savefile};
use std::io::{Read, Seek, SeekFrom, Result, Cursor};
use std::io;
use std::{thread, time};
use byteorder::{ReadBytesExt, LittleEndian, BigEndian};
mod protocol;



pub trait Tell: Seek {
    fn tell(&mut self) -> Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T> Tell for T where T: Seek { }

#[derive(Debug, Clone)]
struct Ip{
    ip_first: u8,
    ip_two: u8,
    ip_three: u8,
    ip_four: u8
}
impl Ip{
    fn new<R: Read+Seek>(cur: &mut R) -> Ip{
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

    fn format_ip(&self, port: &u16) -> String{
        format!("{}.{}.{}.{}:{}", self.ip_first.clone(), self.ip_two.clone(), self.ip_three.clone(),self.ip_four.clone(), port.clone())
    }
}

#[derive(Debug, Clone)]
struct HostInfo{
    source: Ip,
    destination: Ip,
    source_port: u16,
    destination_port: u16,
    pro: protocol::ClientProtocol
}
impl HostInfo{
    fn new(data: &[u8]) -> HostInfo{
        let mut cur = Cursor::new(data);
        cur.seek(io::SeekFrom::Current(26)).unwrap();
        let source = Ip::new(&mut cur);
        let destination = Ip::new(&mut cur);
        let source_port = cur.read_u16::<BigEndian>().unwrap();
        let destination_port = cur.read_u16::<BigEndian>().unwrap();
        cur.seek(io::SeekFrom::Current(16)).unwrap();
        let code = cur.read_u8().unwrap();
        let mut pro= protocol::ClientProtocol::new(code.clone());
//        match pro{
//            protocol::ClientProtocol::Null => {
//                pro = protocol::ServerProtocl::new(code);
//            }
//            _ =>{}
//        }
        HostInfo{
            source,
            destination,
            source_port,
            destination_port,
            pro
        }
    }

    fn check_port(&self) -> bool{
        //println!("{:?}, {:?}", &self.source_port, &self.destination_port);
        if self.source_port == 3306{
            return true;
        }else if self.destination_port == 3306{
            return true;
        }else{
            return false;
        }
    }
}

fn main() {
    let devices = Device::list().unwrap();
    for device in devices{
        if &device.name == &String::from("eth0"){
            //let c = Device::from(device);
            let mut cap = Capture::from_device(device).unwrap()
                .promisc(true)
                .snaplen(65535).open().unwrap();
            while let Ok(packet) = cap.next() {
                let host_info = HostInfo::new(packet.data);
                if host_info.check_port(){
                    println!("time: {:?} source: {:?}   destination: {:?}",
                             &packet.header, &host_info.source.format_ip(&host_info.source_port),
                             &host_info.destination.format_ip(&host_info.destination_port));
                }
            }
        }
    }
}


