use tun_tap::{Iface, Mode};

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let nic = Iface::new("tun0", Mode::Tun).expect("");
    //to receive icmp we need to set buffer size to 1504 because icmp packet size is 1500
    let mut buffer = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buffer[..])?;
        let bytes = &buffer[..nbytes];
        let flags = u16::from_be_bytes([bytes[0], bytes[1]]);
        let proto = u16::from_be_bytes([bytes[2], bytes[3]]);

        if proto != 0x0800 {
            // eprintln!("not ipv4");
            continue;
        }
        
        
        
        eprintln!("read {} bytes: {:?}", nbytes, bytes);
    }
    Ok(())
}
