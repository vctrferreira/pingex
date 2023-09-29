use std::{net::{Ipv4Addr, SocketAddr, IpAddr}, time::Duration, mem::MaybeUninit};
use socket2::{Socket, SockAddr, Domain, Type, Protocol};

use super::packet::IcmpV4Packet;


fn ip_to_socket(ip: &IpAddr) -> SocketAddr {
    SocketAddr::new(*ip, 0)
}

pub struct IcmpConfigV4 {
    pub timeout: Option<Duration>,
}
pub struct IcmpSocketV4 {
    buffer: Vec<u8>,
    pub socket: Socket,
    config: IcmpConfigV4,
}

impl IcmpSocketV4 {
    pub fn new() -> Self {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).unwrap();
        Self {
            buffer: vec![0; 1024],
            socket,
            config: IcmpConfigV4 {
                timeout: Some(Duration::from_secs(5)),
            },
        }
    }

    pub fn bind(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        let sock = ip_to_socket(&IpAddr::V4(addr.clone()));
        self.socket.bind(&(sock.into()))?;
        Ok(())
    }

    pub fn send_to(&mut self, dest: Ipv4Addr, packet: IcmpV4Packet) -> std::io::Result<()> {
        let dest = ip_to_socket(&IpAddr::V4(dest));
        self.socket
            .send_to(&packet.with_checksum().get_bytes(true), &(dest.into()))?;
        Ok(())
    }

    pub fn rcv_from(&mut self) -> std::io::Result<(IcmpV4Packet, SockAddr)> {
        self.socket.set_read_timeout(self.config.timeout)?;
        let mut buf =
            unsafe { &mut *(self.buffer.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        let (read_count, addr) = self.socket.recv_from(&mut buf)?;
        Ok((self.buffer[0..read_count].try_into().unwrap(), addr))
    }

}

#[cfg(test)]
mod test {

}