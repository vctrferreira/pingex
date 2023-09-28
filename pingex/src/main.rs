mod linux;

use std::env;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use linux::icmp_socket::IcmpSocketV4;
use linux::packet::{IcmpV4Message, IcmpV4Packet};
use crate::linux::packet::WithEchoRequest;

const DEFAULT_ADDR: &str = "0.0.0.0";

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    let splited_args: Vec<&str> = args[1].split(",").collect();
    let addr = splited_args[0];
    let parsed_addr = addr.parse().unwrap();
    let final_seq = splited_args[1].parse::<u16>().unwrap();
    let interval_milliseconds = splited_args[2].parse::<u32>().unwrap();

    let packet_handler = move |pkt: IcmpV4Packet, send_time: Instant, addr: Ipv4Addr| -> Option<()> {
        let now = Instant::now();
        let elapsed = now - send_time;
        if addr == parsed_addr {
            if let IcmpV4Message::EchoReply {
                identifier: _,
                sequence,
                payload: _,
            } = pkt.message
            {
                // println!(
                //     "Ping {} seq={} time={}ms size={}",
                //     addr,
                //     sequence,
                //     (elapsed.as_micros() as f64) / 1000.0,
                //     payload.len()
                // );

                eprintln!("{},{},{}", addr, sequence, elapsed.as_micros());

            } else {
                // eprintln!("Discarding non-reply {:?}", pkt);
                return None;
            }
            Some(())
        } else {
            eprintln!("Discarding packet from {}", addr);
            None
        }
    };
    
    // eprintln!("addr: {}, seq: {}, interval: {}", addr, seq, interval);
    // eprintln!("{},{},{}", addr, final_seq, interval);

    let mut socket_v4 = IcmpSocketV4::new();
    let mut sequence = 0;

    socket_v4
        .bind(DEFAULT_ADDR.parse().unwrap())
        .unwrap();

    loop {
        let packet = IcmpV4Packet::with_echo_request(42, sequence, vec![
            0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
        ]).unwrap();

        let send_time = Instant::now();

        socket_v4.send_to(parsed_addr, packet).unwrap();
        std::thread::sleep(Duration::from_millis(interval_milliseconds as u64));

        loop {
            let (resp, sock_addr) = match socket_v4.rcv_from() {
                Ok(tpl) => tpl,
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            eprintln!("{},{},{}", addr, sequence, -1);
                            break;
                        }
                        _ => {
                            panic!("Error receiving packet: {:?}", e);
                        }
                    }
                }
            };
            if packet_handler(resp, send_time, *sock_addr.as_socket_ipv4().unwrap().ip()).is_some()
            {
                break;
            }
        }
        sequence = sequence.wrapping_add(1);

        if sequence >= final_seq {
            break;
        }
    }
}



