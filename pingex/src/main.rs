mod linux;

use crate::linux::packet::WithEchoRequest;
use linux::icmp_socket::IcmpSocketV4;
use linux::packet::{IcmpV4Message, IcmpV4Packet};
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_ADDR: &str = "0.0.0.0";
#[derive(Clone)]
pub struct ArgsData {
    target_addr: Ipv4Addr,
    final_seq: u16,
    interval_milliseconds: u32,
}

#[derive(Clone, Debug)]
pub struct SequenceValidator {
    sequence: u16,
    time: Instant,
    processed: bool,
}

impl SequenceValidator {
    fn new(sequence: u16, time: Instant) -> Self {
        Self {
            sequence,
            time,
            processed: false,
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    let splited_args: Vec<&str> = args[1].split(",").collect();
    let addr = splited_args[0];
    let args_data = ArgsData {
        target_addr: addr.parse().unwrap(),
        final_seq: splited_args[1].parse::<u16>().unwrap(),
        interval_milliseconds: splited_args[2].parse::<u32>().unwrap(),
    };

    let args_data_clone = args_data.clone();

    let packet_handler =
        move |pkt: IcmpV4Packet, send_time: Instant, addr: Ipv4Addr| -> Option<()> {
            let now = Instant::now();
            let elapsed = now - send_time;
            if addr == args_data.target_addr {
                if let IcmpV4Message::EchoReply {
                    identifier: _,
                    sequence,
                    payload: _,
                } = pkt.message
                {
                    eprintln!("{},{},{}", addr, sequence, elapsed.as_micros());
                } else {
                    return None;
                }
                Some(())
            } else {
                eprintln!("Discarding packet from {}", addr);
                None
            }
        };

    let socket_v4 = Arc::new(Mutex::new(IcmpSocketV4::new()));
    socket_v4
        .lock()
        .unwrap()
        .bind(DEFAULT_ADDR.parse().unwrap())
        .unwrap();

    let sequence_validator = Arc::new(Mutex::new(Vec::<SequenceValidator>::new()));

    let socket_v4_clone = socket_v4.clone();
    let socket_v4_clone_read = socket_v4.clone();
    let sequence_validator_clone = sequence_validator.clone();
    let sequence_validator_clone_read = sequence_validator.clone();

    let terminate_flag = Arc::new(AtomicBool::new(false));

    let send_socket_handle = send_socket(
        socket_v4_clone,
        sequence_validator_clone,
        terminate_flag.clone(),
        args_data,
    );

    let read_socket_handle = tokio::task::spawn(read_socket(
        socket_v4_clone_read,
        sequence_validator_clone_read,
        packet_handler,
        args_data_clone,
        terminate_flag.clone(),
    ));

    tokio::join!(send_socket_handle, read_socket_handle);
}

async fn read_socket(
    socket_v4_clone: Arc<Mutex<IcmpSocketV4>>,
    sequence_validator_clone: Arc<Mutex<Vec<SequenceValidator>>>,
    packet_handler: impl Fn(IcmpV4Packet, Instant, Ipv4Addr) -> Option<()> + Send + Sync + 'static,
    args_data: ArgsData,
    terminate_flag: Arc<AtomicBool>,
) {
    loop {
        if terminate_flag.load(Ordering::Relaxed) {
            break;
        }

        let mut seq_validator_guard = sequence_validator_clone.lock().unwrap();
        let seq_validator_guard_filtered: Vec<SequenceValidator> = seq_validator_guard
            .clone()
            .into_iter()
            .filter(|x| x.processed == false)
            .collect();

        if seq_validator_guard_filtered.len() > 0 {
            match socket_v4_clone.lock().unwrap().rcv_from() {
                Ok(tpl) => {
                    let (resp, sock_addr) = tpl;
                    let index = seq_validator_guard
                        .iter()
                        .position(|x| x.sequence == resp.message.get_sequence())
                        .unwrap();

                    let send_time = seq_validator_guard[index].time;

                    // let sequence = seq_validator_guard[index].sequence;
                    if packet_handler(resp, send_time, *sock_addr.as_socket_ipv4().unwrap().ip())
                        .is_some()
                    {
                        seq_validator_guard[index].processed = true;
                        // eprintln!("flag: {}", terminate_flag.load(Ordering::Relaxed));
                        drop(seq_validator_guard);
                        if terminate_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        let find_index = seq_validator_guard
                            .iter()
                            .position(|x| x.processed == false)
                            .unwrap();
                        seq_validator_guard[find_index].processed = true;
                        eprintln!(
                            "{},{},{}",
                            args_data.target_addr, seq_validator_guard[find_index].sequence, -1
                        );

                        // eprintln!("flag: {}", terminate_flag.load(Ordering::Relaxed));
                        drop(seq_validator_guard);
                        if terminate_flag.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    _ => {
                        panic!("Error receiving packet: {:?}", e);
                    }
                },
            }
        } else {
            drop(seq_validator_guard);
            if terminate_flag.load(Ordering::Relaxed) {
                break;
            }
        }
    }
}

async fn send_socket(
    socket_v4_clone: Arc<Mutex<IcmpSocketV4>>,
    sequence_validator_clone: Arc<Mutex<Vec<SequenceValidator>>>,
    terminate_flag: Arc<AtomicBool>,
    args_data: ArgsData,
) {
    loop {
        if terminate_flag.load(Ordering::Relaxed) {
            break;
        }

        let mut sequence_validator_guard = sequence_validator_clone.lock().unwrap();
        let sequence = (sequence_validator_guard.len().clone() as u16);
        let packet = IcmpV4Packet::with_echo_request(
            42,
            sequence,
            vec![
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            ],
        )
        .unwrap();

        // eprintln!("---len: {}", sequence);

        let seq_valitador_entry = SequenceValidator {
            sequence,
            time: Instant::now(),
            processed: false,
        };

        socket_v4_clone
            .lock()
            .unwrap()
            .send_to(args_data.target_addr, packet)
            .unwrap();

        sequence_validator_guard.push(seq_valitador_entry);
        let sequence = sequence_validator_guard.len().clone() as u16;

        if sequence >= args_data.final_seq {
            terminate_flag.store(true, Ordering::Relaxed);
            // eprintln!("flag: {}", terminate_flag.load(Ordering::Relaxed));
            break;
        }

        drop(sequence_validator_guard);

        tokio::time::sleep(Duration::from_millis(
            args_data.interval_milliseconds as u64,
        ))
        .await;
    }
}
