mod linux;

use crate::linux::packet::WithEchoRequest;
use linux::icmp_socket::IcmpSocketV4;
use linux::packet::{IcmpV4Message, IcmpV4Packet};
use std::env;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

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

enum ErrorType {
    Timeout = -1,
}

fn get_args(args: String) -> ArgsData {
    let splited_args: Vec<&str> = args.split(",").collect();
    let addr = splited_args[0];
    ArgsData {
        target_addr: addr.parse().unwrap(),
        final_seq: splited_args[1].parse::<u16>().unwrap(),
        interval_milliseconds: splited_args[2].parse::<u32>().unwrap(),
    }
}

async fn pingex(
    args_data: ArgsData,
    success_handler: impl Fn(Ipv4Addr, u16, Duration),
    error_handler: impl Fn(Ipv4Addr, u16, ErrorType),
) {
    let args_data_clone = args_data.clone();

    let socket_v4 = Arc::new(Mutex::new(IcmpSocketV4::new()));
    socket_v4
        .lock()
        .await
        .bind(DEFAULT_ADDR.parse().unwrap())
        .unwrap();

    let sequence_validator = Arc::new(Mutex::new(Vec::<SequenceValidator>::new()));

    let socket_v4_clone: Arc<Mutex<IcmpSocketV4>> = socket_v4.clone();
    let socket_v4_clone_read = socket_v4.clone();
    let sequence_validator_clone = sequence_validator.clone();
    let sequence_validator_clone_read = sequence_validator.clone();

    let terminate_flag = Arc::new(AtomicBool::new(false));
    let terminate_flag_clone = terminate_flag.clone();

    let send_socket_handle = send_socket(
        socket_v4_clone,
        sequence_validator_clone,
        terminate_flag.clone(),
        args_data,
    );

    let read_socket_handle = read_socket(
        socket_v4_clone_read,
        sequence_validator_clone_read,
        success_handler,
        error_handler,
        args_data_clone,
        terminate_flag_clone.clone(),
    );

    tokio::join!(send_socket_handle, read_socket_handle);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let args_data = get_args(args[1].clone());

    let success_handler = |addr: Ipv4Addr, sequence: u16, elapsed: Duration| {
        eprintln!("{},{},{}", addr, sequence, elapsed.as_micros());
    };
    let error_handler = |addr: Ipv4Addr, sequence: u16, error_type: ErrorType| {
        eprintln!("{},{},{}", addr, sequence, error_type as i32);
    };

    pingex(args_data, success_handler, error_handler).await;
}

async fn read_socket(
    socket_v4_clone: Arc<Mutex<IcmpSocketV4>>,
    sequence_validator_clone: Arc<Mutex<Vec<SequenceValidator>>>,
    success_handler: impl Fn(Ipv4Addr, u16, Duration),
    error_handler: impl Fn(Ipv4Addr, u16, ErrorType),
    args_data: ArgsData,
    terminate_flag: Arc<AtomicBool>,
) {
    loop {
        if terminate_flag.load(Ordering::Relaxed) {
            break;
        }

        let mut seq_validator_guard = sequence_validator_clone.lock().await;
        let seq_validator_guard_filtered: Vec<SequenceValidator> = seq_validator_guard
            .clone()
            .into_iter()
            .filter(|x| x.processed == false)
            .collect();

        if seq_validator_guard_filtered.len() > 0 {
            match socket_v4_clone.lock().await.rcv_from() {
                Ok(tpl) => {
                    let (resp, sock_addr) = tpl;
                    let index = seq_validator_guard
                        .iter()
                        .position(|x| x.sequence == resp.message.get_sequence());
                    
                    if index.is_none() {
                        continue;
                    }

                    let index = index.unwrap();

                    let send_time = seq_validator_guard[index].time;

                    let now = Instant::now();
                    let elapsed = now - send_time;
                    let addr = *sock_addr.as_socket_ipv4().unwrap().ip();
                    if addr == args_data.target_addr {
                        if let IcmpV4Message::EchoReply {
                            identifier: _,
                            sequence,
                            payload: _,
                        } = resp.message
                        {
                            success_handler(addr, sequence, elapsed);
                            seq_validator_guard[index].processed = true;
                            if terminate_flag.load(Ordering::Relaxed) {
                                break;
                            }

                            if seq_validator_guard[index].sequence >= args_data.final_seq {
                                terminate_flag.store(true, Ordering::Relaxed);
                                break;
                            }

                            drop(seq_validator_guard);
                            continue;
                        }
                    }
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        let find_index = seq_validator_guard
                            .iter()
                            .position(|x| x.processed == false)
                            .unwrap();

                        let send_time = seq_validator_guard[find_index].time;

                        if send_time.elapsed().as_millis() > 5000 {
                            error_handler(
                                args_data.target_addr,
                                seq_validator_guard[find_index].sequence,
                                ErrorType::Timeout,
                            );

                            seq_validator_guard[find_index].processed = true;

                            if seq_validator_guard[find_index].sequence >= args_data.final_seq {
                                terminate_flag.store(true, Ordering::Relaxed);
                                break;
                            }
                            drop(seq_validator_guard);

                            continue;
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

        let mut sequence_validator_guard = sequence_validator_clone.lock().await;
        let sequence: u16 = u16::try_from(sequence_validator_guard.len()).unwrap();
        let packet = IcmpV4Packet::with_echo_request(
            42,
            sequence,
            vec![
                0x20, 0x20, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x66, 0x6c, 0x65, 0x73, 0x68, 0x20,
            ],
        )
        .unwrap();

        let seq_valitador_entry = SequenceValidator {
            sequence,
            time: Instant::now(),
            processed: false,
        };

        socket_v4_clone
            .lock()
            .await
            .send_to(args_data.target_addr, packet)
            .unwrap();

        sequence_validator_guard.push(seq_valitador_entry);

        if sequence >= args_data.final_seq {
            break;
        }

        drop(sequence_validator_guard);

        tokio::time::sleep(Duration::from_millis(
            args_data.interval_milliseconds as u64,
        ))
        .await;
    }
}

#[cfg(test)]
mod tests {
    use crate::get_args;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[tokio::test]
    async fn should_have_timeout() {
        let success_handler = |_addr: Ipv4Addr, _sequence: u16, _elapsed: Duration| {
            assert!(false);
        };

        let error_handler = |_addr: Ipv4Addr, _sequence: u16, error_type: super::ErrorType| {
            println!("error type");
            assert_eq!(error_type as i32, -1);
        };

        let args_data = get_args("192.6.6.6,1,1000".to_string());

        super::pingex(args_data, success_handler, error_handler).await;
    }

    #[tokio::test]
    async fn should_have_success() {
        let success_handler = |_addr: Ipv4Addr, _sequence: u16, elapsed: Duration| {
            assert!(elapsed.as_micros() > 0);
        };

        let error_handler = |_addr: Ipv4Addr, _sequence: u16, _error_type: super::ErrorType| {
            assert!(false);
        };

        let args_data = get_args("127.0.0.1,1,1000".to_string());
        super::pingex(args_data, success_handler, error_handler).await;
    }
}
