// SPDX-License-Identifier: Apache-2.0 OR MIT

mod skel {
    include!(concat!(env!("OUT_DIR"), "/exec_tracker.skel.rs"));
}
mod correlator;

use skel::*;

use clap::{Parser, Subcommand};
use serde_json;
use std::mem::MaybeUninit;
use std::time::Duration;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;

#[derive(Parser)]
#[command(name = "phantomwatch")]
#[command(about = "eBPF-based fileless malware detector for Linux")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the detector
    Run,
    /// Check kernel compatibility
    Check,
}

#[repr(C)]
#[derive(Debug)]
struct PwEvent {
    timestamp_ns: u64,
    event_type: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    payload: [u8; 512],
}

unsafe impl Plain for PwEvent {}

fn check_kernel() {
    print!("Kernel: ");
    match std::fs::read_to_string("/proc/version") {
        Ok(v) => println!("{}", v.split_whitespace().nth(2).unwrap_or("unknown")),
        Err(_) => println!("unknown"),
    }

    print!("BTF:     ");
    if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        println!("available");
    } else {
        println!("NOT available (required)");
    }

    print!("BPF-LSM: ");
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(lsm) => {
            if lsm.contains("bpf") {
                print!("enabled ({})", lsm.trim());
            } else {
                println!("NOT enabled (add 'lsm=...,bpf' to boot params)");
            }
        }
        Err(_) => println!("unknown"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match cli.command {
        Commands::Check => {
            check_kernel();
            return Ok(());
        }
        Commands::Run => {}
    }
    let builder = ExecTrackerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    info!("phantomwatch running. Press Ctrl-C to stop.");

    let correlator = std::sync::Arc::new(std::sync::Mutex::new(correlator::Correlator::new(30)));

    let corr = correlator.clone();
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, move |data: &[u8]| {
        let event = match plain::from_bytes::<PwEvent>(data) {
            Ok(e) => e,
            Err(_) => return 0,
        };

        let comm = std::str::from_utf8(&event.comm)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string();

        let mut corr = corr.lock().unwrap();

        match event.event_type {
            1 => {
                let filename = std::str::from_utf8(&event.payload)
                    .unwrap_or("?")
                    .trim_end_matches('\0')
                    .to_string();
                let argv = std::str::from_utf8(&event.payload[256..512])
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();

                debug!(
                    pid = event.pid,
                    ppid = event.ppid,
                    comm = comm,
                    file = filename,
                    "exec event"
                );

                if let Some(alert) =
                    corr.handle_exec(event.pid, event.ppid, event.uid, &comm, &filename, &argv)
                {
                    let json = serde_json::to_string(&alert).unwrap();
                    println!("{}", json)
                }
            }
            2 => {
                let ip = std::net::Ipv4Addr::new(
                    event.payload[0],
                    event.payload[1],
                    event.payload[2],
                    event.payload[3],
                );
                let port = u16::from_le_bytes([event.payload[4], event.payload[5]]);

                debug!(
                    pid = event.pid,
                    comm = comm,
                    dest = format!("{}:{}", ip, port),
                    "connect event"
                );

                corr.handle_connect(event.pid, event.ppid, event.uid, &comm, ip, port);
            }
            3 => {
                let oldfd = i32::from_le_bytes([
                    event.payload[0],
                    event.payload[1],
                    event.payload[2],
                    event.payload[3],
                ]);
                let newfd = i32::from_le_bytes([
                    event.payload[4],
                    event.payload[5],
                    event.payload[6],
                    event.payload[7],
                ]);

                debug!(
                    pid = event.pid,
                    comm = comm,
                    oldfd = oldfd,
                    newfd = newfd,
                    "dup2 event"
                );

                corr.handle_dup2(event.pid, event.ppid, event.uid, &comm, newfd);
            }
            4 => {
                debug!(pid = event.pid, comm = comm, "memfd_create event");
                corr.handle_memfd(event.pid, event.ppid, event.uid, &comm);
            }
            5 => {
                debug!(pid = event.pid, comm = comm, "execveat AT_EMPTY_PATH event");
                if let Some(alert) = corr.handle_execveat(event.pid, event.ppid, event.uid, &comm) {
                    let json = serde_json::to_string(&alert).unwrap();
                    println!("{}", json);
                }
            }
            6 => {
                let request = u32::from_le_bytes([
                    event.payload[0],
                    event.payload[1],
                    event.payload[2],
                    event.payload[3],
                ]);
                let target_pid = u32::from_le_bytes([
                    event.payload[4],
                    event.payload[5],
                    event.payload[6],
                    event.payload[7],
                ]);

                debug!(
                    pid = event.pid,
                    comm = comm,
                    target_pid = target_pid,
                    request = request,
                    "ptrace event"
                );

                if let Some(alert) =
                    corr.handle_ptrace(event.pid, event.ppid, event.uid, &comm, target_pid)
                {
                    let json = serde_json::to_string(&alert).unwrap();
                    println!("{}", json);
                }
            }
            _ => {}
        }

        0
    })?;
    let rb = rb_builder.build()?;

    loop {
        rb.poll(Duration::from_millis(100))?;
        correlator.lock().unwrap().cleanup_stale();
    }
}
