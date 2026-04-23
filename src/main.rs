// SPDX-License-Identifier: Apache-2.0 OR MIT

mod skel {
    include!(concat!(env!("OUT_DIR"), "/exec_tracker.skel.rs"));
}
mod correlator;

use skel::*;

use serde_json;
use std::mem::MaybeUninit;
use std::time::Duration;

use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;

#[repr(C)]
#[derive(Debug)]
struct PwEvent {
    timestamp_ns: u64,
    event_type: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: [u8; 16],
    payload: [u8; 256],
}

unsafe impl Plain for PwEvent {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let builder = ExecTrackerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    eprintln!("phantomwatch running. Press Ctrl-C to stop.");

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

                eprintln!(
                    "[EXEC] pid={} ppid={} comm={} file={}",
                    event.pid, event.ppid, comm, filename,
                );

                if let Some(alert) =
                    corr.handle_exec(event.pid, event.ppid, event.uid, &comm, &filename)
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

                eprintln!(
                    "[CONNECT] pid={} comm={} dest={}:{}",
                    event.pid, comm, ip, port,
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

                eprintln!(
                    "[DUP2] pid={} comm={} oldfd={} newfd={}",
                    event.pid, comm, oldfd, newfd,
                );

                corr.handle_dup2(event.pid, event.ppid, event.uid, &comm, newfd);
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
