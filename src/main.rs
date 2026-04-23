// SPDX-License-Identifier: Apache-2.0 OR MIT

mod skel {
    include!(concat!(env!("OUT_DIR"), "/exec_tracker.skel.rs"));
}

use skel::*;

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

fn handle_event(data: &[u8]) -> i32 {
    let event = match plain::from_bytes::<PwEvent>(data) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    let comm = std::str::from_utf8(&event.comm)
        .unwrap_or("?")
        .trim_end_matches('\0');

    match event.event_type {
        1 => {
            let filename = std::str::from_utf8(&event.payload)
                .unwrap_or("?")
                .trim_end_matches('\0');
            println!(
                "[EXEC] pid={} ppid={} uid={} comm={} file={}",
                event.pid, event.ppid, event.uid, comm, filename,
            );
        }
        2 => {
            let ip = [
                event.payload[0],
                event.payload[1],
                event.payload[2],
                event.payload[3],
            ];
            let port = u16::from_le_bytes([event.payload[4], event.payload[5]]);
            println!(
                "[CONNECT] pid={} uid={} comm={} dest={}.{}.{}.{}:{}",
                event.pid, event.uid, comm, ip[0], ip[1], ip[2], ip[3], port,
            );
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
            println!(
                "[DUP2] pid={} uid={} comm={} oldfd={} newfd={}",
                event.pid, event.uid, comm, oldfd, newfd,
            );
        }
        _ => {}
    }

    0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let builder = ExecTrackerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    eprintln!("phantomwatch running. Press Ctrl-C to stop.");

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, handle_event)?;
    let rb = rb_builder.build()?;

    loop {
        rb.poll(Duration::from_millis(100))?;
    }
}
