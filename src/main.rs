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
    filename: [u8; 256],
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

    let filename = std::str::from_utf8(&event.filename)
        .unwrap_or("?")
        .trim_end_matches('\0');

    println!(
        "[EXEC] pid={} ppid={} uid={} comm={:16} file={}",
        event.pid, event.ppid, event.uid, comm, filename,
    );

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
